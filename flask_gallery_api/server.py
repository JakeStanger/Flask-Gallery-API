import os
import re
import traceback
from fractions import Fraction
from functools import wraps

import pkg_resources
from flask import Flask, render_template, request, send_file, make_response, jsonify, url_for, flash
from flask_login import LoginManager, login_required, login_user, logout_user
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token, \
    jwt_refresh_token_required
from werkzeug.datastructures import FileStorage
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename, redirect
from PIL import ExifTags, ImageEnhance
import PIL.Image
from datetime import datetime
import json
import requests

# Module resolution is weird depending on how program starts
try:
    from .database import *
except ModuleNotFoundError:
    from database import *

with open('server_settings.json', 'r') as f:
    settings = json.loads(f.read())

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = settings['database_uri']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.update(SECRET_KEY=settings['secret_key'])
app.config['JWT_SECRET_KEY'] = settings['secret_key']

CORS(app)

jwt = JWTManager(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

init(app)


def to_fraction(num: float):
    if not num:
        return None
    return str(Fraction(num).limit_denominator(max_denominator=100))


app.jinja_env.globals['to_fraction'] = to_fraction


def get_friendly_name(filename: str) -> str:
    return filename.split('.')[0].replace('_', ' ').replace('-', ' ').title().strip()


def get_current_user() -> User:
    from flask_login import current_user
    return current_user


@login_manager.user_loader
def get_user(user_id):
    if re.match('^[0-9]$', user_id):
        user = session().query(User).filter_by(id=user_id).first()
    else:
        user = session().query(User).filter_by(username=user_id).first()
    return user


def require_can_upload(func):
    # @login_required
    @jwt_required
    @wraps(func)
    def admin_wrapper(*args, **kwargs):
        user = get_user(get_jwt_identity())
        if not user.can_upload:
            # logger.info("User %s attempted to send an admin-only request without admin privileges.")
            return make_response("Only administrators can do this.", 401)

        return func(*args, **kwargs)

    return admin_wrapper


def require_can_edit(func):
    # @login_required
    @jwt_required
    @wraps(func)
    def admin_wrapper(*args, **kwargs):
        user = get_user(get_jwt_identity())
        if not user.can_edit:
            # logger.info("User %s attempted to send an admin-only request without admin privileges.")
            return make_response("Only administrators can do this.", 401)

        return func(*args, **kwargs)

    return admin_wrapper


# @app.route('/', methods=['GET'])
# def index():
#     return render_template('main.html', title='Home')

@app.route('/user', methods=['GET'])
@jwt_required
def user():
    # user = get_current_user()
    #
    # if not user.is_authenticated:
    username = get_jwt_identity()
    if not username:
        user = get_current_user()
    else:
        user = get_user(username)

    if user.is_authenticated:
        return jsonify({
            'username': user.username,
            'can_edit': user.can_edit,
            'can_upload': user.can_upload
        })
    else:
        return jsonify({
            'username': None,
            'can_edit': False,
            'can_upload': False
        })


@app.route('/image', methods=['GET'])
def images():
    tags = request.args.get('tags')
    locations = request.args.get('locations')
    query = request.args.get('query')

    if tags:
        tags = tags.split(',')
    if locations:
        locations = locations.split(',')

    base_query = session().query(Image).order_by(Image.taken_time.desc())

    if tags and len(tags) > 0:
        base_query = base_query.filter(Image.tags.any(
            Tag.name.in_(tags)))

    if locations and len(locations) > 0:
        base_query = base_query.filter(
            Image.location.has(Location.name.in_(locations)))

    if query and len(query) > 0:
        base_query = base_query.filter(Image.name.ilike('%' + query + '%'))

    images = base_query.all()

    return jsonify([*map(lambda im: {
        "name": im.name,
        "description": im.description,
        "filename": im.filename,
        "tags": [*map(lambda t: t.name, im.tags)],
        "location": im.location.name if im.location else None,
        "taken_time": im.taken_time,
        "width": im.width,
        "height": im.height
    }, images)])


@app.route('/tag', methods=['GET'])
def tags():
    tags = session().query(Tag).all()
    return jsonify(*map(lambda t: t.name, [*filter(lambda t: len(t.images) > 0, tags)]))


@app.route('/location', methods=['GET'])
def locations():
    locations = session().query(Location).all()
    return jsonify(*map(lambda l: l.name, locations))


@app.route('/image/<string:filename>/info', methods=['GET'])
def image(filename: str):
    print(filename)
    try:
        im = session().query(Image).filter_by(filename=filename.strip()).one()
        return jsonify({
            "name": im.name,
            "description": im.description,
            "filename": im.filename,
            "tags": [*map(lambda t: t.name, im.tags)],
            "location": im.location.name if im.location else None,
            "taken_time": im.taken_time,
            "width": im.width,
            "height": im.height,
            "exposure": to_fraction(im.exposure),
            "focal_length": im.focal_length,
            "aperture": im.aperture,
            "iso": im.iso
        })
    except Exception as e:
        traceback.print_exc()
        return make_response("404", 404)


@app.route('/image/<string:filename>', methods=['GET'])
@app.route('/image/<string:filename>/<full>', methods=['GET'])
def image_view(filename: str, full: bool = False):
    try:
        image = session().query(Image).filter_by(filename=filename).one()
        return send_file(os.path.join(settings['upload_directory'], image.filename + ('.thumb' if not full else '.marked')),
                         mimetype='image/jpeg')
    except Exception as e:
        traceback.print_exc()
        return make_response("404", 404)


@app.route('/image/<string:filename>/edit', methods=['GET', 'POST'])
@app.route('/image/edit', methods=['POST'])
@require_can_edit
def image_edit(filename: str = None):
    if not filename:
        filename = secure_filename(request.json.get('filename'))
    try:
        image = session().query(Image).filter_by(filename=filename).one()
        if request.method == 'POST':
            get = lambda x: request.json.get(x)

            if get('name'):
                image.name = get('name')
            if get('description'):
                image.description = get('description')

            if get('tags'):
                tag_list = []
                for tag in get('tags'):
                    tag_name = tag.lower()
                    db_tag = session().query(Tag).filter_by(name=tag_name).first()
                    if db_tag:
                        tag_list.append(db_tag)
                    else:
                        db_tag = Tag(name=tag_name)
                        session().add(db_tag)
                        tag_list.append(session().query(Tag).filter_by(name=tag_name).one())

                image.tags = tag_list

            if get('location'):
                location_name = get('location').title()
                db_location = session().query(Location).filter_by(name=location_name).first()
                if db_location:
                    image.location = db_location
                else:
                    db_location = Location(name=location_name)
                    session().add(db_location)
                    image.location = session().query(Location).filter_by(name=location_name).one()

            session().commit()

            flash("Image succesfully uploaded", category='success')
            # return redirect(url_for('index'))
            return jsonify({'msg': 'Success'})
        else:
            tags = [*map(lambda t: t.name, session().query(Tag).all())]
            image_tags = [*map(lambda t: t.name, image.tags)]
            locations = [*map(lambda l: l.name, session().query(Location).all())]
            return render_template('edit_image.html', image=image, tags=tags, locations=locations,
                                   image_tags=image_tags, title='Edit %s' % image.name)
    except Exception as e:
        traceback.print_exc()
        flash("The image could not be found. This is a bug! " + str(e), category='error')
        return redirect(request.referrer)


def reduce_opacity(im, opacity):
    """Returns an image with reduced opacity."""
    assert opacity >= 0 and opacity <= 1
    if im.mode != 'RGBA':
        im = im.convert('RGBA')
    else:
        im = im.copy()
    alpha = im.split()[3]
    alpha = ImageEnhance.Brightness(alpha).enhance(opacity)
    im.putalpha(alpha)
    return im


def watermark(im, mark, position, opacity: float=1):
    """Adds a watermark to an image."""
    if opacity < 1:
        mark = reduce_opacity(mark, opacity)
    if im.mode != 'RGBA':
        im = im.convert('RGBA')
    # create a transparent layer the size of the image and draw the
    # watermark in that layer.
    layer = PIL.Image.new('RGBA', im.size, (0, 0, 0, 0))
    if position == 'tile':
        for y in range(0, im.size[1], mark.size[1]):
            for x in range(0, im.size[0], mark.size[0]):
                layer.paste(mark, (x, y))
    elif position == 'scale':
        # scale, but preserve the aspect ratio
        ratio = min(
            float(im.size[0]) / mark.size[0], float(im.size[1]) / mark.size[1])
        w = int(mark.size[0] * ratio)
        h = int(mark.size[1] * ratio)
        mark = mark.resize((w, h))
        layer.paste(mark, ((im.size[0] - w) / 2, (im.size[1] - h) / 2))
    else:
        layer.paste(mark, position)
    # composite the watermark with the layer
    return PIL.Image.composite(layer, im, layer).convert("RGB")


@app.route('/upload', methods=['GET', 'POST', 'DELETE'])
@require_can_upload
def upload():
    if request.method == 'GET':
        locations = session().query(Location).all()
        tags = session().query(Tag).all()
        return render_template('upload.html', locations=[*map(lambda location: location.name, locations)],
                               tags=[*map(lambda tag: tag.name, tags)], title='Upload')

    elif request.method == 'POST':
        file: FileStorage = request.files['file']

        if 'image/' in file.mimetype:
            filename = secure_filename(file.filename)
            filepath = os.path.join(settings['upload_directory'], filename)
            if not os.path.exists(filepath):
                try:
                    file.save(filepath)

                    pil_img = PIL.Image.open(filepath)

                    width, height = pil_img.size

                    # Get EXIF data
                    if hasattr(pil_img, '_getexif'):
                        exif_data = pil_img._getexif()
                        if exif_data:
                            exif = {
                                ExifTags.TAGS[k]: v
                                for k, v in exif_data.items()
                                if k in ExifTags.TAGS
                            }
                        else:
                            exif = None
                    else:
                        exif = None

                    # Save thumbnail
                    thumb = pil_img.copy()
                    thumb.thumbnail((360, 10000), PIL.Image.ANTIALIAS)
                    thumb.save(filepath + ".thumb", "JPEG")

                    # Save watermarked version
                    mark = PIL.Image.open(pkg_resources.resource_filename('flask_gallery_api', 'res/overlay.png'))
                    watermark(pil_img, mark, 'tile', 0.1).save(filepath + ".marked", "JPEG")

                    # Get image_view tags
                    api_key = settings['imagga_api_key']
                    api_secret = settings['imagga_api_secret']
                    image_url = '%s/%s' % (settings['external_url'], filename)

                    tag_list = []
                    response = requests.get(
                        'https://api.imagga.com/v2/tags?image_url=%s&limit=5&threshold=25' % image_url,
                        auth=(api_key, api_secret))
                    try:
                        response.raise_for_status()
                    except requests.exceptions.HTTPError as error:
                        print(error)

                    if response.ok:
                        tags = [*map(lambda x: x['tag']['en'],
                                     response.json()['result']['tags'])][:5]

                        for tag in tags:
                            db_tag = session().query(Tag).filter_by(name=tag).first()
                            if db_tag:
                                tag_list.append(db_tag)
                            else:
                                db_tag = Tag(name=tag)
                                session().add(db_tag)
                                tag_list.append(session().query(Tag).filter_by(name=tag).first())
                    else:
                        print("Error occurred while receiving tags")
                        print(response.status_code, response.text)

                    friendly_name = get_friendly_name(filename)

                    db_image = Image(name=get_friendly_name(friendly_name),
                                              filename=filename,
                                              width=width, height=height,
                                              tags=tag_list)

                    def get_exif_key(keyname: str, div: bool = False):
                        if keyname in exif:
                            if div:
                                try:
                                    return exif[keyname][0] / exif[keyname][1]
                                except:
                                    return None
                            return exif[keyname]
                        else:
                            return None

                    if exif:
                        db_image.exposure = get_exif_key('ExposureTime', True)
                        db_image.focal_length = get_exif_key('FocalLength', True)
                        db_image.aperture = get_exif_key('FNumber', True)
                        db_image.iso = get_exif_key('ISOSpeedRatings')
                        db_image.camera_model = get_exif_key('Model')
                        if get_exif_key('DateTimeOriginal'):
                            db_image.taken_time = datetime.strptime(get_exif_key('DateTimeOriginal'),
                                                                    '%Y:%m:%d %H:%M:%S')

                    session().add(db_image)
                    session().commit()
                    # os.remove(filepath)
                except Exception as e:
                    traceback.print_exc()
                    os.remove(filepath)
                    return make_response("An unknown error occurred: " + str(e), 500)

            else:
                return make_response("An image with this name already exists", 400)  # TODO JSON

            return make_response(jsonify({'name': friendly_name, 'filename': filename, 'tags': tags}), 201)

    elif request.method == 'DELETE':
        print(request.form, request.headers)
        return make_response("Files deleted", 501)  # TODO: Add delete method


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not request.is_json:
            username = request.form.get('username').lower()
            password = request.form.get('password')
            remember = request.form.get('remember') is not None
            user = get_user(username)

            if user:
                if check_password_hash(user.password, password):
                    login_user(user, remember)
                    return redirect(request.args.get('next') or '/')
                else:
                    flash("Incorrect password", category='error')
            else:
                flash("That username does not exist", category='error')
        else:
            username = request.json.get('username', None)
            password = request.json.get('password', None)

            if not username:
                return jsonify({"msg": "Missing username parameter"}), 400
            if not password:
                return jsonify({"msg": "Missing password parameter"}), 400

            user = get_user(username)
            if user and check_password_hash(user.password, password):
                access_token = create_access_token(identity=username)
                refresh_token = create_refresh_token(identity=username)

                return jsonify(access_token=access_token, refresh_token=refresh_token), 200
            else:
                return jsonify({"msg": "Bad username or password"}), 401

    return render_template('login.html', title='Login')


@app.route('/signup', methods=['POST'])
def sign_up():
    data = request.form or request.json
    username = data.get('username').lower()
    password = data.get('password')
    remember = request.form.get('remember') is not None

    # noinspection PyArgumentList
    user = User(username=username, password=generate_password_hash(password))
    session().add(user)
    session().commit()

    user = get_user(username)
    login_user(user, remember)
    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200


def run():
    app.run()


if __name__ == '__main__':
    app.run()

