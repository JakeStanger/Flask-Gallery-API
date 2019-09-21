from flask_login import UserMixin
from .db import database

db = database()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=True, nullable=False)

    can_edit = db.Column(db.Boolean, default=False)
    can_upload = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %s>' % self.username


image_tag = db.Table('image_tag', db.metadata,
                     db.Column('image_id', db.ForeignKey('images.id'), primary_key=True),
                     db.Column('tag_id', db.ForeignKey('tags.id'), primary_key=True))


class Image(db.Model):
    __tablename__ = 'images'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    filename = db.Column(db.String(128), nullable=False, unique=True)

    width = db.Column(db.Integer)
    height = db.Column(db.Integer)
    exposure = db.Column(db.Float)  # ExposureTime[0] (in s)
    focal_length = db.Column(db.Integer)  # FocalLength[0] / FocalLength[1] (in mm)
    aperture = db.Column(db.Integer)  # FNumber[0] / FNumber[1]
    iso = db.Column(db.Integer)  # ISOSpeedRatings
    camera_model = db.Column(db.String(32))  # Model

    taken_time = db.Column(db.DateTime)  # DateTimeOriginal

    deleted = db.Column(db.Boolean)

    location_key = db.Column(db.Integer, db.ForeignKey('locations.id'))

    location = db.relationship('Location', back_populates='images')
    tags = db.relationship('Tag', secondary=image_tag, back_populates='images')

    def __repr__(self):
        return '<Image %s>' % self.name


class Location(db.Model):
    __tablename__ = 'locations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False, unique=True)
    images = db.relationship('Image', back_populates='location')

    def __repr__(self):
        return '<Location %s>' % self.name


class Tag(db.Model):
    __tablename__ = 'tags'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False, unique=True)
    images = db.relationship('Image', secondary=image_tag, back_populates='tags')

    def __repr__(self):
        return '<Tag %s>' % self.name
