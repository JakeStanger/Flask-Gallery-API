from flask_sqlalchemy import SQLAlchemy

db: SQLAlchemy = SQLAlchemy()


def init(app):
    with app.app_context():
        db.init_app(app)
        db.create_all()


def session():
    return db.session


def database():
    return db
