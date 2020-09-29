# -*- encoding: utf-8 -*-
"""
Python Application
Developer : ANAND VITTHAL ADAKE
Gmail     : anandadake007@gmail.com
GitHub    : anandadake/flask-jwt-based-user-authorization
"""

class Config(object):
    # Configuration base, for all environments.
    DEBUG = False
    TESTING = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///application.db'
    SECRET_KEY = "SECRET_KEY"
    CSRF_ENABLED = True


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///application.db'


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'oracle://username:password@hostname:1521/instance_name/blasim'


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost:5432/blasim'