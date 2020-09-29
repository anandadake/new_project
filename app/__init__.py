# -*- encoding: utf-8 -*-
"""
Python Application
Developer : ANAND VITTHAL ADAKE
Gmail     : anandadake007@gmail.com
GitHub    : anandadake/flask-jwt-based-user-authorization
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate


app = Flask(__name__)

# Configuration of application, see configuration.py, choose one and uncomment.
app.config.from_object('app.configuration.DevelopmentConfig')
# app.config.from_object('app.configuration.TestingConfig')
# app.config.from_object('app.configuration.ProductionConfig')

db = SQLAlchemy(app)  # flask-sqlalchemy
migrate = Migrate(app, db)
CORS(app)  # App level CORS allow

from . import views
# Registering the auth blueprints here
from app.auth import auth as auth_blueprint
app.register_blueprint(auth_blueprint)