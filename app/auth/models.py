# -*- encoding: utf-8 -*-
"""
Python Application
Developer : ANAND VITTHAL ADAKE
Gmail     : anandadake007@gmail.com
GitHub    : anandadake/flask-jwt-based-user-authorization
"""
import json

from werkzeug.security import generate_password_hash

from app import db


class User(db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))
    authorities = db.Column(db.String(50))
    activated = db.Column(db.Boolean)

    def serialize(self):
        pass

    def to_dto(self):
        return {
            'id': self.id,
            'username': self.username,
            'firstName': self.firstName,
            'lastName': self.lastName,
            'email': self.email,
            'password': self.password,
            'authorities': json.loads(self.authorities),
            'activated': self.activated
        }

    def __init__(self, username, firstName, lastName, email, password, authorities, activated=False):
        self.username = username
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.password = generate_password_hash(password, method='sha256')
        self.authorities = authorities
        self.activated = activated

    # This from json method is used for creating a user from a JSON.
    @staticmethod
    def from_json(json_post):
        username = json_post.get('username')
        firstName = json_post.get('firstName')
        lastName = json_post.get('lastName')
        email = json_post.get('email')
        password = json_post.get('password')
        authorities = json_post.get('authorities')
        activated = json_post.get('activated')

        user = User(
            username=username,
            firstName=firstName,
            lastName=lastName,
            email=email,
            password=password,
            authorities=authorities,
            activated=activated
        )
        return user