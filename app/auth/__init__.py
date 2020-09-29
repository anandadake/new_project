# -*- encoding: utf-8 -*-
"""
Python Application
Developer : ANAND VITTHAL ADAKE
Gmail     : anandadake007@gmail.com
GitHub    : anandadake/flask-jwt-based-user-authorization
"""

from flask import Blueprint

auth = Blueprint(
    'auth', __name__,
    static_folder='static',
    static_url_path='/api/static',
    template_folder='templates'
)

from . import views