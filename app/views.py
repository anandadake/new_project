# -*- encoding: utf-8 -*-
"""
Python Application
Developer : ANAND VITTHAL ADAKE
Gmail     : anandadake007@gmail.com
GitHub    : anandadake/flask-jwt-based-user-authorization
"""

from app import app

@app.route('/')
def home():
    return '<H1>Welcome to Main Module</H1>'

@app.route('/home')
def home_page():
    return '<H1>Welcome to Main Module</H1>'

# ====================