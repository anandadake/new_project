# -*- encoding: utf-8 -*-
"""
Python Application
Developer : ANAND VITTHAL ADAKE
Gmail     : anandadake007@gmail.com
GitHub    : anandadake/flask-jwt-based-user-authorization
"""

import jwt, json, datetime
from flask import request, make_response, jsonify
from functools import wraps

from app import app, db
from app.auth.models import User


"""
fetch the jwt token from 'Authorization' request header and validate.
"""
def token_required(f):
    # noinspection PyBroadException
    @wraps(f)
    def wrap(*args, **kwargs):
        token = request.headers['Authorization'].split(' ')[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(*args, **kwargs)

    return wrap

"""
provide the jwt token for valid user
"""
@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    auth = request.get_json()
    user = User.query.filter_by(username=auth['username']).first()
    if not user:
        return jsonify({'Could not verify!'}), 401

    if auth and auth['username'] == user.username and auth['password'] == user.password:
        token = jwt.encode(
            {'user': auth['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'id_token': token.decode('UTF-8')})

    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm = "Login Required"'})

"""
return all user's in database
"""
@app.route('/api/accounts', methods=['GET'])
# @token_required
def get_all_account():
    users = User.query.all()
    return jsonify([user.to_dto() for user in users])

"""
return user(self) details based on username fetch from jwt token 
"""
@app.route('/api/account', methods=['GET'])
@token_required
def get_self_account():
    user = get_user()
    return jsonify(user.to_dto())

"""
return requested user details based on username
"""
@app.route('/api/account/<username>', methods=['GET'])
@token_required
def get_one_account(username):

    # Todo: add admin check

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    return jsonify(user.to_dto())

"""
check's requested username is available for new user or not.
"""
@app.route('/api/account/check-username/<username>', methods=['GET'])
def check_for_account_username(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'allowed': True})
    else:
        return jsonify({'allowed': False})

@app.route('/api/account', methods=['GET', 'POST'])
# @token_required
def create_account():
    new_user = User.from_json(request.get_json())
    if new_user:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'New account created!'})

    clear_data()
    add_data()
    return jsonify({'message': 'New accounts added!'})

"""
promote the user authorities to admin
"""
@app.route('/api/account/<username>', methods=['PUT'])
@token_required
def update_account(username):
    args = request.args
    if  'action' not in request.args:
        return jsonify({'message': 'No action found!'})
    action = args['action']
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'No account found!'})
    if action == 'activate':
        user.activated = True
    if action == 'promote':
        user.authorities = json.dumps(['ROLE_ADMIN'])
    db.session.commit()

    return jsonify({'message': 'The account has been {}!'.format(action)})

"""
delete the user from database
"""
@app.route('/api/account/<username>', methods=['DELETE'])
@token_required
def delete_account(username):
    user = User.query.filter_by(username=username).first()

    # Todo : add admin check

    if not user:
        return jsonify({'message': 'No user found!'})
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The account has been deleted!'})

@app.route('/api/home')
def auth_home():
    return '<H1>Welcome to User Authorization Module</H1>'

# ====================
"""
return user(self) details from database based on username fetch from jwt token 
"""
def get_user():
    token = request.headers['Authorization'].split(' ')[1]
    data = jwt.decode(token, app.config['SECRET_KEY'])
    current_user = User.query.filter_by(username=data['user']).first()
    return current_user

"""
add basic data in tables
"""
# noinspection PyBroadException
def add_data():
    users = []
    # authorities = ["ROLE_ADMIN", "ROLE_EXPERT", "ROLE_USER"]
    test = {'firstName': 'anand', 'lastName': 'adake', 'email': 'anand@trisimtechnology.com', 'username': 'test',
            'password': 'test', 'authorities': json.dumps(['ROLE_ADMIN'])}
    admin = {'firstName': 'anand', 'lastName': 'adake', 'email': 'anand@trisimtechnology.com', 'username': 'admin',
             'password': 'admin', 'authorities': json.dumps(['ROLE_ADMIN'])}
    expert = {'firstName': 'anand', 'lastName': 'adake', 'email': 'anand@trisimtechnology.com',
              'username': 'expert', 'password': 'expert', 'authorities': json.dumps(['ROLE_EXPERT'])}
    user = {'firstName': 'anand', 'lastName': 'adake', 'email': 'anand@trisimtechnology.com', 'username': 'user',
            'password': 'user', 'authorities': json.dumps(['ROLE_USER'])}
    users.append(test)
    users.append(admin)
    users.append(expert)
    users.append(user)

    new_users = []
    for user in users:
        new_user = User(firstName=user['firstName'], lastName=user['lastName'], email=user['email'],
                        username=user['username'], password=user['password'], authorities=user['authorities'])
        new_users.append(new_user)
    status = False
    try:
        db.session.add_all(new_users)
        db.session.commit()
        status = True
    except:
        status = False

    return status

"""
delete all records from all tables.
"""
# noinspection PyBroadException
def clear_data():
    status = True
    try:
        meta = db.metadata
        for table in reversed(meta.sorted_tables):
            print('Clear table %s' % table)
            db.session.execute(table.delete())
        db.session.commit()
    except:
        status = False

    return status