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
from werkzeug.security import check_password_hash

from app import app, db
from app.auth.models import User

@app.route('/api/home')
def auth_home():
    return '<H1>Welcome to User Authorization Module</H1>'

"""
fetch the jwt token from 'Authorization' request header and validate the user.
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
Checks is request has Admin Rights, for admin specific api/operation.
"""
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        user = get_user()
        authorities = json.loads(user.authorities),
        if not 'ROLE_ADMIN' in authorities:
            return jsonify({'message': 'Access Denied'}), 401
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

    if check_password_hash(user.password, auth['password']):
        token = jwt.encode(
            {'user': auth['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'id_token': token.decode('UTF-8')})

    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm = "Login Required"'})

"""
return user(self) details based on username fetch from jwt token 
"""
@app.route('/api/account', methods=['GET'])
@token_required
def get_account():
    user = get_user()
    return jsonify(user.to_dto())

"""
@:param User
@:returns updated user details
"""
@app.route('/api/account', methods=['PUT'])
@token_required
def update_account():
    user = User.from_json(request.get_json())
    _user = get_user()
    if _user:
        _user.username = user.username
        _user.password = user.password
        _user.firstName = user.firstName
        _user.lastName = user.lastName
        _user.email = user.email
        db.session.commit()
        return jsonify(user.to_dto())

"""
delete the user from database
"""
@app.route('/api/account', methods=['DELETE'])
@token_required
def delete_account():
    user = get_user()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'The account has been deleted!'})


# ==================== Admin routes ====================
"""
@:param username 
@:returns requested User details
"""
@app.route('/api/users/<username>', methods=['GET'])
@token_required
@admin_required
def find_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify(user.to_dto())
    return jsonify({'message': 'user not found!'}),404

"""
@:param User model 
@:returns saved User model
"""
@app.route('/api/users', methods=['POST'])
@token_required
@admin_required
def create_user():
    new_user = User.from_json(request.get_json())
    if new_user:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(new_user.to_dto())
    return jsonify({'message': 'New accounts not added!'}),500

"""
@:param User model 
@:returns updated User model
"""
@app.route('/api/users', methods=['PUT'])
@token_required
@admin_required
def update_user():
    user = User.from_json(request.get_json())
    _user = get_user()
    if _user:
        _user.username = user.username
        _user.password = user.password
        _user.firstName = user.firstName
        _user.lastName = user.lastName
        _user.email = user.email
        _user.authorities = user.authorities
        _user.activated = user.activated
        db.session.commit()
        return jsonify(user.to_dto())
    return jsonify({'message': 'Accounts not Updated!'}),500

"""
@:param User model 
@:returns all saved User model
"""
@app.route('/api/users', methods=['GET'])
def query_user():
    users = User.query.all()
    return jsonify([user.to_dto() for user in users])

"""
@:param valid username 
@:returns delete message
"""
@app.route('/api/users/<username>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'The account has been deleted!'})
    return jsonify({'message': 'user not found!'}),404

"""
@:param valid username  
@:returns array of string of authorities of user
"""
@app.route('/api/users/authorities', methods=['GET'])
@token_required
def query_authorities():
    users = get_user()
    return jsonify(json.loads(users.authorities))

"""
@:param valid username 
@:returns activated message
"""
@app.route('/api/users/<username>', methods=['PUT'])
@token_required
@admin_required
def activate_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user.activated = True
        db.session.commit()
        return jsonify({'message': 'Account has been Activated !'})
    return jsonify({'message': 'Accounts not Updated!'}),500

# ==================== Core Function ====================
"""
return user(self) details from database based on username fetch from jwt token 
"""
def get_user():
    token = request.headers['Authorization'].split(' ')[1]
    data = jwt.decode(token, app.config['SECRET_KEY'])
    current_user = User.query.filter_by(username=data['user']).first()
    return current_user


# ==================== Development ====================
"""
add user entries into users table of database.
"""
@app.route('/api/users/add', methods=['GET','POST','PUT'])
# @token_required
# @admin_required
def fill_user_data():
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
        new_user = User(firstName=user['firstName'],
                        lastName=user['lastName'],
                        email=user['email'],
                        username=user['username'],
                        password=user['password'],
                        authorities=user['authorities'],
                        activated=True
                        )
        new_users.append(new_user)
    # noinspection PyBroadException
    try:
        db.session.add_all(new_users)
        db.session.commit()
    except:
        pass
    return jsonify([user.to_dto() for user in new_users])

"""
clear user entries from users table of database.
"""
@app.route('/api/users/clean', methods=['GET','POST','PUT'])
# @token_required
# @admin_required
def clean_user_data():
    User.query.delete()
    db.session.commit()
    return jsonify({'message': 'All users deleted from users table!'})

"""
deletes the all tables with data from database. (whole cleanup)
"""
@app.route('/api/tables/clean', methods=['GET','POST','PUT'])
# @token_required
# @admin_required
def clean_data():
    # noinspection PyBroadException
    try:
        meta = db.metadata
        for table in reversed(meta.sorted_tables):
            print('Clear table %s' % table)
            db.session.execute(table.delete())
        db.session.commit()
    except:
        pass
    return jsonify({'message': 'All the tables in thw database !'})