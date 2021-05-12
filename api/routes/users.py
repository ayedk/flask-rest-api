#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask import Blueprint
from flask import request
from flask import url_for, render_template_string
from api.utils.responses import response_with
from api.utils import responses as resp
from api.models.users import User, UserSchema
from api.utils.database import db
from flask_jwt_extended import create_access_token
from api.utils.token import generate_verification_token, confirm_verification_token
import datetime

user_routes = Blueprint("user_routes", __name__)

@user_routes.route('/', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        if(User.find_by_email(data['email']) is not None or User.find_by_username(data['username']) is not None):
            return response_with(resp.INVALID_INPUT_422)
        data['password'] = User.generate_hash(data['password'])
        user_schmea = UserSchema()
        user, error = user_schmea.load(data)
        token = generate_verification_token(data['email'])
        result = user_schmea.dump(user.create()).data
        return response_with(resp.SUCCESS_201)
    except Exception as e:
        print(e)
        return response_with(resp.INVALID_INPUT_422)
     
@user_routes.route('/login', methods=['POST'])
def authenticate_user():
    try:
        data = request.get_json()
        if data.get('email') :
            current_user = User.find_by_email(data['email']) 
        elif data.get('username') :
            current_user = User.find_by_username(data['username'])
        if not current_user:
            return response_with(resp.SERVER_ERROR_404)
        if current_user and not current_user.isVerified:
            return response_with(resp.BAD_REQUEST_400)
        if User.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = current_user.username)
            return response_with(resp.SUCCESS_200, value={'message': 'Logged in as admin', "access_token": access_token})
        else:
            return response_with(resp.UNAUTHORIZED_401)
    except Exception as e:
        print(e)
        return response_with(resp.INVALID_INPUT_422)