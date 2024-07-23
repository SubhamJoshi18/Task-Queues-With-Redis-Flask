from flask.views import MethodView
from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError
from db import db
from models import User
from schemas import UserSchema
from flask import jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from errors.token import TokenOperationException
from datetime import datetime, timedelta
from flask_jwt_extended import get_jwt,jwt_required,create_refresh_token,get_jwt_identity
from blocklist.blocklist import BLOCKLIST
from middleware.auth_middleware import token_required

blp = Blueprint('Users', __name__, description='Operations on Users')

@blp.route('/register')
class UserRegister(MethodView):
    def post(self):
        user_data = request.get_json()
        username = user_data['username']
        password = user_data['password']
        print(username, password)
        # Validate username length
        if len(username) > 50:
            abort(400, message='Username exceeds maximum length')

        exists_user = User.query.filter_by(username=username).first()
        if exists_user:
            abort(409, message='A user with that username already exists')

        user = User(
            username=username,
            password=generate_password_hash(password)
        )

        try:
            db.session.add(user)
            db.session.commit()
        except SQLAlchemyError as error_message:
            db.session.rollback()
            return jsonify(message=str(error_message), statusCode=500), 500
        else:
            return jsonify(message='User Created Successfully', statusCode=201), 201

@blp.route("/user/<string:id>")
class UserMethod(MethodView):
    @blp.response(200, UserSchema)
    def get(self, id):
        user = User.query.filter_by(id=int(id)).first()
        if not user:
            abort(404, message='User not found')
        return user

    def delete(self, id):
        user = User.query.filter_by(id=int(id)).first()
        if not user:
            return jsonify(message="User not available"), 404

        main_user = User.query.get_or_404(int(id))
        db.session.delete(main_user)
        db.session.commit()
        return jsonify(message="User deleted successfully"), 200

@blp.route('/login', methods=['POST'])
class LoginMethod(MethodView):
    def post(self):
        user_data = request.get_json()
        username = user_data['username']
        password = user_data['password']
        if not username or not password:
            abort(409, message="Invalid Credentials")
        exist_user = User.query.filter_by(username=username).first()
        if not exist_user:
            abort(403, 'User does not exists')
        check_password = check_password_hash(exist_user.password, password)
        if not check_password:
            abort(403, 'Password does not match')
        additional_claims  = {
            'role':'admin',
            'email_verified':True
        }

        try:

            token = create_access_token(identity=exist_user.id, additional_claims=additional_claims,expires_delta=timedelta(minutes=30))
            refresh_token = create_refresh_token(identity=exist_user.id)
            if len(token) == 0:
                raise TokenOperationException('Token length 0')
        except Exception as e:
            abort(403, message=e.message)
        else:
            return {
                "access_token": token,
                "refresh_token":refresh_token
            }


@blp.route('/logout',methods=['POST'])
@token_required
@jwt_required()
class UserLogout(MethodView):
    def logout(self):
        jti = get_jwt()['jti']
        BLOCKLIST.add(jti)
        return {'message':"Logout SuccessFully"}
    


@blp.route('/refresh-token',methods=['POST'])
@token_required
@jwt_required(refresh=True)
class TokenRefresh(MethodView):
    def refresh_token(self):
        user_data = get_jwt_identity()
        new_token =create_refresh_token(identity=user_data,fresh=False)
        return {"access_token":new_token}

