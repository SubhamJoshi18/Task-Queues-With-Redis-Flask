from flask import Flask
from flask_smorest import abort,Blueprint
from flask.views import MethodView
from flask_jwt_extended import jwt_required,get_jwt_identity,get_jwt
from middleware.auth_middleware import token_required

blp = Blueprint('UserProfile',__name__,description='Operation on User Profile')


@blp.route('/user', methods=['GET'])
class UserProfile(MethodView):
  
  @token_required
  @jwt_required()
  
  def get(self):
    jwt = get_jwt()
    if not jwt.get('email_verified'):
      abort(message='Email is not verified')
    print('this is a get')
    user = get_jwt_identity()
    return {"user":user}