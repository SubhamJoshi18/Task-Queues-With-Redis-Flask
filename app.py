from flask import Flask,jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
import secrets
import os
from db import db
from resources.user import blp as userBlueprint
from resources.user_profile import blp as userProfileBlueprint
from blocklist.blocklist import BLOCKLIST

def start_server(db_url=None):
  app = Flask(__name__)

  app.config['PROPAGATE_EXCEPTIONS'] = True
  app.config['API_TITLE'] = 'Testing Api'
  app.config['API_VERSION'] = 'v1'
  app.config['OPENAPI_VERSION'] = '3.0.1'
  app.config['OPENAPI_URL_PREFIX'] = '/'
  app.config['OPENAPI_SWAGGER_UI_PATH'] = '/swagger-ui'
  app.config['OPENAPI_SWAGGER_UI_URL'] = 'https://cdn.jsdelivr.net/npm/swagger-ui-dist/'
  app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL') or "postgresql+psycopg2://postgres:admin@localhost:5432/random_flask"
  app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY')

  
  db.init_app(app)
  jwt = JWTManager(app)
  api = Api(app)
  api.register_blueprint(userBlueprint)
  api.register_blueprint(userProfileBlueprint)

  @jwt.token_in_blocklist_loader
  def check_if_token_is_in_blocklist(jwt_header,jwt_payload):
    return jwt_payload['jti'] in BLOCKLIST
  
  @jwt.revoked_token_loader
  def revoked_token_callback(jwt_header,jwt_payload):
    return (
      jsonify({
        "description":"The tokeh has been revoked", 
        "error":"token_revoked"
      })
    )
  
  @jwt.expired_token_loader
  def expired_token_callback(jwt_header,jwt_payload):
    return (
      jsonify({"message":"The token has expired", "error":"Token_expried"}),401
    )
  

 
  ''' 
  incase if there is no middleware
 
  @jwt.invalid_token_loader
  def invalid_token_callback(error):
    return (
      jsonify({"message":"Signature verification failed","error":"invalid_token"})
    )

    '''

  
  




  return app

app = start_server()
