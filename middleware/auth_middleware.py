from functools import wraps
from flask import request,jsonify

def token_required(func):
  wraps(func)
  def decorator(*args,**kwargs):
    token = None
    if 'Authorization' in request.headers:
      token = request.headers['Authorization']
      if token.startswith('Bearer '):
        token = token[7:]
      try:
        return func(*args,**kwargs)
      except Exception as e:
        return jsonify(message=str(e), data=None,error='Unauthorized'),401
      
    return jsonify(message='Authoirzation token is missing', data=None,error='Unauthrozied'),401
  
  return decorator
