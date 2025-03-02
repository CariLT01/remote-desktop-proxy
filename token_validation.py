import jwt
from flask import request
import logging
from settings import *
from utils import *
import datetime

def generate_jwt_token(username: str):

    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1) # token wil expire in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return token
def check_token(token: str):
    try:
        _ = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
    except Exception as e:
        logging.error(f"Unknown exception while decoding JWT token: {e}")

def check_token_request(check_admin:bool=False) -> bool:
    try:
        authorization = request.headers.get("Authorization")
        if authorization == None:
            return False
        token = authorization.split(" ")[1]
        if check_token(str(token)) == False:
            return False
        if check_admin == True:
            if is_admin_user(get_username_from_jwt(str(token))) == False:
                logging.error("is not admin")
                return False
        return True
    except Exception as e:
        logging.error(f"Failed to check token from request: {e}")
        return False
def create_jwt_provider_token(name:str, id:str):
    payload = {
        "token_name": name,
        "token_id": id,
        'token_type': "provider",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=60) # token wil expire in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return token
def get_username_from_jwt(token: str):
    if check_provider_token(token)==False:
        return None
    payload = jwt.decode(token, SECRET_KEY, ["HS256"])
    return payload.get("username")
def check_provider_token(token: str):
    try:
        if check_token(token) == False:
            logging.error(f"Invalid or expired token")
            return False
            
        decoded = jwt.decode(token, SECRET_KEY, ["HS256"])

        token_type = decoded.get("token_type")
        token_id = decoded.get("token_id")
        token_name = decoded.get("token_name")

        if not token_type or not token_id or not token_name:
            logging.error(f"token validation: one field is none")
            return False
        if token_type != "provider":
            logging.error(f"token type is not provider")
            return False
        
        return True
    except Exception as e:
        logging.error(f"token validation unexpected error: {e}")
        return False