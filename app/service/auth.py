import binascii
import copy
import datetime
import os

from database.constants import K_TOKEN_LIFE_TIME
from database.nosql import db_access_token
from database.nosql import db_client
from database.nosql import db_refresh_token
from database.nosql import db_user


last_user_id = 0


def register(username, password, full_name, npm):
    global last_user_id

    user = get_user_by_username(username)
    if user is not None:
        return None

    user = db_user[username] = {
        "id": last_user_id + 1,
        "username": username,
        "password": password,
        "full_name": full_name,
        "npm": npm,
    }
    last_user_id += 1

    return user


def get_user_by_username(username):
    return copy.deepcopy(db_user.get(username))


def authenticate_user(username, password):
    user = db_user.get(username)
    if user is None:
        return False

    return user["password"] == password


def authenticate_client(client_id, client_secret):
    client = db_client.get(client_id)
    if client is None:
        return False

    return client["client_secret"] == client_secret


def generate_token(username, client_id):
    access_token = __generate_token()
    refresh_token = __generate_token()

    user_data = {
        "username": username,
        "client_id": client_id,
    }

    db_access_token[access_token] = {
        **user_data,
        "expired_at": (
            datetime.datetime.now() + datetime.timedelta(seconds=K_TOKEN_LIFE_TIME)),
        "refresh_token": refresh_token,
    }

    db_refresh_token[refresh_token] = {
        **user_data,
    }

    return access_token, refresh_token


def __generate_token():
    token = ""
    while token == "" or token in db_access_token:
        token = binascii.hexlify(os.urandom(20)).decode()

    return token


def get_user_by_token(access_token):
    data = copy.deepcopy(db_access_token.get(access_token))
    if not is_access_token_valid(data):
        db_access_token.pop(access_token, None)
        return None

    user = get_user_by_username(data["username"])

    user_id = user["id"]
    user.pop("id", None)
    user.pop("password", None)
    user.pop("username", None)

    return {
        **user,
        "user_id": user_id,
        "expires": None,
        "client_id": data["client_id"],
        "refresh_token": data["refresh_token"],
    }


def is_access_token_valid(access_token_data):
    if access_token_data is None:
        return False

    return access_token_data["expired_at"] > datetime.datetime.now()
