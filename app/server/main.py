from fastapi import FastAPI
from fastapi import Form
from fastapi import Header
from fastapi import Response
from fastapi import status
from typing import Optional

from database.constants import K_TOKEN_LIFE_TIME
from models.User import User
from service import auth


app = FastAPI()


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    full_name: Optional[str] = Form(""),
    npm: Optional[str] = Form(""),
):
    user = auth.register(username, password, full_name, npm)

    if user is None:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": "User already exists"}

    return {
        "user_id": user["id"],
        "username": username
    }


@app.post("/oauth/token", status_code=status.HTTP_200_OK)
async def login(
    response: Response,
    username: Optional[str] = Form(""),
    password: Optional[str] = Form(""),
    grant_type: Optional[str] = Form(""),
    client_id: Optional[str] = Form(""),
    client_secret: Optional[str] = Form(""),
):
    DEFAULT_ERROR_RESPONSE = {
        "error": "invalid_request",
        "error_description": "ada kesalahan masbro!",
    }

    if (
        "" in [username, password, grant_type, client_id, client_secret]
        or not auth.authenticate_user(username, password)
        or not auth.authenticate_client(client_id, client_secret)
        or grant_type != "password"
    ):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return DEFAULT_ERROR_RESPONSE

    access_token, refresh_token = auth.generate_token(username, client_id)

    return {
        "access_token": access_token,
        "expires_in": K_TOKEN_LIFE_TIME,
        "token_type": "Bearer",
        "scope": None,
        "refresh_token": refresh_token,
    }


@app.post("/oauth/resource", status_code=status.HTTP_200_OK)
async def resource(
    response: Response,
    authorization: Optional[str] = Header(None),
):
    DEFAULT_ERROR_RESPONSE = {
        "error": "invalid_token",
        "error_description": "Token Salah masbro"
    }

    if authorization is None or not authorization.startswith("Bearer "):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return DEFAULT_ERROR_RESPONSE

    access_token = authorization.split(" ")[1]

    user_data = auth.get_user_by_token(access_token)
    if user_data is None:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return DEFAULT_ERROR_RESPONSE

    return {
        "access_token": access_token,
        **user_data,
    }
