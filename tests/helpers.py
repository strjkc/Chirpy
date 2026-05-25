import os
import uuid

from tests.api.http_client import Client


def get_valid_user():
    return {"email": f"{uuid.uuid4()}@test.com", "password": "TestPass123"}


def create_user():
    user = get_valid_user()
    url = os.getenv("BASE_URL")
    client = Client(url)
    status, body = client.post("/api/users", user)
    if status == 201:
        return user
    return None


def log_in(user):
    url = os.getenv("BASE_URL")
    client = Client(url)
    payload = {
        "email": user.get("email"),
        "password": user.get("password"),
        "expires_in_seconds": 300,
    }
    status, body = client.post("/api/login", payload)
    if status == 200:
        return body
    return None


def create_user_and_log_in():
    user = create_user()
    logged_in_user = log_in(user)
    return logged_in_user


def create_chrip(http_client, logged_in_user):
    user = logged_in_user
    payload = {"body": f"{uuid.uuid4()}"}
    status, body = http_client.post(
        "/api/chirps", payload=payload, token=user.get("token")
    )
    return body
