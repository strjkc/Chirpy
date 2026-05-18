import types
import os
from dataclasses import dataclass
from typing import Any
from helpers import get_valid_user
from dotenv import load_dotenv
import pytest

load_dotenv()

from client import Client
@pytest.fixture(scope="module")
def client():
    base_url = os.getenv("BASE_URL")
    http_client = Client(base_url)
    return http_client

@pytest.fixture
def valid_user():
    return get_valid_user()

@pytest.fixture
def create_user(client, valid_user):
    status, body = client.post("/api/users", valid_user)
    if status == 201:
        return valid_user
    return None


#login
#valid login - token retreived
#invalid email, correct pass
#empty email, correct pass
#valid email incorrect pass
#valid email empty pass
#valid email missing pass

#delete user
#update user password
#update user email

def test_create_user_positive(client, valid_user):
    payload = valid_user
    status, body = client.post("/api/users", payload)
    assert status == 201
    assert "id" in body
    assert "created_at" in body
    assert "updated_at" in body
    assert "email" in body
    assert body["email"] == payload["email"]
    assert body.get("is_chirpy_red") == False

@dataclass
class Case:
    name: str
    payload: Any
    expected_result: Any

create_user_negative_cases = [
    Case(
        name="No Email",
        payload= lambda user: {
            "password": user.get("password")
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="No Password",
        payload= lambda user: {
            "email": user.get("email")
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Empty Password",
        payload= lambda user: {
            "email": user.get("email"),
            "password": ""
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Empty Email",
        payload=lambda user: {
            "email": "",
            "password": user.get("password")
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Invalid Email",
        payload= lambda user:{
            "email": "randomtext",
            "password": user.get("password")
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Weak Password",
        payload= lambda user:{
            "email": user.get("email"),
            "password": "password"
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Short Password",
        payload= lambda user:{
            "email": user.get("email"),
            "password": "1"
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
]

def test_duplicate_user_cant_be_created(client, valid_user):
    payload = valid_user
    status, body = client.post("/api/users", payload)
    assert status == 201
    status, body = client.post("/api/users", payload)
    assert status == 400

@pytest.mark.parametrize("case", create_user_negative_cases, ids=[case.name for case in create_user_negative_cases])
def test_create_user_negative(client, case):
    user = get_valid_user()
    payload = case.payload(user)
    status, body = client.post("/api/users", payload)
    assert "error" in body
    assert case.expected_result == status


login_user_negative_cases = [
    Case(
        name="No Email",
        payload= lambda user: {
            "password": user.get("password")
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="No Password",
        payload= lambda user: {
            "email": user.get("email")
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Empty Password",
        payload= lambda user: {
            "email": user.get("email"),
            "password": ""
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Empty Email",
        payload=lambda user: {
            "email": "",
            "password": user.get("password")
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Invalid Email",
        payload= lambda user:{
            "email": "randomtext",
            "password": user.get("password")
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
    Case(
        name="Wrong Password",
        payload= lambda user:{
            "email": user.get("email"),
            "password": "password"
        },
        expected_result=types.SimpleNamespace(
            status=400,
            body={"error": "Invalid email or password"}
        )
    ),
]



def test_user_can_login(client, create_user):
    payload = {
        "email": create_user.get("email"),
        "password":create_user.get("password"),
        "expires_in_seconds": 300
    }
    status, body = client.post("/api/login", payload)
    assert status == 200
    assert "token" in body

@pytest.mark.parametrize("case", login_user_negative_cases, ids=[case.name for case in login_user_negative_cases])
def test_user_can_log_in_negative(case, create_user, client):
    payload = case.payload(create_user)
    status, body = client.post("/api/login", payload)
    assert status == case.expected_result
    assert "error" in body