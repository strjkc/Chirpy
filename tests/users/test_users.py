import os
import tests.helpers as helpers
from dotenv import load_dotenv
import pytest
from tests.client import Client
from user_test_cases import create_user_negative_cases, login_user_negative_cases

load_dotenv()

@pytest.fixture(scope="module")
def client():
    base_url = os.getenv("BASE_URL")
    http_client = Client(base_url)
    return http_client

@pytest.fixture
def valid_user():
    return helpers.get_valid_user()

@pytest.fixture
def create_user(client, valid_user):
    return helpers.create_user()


@pytest.fixture
def log_in_new_user(client ):
    return helpers.create_user_and_log_in()

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



def test_duplicate_user_cant_be_created(client, valid_user):
    payload = valid_user
    status, body = client.post("/api/users", payload)
    assert status == 201
    status, body = client.post("/api/users", payload)
    assert status == 400

@pytest.mark.parametrize("case", create_user_negative_cases, ids=[case.name for case in create_user_negative_cases])
def test_create_user_negative(client, case):
    user = helpers.get_valid_user()
    payload = case.payload(user)
    status, body = client.post("/api/users", payload)
    assert "error" in body
    assert case.expected_result == status

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

def test_update_user(client, log_in_new_user):
    payload = {
        "email": "new_email@test.com",
        "password": "superNewPass"
    }
    status, body = client.put("/api/users", payload, log_in_new_user.get("token"))
    assert status == 201
    assert body["email"] == payload["email"]
    assert body["password"] != log_in_new_user["password"]

def test_duplicate_user_update(client, log_in_new_user, create_user):
    payload = {
        "email": create_user.get("email"),
        "password": "newPass123@1"
    }
    status, _ = client.put("/api/users", payload, log_in_new_user.get("token"))
    assert status == 403

def test_duplicate_user_update2(client, log_in_new_user, create_user):
    payload = {
        "email": "new_bla@test.com",
        "password": create_user.get("password")
    }
    status, _ = client.put("/api/users", payload, log_in_new_user.get("token"))
    assert status == 201


def test_updated_user_can_log_in(client, log_in_new_user):
    payload = {
        "email": "new_email2@test.com",
        "password": "superNewPass"
    }
    _, _ = client.put("/api/users", payload, log_in_new_user.get("token"))
    status, body = client.post("/api/login", payload)
    assert status == 200
    assert "token" in body


def test_update_user_no_auth(client, log_in_new_user):
    payload = {
        "email": "new_email@test.com",
        "password": "superNewPass"
    }
    status, body = client.put("/api/users", payload)
    assert status == 401
