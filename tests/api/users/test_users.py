import pytest
from user_test_cases import create_user_negative_cases, login_user_negative_cases

import tests.helpers as helpers


@pytest.fixture
def valid_user():
    return helpers.get_valid_user()


def test_create_user_positive(http_client, valid_user, db_connection, cleanup_users):
    payload = valid_user
    status, body = http_client.post("/api/users", payload)
    assert status == 201
    cleanup_users.append(valid_user)
    assert "id" in body
    assert "created_at" in body
    assert "updated_at" in body
    assert "email" in body
    assert body["email"] == payload["email"]
    assert body.get("is_chirpy_red") == False
    mail = db_connection.select_cell("users", "email", "email", valid_user.get("email"))
    assert mail == valid_user.get("email")


def test_duplicate_user_cant_be_created(http_client, valid_user):
    payload = valid_user
    status, body = http_client.post("/api/users", payload)
    assert status == 201
    status, body = http_client.post("/api/users", payload)
    assert status == 400


@pytest.mark.parametrize(
    "case",
    create_user_negative_cases,
    ids=[case.name for case in create_user_negative_cases],
)
def test_create_user_negative(http_client, case):
    user = helpers.get_valid_user()
    payload = case.payload(user)
    status, body = http_client.post("/api/users", payload)
    assert "error" in body
    assert case.expected_result == status


def test_user_can_login(http_client, create_user):
    payload = {
        "email": create_user.get("email"),
        "password": create_user.get("password"),
        "expires_in_seconds": 300,
    }
    status, body = http_client.post("/api/login", payload)
    assert status == 200
    assert "token" in body


@pytest.mark.parametrize(
    "case",
    login_user_negative_cases,
    ids=[case.name for case in login_user_negative_cases],
)
def test_user_can_log_in_negative(case, create_user, http_client):
    payload = case.payload(create_user)
    status, body = http_client.post("/api/login", payload)
    assert status == case.expected_result
    assert "error" in body


def test_update_user(http_client, crt_usr_and_login):
    payload = {"email": "new_email@test.com", "password": "superNewPass"}
    status, body = http_client.put(
        "/api/users", payload, crt_usr_and_login.get("token")
    )
    assert status == 201
    assert body["email"] == payload["email"]
    assert body["password"] != crt_usr_and_login["password"]


def test_duplicate_user_update(http_client, crt_usr_and_login, create_user):
    payload = {"email": create_user.get("email"), "password": "newPass123@1"}
    status, _ = http_client.put("/api/users", payload, crt_usr_and_login.get("token"))
    assert status == 403


def test_duplicate_user_update2(http_client, crt_usr_and_login, create_user):
    payload = {"email": "new_bla@test.com", "password": create_user.get("password")}
    status, _ = http_client.put("/api/users", payload, crt_usr_and_login.get("token"))
    assert status == 201


def test_updated_user_can_log_in(http_client, crt_usr_and_login):
    payload = {"email": "new_email2@test.com", "password": "superNewPass"}
    _, _ = http_client.put("/api/users", payload, crt_usr_and_login.get("token"))
    status, body = http_client.post("/api/login", payload)
    assert status == 200
    assert "token" in body


def test_update_user_no_auth(http_client, crt_usr_and_login):
    payload = {"email": "new_email@test.com", "password": "superNewPass"}
    status, body = http_client.put("/api/users", payload)
    assert status == 401
