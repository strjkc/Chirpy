import os

import pytest
from dotenv import load_dotenv

import tests.helpers as helpers
from tests.api.db_client import DbClient
from tests.api.http_client import Client

load_dotenv()


@pytest.fixture(scope="module")
def http_client():
    base_url = os.getenv("BASE_URL")
    http_client = Client(base_url)
    return http_client


@pytest.fixture(scope="module")
def db_connection():
    db_host = os.getenv("DB_HOST")
    client = DbClient(db_host, "chirpy", "postgres")
    yield client
    client.close()


@pytest.fixture
def create_user(http_client, valid_user, db_connection):
    user = helpers.create_user()
    yield user
    db_connection.cleanup("users", "email", user.get("email"))


@pytest.fixture
def cleanup_users(db_connection):
    users_to_del = []
    yield users_to_del
    for user in users_to_del:
        db_connection.cleanup("users", "email", user.get("email"))


@pytest.fixture
def crt_usr_and_login(http_client, db_connection):
    user = helpers.create_user_and_log_in()
    yield user
    db_connection.cleanup("users", "email", user.get("email"))
