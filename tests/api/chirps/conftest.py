import pytest

import tests.helpers as helpers


@pytest.fixture
def cleanup_chirps(db_connection):
    chirps = []
    yield chirps
    for chirp in chirps:
        db_connection.cleanup("chirps", "id", chirp.get("id"))


@pytest.fixture
def create_chirp(http_client, db_connection):
    user = helpers.create_user_and_log_in()
    body = helpers.create_chrip(http_client, user)
    yield {"chirp": body, "user": user}
    db_connection.cleanup("chirps", "id", body.get("id"))


@pytest.fixture
def create_multiple_chirps(http_client, db_connection):
    user = helpers.create_user_and_log_in()
    chirps = []

    def _create_chirps(num):
        created_chirps = []
        for i in range(num):
            body = helpers.create_chrip(http_client, user)
            created_chirps.append(body)
            chirps.append(body)
        return created_chirps

    yield _create_chirps
    for chirp in chirps:
        db_connection.cleanup("chirps", "id", chirp.get("id"))
