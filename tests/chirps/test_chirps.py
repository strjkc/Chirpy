import tests.helpers as helpers

#x mux.HandleFunc("POST /api/validate_chirp", handlerPostChirp)

#CREATE CHIRPS - can be parametrized
def test_create_chirp(http_client, crt_usr_and_login, cleanup_chirps):
    payload = {
        "body": "Test Chirp"
    }
    status, body = http_client.post("/api/chirps", payload, crt_usr_and_login.get("token"))
    cleanup_chirps.append(body)
    assert status == 201

def test_empty_chirp(http_client, crt_usr_and_login, cleanup_chirps):
    payload = {
        "body": ""
    }
    status, body = http_client.post("/api/chirps", payload, crt_usr_and_login.get("token"))
    cleanup_chirps.append(body)
    assert status == 400

def test_long_chirp(http_client, crt_usr_and_login, cleanup_chirps):
    payload = {
        "body": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
    status, body = http_client.post("/api/chirps", payload, crt_usr_and_login.get("token"))
    cleanup_chirps.append(body)
    assert status == 400


def test_create_chirp_no_auth(http_client, crt_usr_and_login, cleanup_chirps):
    payload = {
        "body": "Test Chirp"
    }
    status, body = http_client.post("/api/chirps", payload)
    cleanup_chirps.append(body)
    assert status == 401

# DELETE CHIRPS
def test_delete_chirp(db_connection, http_client, create_chirp):
    path = f"/api/chirps/{create_chirp.get("chirp").get("id")}"
    status, body = http_client.delete(path, token=create_chirp.get("user").get("token"))
    assert status == 204
    result = db_connection.select_cell("chirps", "id", "id", create_chirp.get("chirp").get("id"))
    assert result is None

def test_delete_others_chirp(db_connection, http_client, create_chirp, cleanup_users):
    other_user = helpers.create_user_and_log_in()
    cleanup_users.append(other_user)
    path = f"/api/chirps/{create_chirp.get("chirp").get("id")}"
    status, body = http_client.delete(path, other_user.get("token"))
    assert status == 403
    result = db_connection.select_cell("chirps", "id", "id", create_chirp.get("chirp").get("id"))
    assert f"{result}" == create_chirp.get("chirp").get("id")

def test_delete_removed_chirp(db_connection, http_client, create_chirp, cleanup_users):
    db_connection.cleanup("chirps", "id", create_chirp.get("chirp").get("id"))
    path = f"/api/chirps/{create_chirp.get("chirp").get("id")}"
    status, body = http_client.delete(path, create_chirp.get("user").get("token"))
    assert status == 404
    result = db_connection.select_cell("chirps", "id", "id", create_chirp.get("chirp").get("id"))
    assert f"{result}" == create_chirp.get("chirp").get("id")

def test_delete_chirp_no_auth(db_connection, http_client, create_chirp):
    path = f"/api/chirps/{create_chirp.get("chirp").get("id")}"
    status, body = http_client.delete(path, )
    assert status == 401
    result = db_connection.select_cell("chirps", "id", "id", create_chirp.get("chirp").get("id"))
    assert result is not None


def test_get_chirps_no_auth(http_client, create_multiple_chirps):
    _ = create_multiple_chirps(5)
    status, body = http_client.get("/api/chirps")
    assert status == 200
    assert len(body) == 5

def test_get_chirps_auth(http_client, create_multiple_chirps, crt_usr_and_login):
    status, body = http_client.get("/api/chirps", token=crt_usr_and_login.get("token"))
    assert status == 200
    assert len(body) == 5

def test_get_chirps_none(http_client):
    status, body = http_client.get("/api/chirps")
    assert status == 200
    assert len(body) == 0

#Postchirp
#user is authenticated
    #over 140 chars - error
    #140 chars - ok
    #under 140 chras ok
    #0 chars - error
    #profane words send - masked
#user is not authenticated
    # over 140 chars - error
    # 140 chars - ok
    # under 140 chras ok
    # 0 chars - error
    # profane words send - masked