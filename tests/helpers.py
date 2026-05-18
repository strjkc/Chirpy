import uuid

def get_valid_user():
    return {
        "email": f"{uuid.uuid4()}@test.com",
        "password": "TestPass123"
    }