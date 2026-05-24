from locust import HttpUser, task, between
from uuid import uuid4
from random import randint
from TestShape import TestShape

def get_valid_user():
    return {
        "email": f"{uuid4()}@test.com",
        "password": "TestPass123"
    }

class User(HttpUser):
    wait_time = between(1,3)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chirps = []
        self.token = None
        self.headers = {}

    def on_start(self):
        user = get_valid_user()
        self.client.post("/api/users", json=user)
        resp = self.client.post("/api/login", json=user)
        self.token = resp.json()["token"]
        self.headers = {
            "Authorization": f"Bearer {self.token}"
        }
        payload = {
            "body": f"chirp: {uuid4()}"
        }
        resp = self.client.post("/api/chirps", json=payload, headers=self.headers)
        self.chirps.append(resp.json())

    @task(10)
    def create_chirp(self):
        payload = {
            "body": f"chirp: {uuid4()}"
        }
        resp = self.client.post("/api/chirps", json=payload, headers=self.headers)
        self.chirps.append(resp.json())

    @task
    def get_chirp(self):
        index = randint(0, len(self.chirps)-1)
        chirp_id = self.chirps[index]["id"]
        self.client.get(f"/api/chirps/{chirp_id}")

    @task
    def get_chirps(self):
        self.client.get(f"/api/chirps")
