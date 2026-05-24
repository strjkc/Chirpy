from dataclasses import dataclass
from typing import Any
import types

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



