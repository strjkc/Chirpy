import requests

class Client():
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token

    def get(self, path, token=None):
        try:
            url = f"{self.base_url}{path}"
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            resp = requests.get(url, headers=headers if headers else None)
            resp_body = None
            if resp.headers.get("Content-Type"):
               if resp.headers.get("Content-Type") == "application/json":
                    resp_body = resp.json()
            status = resp.status_code
            return status, resp_body
        except requests.exceptions.JSONDecodeError as e:
            print(f"Error decoding response: {e}")
            return 0, {}

    def post(self, path:str, payload:dict, token=None) -> tuple[int, dict]:
        try:
            url = f"{self.base_url}{path}"
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            resp = requests.post(url, json=payload, headers=headers if headers else None)
            resp_body = resp.json()
            status = resp.status_code
            return status, resp_body
        except requests.exceptions.JSONDecodeError as e:
            print(f"Error decoding response: {e}")
            return 0, {}
    def put(self, path:str, payload:dict, token=None) -> tuple[int, dict]:
        try:
            url = f"{self.base_url}{path}"
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            resp = requests.put(url, json=payload, headers= headers if headers else None)
            resp_body = resp.json()
            status = resp.status_code
            return status, resp_body
        except requests.exceptions.JSONDecodeError as e:
            print(f"Error decoding response: {e}")
            return 0, {}
    def delete(self, path, token=None) -> tuple[int, dict]:
        try:
            url = f"{self.base_url}{path}"
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            resp = requests.delete(url, headers=headers if headers else None)
            resp_body= None
            if resp.headers.get("Content-Type"):
               if resp.headers.get("Content-Type") == "application/json":
                    resp_body = resp.json()
            status = resp.status_code
            return status, resp_body
        except requests.exceptions.JSONDecodeError as e:
            print(f"Error decoding response: {e}")
            return 0, {}