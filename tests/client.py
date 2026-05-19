import requests

class Client():
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token

    def post(self, path:str, payload:dict) -> tuple[int, dict]:
        try:
            url = f"{self.base_url}{path}"
            resp = requests.post(url, json=payload)
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