from locust import LoadTestShape

class TestShape(LoadTestShape):
    ramp = [
        {"duration": 60, "users": 100, "spawn_rate": 10},
        {"duration": 120, "users": 300, "spawn_rate": 15},
        {"duration": 240, "users": 500, "spawn_rate": 30},
        {"duration": 300, "users": 1000, "spawn_rate": 50},
    ]

    def tick(self):
        run_time = self.get_run_time()
        for stage in self.ramp:
            if run_time < stage.get("duration"):
                return stage.get("users"), stage.get("spawn_rate")
        return None

