"""Load profile for the appointment API.

Shaped like real traffic rather than like a benchmark. Each simulated user
logs in once and then works with the token it was given, because that is what
a real client does — logging in on every request would measure bcrypt and
nothing else, and bcrypt is slow on purpose.

The mix is read-heavy: people look at their calendar far more often than they
book. Every user belongs to one of the seeded clinics chosen at random, so the
load is spread across clinics rather than hammering one.

Run against a server you started yourself:

    python -m scripts.seed_load --reset
    RATE_LIMIT_ENABLED=false uvicorn app.main:app --port 8000 --workers 1
    locust -f locustfile.py --headless -u 50 -r 10 -t 60s --host http://127.0.0.1:8000

Rate limiting is turned off for the run. Every request comes from one address,
which is exactly what the limiter exists to stop, so leaving it on would
measure the limiter refusing us rather than the system underneath.
"""

import random
from datetime import UTC, datetime, timedelta

from locust import HttpUser, between, task

CLINIC_COUNT = 50
PASSWORD = "loadtestpassword1"


class ClinicStaff(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        """Log in once, keep the token, like any real client."""
        self.clinic = f"load-{random.randint(0, CLINIC_COUNT - 1):03d}"
        reply = self.client.post(
            "/auth/login",
            headers={"X-Tenant-Slug": self.clinic},
            json={"email": f"admin0@{self.clinic}.example.com", "password": PASSWORD},
            name="POST /auth/login",
        )
        if reply.status_code != 200:
            self.token = None
            return
        self.token = reply.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

        listed = self.client.get(
            "/appointments", headers=self.headers, name="GET /appointments"
        )
        rows = listed.json() if listed.status_code == 200 else []
        self.known = [row["id"] for row in rows][:20]
        self.patient_id = rows[0]["patient_id"] if rows else None
        self.provider_id = rows[0]["provider_id"] if rows else None

    @task(10)
    def list_appointments(self) -> None:
        if not self.token:
            return
        self.client.get(
            "/appointments",
            headers=self.headers,
            params={"limit": 50},
            name="GET /appointments",
        )

    @task(5)
    def read_one(self) -> None:
        if not self.token or not self.known:
            return
        self.client.get(
            f"/appointments/{random.choice(self.known)}",
            headers=self.headers,
            name="GET /appointments/{id}",
        )

    @task(3)
    def who_am_i(self) -> None:
        if not self.token:
            return
        self.client.get("/auth/me", headers=self.headers, name="GET /auth/me")

    @task(2)
    def book(self) -> None:
        """Far-future slots at random minutes, so bookings rarely collide.

        A collision is a correct 409, but a run full of them would be
        measuring the exclusion constraint rather than the write path.
        """
        if not self.token or not self.patient_id:
            return
        start = datetime.now(UTC) + timedelta(
            days=random.randint(400, 3000), minutes=random.randint(0, 1400)
        )
        self.client.post(
            "/appointments",
            headers=self.headers,
            json={
                "patient_id": self.patient_id,
                "provider_id": self.provider_id,
                "scheduled_start": start.isoformat(),
                "scheduled_end": (start + timedelta(minutes=30)).isoformat(),
                "reason": "Load test booking",
            },
            name="POST /appointments",
        )
