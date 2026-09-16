from fastapi import FastAPI

from app.routers import appointments, auth

app = FastAPI(title="Healthcare Appointment API")

app.include_router(auth.router)
app.include_router(appointments.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
