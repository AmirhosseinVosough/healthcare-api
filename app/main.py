from fastapi import FastAPI

app = FastAPI(title="Healthcare Appointment API")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
