from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.redis import lifespan
from app.middleware import RequestId
from app.routers import appointments, auth

app = FastAPI(title="Healthcare Appointment API", lifespan=lifespan)

app.add_middleware(RequestId)

app.include_router(auth.router)
app.include_router(appointments.router)


@app.exception_handler(ConnectionError)
@app.exception_handler(OperationalError)
@app.exception_handler(DBAPIError)
async def database_unreachable(request: Request, exc: Exception) -> JSONResponse:
    """A database we cannot reach is a 503, not a 500.

    Three types, because the failure arrives differently depending on when it
    happens. Once a connection exists, SQLAlchemy wraps the problem in its own
    OperationalError. Failing to open one in the first place never reaches
    SQLAlchemy at all — asyncpg raises a plain ConnectionRefusedError straight
    from the socket. ConnectionError rather than OSError so an ordinary
    file-handling bug of ours still surfaces as the 500 it is.

    500 says we wrote something wrong. 503 says the service is temporarily
    unable to answer and it is worth trying again — which is true, and which
    load balancers and clients already know how to act on.

    The exception text is deliberately not passed on. Connection errors carry
    hostnames, ports and usernames.
    """
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Temporarily unable to reach the database."},
        headers={"Retry-After": "30"},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
