"""Signup, registration and login. None of these require a token."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rate_limit import RateLimiter
from app.core.revocation import RevokedTokens
from app.core.security import (
    dummy_verify_async,
    hash_password_async,
    verify_password_async,
)
from app.core.tokens import (
    TokenClaims,
    TokenError,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.database.models import Tenant, User, UserRole
from app.database.session import get_db, use_tenant
from app.dependencies.auth import CurrentUser, get_access_claims, get_current_user
from app.dependencies.rate_limit import RateLimit
from app.dependencies.tenant import get_tenant
from app.schemas.auth import (
    ClinicOut,
    ClinicSignupRequest,
    ClinicSignupResponse,
    LoginRequest,
    LogoutRequest,
    PatientRegisterRequest,
    RefreshRequest,
    TokenResponse,
    UserOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
CurrentClinic = Annotated[Tenant, Depends(get_tenant)]


def _invalid_credentials() -> HTTPException:
    """One identical answer for every failed login.

    Same wording whether the email is unknown, the password is wrong, or the
    account is switched off. Any difference between those three would tell an
    attacker which emails are real.
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _issue_tokens(user: User) -> TokenResponse:
    access = create_access_token(
        user_id=user.id, tenant_id=user.tenant_id, role=user.role
    )
    refresh = create_refresh_token(
        user_id=user.id, tenant_id=user.tenant_id, role=user.role
    )
    return TokenResponse(
        access_token=access.token,
        refresh_token=refresh.token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/signup",
    dependencies=[Depends(RateLimit("signup"))],
    status_code=status.HTTP_201_CREATED,
    response_model=ClinicSignupResponse,
    summary="Create a new clinic and its first admin",
)
async def signup_clinic(payload: ClinicSignupRequest, db: DbSession):
    """Both rows are written in one transaction.

    If the admin cannot be created, the clinic is not created either — there is
    no state where a clinic exists that nobody can log into.
    """
    clinic = Tenant(name=payload.clinic_name, slug=payload.clinic_slug)
    db.add(clinic)
    try:
        await db.flush()  # assigns clinic.id without ending the transaction
        # The clinic exists now, so claim it before inserting its first user.
        # Without this the insert is refused by the policy, which is the
        # correct behaviour: nothing writes a user without saying whose.
        await use_tenant(db, clinic.id)
        admin = User(
            tenant_id=clinic.id,
            email=payload.email,
            hashed_password=await hash_password_async(payload.password),
            full_name=payload.full_name,
            role=UserRole.ADMIN,
        )
        db.add(admin)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That clinic address is already taken",
        ) from None

    return ClinicSignupResponse(
        clinic=ClinicOut.model_validate(clinic), admin=UserOut.model_validate(admin)
    )


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=UserOut,
    summary="Register as a patient at an existing clinic",
)
async def register_patient(
    payload: PatientRegisterRequest, clinic: CurrentClinic, db: DbSession
):
    patient = User(
        tenant_id=clinic.id,
        email=payload.email,
        hashed_password=await hash_password_async(payload.password),
        full_name=payload.full_name,
        # Fixed here, never read from the request. This is the line that stops
        # anyone signing themselves up as an admin.
        role=UserRole.PATIENT,
    )
    db.add(patient)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That email is already registered at this clinic",
        ) from None

    return UserOut.model_validate(patient)


@router.post(
    "/login",
    dependencies=[Depends(RateLimit("login"))],
    response_model=TokenResponse,
    summary="Exchange a password for tokens",
)
async def login(
    request: Request, payload: LoginRequest, clinic: CurrentClinic, db: DbSession
):
    """Two guards, and a rule between them: a correct password always wins.

    Guard 1 (per caller) already ran as a dependency above. Guard 2 (per
    account) is here, because it needs the email. It counts only FAILED
    logins, and it is checked in an order that matters: the password is
    verified BEFORE the budget can refuse anyone, so an attacker filling the
    budget with wrong guesses can never lock the real owner out — the moment
    they type the right password, they are in.
    """
    limiter = RateLimiter(request.app.state.redis)
    # Keyed on the submitted email whether or not it exists, so an attacker
    # cannot tell a real account from an invented one by how it is refused.
    account_key = f"ratelimit:account:{clinic.id}:{payload.email}"

    async def account_over_budget() -> bool:
        if not settings.rate_limit_enabled:
            return False
        try:
            decision = await limiter.peek(
                account_key,
                limit=settings.account_rate_limit,
                window_seconds=settings.account_rate_window_seconds,
            )
        except (RedisError, OSError) as exc:
            # Fail closed, same as everywhere else.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Login is briefly unavailable. Please try again shortly.",
                headers={"Retry-After": "30"},
            ) from exc
        return not decision.allowed

    async def note_failure() -> None:
        if settings.rate_limit_enabled:
            try:
                await limiter.record_failure(
                    account_key,
                    window_seconds=settings.account_rate_window_seconds,
                )
            except (RedisError, OSError):
                # A failure we could not record is not worth turning a 401 into
                # a 503 over. The per-address guard still applies.
                pass

    user = await db.scalar(
        select(User).where(User.tenant_id == clinic.id, User.email == payload.email)
    )

    # The password is checked FIRST, so a correct one is honoured even when the
    # account budget is already full.
    if user is not None and user.is_active:
        if await verify_password_async(payload.password, user.hashed_password):
            # Success wipes the failure count: the real owner just proved
            # themselves, so the attacker's noise should not linger.
            if settings.rate_limit_enabled:
                await limiter.clear(account_key)
            return _issue_tokens(user)
    else:
        # Unknown or inactive account: spend the same time a real check costs,
        # so timing gives nothing away.
        await dummy_verify_async()

    # We are on the failure path. Record it, and only now consult Guard 2 — if
    # this account has failed too many times, say so; otherwise the plain 401.
    await note_failure()
    if await account_over_budget():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again shortly.",
            headers={"Retry-After": str(settings.account_rate_window_seconds)},
        )
    raise _invalid_credentials()


@router.get(
    "/me",
    response_model=UserOut,
    summary="Who the current token belongs to",
)
async def read_me(user: Annotated[CurrentUser, Depends(get_current_user)]):
    """The first route behind a token. Everything in Phase 5 sits behind the
    same dependency, which is why this one is worth proving on its own."""
    return UserOut.model_validate(user)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel the tokens you are holding",
)
async def logout(
    request: Request,
    caller: Annotated[CurrentUser, Depends(get_current_user)],
    claims: Annotated[TokenClaims, Depends(get_access_claims)],
    payload: LogoutRequest | None = None,
) -> Response:
    """Stop honouring this token, and the refresh token if one is handed in.

    Requires a working token, so nobody can fill the revocation list with
    invented ids. Calling it twice is harmless — the second call revokes an
    already-revoked token, which changes nothing.
    """
    revoked = RevokedTokens(request.app.state.redis)
    await revoked.revoke(claims)

    if payload is not None and payload.refresh_token:
        try:
            refresh_claims = decode_token(
                payload.refresh_token, expected_type=TokenType.REFRESH
            )
        except TokenError:
            # Already expired or not a real refresh token. Nothing to cancel,
            # and no reason to fail a logout over it.
            pass
        else:
            # Only your own. Otherwise handing in somebody else's refresh
            # token would log them out.
            if refresh_claims.sub == caller.id:
                await revoked.revoke(refresh_claims)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/refresh",
    dependencies=[Depends(RateLimit("refresh"))],
    response_model=TokenResponse,
    summary="Trade a refresh token for a new pair",
)
async def refresh(request: Request, payload: RefreshRequest, db: DbSession):
    """Rotation: the token handed in is cancelled and a new pair issued.

    A refresh token is good for a week, which is a long time for something
    that might be sitting in a stolen backup. Rotating on every use means a
    copy is only useful until the real holder next refreshes — at which point
    the copy stops working.

    It also turns theft into something detectable. A token that has already
    been rotated away being presented again means two parties hold it, and the
    honest one is about to be locked out. That case is treated as theft below.
    """
    revoked = RevokedTokens(request.app.state.redis)

    try:
        claims = decode_token(payload.refresh_token, expected_type=TokenType.REFRESH)
    except TokenError:
        raise _invalid_credentials() from None

    if await revoked.is_revoked(claims.jti):
        # Either a logout, or the same token being used twice. We cannot tell
        # which from here, and both mean this one is finished.
        raise _invalid_credentials()

    await use_tenant(db, claims.tid)
    user = await db.scalar(
        select(User)
        .join(Tenant, Tenant.id == User.tenant_id)
        .where(
            User.id == claims.sub,
            User.tenant_id == claims.tid,
            User.is_active.is_(True),
            Tenant.is_active.is_(True),
        )
    )
    if user is None:
        raise _invalid_credentials()

    # Cancel the one just used before handing out its replacement, so there is
    # never a moment where both work.
    await revoked.revoke(claims)
    return _issue_tokens(user)
