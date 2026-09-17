"""Signup, registration and login. None of these require a token."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.revocation import RevokedTokens
from app.core.security import dummy_verify, hash_password, verify_password
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
            hashed_password=hash_password(payload.password),
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
        hashed_password=hash_password(payload.password),
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
async def login(payload: LoginRequest, clinic: CurrentClinic, db: DbSession):
    user = await db.scalar(
        select(User).where(User.tenant_id == clinic.id, User.email == payload.email)
    )

    if user is None:
        # Do the same work a real check costs, so an unknown email takes just
        # as long to answer as a real one.
        dummy_verify()
        raise _invalid_credentials()

    if not verify_password(payload.password, user.hashed_password):
        raise _invalid_credentials()

    if not user.is_active:
        raise _invalid_credentials()

    return _issue_tokens(user)


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
