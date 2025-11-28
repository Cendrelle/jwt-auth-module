import jwt
import uuid
import hashlib
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone


ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
REFRESH_TOKEN_LIFETIME = timedelta(days=7)
JWT_ALGORITHM = "HS256" 


def generate_jti():

    return str(uuid.uuid4())


def hash_token(token: str) -> str:

    return hashlib.sha256(token.encode()).hexdigest()


def create_jwt(payload: dict, lifetime: timedelta) -> str:
    """Crée un JWT signé avec une durée de vie donnée."""
    now = datetime.utcnow()
    exp = now + lifetime
    payload.update({
        "iat": now,
        "exp": exp,
        "jti": generate_jti(),
    })
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt(token: str) -> dict:
    """Vérifie et décode un JWT."""
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])


def make_access_token(user_id: int) -> str:
    """Crée un access token court (utilisé pour les requêtes API)."""
    payload = {"user_id": user_id, "type": "access"}
    return create_jwt(payload, ACCESS_TOKEN_LIFETIME)


def make_refresh_token(user_id: int) -> str:
    """Crée un refresh token longue durée."""
    payload = {"user_id": user_id, "type": "refresh"}
    return create_jwt(payload, REFRESH_TOKEN_LIFETIME)
