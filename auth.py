from datetime import datetime, timedelta, timezone
from time import time
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
import redis.asyncio as redis
from fastapi import HTTPException

from crud import get_user_by_username
from db_models import User
from config import settings
from db_conf import get_db


#redis
redis_client = redis.from_url("redis://localhost:6379", decode_responses=True)

MAX_ATTEMPTS = 5
BLOCK_TIME = 60  # секунд

async def check_rate_limit(username: str):
    key = f"login_attempts:{username}"

    # INCR создаёт ключ, если его нет, и увеличивает на 1
    attempts = await redis_client.incr(key)

    # Если это первая попытка, задаём TTL
    if attempts == 1:
        await redis_client.expire(key, BLOCK_TIME)

    if attempts > MAX_ATTEMPTS:
        ttl = await redis_client.ttl(key)
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {ttl} seconds."
        )



#config
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")



# password
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


#Token
def create_token(data: dict, expires_delta: timedelta, token_type: str = "access") -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "type": token_type})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

    
def create_access_token(data: dict) -> str:
    return create_token(data, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES), token_type="access")

def create_refresh_token(data: dict) -> str:
    return create_token(data, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS), token_type="refresh")


class TokenData(BaseModel):
    username: Optional[str] = None
    type: Optional[str] = None



#Аутентификация
async def auth_user(db: AsyncSession, username: str, password: str) -> Optional[User]:
    user = await get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return user


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str | None = payload.get("sub")
        token_type = payload.get("type")

        if username is None or token_type != "access":
            raise credentials_exception
        token_data = TokenData(username=username, type=token_type)
    except JWTError:
        raise credentials_exception

    user = await get_user_by_username(db, token_data.username)
    if user is None:
        raise credentials_exception
    return user
    


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user








