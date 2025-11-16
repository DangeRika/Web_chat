from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

#from websocket_router import router as ws_router

from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt, JWTError
from config import settings
from auth import verify_password
from sqlalchemy import select

from crud import create_message, get_or_create_private_chat, get_user_chats_by_public_id, get_chat_messages 
from init_db import init_db
from db_conf import get_db
from crud import get_all_users, get_user_by_id, get_user_by_public_id, create_user, delete_user, get_messages_between
from crud import get_refresh_tokens_by_user
from crud import save_refresh_token_hash
from crud import revoke_user_refresh_tokens
from models import UserCreate, MessageCreate, UserRead, MessageRead
from auth import (
    auth_user,
    get_current_user,
    create_access_token,
    create_refresh_token,
    hash_password,
    check_rate_limit
)
from db_models import User, Message



app = FastAPI(title="Welcome to the chat buddy...")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # или ["http://localhost:5500"] если хочешь ограничить
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    )



#app.include_router(ws_router)



@app.on_event("startup")
async def on_startup():
    await init_db()



@app.get("/")
def main_page():
    return "welcome"



# ---------------- AUTH ----------------

@app.post("/auth/register")
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """Регистрация нового пользователя"""
    user.password = hash_password(user.password)
    db_user = await create_user(db, user)
    return db_user


@app.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """Вход с логином/паролем и выдачей JWT токена"""
    # Простая защита от брутфорса
    await check_rate_limit(form_data.username)

    user = await auth_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )


    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})
    
    # Сохраняем хэш в БД
    refresh_token_hash = hash_password(refresh_token)
    await save_refresh_token_hash(db, user.id, refresh_token_hash)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@app.post("/refresh")
async def refresh_token_endpoint(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    try:
        payload = jwt.decode(
            refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        username: str | None = payload.get("sub")
        token_type = payload.get("type")

        if username is None or token_type != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user_tokens = await get_refresh_tokens_by_user(db, username)
    valid = False
    for t in user_tokens:
        if verify_password(refresh_token, t.token_hash):
            valid = True
            break
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

    new_access_token = create_access_token(data={"sub": username})
    return {"access_token": new_access_token, "token_type": "bearer"}


@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Выход — удаляем все refresh токены пользователя"""
    #from crud import revoke_user_refresh_tokens
    await revoke_user_refresh_tokens(db, current_user.id)
    return {"detail": "Logged out successfully"}


# ---------------- USERS ----------------

@app.get("/users", response_model=list[UserRead])
async def read_all_users(db: AsyncSession = Depends(get_db)):
    """Список всех пользователей (только для администратора в будущем)"""
    return await get_all_users(db)


@app.get("/users/me", response_model=UserRead)
async def get_me(current_user: User = Depends(get_current_user)):
    """Получаем информацию о текущем пользователе"""
    return current_user


@app.get("/users/to/{user_id}", response_model=UserRead)
async def read_user_by_id(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user




# ---------------- chat & messages ----------------


#Найти пользователя по публичному айди
@app.get("/users/public/{public_id}", response_model=UserRead)
async def find_user_by_public_id(public_id: str, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_public_id(db, public_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user



#Написать пользователю
@app.post("/chat/{public_id}/send", response_model=MessageRead)
async def send_message(
    public_id: str,
    message: MessageCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):

    if public_id == current_user.public_id:
        raise HTTPException(status_code=400, detail="Cannot send message to yourself")

    """Отправить сообщение другому пользователю"""
    recipient = await get_user_by_public_id(db, public_id)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")


    chat = await get_or_create_private_chat(db=db, user1_id=current_user.id, user2_id=recipient.id)

    msg = await create_message(
        db=db,
        sender_public=current_user.public_id,
        recipient_public=recipient.public_id,
        content=message.content
    )

    return msg



#Получить историю чата с другим пользователем
@app.get("/chat/{public_id}", response_model=list[MessageRead])
async def get_chat_messages(
    public_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):

    """Получить историю сообщений с другим пользователем"""
    recipient = await get_user_by_public_id(db, public_id)
    if not recipient:
        raise HTTPException(status_code=404, detail="User not found")

    if recipient.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot get chat with yourself")


    chat = await get_or_create_private_chat(db=db, user1_id=current_user.id, user2_id=recipient.id)


    # Получаем все сообщения чата
    result = await db.execute(
        select(Message)
        .where(Message.chat_id == chat.id)
        .order_by(Message.created_at)
    )

    messages = result.scalars().all()

    return messages














