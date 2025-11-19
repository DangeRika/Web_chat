from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

#from websocket_router import router as ws_router

from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt, JWTError
from config import settings
from auth import verify_password
from security import verify_user_access 
from sqlalchemy import select
from typing import List

from crud import create_message, get_or_create_private_chat, get_chat_messages 
from init_db import init_db
from db_conf import get_db
from crud import get_current_user_chats_by_public_id
from crud import get_all_users, get_user_by_id, get_user_by_public_id, create_user, delete_user, get_messages_between
from crud import get_refresh_tokens_by_user
from crud import save_refresh_token_hash
from crud import revoke_user_refresh_tokens
from models import UserCreate, MessageCreate, UserRead, MessageRead, NewMessageRead, UserIsAdminRead
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









# ----------- -- For Admin -----------

def admin_check(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    return current_user





@app.get("/users", response_model=list[UserIsAdminRead])
async def read_all_users(db: AsyncSession = Depends(get_db), current_user: User = Depends(admin_check)):
    """Список всех пользователей (только для администратора)"""
    return await get_all_users(db)






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



@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Выход — удаляем все refresh токены пользователя"""
    #from crud import revoke_user_refresh_tokens
    await revoke_user_refresh_tokens(db, current_user.id)
    return {"detail": "Logged out successfully"}



@app.post("/refresh")
async def refresh_token_endpoint(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    # -------- ДЕКОДИРОВАНИЕ JWT --------
    try:
        payload = jwt.decode(
            refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        username: str | None = payload.get("sub")
        token_type = payload.get("type")

        if username is None or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token")

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # -------- ПРОВЕРКА В БД --------
    stored_tokens = await get_refresh_tokens_by_user(db, username)

    matched_token = None
    for t in stored_tokens:
        if verify_password(refresh_token, t.token_hash):  # bcrypt сравнение
            matched_token = t
            break

    if not matched_token:
        raise HTTPException(status_code=401, detail="Token revoked")

    # -------- РОТАЦИЯ REFRESH TOKEN --------
    # Удаляем старый записанный токен
    await delete_refresh_token(db, matched_token.id)

    # Создаем новый refresh и access токены
    new_access = create_access_token({"sub": username})
    new_refresh = create_refresh_token({"sub": username})

    # Записываем новый refresh token (только hash!)
    await store_refresh_token(
        db=db,
        username=username,
        token_hash=hash_password(new_refresh)
    )

    # -------- ОТДАЕМ НОВЫЕ ТОКЕНЫ --------
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer"
    }




# ---------------- USERS ----------------



#Профиль пользователя
@app.get("/user/profile/me", response_model=UserRead)
async def get_me(current_user: User = Depends(get_current_user)):
    """Получаем информацию о текущем пользователе"""
    return current_user



# ---------------- chat & messages ----------------



@app.get("/chat/list")
async def get_chats_list(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    chats = await get_current_user_chats_by_public_id(db=db, user=current_user)
    return chats



#Найти пользователя по публичному айди
@app.get("/users/public/{public_id}", response_model=UserRead)
async def find_user_by_public_id(public_id: str, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_public_id(db, public_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user



#Получить историю чата с другим пользователем
@app.get("/chat/{public_id}/history", response_model=List[NewMessageRead])
async def get_chat_history(
    public_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    recipient = await get_user_by_public_id(db, public_id)
    if not recipient:
        raise HTTPException(status_code=404, detail="User not found")
    if recipient.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot chat with yourself")

    chat = await get_or_create_private_chat(db=db, user1_id=current_user.id, user2_id=recipient.id)

    stmt = (
        select(Message, User.username, User.public_id)
        .join(User, Message.sender_id == User.id)
        .where(Message.chat_id == chat.id)
        .order_by(Message.created_at)
    )
    result = await db.execute(stmt)
    rows = result.all()

    messages = []    
    for msg, sender_username, sender_public_id in rows:
        if msg.sender_id == current_user.id:
            recipient_user = recipient
        else:
            recipient_user = current_user

        messages.append({
            "id": msg.id,
            "chat_id": msg.chat_id,
            "sender_id": msg.sender_id,
            "content": msg.content,
            "created_at": msg.created_at,
            "sender_username": sender_username,
            "sender_public_id": sender_public_id,
            "recipient_username": recipient_user.username,
            "recipient_public_id": recipient_user.public_id,
        })

    return messages




# IN WORK..........
#Написать пользователю
#Через вебсокет
#@app.post("/chat/{public_id}/send", response_model=MessageRead)
#пОЛУЧИТЬ СООБЩЕНИЯ от пользователя
#Через вебсокет


#статусы онлайн/офлайн






