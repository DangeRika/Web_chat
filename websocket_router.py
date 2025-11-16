from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from typing import Dict, Set

from jose import jwt, JWTError
from sqlalchemy import select

from config import settings
from db_conf import get_db
from db_models import Chat, User
from crud import get_user_by_username

router = APIRouter()

# словарь: chat_id → set(websockets)
active_connections: Dict[str, Set[WebSocket]] = {}


async def connect(chat_id: int, websocket: WebSocket):
    chat_id = str(chat_id)
    await websocket.accept()

    if chat_id not in active_connections:
        active_connections[chat_id] = set()

    active_connections[chat_id].add(websocket)


def disconnect(chat_id: int, websocket: WebSocket):
    chat_id = str(chat_id)

    if chat_id not in active_connections:
        return

    active_connections[chat_id].remove(websocket)

    if len(active_connections[chat_id]) == 0:
        del active_connections[chat_id]


async def broadcast(chat_id: int, message: dict):
    chat_id = str(chat_id)

    if chat_id in active_connections:
        for ws in list(active_connections[chat_id]):
            await ws.send_json(message)


@router.websocket("/ws/chat/{chat_id}")
async def websocket_chat(websocket: WebSocket, chat_id: int, db=Depends(get_db)):
    # 1. Получаем token
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close()
        return

    # 2. Декодируем токен
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
    except JWTError:
        await websocket.close()
        return

    # 3. Находим пользователя по username
    user = await get_user_by_username(db, username)
    if not user:
        await websocket.close()
        return

    # 4. Проверяем, имеет ли право находиться в чате
    result = await db.execute(select(Chat).where(Chat.id == chat_id))
    chat = result.scalar_one_or_none()

    if not chat:
        await websocket.close()
        return

    if user.id not in [chat.user1_id, chat.user2_id]:
        await websocket.close()
        return

    # 5. Подключаем
    await connect(chat_id, websocket)

    # 6. Цикл получения сообщений
    try:
        while True:
            data = await websocket.receive_json()

            # можно тут сохранять в БД

            await broadcast(chat_id, data)

    except WebSocketDisconnect:
        disconnect(chat_id, websocket)
