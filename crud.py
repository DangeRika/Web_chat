from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from db_models import User, Message, Chat, ChatMember
from models import UserCreate, MessageCreate
from fastapi import HTTPException
from sqlalchemy import func, desc
from security import verify_user_access
from fastapi import Depends

# ---------------- Users ----------------


async def get_user_by_id(db: AsyncSession, user_id: int) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_public_id(db: AsyncSession, public_id: str) -> User | None:
    result = await db.execute(select(User).where(User.public_id == public_id))
    return result.scalar_one_or_none()


async def get_user_by_username(db: AsyncSession, username: str):
    result = await db.execute(
        select(User).where(User.username == username)
    )
    return result.scalar_one_or_none()



# ONLY FOR ADMIN 
async def get_all_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User))
    return result.scalars().all()

# При регистрации тока 
async def create_user(db: AsyncSession, user: UserCreate) -> User:
    db_user = User(**user.model_dump())
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user    


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()
    
# ONLY FOR ADMIN
async def delete_user(db: AsyncSession, user_id: int):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.delete(user)
    await db.commit()
    return {"detail": f"User {user_id} deleted"}
    


# async def edit_user(db: AsyncSession, user_id: int)
# asybc def delete_my_account(db: AsyncSession, current_id: int)



# ---------------- Chats & Messages ----------------



async def get_messages_between(db: AsyncSession, user1_id: int, user2_id: int) -> list[Message]:
    result = await db.execute(
        select(Message)
        .where(
            ((Message.sender_id == user1_id) & (Message.recipient_id == user2_id)) |
            ((Message.sender_id == user2_id) & (Message.recipient_id == user1_id))
        )
        .order_by(Message.created_at)
    )
    return result.scalars().all()



async def create_message(db: AsyncSession, sender_public: str, recipient_public: str, content: str) -> Message:
    # Находим пользователей
    result = await db.execute(select(User).where(User.public_id == sender_public))
    sender = result.scalar_one_or_none()
    if not sender:
        raise HTTPException(status_code=404, detail="Sender not found")

    result = await db.execute(select(User).where(User.public_id == recipient_public))
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    # Получаем или создаём чат 1 на 1
    chat = await get_or_create_private_chat(db, sender.id, recipient.id)

    # Создаём сообщение
    db_message = Message(chat_id=chat.id, sender_id=sender.id, recipient_id=recipient.id, content=content)
    db.add(db_message)
    await db.commit()
    await db.refresh(db_message)
    return db_message




async def get_or_create_private_chat(db, user1_id, user2_id):

    # ищем существующий чат с этими двумя пользователями
    result = await db.execute(
        select(Chat)
        .join(ChatMember)
        .group_by(Chat.id)
        .having(func.count(ChatMember.id) == 2)
        .where(ChatMember.user_id.in_([user1_id, user2_id]))
    )

    chat = result.scalar_one_or_none()
    if chat:
        return chat

    # если нет, создаём новый чат
    chat = Chat()
    db.add(chat)
    await db.commit()
    await db.refresh(chat)
    
    db.add_all([ChatMember(chat_id=chat.id, user_id=user1_id),
                ChatMember(chat_id=chat.id, user_id=user2_id)])
    await db.commit()
    return chat
    


# Получить список чатов пользователя
async def get_current_user_chats_by_public_id(db: AsyncSession, user: User = Depends(verify_user_access)) -> list[dict]:
    """
    Получить список чатов текущего пользователя с собеседниками.
    user — уже проверенный через verify_user_access
    """
    # Получаем чаты, исключая самого пользователя
    result = await db.execute(
        select(
            Chat.id,
            Chat.created_at,
            User.id.label("peer_id"),
            User.username.label("peer_username"),
            User.public_id.label("peer_public_id")  # добавляем public_id
        )
        .join(ChatMember, Chat.id == ChatMember.chat_id)
        .join(User, User.id == ChatMember.user_id)
        .where(ChatMember.user_id != user.id)
        .where(Chat.id.in_(
            select(ChatMember.chat_id).where(ChatMember.user_id == user.id)
        ))
    )

    return [
        {
            "chat_id": row.id,
            "created_at": row.created_at,
            "peer_id": row.peer_id,
            "peer_username": row.peer_username,
            "peer_public_id": row.peer_public_id  # возвращаем public_id
        }
        for row in result
    ]





# Получить сообщения чата
async def get_chat_messages(db: AsyncSession, chat_id: int) -> list[Message]:
    result = await db.execute(
        select(Message).where(Message.chat_id == chat_id).order_by(Message.created_at)
    )
    return result.scalars().all()






#---------------- Tokens ----------------

from db_models import RefreshToken

async def save_refresh_token_hash(db: AsyncSession, user_id: int, token_hash: str):
    token = RefreshToken(user_id=user_id, token_hash=token_hash)
    db.add(token)
    await db.commit()
    return token


async def get_refresh_tokens_by_user(db: AsyncSession, username: str):
    from db_models import User
    result = await db.execute(
        select(RefreshToken).join(User).where(User.username == username)
    )
    return result.scalars().all()


async def get_refresh_tokens_by_user_id(db: AsyncSession, user_id: int):
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == user_id)
    )
    return result.scalars().all()



async def revoke_user_refresh_tokens(db: AsyncSession, user_id: int):
    await db.execute(
        RefreshToken.__table__.delete().where(RefreshToken.user_id == user_id)
    )
    await db.commit()

