from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from db_models import User, Message
from models import UserCreate, MessageCreate
from fastapi import HTTPException


# ---------------- Users ----------------


async def get_user_by_id(db: AsyncSession, user_id: int) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


# ONLY FOR ADMIN 
async def get_all_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User))
    return result.scalars().all()

# При регистрации тока 
async def create_user(db: AsyncSession, user: UserCreate) -> User:
    db_user = User(**user.dict())
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



# ---------------- Messages ----------------



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



async def create_message(db: AsyncSession, message: MessageCreate, sender_id: int) -> Message:
    db_message = Message(sender_id=sender_id, **message.dict())
    db.add(db_message)
    await db.commit()
    await db.refresh(db_message)
    return db_message





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


async def revoke_user_refresh_tokens(db: AsyncSession, user_id: int):
    await db.execute(
        RefreshToken.__table__.delete().where(RefreshToken.user_id == user_id)
    )
    await db.commit()

