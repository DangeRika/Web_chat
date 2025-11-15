from pydantic import BaseModel
from datetime import datetime


# ------------------- USERS -------------------
class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str  # при регистрации

class UserRead(UserBase):
    id: int
    is_admin: bool

    class Config:
        orm_mode = True


# ------------------- MESSAGES -------------------
class MessageBase(BaseModel):
    content: str

class MessageCreate(MessageBase):
    recipient_id: int
    content: str

class MessageRead(MessageBase):
    id: int
    sender_id: int
    recipient_id: int
    content: str
    created_at: datetime

    class Config:
        orm_mode = True
