from pydantic import BaseModel
from datetime import datetime


# ------------------- USERS -------------------
class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str  # при регистрации

class UserRead(UserBase):
    public_id: str

    class Config:
        orm_mode = True


class UserIsAdminRead(UserBase):
    id: int
    public_id: str
    is_admin: bool

    class Config:
        orm_mode = True
    
# ------------------- MESSAGES -------------------
class MessageBase(BaseModel):
    id: int

class MessageCreate(MessageBase):
    content: str

class MessageRead(MessageBase):
    id: int
    sender_username: str
    sender_public_id: str
    content: str
    recipient_username: str
    recipient_public_id: str
    created_at: datetime
            
    class Config:
        orm_mode = True

            
class NewMessageRead(MessageBase):
    id: int
    sender_username: str
    sender_public_id: str
    content: str
    recipient_username: str
    recipient_public_id: str
    created_at: datetime             

    class Config:
        orm_mode = True
