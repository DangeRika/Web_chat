from pydantic import BaseModel, field_validator, Field
from datetime import datetime
from typing import Optional 
from sqlalchemy import DateTime


# ------------------- USERS -------------------
class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str  # при регистрации

class UserRead(UserBase):
    public_id: str
    #avatar: 
    description: Optional[str] = None


    model_config = {
            "from_attributes": True,
            "extra": "ignore",
            "populate_by_name": True
        }
    
    @field_validator("description", mode="before")
    def empty_to_none(cls, v):
        if v == "" or v is None:
            return None
        return v
    
    
class UserUpdate(BaseModel):
    #username: Optional[str] = Field(None, min_length=1)
    description: Optional[str] = None

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
