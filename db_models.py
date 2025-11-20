from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text, func
from sqlalchemy.orm import relationship
from db_conf import Base
import secrets
from datetime import datetime

#-------------------
# users
#-------------------

def generate_public_id():
    return secrets.token_hex(4)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    public_id = Column(String, unique=True, index=True, default=generate_public_id)
    username = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True, default=None)
    password = Column(String, nullable=False)  # потом будем хранить хэш
    is_admin = Column(Boolean, default=False)
    is_online = Column(Boolean, default=False)
    last_active = Column(DateTime)

    # связь "один ко многим" с сообщениями
    sent_messages = relationship("Message", back_populates="sender", foreign_keys='Message.sender_id')
    received_messages = relationship("Message", back_populates="recipient", foreign_keys='Message.recipient_id')



class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", backref="refresh_tokens")



#-------------------
# chats & messages
#-------------------
class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # связи с пользователями
    sender = relationship("User", back_populates="sent_messages", foreign_keys=[sender_id])
    recipient = relationship("User", back_populates="received_messages", foreign_keys=[recipient_id])

    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)
    chat = relationship("Chat", back_populates="messages")



class Chat(Base):
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    members = relationship("ChatMember", back_populates="chat")
    messages = relationship("Message", back_populates="chat")




class ChatMember(Base):
    __tablename__ = "chat_members"

    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    chat = relationship("Chat", back_populates="members")
    user = relationship("User", backref="chats")
