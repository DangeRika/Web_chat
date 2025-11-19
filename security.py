from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db_conf import get_db
from db_models import User

async def verify_user_access(public_id: str, 
                             current_user: User = Depends(lambda: None), 
                             db: AsyncSession = Depends(get_db)):
    from auth import get_current_user  # локальный импорт
    current_user = await get_current_user()
    
    result = await db.execute(select(User).where(User.public_id == public_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if current_user.public_id != user.public_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return user

