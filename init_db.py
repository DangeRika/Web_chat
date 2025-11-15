from db_conf import engine, Base
from db_models import User, Message  # импортируем все модели

async def init_db():
    async with engine.begin() as conn:
        # создаёт все таблицы, которых ещё нет
        await conn.run_sync(Base.metadata.create_all)
    print("Tables checked/created successfully!")
