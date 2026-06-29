from sqlalchemy import text
from app.db.session import engine
from app.models.models import Base


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_uploads (
                id UUID PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                source VARCHAR(50) NOT NULL,
                uploaded_at TIMESTAMPTZ
            )
        """))
        await conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS upload_id UUID"))
        await conn.execute(text("""
            DO $$
            BEGIN
              IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'findings_upload_id_fkey'
              ) THEN
                ALTER TABLE findings
                ADD CONSTRAINT findings_upload_id_fkey
                FOREIGN KEY (upload_id) REFERENCES scan_uploads(id) ON DELETE SET NULL;
              END IF;
            END $$;
        """))
