from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from config import DB_PATH

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _migrate(eng):
    """Add new columns to existing tables without dropping data."""
    migrations = [
        ("devices",    "location_id", "INTEGER REFERENCES locations(id)"),
        ("dns_queries","location_id", "INTEGER REFERENCES locations(id)"),
        ("alerts",     "location_id", "INTEGER REFERENCES locations(id)"),
    ]
    with eng.connect() as conn:
        for table, column, col_def in migrations:
            try:
                result = conn.execute(text(f"PRAGMA table_info({table})"))
                existing = {row[1] for row in result}
                if column not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
                    conn.commit()
            except Exception:
                pass


def init_db():
    from models import Location, Device, DNSQuery, Alert, AppSetting  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _migrate(engine)
