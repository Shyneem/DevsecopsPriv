# app/db.py
import os
import sqlite3
from datetime import datetime, timezone
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")

# Definimos los argumentos de conexión por defecto
connect_args = {}

# SI NO ES SQLITE, añadimos el SSL 
if not DATABASE_URL.startswith("sqlite"):
    connect_args["sslmode"] = "require"

engine = create_engine(
    DATABASE_URL, 
    connect_args=connect_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# SQLite fallback registration for PL/pgSQL functions during tests or local SQLite runs
def _parse_sqlite_dt(val):
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is not None:
            return val.astimezone(timezone.utc).replace(tzinfo=None)
        return val
    if isinstance(val, str):
        try:
            cleaned = val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except Exception:
            return None
    return None


def _sqlite_calculate_dwell_time(first_seen, last_seen):
    t1 = _parse_sqlite_dt(first_seen)
    t2 = _parse_sqlite_dt(last_seen)
    if not t1 or not t2:
        return None
    return (t2 - t1).total_seconds() / 86400.0


def _sqlite_calculate_vuln_age(first_seen, now=None):
    t1 = _parse_sqlite_dt(first_seen)
    if not t1:
        return None
    t2 = _parse_sqlite_dt(now) if now else datetime.now(timezone.utc).replace(tzinfo=None)
    return (t2 - t1).total_seconds() / 86400.0


@event.listens_for(Engine, "connect")
def register_sqlite_functions(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        dbapi_connection.create_function("calculate_dwell_time", 2, _sqlite_calculate_dwell_time)
        dbapi_connection.create_function("calculate_vuln_age", 1, _sqlite_calculate_vuln_age)
        dbapi_connection.create_function("calculate_vuln_age", 2, _sqlite_calculate_vuln_age)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
