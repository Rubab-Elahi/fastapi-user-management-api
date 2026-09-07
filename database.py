import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")


def get_db_connection():
    """Helper function to obtain a PostgreSQL database connection with RealDictCursor."""
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is missing. Please set it in Vercel Project Settings.")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    """Initialize PostgreSQL tables if they do not exist."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Table for storing users with hashed password and role
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password TEXT NOT NULL DEFAULT '',
                        role VARCHAR(50) NOT NULL DEFAULT 'student',
                        created_by VARCHAR(255) NOT NULL DEFAULT ''
                    );
                    """
                )
                cursor.execute(
                    "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by VARCHAR(255) NOT NULL DEFAULT '';"
                )

                # Table for active sessions/tokens (for sign out / blacklisting)
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS token_blacklist (
                        token TEXT PRIMARY KEY,
                        blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )

                # Table for password reset requests
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS reset_tokens (
                        token TEXT PRIMARY KEY,
                        email VARCHAR(255) NOT NULL,
                        expires_at TIMESTAMP NOT NULL
                    );
                    """
                )

                # Table for active session tokens
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        token TEXT PRIMARY KEY,
                        email VARCHAR(255) NOT NULL,
                        expires_at TIMESTAMP NOT NULL
                    );
                    """
                )
            conn.commit()
    except Exception as e:
        print(f"[DATABASE NOTICE] PostgreSQL init check: {e}")