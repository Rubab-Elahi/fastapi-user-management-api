import sqlite3

DB_FILE = "users.db"


def get_db_connection():
    """Helper function to obtain a database connection with Row factory."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Table for storing users with hashed password
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL DEFAULT ''
            )
        """
        )

        # Migration check: Ensure password column exists if users table was created in an older schema version
        cursor.execute("PRAGMA table_info(users)")
        columns = [row["name"] for row in cursor.fetchall()]
        if "password" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN password TEXT NOT NULL DEFAULT ''")

        # Table for active sessions/tokens (for sign out / blacklisting)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS token_blacklist (
                token TEXT PRIMARY KEY,
                blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Table for password reset requests
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS reset_tokens (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """
        )

        # Table for active session tokens
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """
        )
        conn.commit()