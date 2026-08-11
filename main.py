import sqlite3
from typing import List
from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, EmailStr

app = FastAPI(title="User Management API")

DB_FILE = "users.db"


# --- DATABASE HELPERS ---


def get_db_connection():
    """Helper function to obtain a database connection with Row factory."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Returns output as key-dict
    return conn


def init_db():
    """Create the users table if it doesn't already exist."""
    with get_db_connection() as conn:  #with acting as a context manager ,manages the connection of database 
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE
            )
            """
        )


# Initialize SQLite table on app startup
init_db()


# --- PYDANTIC SCHEMAS ---


class UserCreate(BaseModel):
    id: int
    email: EmailStr
    name: str


class UserUpdate(BaseModel):
    name: str
    email: EmailStr


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    name: str


# --- ROUTES ---


@app.get("/")
def read_root():
    return {
        "message": "Welcome to User Management API",
        "docs": "Go to /docs to view interactive documentation",
        "users_endpoint": "/users",
    }


@app.get("/request-info")
def get_request_info(request: Request):
    return {
        "client_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "url": str(request.url),
        "query_params": dict(request.query_params),
    }


# 1. CREATE (POST)
@app.post(
    "/create-users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(user: UserCreate):
    """Create a new user in SQLite."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check for existing ID
        cursor.execute("SELECT id FROM users WHERE id = ?", (user.id,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with ID '{user.id}' already exists",
            )

        # Check for existing Email
        cursor.execute("SELECT email FROM users WHERE email = ?", (user.email,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with Email '{user.email}' already exists",
            )

        cursor.execute(
            "INSERT INTO users (id, name, email) VALUES (?, ?, ?)",
            (user.id, user.name, user.email),
        )

    return user.model_dump()


# 2. READ ALL (GET)
@app.get("/get-users", response_model=List[UserResponse])
def get_all_users():
    """Retrieve all users from SQLite."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email FROM users")
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


# 3. READ ONE BY ID (GET)
@app.get("/get-users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: int):
    """Retrieve a single user by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, email FROM users WHERE id = ?", (user_id,)
        )
        row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return dict(row)


# 4. UPDATE (PUT)
@app.put("/update-users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user: UserUpdate):
    """Update user details by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        cursor.execute(
            "UPDATE users SET name = ?, email = ? WHERE id = ?",
            (user.name, user.email, user_id),
        )

    return {"id": user_id, "name": user.name, "email": user.email}


# 5. DELETE
@app.delete("/delete-users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int):
    """Delete a user by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

    return None