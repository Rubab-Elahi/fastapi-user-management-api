from typing import List
from fastapi import FastAPI, HTTPException, Request, status

from database import get_db_connection, init_db
from schemas import UserCreate, UserResponse, UserUpdate

app = FastAPI(title="User Management API")

# Initialize SQLite table on app startup
init_db()


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

        # Check for existing Email
        cursor.execute("SELECT email FROM users WHERE email = ?", (user.email,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with Email '{user.email}' already exists",
            )

        cursor.execute(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            (user.name, user.email),
        )
        user_id = cursor.lastrowid

    return {"id": user_id, "name": user.name, "email": user.email}


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