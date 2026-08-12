from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks, status, Form

import secrets

from database import get_db_connection, init_db
from schemas import (
    UserCreate,
    UserResponse,
    UserUpdate,
    SignInRequest,
    TokenResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    MessageResponse,
)
from utils import (
    hash_password,
    verify_password,
    verify_token,
    create_access_token,
    send_reset_email_mock,
    SimpleOAuth2PasswordRequestForm,
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

app = FastAPI(title="User Management API")

# Initialize SQLite tables on app startup
init_db()


# Helper functions and JWT configs imported from utils.py


# --- EXISTING ROUTES ---

@app.get("/")
def read_root():
    return {
        "message": "Welcome to User Management API",
        "docs": "Go to /docs to view interactive documentation",
        "users_endpoint": "/get-users",
    }


@app.get("/request-info")
def get_request_info(request: Request):
    return {
        "client_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "url": str(request.url),
        "query_params": dict(request.query_params),
    }


# 1. CREATE USER (POST)
@app.post(
    "/create-users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(user: UserCreate):
    """Create a new user with password in SQLite (Unprotected)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT email FROM users WHERE email = ?", (user.email,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with Email '{user.email}' already exists",
            )

        # Hash password before storing
        hashed_pw = hash_password(user.password)
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (user.name, user.email, hashed_pw),
        )
        user_id = cursor.lastrowid

    return {"id": user_id, "name": user.name, "email": user.email}




# 2. READ ALL (GET)
@app.get("/get-users", response_model=List[UserResponse])
def get_all_users(token: str = Depends(verify_token)):
    """Retrieve all users from SQLite (Protected)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email FROM users")
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


# 3. READ ONE BY ID (GET)
@app.get("/get-users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: int, token: str = Depends(verify_token)):
    """Retrieve a single user by ID (Protected)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return dict(row)


# 4. UPDATE (PUT)
@app.put("/update-users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user: UserUpdate, token: str = Depends(verify_token)):
    """Update user details by ID (Protected)."""
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
def delete_user(user_id: int, token: str = Depends(verify_token)):
    """Delete a user by ID (Protected)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

    return None


# --- AUTHENTICATION ROUTES ---

# 6. SIGN IN (POST)
@app.post("/sign-in", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def sign_in(form_data: SimpleOAuth2PasswordRequestForm = Depends()):
    """Validates user credentials and issues an active JWT access token."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE email = ?", (form_data.username,))
        row = cursor.fetchone()

        # Validate existence and matching password
        if not row or not verify_password(form_data.password, row["password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        # Issue a secure JWT access token
        encoded_jwt, expire = create_access_token(form_data.username)

        # Store in session table to track logouts/active sessions
        cursor.execute(
            "INSERT INTO user_sessions (token, email, expires_at) VALUES (?, ?, ?)",
            (encoded_jwt, form_data.username, expire.isoformat()),
        )

    return TokenResponse(
        access_token=encoded_jwt,
        token_type="bearer",
        message="Signed in successfully.",
    )


# 7. SIGN OUT (POST)
@app.post("/sign-out", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def sign_out(token: str = Depends(verify_token)):
    """Invalidates the provided token by removing it from the user_sessions table."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE token = ?", (token,))

    return MessageResponse(message="Successfully signed out.")


# 8. FORGOT PASSWORD (POST)
@app.post("/forgot-password", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def forgot_password(payload: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    """Generates a 15-minute reset token and emails it asynchronously."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE email = ?", (payload.email,))
        user = cursor.fetchone()

        if user:
            reset_token = secrets.token_urlsafe(32)
            expiration = datetime.now(timezone.utc) + timedelta(minutes=15)

            cursor.execute(
                "INSERT INTO reset_tokens (token, email, expires_at) VALUES (?, ?, ?)",
                (reset_token, payload.email, expiration.isoformat()),
            )

            # Asynchronous background process so HTTP response stays instant
            background_tasks.add_task(send_reset_email_mock, payload.email, reset_token)

    # Security Best Practice: Don't reveal if email exists or not
    return MessageResponse(
        message="If an account with that email exists, a reset link has been sent."
    )


# 9. RESET PASSWORD (POST)
@app.post("/reset-password", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def reset_password(payload: ResetPasswordRequest):
    """Validates the reset token and updates the user's password."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT email, expires_at FROM reset_tokens WHERE token = ?", (payload.token,)
        )
        token_row = cursor.fetchone()

        if not token_row:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token.",
            )

        # Check expiration timestamp
        expires_at = datetime.fromisoformat(token_row["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            cursor.execute("DELETE FROM reset_tokens WHERE token = ?", (payload.token,))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired.",
            )

        # Update user password
        email = token_row["email"]
        hashed_pw = hash_password(payload.new_password)
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_pw, email))

        # Consume token so it cannot be re-used
        cursor.execute("DELETE FROM reset_tokens WHERE token = ?", (payload.token,))

    return MessageResponse(message="Password successfully reset. You can now sign in.")