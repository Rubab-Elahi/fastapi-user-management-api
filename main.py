from datetime import datetime, timedelta, timezone
import secrets
from typing import List

from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks, status, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

app = FastAPI(title="User Management API")

# Allow Streamlit frontend to make requests
# Allow local development and Streamlit Cloud production domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from any origin, including Streamlit Cloud
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    get_current_user,
    create_access_token,
    send_reset_email,
    send_signup_confirmation_email,
    send_signin_confirmation_email,
    send_password_reset_success_email,
    SimpleOAuth2PasswordRequestForm,
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

# Initialize database on app startup
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
def create_user(
    user: UserCreate,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """Create a new user with password and role in PostgreSQL."""
    auth_header = request.headers.get("Authorization")
    creator_email = ""
    creator_role = ""
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            current_user = get_current_user(token)
            creator_email = current_user.get("email", "")
            creator_role = str(current_user.get("role", "")).lower()
        except Exception:
            creator_email = ""
            creator_role = ""

    role_value = user.role.value if hasattr(user.role, "value") else str(user.role)

    # Role Creation Permission Matrix
    allowed_creation_roles = {
        "vice principal": ["principal", "admin", "student"],
        "principal": ["admin", "student"],
        "admin": ["student"],
    }

    if creator_role in allowed_creation_roles:
        if role_value.lower() not in allowed_creation_roles[creator_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: {creator_role.title()} can only create users with roles: {', '.join(allowed_creation_roles[creator_role])}.",
            )

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT email FROM users WHERE email = %s", (user.email,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with Email '{user.email}' already exists",
            )

        hashed_pw = hash_password(user.password)

        cursor.execute(
            "INSERT INTO users (name, email, password, role, created_by) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (user.name, user.email, hashed_pw, role_value, creator_email),
        )
        row = cursor.fetchone()
        user_id = row["id"]

    background_tasks.add_task(send_signup_confirmation_email, user.email, user.name)

    return {"id": user_id, "name": user.name, "email": user.email, "role": role_value}


# 2. READ ALL (GET)
@app.get("/get-users", response_model=List[UserResponse]) 
def get_all_users(
    role: str = None,
    current_user: dict = Depends(get_current_user)
):
    """Retrieve users from PostgreSQL (Protected). Admin, Principal, and Vice Principal access only created users."""
    user_role = str(current_user.get("role", "")).lower()
    user_email = current_user.get("email", "")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        if user_role in ["admin", "principal", "vice principal"]:
            if role and role.strip():
                cursor.execute(
                    "SELECT id, name, email, role FROM users WHERE created_by = %s AND LOWER(role) = LOWER(%s)",
                    (user_email, role.strip()),
                )
            else:
                cursor.execute(
                    "SELECT id, name, email, role FROM users WHERE created_by = %s",
                    (user_email,),
                )
        else:
            if role and role.strip():
                cursor.execute("SELECT id, name, email, role FROM users WHERE LOWER(role) = LOWER(%s)", (role.strip(),))
            else:
                cursor.execute("SELECT id, name, email, role FROM users")
        rows = cursor.fetchall()

    return [dict(row) for row in rows] 

    
# 3. READ ONE BY ID (GET) 
@app.get("/get-users/{user_id}", response_model=UserResponse) 
def get_user_by_id(
    user_id: int,
    current_user: dict = Depends(get_current_user)
): 
    """Retrieve a single user by ID (Protected). Admin, Principal, and Vice Principal access only created users."""
    user_role = str(current_user.get("role", "")).lower()
    user_email = current_user.get("email", "")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, role, created_by FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if user_role in ["admin", "principal", "vice principal"] and row["created_by"] != user_email and row["email"] != user_email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access forbidden: {current_user.get('role')} can only access users they created.",
        )

    return dict(row)


from typing import List
from fastapi import Query

# 4. READ USERS BY ROLE (GET)
@app.get("/get-users-by-role", response_model=List[UserResponse])
def get_users_by_role(
    role: str = Query(..., description="Enter the role to filter users (e.g., principal, vice principal, admin, student)"), 
    current_user: dict = Depends(get_current_user)
):
    """Retrieve users matching a specific role (Protected). Admin, Principal, and Vice Principal access only created users."""
    user_role = str(current_user.get("role", "")).lower()
    user_email = current_user.get("email", "")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        if user_role in ["admin", "principal", "vice principal"]:
            cursor.execute(
                "SELECT id, name, email, role FROM users WHERE created_by = %s AND LOWER(role) = LOWER(%s)",
                (user_email, role.strip()),
            )
        else:
            cursor.execute("SELECT id, name, email, role FROM users WHERE LOWER(role) = LOWER(%s)", (role.strip(),))
        rows = cursor.fetchall()

    return [dict(row) for row in rows]

# 5. UPDATE (PUT)
@app.put("/update-users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update user details by ID (Protected). Admin, Principal, and Vice Principal update only created users."""
    user_role = str(current_user.get("role", "")).lower()
    user_email = current_user.get("email", "")

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT name, email, role, created_by FROM users WHERE id = %s", (user_id,))
        old_user = cursor.fetchone()
        if not old_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        if user_role in ["admin", "principal", "vice principal"] and old_user["created_by"] != user_email and old_user["email"] != user_email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: {current_user.get('role')} can only update users they created.",
            )

        allowed_creation_roles = {
            "vice principal": ["principal", "admin", "student"],
            "principal": ["admin", "student"],
            "admin": ["student"],
        }

        old_email = old_user["email"]
        new_name = user.name if user.name is not None else old_user.get("name")
        new_email = user.email if user.email is not None else old_email
        role_value = user.role.value if user.role and hasattr(user.role, "value") else (str(user.role) if user.role else old_user.get("role"))

        if user_role in allowed_creation_roles:
            if role_value.lower() not in allowed_creation_roles[user_role]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: {current_user.get('role')} cannot assign role '{role_value}'. Allowed roles: {', '.join(allowed_creation_roles[user_role])}.",
                )

        cursor.execute(
            "UPDATE users SET name = %s, email = %s, role = %s WHERE id = %s",
            (new_name, new_email, role_value, user_id),
        )
        cursor.execute(
            "UPDATE user_sessions SET email = %s WHERE email = %s",
            (new_email, old_email),
        )

    return {"id": user_id, "name": new_name, "email": new_email, "role": role_value}


# 6. DELETE
@app.delete("/delete-users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Delete a user by ID (Protected). Admin, Principal, and Vice Principal delete only created users."""
    user_role = str(current_user.get("role", "")).lower()
    user_email = current_user.get("email", "")

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id, email, created_by FROM users WHERE id = %s", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        if user_role in ["admin", "principal", "vice principal"] and user_row["created_by"] != user_email and user_row["email"] != user_email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: {current_user.get('role')} can only delete users they created.",
            )

        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))

    return None


# --- AUTHENTICATION ROUTES ---

# 6. SIGN IN (POST)
@app.post("/sign-in", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def sign_in(
    background_tasks: BackgroundTasks,
    form_data: SimpleOAuth2PasswordRequestForm = Depends(),
):
    """Validates user credentials and issues an active JWT access token."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, role, password FROM users WHERE email = %s", (form_data.username,))
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
            "INSERT INTO user_sessions (token, email, expires_at) VALUES (%s, %s, %s)",
            (encoded_jwt, form_data.username, expire.isoformat()),
        )

        user_role = str(row["role"]) if row.get("role") else "student"

    # Asynchronous background task to send sign-in notification email
    background_tasks.add_task(send_signin_confirmation_email, form_data.username)

    return TokenResponse(
        access_token=encoded_jwt,
        token_type="bearer",
        message="Signed in successfully.",
        role=user_role,
    )


# 7. SIGN OUT (POST)
@app.post("/sign-out", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def sign_out(token: str = Depends(verify_token)):
    """Invalidates the provided token by removing it from the user_sessions table."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE token = %s", (token,))

    return MessageResponse(message="Successfully signed out.")


# 8. FORGOT PASSWORD (POST)
@app.post("/forgot-password", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def forgot_password(payload: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    """Generates a 15-minute reset token and emails it asynchronously."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE email = %s", (payload.email,))
        user = cursor.fetchone()

        if user:
            reset_token = secrets.token_urlsafe(32)
            expiration = datetime.now(timezone.utc) + timedelta(minutes=15)

            cursor.execute(
                "INSERT INTO reset_tokens (token, email, expires_at) VALUES (%s, %s, %s)",
                (reset_token, payload.email, expiration.isoformat()),
            )

            # Asynchronous background process so HTTP response stays instant
            background_tasks.add_task(send_reset_email, payload.email, reset_token)

    # Security Best Practice: Don't reveal if email exists or not
    return MessageResponse(
        message="If an account with that email exists, a reset link has been sent."
    )


# 9. RESET PASSWORD (POST)
@app.post("/reset-password", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def reset_password(payload: ResetPasswordRequest, background_tasks: BackgroundTasks):
    """Validates the reset token and updates the user's password."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT email, expires_at FROM reset_tokens WHERE token = %s", (payload.token,)
        )
        token_row = cursor.fetchone()

        if not token_row:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token.",
            )

        # Check expiration timestamp
        expires_at = token_row["expires_at"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expires_at:
            cursor.execute("DELETE FROM reset_tokens WHERE token = %s", (payload.token,))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired.",
            )

        # Update user password
        email = token_row["email"]
        hashed_pw = hash_password(payload.new_password)
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))

        # Consume token so it cannot be re-used
        cursor.execute("DELETE FROM reset_tokens WHERE token = %s", (payload.token,))

    # Asynchronous background task to send password reset confirmation email
    background_tasks.add_task(send_password_reset_success_email, email)

    return MessageResponse(message="Password successfully reset. You can now sign in.")

# 9a. RESET PASSWORD FORM (GET)
@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(token: str):
    """Renders the reset password HTML form when the user clicks the email link."""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Password</title>
        <style>
            body {{ font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f9; }}
            .card {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }}
            h2 {{ margin-top: 0; color: #333; }}
            input {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
            button {{ width: 100%; padding: 10px; background-color: #007bff; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }}
            button:hover {{ background-color: #0056b3; }}
            #message {{ margin-top: 15px; font-weight: bold; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Reset Your Password</h2>
            <form onsubmit="submitReset(event)">
                <input type="hidden" id="token" value="{token}">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" placeholder="Enter new password" required>
                <button type="submit">Update Password</button>
            </form>
            <div id="message"></div>
        </div>

        <script>
            async function submitReset(e) {{
                e.preventDefault();
                const token = document.getElementById('token').value;
                const new_password = document.getElementById('new_password').value;
                const messageEl = document.getElementById('message');

                messageEl.style.color = '#333';
                messageEl.innerText = 'Updating...';

                try {{
                    const response = await fetch('/reset-password', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ token: token, new_password: new_password }})
                    }});

                    const data = await response.json();

                    if (response.ok) {{
                        messageEl.style.color = 'green';
                        messageEl.innerText = 'Password is reset. Please sign in again.';
                        setTimeout(() => {{ window.location.href = 'http://localhost:8501/login'; }}, 2000);
                    }} else {{
                        messageEl.style.color = 'red';
                        messageEl.innerText = data.detail || 'An error occurred.';
                    }}
                }} catch (err) {{
                    messageEl.style.color = 'red';
                    messageEl.innerText = 'Server error. Try again later.';
                }}
            }}
        </script>
    </body>
    </html>
    """