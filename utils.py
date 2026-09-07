from datetime import datetime, timedelta, timezone
import secrets
import bcrypt
from fastapi import HTTPException, status, Depends, Form
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from database import get_db_connection

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587


# JWT Config
SECRET_KEY = os.getenv("SECRET_KEY", "fastapi-user-management-secret-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class SimpleOAuth2PasswordRequestForm:
    def __init__(
        self,
        username: str = Form(...),
        password: str = Form(...),
    ):
        self.username = username
        self.password = password


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="sign-in")


def hash_password(password: str) -> str:
    """Hashes a password using Bcrypt directly."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a password against the stored Bcrypt hash directly."""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False


def create_access_token(subject: str, expires_delta: timedelta = None) -> tuple[str, datetime]:
    """Creates a signed JWT token and returns (encoded_token, expiry_datetime)."""
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {"sub": subject, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, expire


def verify_token(token: str = Depends(oauth2_scheme)) -> str:
    """Verifies that the JWT token is valid, active in user_sessions, and not expired."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Verify session is active (e.g. not logged out)
        cursor.execute(
            "SELECT email, expires_at FROM user_sessions WHERE token = %s", (token,)
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has expired or token is invalid.",
            )
        
        session_email = row["email"]
        # Check that user exists in database (matching either current session email or token email)
        cursor.execute("SELECT id FROM users WHERE email = %s OR email = %s", (session_email, email))
        if not cursor.fetchone():
            raise credentials_exception
            
    return token


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Retrieves current authenticated user record dict."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM user_sessions WHERE token = %s", (token,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has expired or token is invalid.",
            )
        
        session_email = row["email"]
        cursor.execute("SELECT id, name, email, role, created_by FROM users WHERE email = %s OR email = %s", (session_email, email))
        user = cursor.fetchone()
        if not user:
            raise credentials_exception
            
    return dict(user)




def send_email(to_email: str, subject: str, html_content: str) -> None:
    """Generic helper function to send emails using Gmail SMTP."""
    print("\n--- [DEBUG] STARTING EMAIL PROCESS ---")
    print(f"[DEBUG] SENDER_EMAIL loaded: '{SENDER_EMAIL}'")
    print(f"[DEBUG] SENDER_PASSWORD present: {bool(SENDER_PASSWORD)}")
    print(f"[DEBUG] Subject: '{subject}'")
    print(f"[DEBUG] Recipient: '{to_email}'")

    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("[DEBUG ERROR] Email credentials missing in environment variables!")
        raise ValueError("Email credentials are missing in environment variables.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email

    msg.attach(MIMEText(html_content, "html"))

    try:
        print(f"[DEBUG] Connecting to SMTP server {SMTP_SERVER}:{SMTP_PORT}...")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            print("[DEBUG] Initiating TLS encryption...")
            server.starttls()
            
            print("[DEBUG] Logging into Gmail SMTP...")
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            
            print(f"[DEBUG] Sending message to {to_email}...")
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
            
        print("[DEBUG SUCCESS] Email sent successfully!\n")

    except smtplib.SMTPAuthenticationError as auth_err:
        print(f"[DEBUG ERROR] Authentication failed! Check your email or App Password.")
        print(f"Details: {auth_err}\n")
    except smtplib.SMTPConnectError as conn_err:
        print(f"[DEBUG ERROR] Could not connect to Google SMTP server.")
        print(f"Details: {conn_err}\n")
    except Exception as e:
        print(f"[DEBUG ERROR] Failed to send email to {to_email}.")
        print(f"Error Type: {type(e).__name__}")
        print(f"Details: {e}\n")


def send_signup_confirmation_email(to_email: str, name: str) -> None:
    """Sends a welcome/signup confirmation email to a newly created user."""
    subject = "Welcome to User Management API - Signup Confirmation"
    html_content = f"""
    <html>
      <body>
        <h3>Welcome, {name}!</h3>
        <p>Thank you for signing up for our service.</p>
        <p>Your account has been successfully created with email: <strong>{to_email}</strong>.</p>
        <p>If you did not perform this signup, please contact support immediately.</p>
      </body>
    </html>
    """
    send_email(to_email, subject, html_content)


def send_signin_confirmation_email(to_email: str) -> None:
    """Sends a notification email when a user signs in."""
    subject = "Security Alert: New Sign-In to Your Account"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html_content = f"""
    <html>
      <body>
        <h3>New Sign-In Detected</h3>
        <p>Hello,</p>
        <p>Your account (<strong>{to_email}</strong>) was signed into on <strong>{now_str}</strong>.</p>
        <p>If this was you, no action is needed. If you did not sign in, please reset your password immediately.</p>
      </body>
    </html>
    """
    send_email(to_email, subject, html_content)


def send_password_reset_success_email(to_email: str) -> None:
    """Sends a confirmation email after password has been successfully reset."""
    subject = "Password Successfully Reset"
    html_content = f"""
    <html>
      <body>
        <h3>Password Reset Successful</h3>
        <p>Hello,</p>
        <p>Your password for account <strong>{to_email}</strong> has been successfully updated.</p>
        <p>You can now sign in with your new password.</p>
        <p>If you did not make this change, please contact support immediately.</p>
      </body>
    </html>
    """
    send_email(to_email, subject, html_content)


def send_reset_email(to_email: str, reset_token: str) -> None:
    """Sends a password reset request email with link pointing to Streamlit UI."""
    reset_link = f"http://localhost:8501/reset-password?token={reset_token}"
    subject = "Password Reset Request"
    html_content = f"""
    <html>
      <body>
        <h3>Password Reset Request</h3>
        <p>You requested a password reset. Click the link below or copy your token to reset your password:</p>
        <p><a href="{reset_link}">Reset Password</a></p>
        <p><strong>Your Reset Token:</strong> <code>{reset_token}</code></p>
        <p>This link will expire in 15 minutes.</p>
      </body>
    </html>
    """
    send_email(to_email, subject, html_content)