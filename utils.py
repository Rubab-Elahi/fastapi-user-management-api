from datetime import datetime, timedelta, timezone
import secrets
import bcrypt
from fastapi import HTTPException, status, Depends, Form
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from database import get_db_connection

# JWT Config
SECRET_KEY = secrets.token_hex(32)
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
            "SELECT email, expires_at FROM user_sessions WHERE token = ?", (token,)
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has expired or token is invalid.",
            )
        
        # Check that user exists in database
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if not cursor.fetchone():
            raise credentials_exception
            
    return token


def send_reset_email_mock(email: str, token: str):
    """Mock function simulating sending an email."""
    print(f"[EMAIL SERVICE] Reset link for {email}: https://app.example.com/reset-password?token={token}")
