from enum import Enum
from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    PRINCIPAL = "principal"
    VICE_PRINCIPAL = "vice principal"
    ADMIN = "admin"
    STUDENT = "student"


# --- User Schemas ---
class UserBase(BaseModel):
    name: str
    email: EmailStr
    role: UserRole = UserRole.STUDENT


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


class UserUpdate(UserBase):
    name: str | None = None
    email: EmailStr | None = None
    role: UserRole | None = None


class UserResponse(UserBase):
    id: int


# --- Authentication Schemas ---
class SignInRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    message: str
    role: str | None = None


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class MessageResponse(BaseModel):
    message: str