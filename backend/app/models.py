"""Module 3: Request shapes. FastAPI rejects anything that does not match."""
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class SignupIn(BaseModel):
    name: str = Field("", max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ScanIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


class MonitorIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=8, max_length=72)


class ProfileUpdateIn(BaseModel):
    name: str = Field(min_length=1, max_length=50)


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=72)


class VerifyEmailIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class AssistantIn(BaseModel):
    message: str = Field(min_length=1, max_length=1000)
    scan_id: str | None = None
    history: list[ChatTurn] = Field(default_factory=list, max_length=20)
