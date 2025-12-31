from pydantic import BaseModel, EmailStr, Field


from typing import Optional


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    firstname: str
    lastname: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
