"""Validated API request and response shapes for user accounts."""

from pydantic import BaseModel, EmailStr, Field

class UserRegisterRequest(BaseModel):
    """Validate the fields used when creating a new record.

    Pydantic applies the declared types and constraints before application code runs.
    """
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

class UserLoginRequest(BaseModel):
    """Validate the fields used when attempting account login.

    Pydantic applies the declared types and constraints before application code runs.
    """
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)
