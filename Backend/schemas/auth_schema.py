
# This file handles auth schema.
from pydantic import BaseModel, EmailStr, Field


# Handle the user register request.
class UserRegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


# Handle the user login request.
class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)
