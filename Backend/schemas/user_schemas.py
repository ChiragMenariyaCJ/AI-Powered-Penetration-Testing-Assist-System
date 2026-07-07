from pydantic import BaseModel, EmailStr

class UserRegisterRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str