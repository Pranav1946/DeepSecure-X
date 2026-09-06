from pydantic import BaseModel, Field, EmailStr, field_validator


class UserCreate(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=50,
        description="Alphanumeric username"
    )

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=100,
        description="Password must be at least 8 characters"
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned or len(cleaned) < 3:
            raise ValueError("Username must contain at least 3 characters")
        return cleaned


class UserLogin(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return v.strip()


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(
        min_length=8,
        max_length=100
    )

    @field_validator("token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Reset token cannot be empty")
        return cleaned