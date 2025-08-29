from pydantic import BaseModel, constr

class LoginRequest(BaseModel):
    identifier: constr(min_length=3, max_length=100)
    password: constr(min_length=6, max_length=128)

class LoginResponse(BaseModel):
    success: bool
    access_token: str | None = None
    refresh_token: str | None = None
    message: str
