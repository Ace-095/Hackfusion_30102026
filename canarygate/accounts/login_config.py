"""Provisional exact JSON-login configuration; never holds passwords or tokens."""
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class LoginConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    method: str
    path: str
    username_field: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    password_field: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    token_field: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    password_env: dict[str, str] = Field(min_length=1, max_length=64)

    @field_validator("method")
    @classmethod
    def only_post(cls, value):
        if value != "POST":
            raise ValueError("authentication requires POST")
        return value

    @field_validator("password_env")
    @classmethod
    def restricted_environment_references(cls, value):
        import re
        if any(not re.fullmatch(r"CANARY_[A-Z0-9_]{1,120}", v) for v in value.values()):
            raise ValueError("password environment names must use the CANARY_ prefix")
        return value

    @model_validator(mode="after")
    def distinct_login_fields(self):
        if self.username_field == self.password_field:
            raise ValueError("username and password fields must be distinct")
        return self
