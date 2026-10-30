"""Draft setup recipe contract; exact recipe schema requires spec review."""

from pydantic import BaseModel


class Recipe(BaseModel):
    accounts: dict
    login: dict
    resources: dict
