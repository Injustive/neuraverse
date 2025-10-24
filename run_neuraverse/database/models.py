from database.base_models import BaseModel
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, JSON, func
from sqlalchemy.ext.hybrid import hybrid_property


class Base(DeclarativeBase):
    pass


class NeuraverseBaseModel(BaseModel):
    __tablename__ = "neuraverse_base"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trivia_token: Mapped[str] = mapped_column(String, nullable=True)
