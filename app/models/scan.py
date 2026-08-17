from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    language = Column(
        String(50),
        nullable=False
    )

    code = Column(
        Text,
        nullable=False
    )

    status = Column(
        String(50),
        nullable=False
    )

    vulnerabilities_found = Column(
        Integer,
        default=0
    )

    results = Column(
        Text,
        nullable=False
    )

    user = relationship(
        "User",
        back_populates="scans"
    )