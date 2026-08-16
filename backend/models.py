from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String
)

from backend.database import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    domain = Column(
        String,
        nullable=False
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    target_id = Column(
        Integer,
        ForeignKey("targets.id"),
        nullable=False
    )

    status = Column(
        String,
        nullable=False,
        default="queued"
    )

    profile = Column(
        String,
        nullable=False,
        default="basic"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False
    )

    module = Column(
        String,
        nullable=False
    )

    result_type = Column(
        String,
        nullable=False
    )

    value = Column(
        String,
        nullable=False
    )

    result_metadata = Column(
        "metadata",
        JSON,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )