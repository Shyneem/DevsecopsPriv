# app/models.py
from datetime import datetime, timezone
from typing import Optional, List, Any
from sqlalchemy import (
    Column,
    Integer,
    Boolean,
    String,
    Text,
    DateTime,
    Numeric,
    UniqueConstraint,
    ForeignKey,
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.sql import func
from .db import Base
from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(
        unique=True, index=True, nullable=False
    )

    role: Mapped[str] = mapped_column(String, default="user")

    password_hash: Mapped[str] = mapped_column(nullable=False)
    is_active: Mapped[bool] = mapped_column(default=False)
    is_default_password: Mapped[bool] = mapped_column(
        nullable=False, default=True
    )
    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    interactions = relationship("UserInteraction", back_populates="user")

class WazuhConnection(Base):
    __tablename__ = "wazuh_connections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    indexer_url: Mapped[str] = mapped_column(String, nullable=False)
    wazuh_user: Mapped[str] = mapped_column(String, nullable=False)
    wazuh_password: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    vulnerabilities: Mapped[List["WazuhVulnerability"]] = relationship("WazuhVulnerability", back_populates="connection", cascade="all, delete-orphan")
    tested: Mapped[bool] = mapped_column(Boolean, default=False)
    last_tested_at: Mapped[Optional[Any]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_ok: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)


class UserInteraction(Base):
    __tablename__ = "user_interactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    endpoint = Column(String, index=True)
    method = Column(String)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="interactions")




class WazuhVulnerability(Base):
    __tablename__ = "wazuh_vulnerabilities"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )
    connection_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("wazuh_connections.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(default="ACTIVE")
    agent_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    agent_name: Mapped[Optional[str]] = mapped_column(String)
    os_full: Mapped[Optional[str]] = mapped_column(Text)
    os_platform: Mapped[Optional[str]] = mapped_column(Text)
    os_version: Mapped[Optional[str]] = mapped_column(Text)
    package_name: Mapped[Optional[str]] = mapped_column(Text)
    package_version: Mapped[Optional[str]] = mapped_column(Text)
    package_type: Mapped[Optional[str]] = mapped_column(Text)
    package_arch: Mapped[Optional[str]] = mapped_column(Text)
    cve_id: Mapped[str] = mapped_column(Text, nullable=False)

    # 💡 Declarar como Optional[str] permite asignar valores de vuln.get() que podrían ser None
    severity: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    score_base: Mapped[Optional[float]] = mapped_column(
        Numeric, nullable=True
    )
    score_version: Mapped[Optional[str]] = mapped_column(Text)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    published_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )
    description: Mapped[Optional[str]] = mapped_column(Text)
    reference: Mapped[Optional[str]] = mapped_column(Text)
    scanner_vendor: Mapped[Optional[str]] = mapped_column(Text)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    connection: Mapped["WazuhConnection"] = relationship(
        "WazuhConnection", back_populates="vulnerabilities"
    )
    history: Mapped[List["VulnerabilityHistory"]] = relationship(
        "VulnerabilityHistory",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint(
            "connection_id",
            "agent_id",
            "package_name",
            "package_version",
            "cve_id",
            name="uniq_wazuh_vuln",
        ),
    )

class VulnerabilityHistory(Base):
    __tablename__ = "vulnerability_history"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey("wazuh_vulnerabilities.id"), nullable=False
    )
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    vulnerability = relationship("WazuhVulnerability", back_populates="history")