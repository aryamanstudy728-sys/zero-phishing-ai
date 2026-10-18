# SQLAlchemy models

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, ForeignKey, Index, String, Text, JSON, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(20), nullable=False)  # gmail, outlook
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # hashed user identifier
    # Privacy: the raw email content is analyzed but never stored
    headers_raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    urls: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    verdict: Mapped[Optional["Verdict"]] = relationship(back_populates="email", uselist=False)
    engagement_events: Mapped[list["EngagementEvent"]] = relationship(back_populates="email")
    feedback: Mapped[Optional["UserFeedback"]] = relationship(back_populates="email", uselist=False)

    __table_args__ = (
        Index("ix_emails_user_provider_received", "user_id", "provider", "received_at"),
        Index("ix_emails_user_message_provider", "user_id", "message_id", "provider", unique=True),
    )


class Verdict(Base):
    __tablename__ = "verdicts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), unique=True)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)  # safe, suspicious, dangerous
    score: Mapped[int] = mapped_column(nullable=False)  # 0-100
    reasons: Mapped[list[dict]] = mapped_column(JSON, default=list)
    authenticity: Mapped[dict] = mapped_column(JSON, default=dict)
    url_reputation: Mapped[dict] = mapped_column(JSON, default=dict)
    llm_analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    analysis_duration_ms: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    email: Mapped["Email"] = relationship(back_populates="verdict")


class EngagementEvent(Base):
    __tablename__ = "engagement_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="SET NULL"), nullable=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    sender_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(20), nullable=False)  # open, reply, dwell
    duration_ms: Mapped[Optional[int]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    email: Mapped[Optional["Email"]] = relationship(back_populates="engagement_events")

    __table_args__ = (
        Index("ix_engagement_user_sender_type", "user_id", "sender_email", "event_type"),
        Index("ix_engagement_user_domain_created", "user_id", "sender_domain", "created_at"),
    )


class UserFeedback(Base):
    __tablename__ = "user_feedback"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), unique=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    correction: Mapped[str] = mapped_column(String(20), nullable=False)  # safe, suspicious, dangerous
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    email: Mapped["Email"] = relationship(back_populates="feedback")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    google_token_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    microsoft_token_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())