from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, DateTime, JSON, Text, func

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class Alert(db.Model):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    message: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="3")
    source: Mapped[str] = mapped_column(String(128), nullable=True)
    destination: Mapped[str] = mapped_column(String(128), nullable=True)
    signature_id: Mapped[int] = mapped_column(Integer, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    additional_data: Mapped[dict] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<Alert {self.id}: {self.message}>"

class SecurityEvent(db.Model):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    message: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="3")
    recommendations: Mapped[dict] = mapped_column(JSON, nullable=True)
    additional_data: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Add missing fields for compatibility
    jira_ticket_id: Mapped[str] = mapped_column(String(128), nullable=True)
    slack_notification_sent: Mapped[bool] = mapped_column(nullable=True, default=False)
    timestamp: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<SecurityEvent {self.id}: {self.message}>"
