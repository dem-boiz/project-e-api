from fastapi_mail import FastMail, MessageSchema, MessageType

from config import email_config
from config.logging_config import get_logger
logger = get_logger("utils")

async def send_invite_email(email: str, invite_url: str): 
    try:
        message = MessageSchema(
            subject="You’re invited to an event!",
            recipients=[email],  # List of recipient emails
            body=f"""
            <h2>You’ve been invited!</h2>
            <p>Click the link below to join the event:</p>
            <a href="{invite_url}">{invite_url}</a>
            """,
            subtype=MessageType.html  # or "plain" for text-only
        )

        fm = FastMail(email_config)
        await fm.send_message(message)
        return {"status": "Invite sent"}
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return {"status": "Invite failed", "error": str(e)}
