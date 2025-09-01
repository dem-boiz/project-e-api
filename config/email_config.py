from fastapi_mail import ConnectionConfig
from pydantic import SecretStr
from typing import cast

from .settings import MAIL_FROM, MAIL_PASSWORD, MAIL_USERNAME

email_config = ConnectionConfig(
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=cast(SecretStr, MAIL_PASSWORD),
    MAIL_FROM=MAIL_FROM,
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    MAIL_SSL_TLS=False,
    MAIL_STARTTLS=True,
)
