import logging
import logging.config
import os
from pathlib import Path

# Create logs directory if it doesn't exist
logs_dir = Path(__file__).parent.parent / "logs"
logs_dir.mkdir(exist_ok=True)

# Get log level from environment variable, default to INFO
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Define log configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    # Formatters define the layout of log messages and are used by handlers.
    # Here we have 3 options, detailed, simple, and json. 
    "formatters": {
        "detailed": {
            "format": "{asctime} | {levelname:8} | {name:15} | {funcName:15} | {lineno:4} | {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "simple": {
            "format": "{asctime} | {levelname:8} | {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "json": {
            "format": '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "function": "%(funcName)s", "line": %(lineno)d, "message": "%(message)s"}',
            "datefmt": "%Y-%m-%d %H:%M:%S"
        }
    },
    # Handlers to be used by the loggers. A logger can write to multiple handlers.
    # For example, the auth logger might write to file_auth for regular auth logs as well as
    # file_error for any errors that occur.
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": LOG_LEVEL,
            "formatter": "simple",
            "stream": "ext://sys.stdout"
        },
        "file_all": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "filename": str(logs_dir / "app.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf8"
        },
        "file_error": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "detailed",
            "filename": str(logs_dir / "errors.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf8"
        },
        "file_auth": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "INFO",
            "formatter": "detailed",
            "filename": str(logs_dir / "auth.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf8"
        },
        "file_api": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "INFO",
            "formatter": "detailed",
            "filename": str(logs_dir / "api.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf8"
        }
    },
    # The various loggers throughout the application. This includes both custom loggers we make,
    # as well as loggers for third-party libraries (e.g. SQLAlchemy, FastAPI).
    "loggers": {
        # Root logger
        "": {
            "level": LOG_LEVEL,
            "handlers": ["console", "file_all"],
            "propagate": False
        },
        # Authentication specific logger
        "auth": {
            "level": "INFO",
            "handlers": ["console", "file_auth", "file_error"],
            "propagate": False
        },
        # API routes logger
        "api": {
            "level": "INFO",
            "handlers": ["console", "file_api", "file_error"],
            "propagate": False
        },
        # Database logger
        "database": {
            "level": "INFO",
            "handlers": ["console", "file_all", "file_error"],
            "propagate": False
        },
        # Service layer logger
        "service": {
            "level": "INFO",
            "handlers": ["console", "file_all", "file_error"],
            "propagate": False
        },
        # SQLAlchemy logger (reduce verbosity)
        "sqlalchemy.engine": {
            "level": "WARNING",
            "handlers": ["file_all"],
            "propagate": False
        },
        # Uvicorn logger
        "uvicorn": {
            "level": "INFO",
            "handlers": ["console", "file_all"],
            "propagate": False
        },
        "uvicorn.access": {
            "level": "INFO",
            "handlers": ["file_api"],
            "propagate": False
        }
    }
}

def setup_logging():
    """Initialize logging configuration"""
    logging.config.dictConfig(LOGGING_CONFIG)
    
    # Create a startup log entry
    logger = logging.getLogger("app")
    logger.info("="*50)
    logger.info("Application starting up")
    logger.info(f"Log level: {LOG_LEVEL}")
    logger.info(f"Logs directory: {logs_dir}")
    logger.info("="*50)

def get_logger(name: str = None):
    """Get a logger instance for the specified name"""
    return logging.getLogger(name)
