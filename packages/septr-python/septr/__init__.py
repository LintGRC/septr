"""Septr — runtime security middleware for AI-generated apps.

Framework adapters:

    from septr import create_septr          # FastAPI / Starlette (ASGI)
    from septr import create_septr_flask    # Flask (WSGI)
"""

from .adapters.fastapi import create_septr
from .adapters.flask import create_septr as create_septr_flask

__all__ = ["create_septr", "create_septr_flask"]
