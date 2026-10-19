"""WSGI giriş nöqtəsi (gunicorn emanet.wsgi:app)."""
from .app import create_app

app = create_app()
