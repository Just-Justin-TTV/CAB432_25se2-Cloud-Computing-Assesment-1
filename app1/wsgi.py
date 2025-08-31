"""
WSGI config for app1 project.

This file sets up the WSGI application used by Django's development server
and any production WSGI-compatible web servers (like Gunicorn or uWSGI).

It exposes the WSGI callable as a module-level variable named ``application``.
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app1.settings')

application = get_wsgi_application()
