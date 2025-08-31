"""
WSGI config for app1 project.

This file sets up the WSGI application used by Django's development server
and any production WSGI-compatible web servers (like Gunicorn or uWSGI).

It exposes the WSGI callable as a module-level variable named ``application``.
"""

import os  # Standard library for environment variable management

from django.core.wsgi import get_wsgi_application  # Provides the WSGI application callable

# Set the default settings module for the Django project.
# This tells Django which settings to use when running the application.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app1.settings')

# Get the WSGI application object for use by WSGI servers.
# This object is the entry point for all HTTP requests.
application = get_wsgi_application()
