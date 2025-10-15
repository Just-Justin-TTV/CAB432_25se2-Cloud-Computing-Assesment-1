#!/bin/sh
set -e

# Apply all pending Django database migrations
echo "Applying database migrations..."
python manage.py migrate --noinput

# Start the Django development server, listening on all interfaces at port 8000
echo "Starting Django server..."
exec python manage.py runserver 0.0.0.0:8000
