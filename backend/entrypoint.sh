#!/bin/bash


# Run migrations
python manage.py migrate
python manage.py collectstatic --noinput

# Start server
gunicorn config.wsgi:application --bind 0.0.0.0:8000 