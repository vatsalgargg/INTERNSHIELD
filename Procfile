web: gunicorn intern_web.wsgi:application --workers 2 --worker-class gevent --timeout 120 --graceful-timeout 30 --keep-alive 5
release: python manage.py collectstatic --noinput

