web: gunicorn intern_web.wsgi:application --workers 4 --worker-class gevent --timeout 120
release: python manage.py collectstatic --noinput
