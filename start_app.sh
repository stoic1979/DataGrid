cd Ingrid
source venv/bin/activate
mkdir .log 2> /dev/null
DEBUG=0 authbind gunicorn wsgi:app -b 0.0.0.0:8000 --access-logfile .log/access.log --error-logfile .log/general.log --workers=5 &

