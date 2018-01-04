cd Ingrid
source venv/bin/activate
mkdir .log 2> /dev/null
uwsgi -s /tmp/ingrid.sock --manage-script-name --mount /Ingrid/app=__init__:app


