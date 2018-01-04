kill $(ps aux | grep 'gunicorn' | awk '{print $2}')
