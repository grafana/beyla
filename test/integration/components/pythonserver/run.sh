export FLASK_APP=main.py

flask hello Joe
sleep 2
flask migrate Joe
sleep 2
gunicorn -w 4 -b 0.0.0.0:8080 main:app