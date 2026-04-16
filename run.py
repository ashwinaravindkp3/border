from gevent import monkey
monkey.patch_all()

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, socketio
from app.mqtt_handler import start_mqtt
from app.database import init_db

init_db()
mqtt_client = start_mqtt()
app = create_app()

if __name__ == '__main__':
    print("Starting BIDS server on http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
