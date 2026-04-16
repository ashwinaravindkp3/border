from flask import Flask, send_from_directory
from flask_socketio import SocketIO
from dotenv import load_dotenv
import os

load_dotenv()

socketio = SocketIO()

def create_app():
    app = Flask(__name__,
                static_folder='../Dashboard/dist',
                static_url_path='/')

    app.secret_key = os.getenv("FLASK_SECRET_KEY")
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit

    from app.routes import bp
    app.register_blueprint(bp)


    socketio.init_app(app,
        cors_allowed_origins="*",
        async_mode='gevent',
        ping_timeout=60,
        ping_interval=25,
        max_http_buffer_size=10 * 1024 * 1024)

    # Dedicated route to serve the 10GB+ map tile directory outside the React build pipeline
    @app.route('/map-tiles/<path:filename>')
    def serve_map_tiles(filename):
        return send_from_directory(os.path.join(app.root_path, 'static/map-tiles'), filename)

    # SPA catch-all: any route not handled by Flask (e.g. browser refresh) serves the React index.html
    @app.errorhandler(404)
    def handle_404(e):
        return send_from_directory(app.static_folder, 'index.html')

    return app
