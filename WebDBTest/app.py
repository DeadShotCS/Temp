from flask import Flask
from routes.explorer import explorer_bp
from routes.manager_routes import mgmt_bp
import os

app = Flask(__name__)
app.secret_key = "DEV_KEY_WEB_DB"

# Register Blueprints
app.register_blueprint(explorer_bp)
app.register_blueprint(mgmt_bp)

if __name__ == '__main__':
    app.run(debug=True, port=5000)