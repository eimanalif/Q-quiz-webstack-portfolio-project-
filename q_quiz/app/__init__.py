from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate


# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    
    # App configuration
    app.config['SECRET_KEY'] = 'your_secret_key'  # Use a strong secret key
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///q_quiz.db'
    
    # Initialize extensions with the app
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Initialize Flask app and other components
    migrate = Migrate(app, db)
    
    from app.routes import main
    app.register_blueprint(main)
    
    return app
