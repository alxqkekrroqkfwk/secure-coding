from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from datetime import datetime

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @app.template_filter('format_datetime')
    def format_datetime(value):
        if not value:
            return ""
        now = datetime.now()
        diff = now - value
        
        if diff.days == 0:
            if diff.seconds < 60:
                return "방금 전"
            elif diff.seconds < 3600:
                return f"{diff.seconds // 60}분 전"
            else:
                return f"{diff.seconds // 3600}시간 전"
        elif diff.days == 1:
            return "어제"
        elif diff.days < 7:
            return f"{diff.days}일 전"
        else:
            return value.strftime("%Y년 %m월 %d일")

    from app import routes, models
    
    with app.app_context():
        db.create_all()

    return app 