from flask import Flask, render_template, redirect, url_for
from config import Config
from extensions import db, login_manager, socketio
from models import init_db, User
from blueprints.auth import auth_bp
from blueprints.academic import academic_bp
from blueprints.attendance import attendance_bp
from blueprints.student import student_bp
from blueprints.reporting import reporting_bp
from flask_login import current_user, login_required
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    socketio.init_app(app)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(academic_bp)
    app.register_blueprint(attendance_bp)
    app.register_blueprint(student_bp)
    app.register_blueprint(reporting_bp)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    @app.route('/')
    def home():
        from flask_login import current_user
        if current_user.is_authenticated:
            if current_user.is_academician():
                return redirect(url_for('academic.dashboard'))
            elif current_user.is_student():
                return redirect(url_for('student.student_dashboard'))
        return render_template('home.html')
    
    @app.context_processor
    def inject_user_type():
        from flask_login import current_user
        return dict(user_type=getattr(current_user, 'UserType', None))
    
    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        init_db(app)
    socketio.run(app, debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))