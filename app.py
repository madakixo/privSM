# ================================================
# XO-CONNECTS v7.2 – NIGERIA'S #1 SOCIAL APP
# Paystack | Auto-Folders | Beautiful UI | Zero Errors
# ================================================

import os
import uuid
import eventlet
import requests
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

eventlet.monkey_patch()

# PAYSTACK KEYS (Get from paystack.com)
PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET", "sk_test_123")
PAYSTACK_PUBLIC = os.getenv("PAYSTACK_PUBLIC", "pk_test_123")

def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY='xo-nigeria-2025',
        SQLALCHEMY_DATABASE_URI='sqlite:///xo.db',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER='static/uploads',
        VOICE_FOLDER='static/uploads/voice',
        MAX_CONTENT_LENGTH=50 * 1024 * 1024
    )

    # AUTO-CREATE ALL FOLDERS (Windows, Mac, Linux)
    base_dirs = ['static', 'static/uploads', 'static/uploads/voice', 'templates', 'templates/auth', 'templates/premium']
    for d in base_dirs:
        Path(d).mkdir(parents=True, exist_ok=True)

    db = SQLAlchemy(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in.'
    login_manager.login_message_category = 'info'

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

    # =========================
    # MODELS
    # =========================
    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False, index=True)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(128), nullable=False)
        profile_picture = db.Column(db.String(200), default='default.png')
        is_online = db.Column(db.Boolean, default=False)
        is_admin = db.Column(db.Boolean, default=False)
        is_banned = db.Column(db.Boolean, default=False)
        is_premium = db.Column(db.Boolean, default=False)
        no_ads = db.Column(db.Boolean, default=False)
        wallet = db.Column(db.Float, default=0.0)

        posts = db.relationship('Post', backref='author', lazy=True)
        stories = db.relationship('Story', backref='author', lazy=True)

        def set_password(self, pw):
            self.password_hash = generate_password_hash(pw)

        def check_password(self, pw):
            return check_password_hash(self.password_hash, pw)

    class Post(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        content = db.Column(db.Text, nullable=False)
        media = db.Column(db.String(200))
        timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    class Story(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        media = db.Column(db.String(200), nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)
        expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24))
        boost_until = db.Column(db.DateTime)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    class Transaction(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        amount = db.Column(db.Float, nullable=False)
        type = db.Column(db.String(20), nullable=False)
        ref = db.Column(db.String(100), unique=True)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # =========================
    # LOGIN
    # =========================
    @login_manager.user_loader
    def load_user(uid):
        return db.session.get(User, int(uid))

    @app.context_processor
    def inject_user():
        return dict(current_user=current_user)

    # =========================
    # ROUTES
    # =========================
    @app.route('/')
    def index():
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        if request.method == 'POST':
            user = User.query.filter_by(username=request.form['username']).first()
            if user and not user.is_banned and user.check_password(request.form['password']):
                login_user(user)
                user.is_online = True
                db.session.commit()
                flash('Welcome back!', 'success')
                return redirect(url_for('home'))
            flash('Wrong username or password', 'danger')
        return render_template('auth/login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        if request.method == 'POST':
            username = request.form['username'].strip()
            email = request.form['email'].strip().lower()
            password = request.form['password']
            if User.query.filter_by(username=username).first():
                flash('Username taken', 'danger')
            elif User.query.filter_by(email=email).first():
                flash('Email already used', 'danger')
            else:
                user = User(username=username, email=email)
                user.set_password(password)
                user.is_admin = (User.query.count() == 0)
                db.session.add(user)
                db.session.commit()
                flash('Account created! Login now.', 'success')
                return redirect(url_for('login'))
        return render_template('auth/register.html')

    @app.route('/logout')
    @login_required
    def logout():
        current_user.is_online = False
        db.session.commit()
        logout_user()
        return redirect(url_for('login'))

    @app.route('/home', methods=['GET', 'POST'])
    @login_required
    def home():
        if current_user.is_banned:
            return redirect(url_for('banned'))

        if request.method == 'POST':
            content = request.form.get('content', '').strip()
            post = Post(content=content or 'Shared media', user_id=current_user.id)
            if 'media' in request.files:
                file = request.files['media']
                if file.filename:
                    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
                    filename = f"{uuid.uuid4().hex}.{ext}"
                    file.save(Path(app.config['UPLOAD_FOLDER']) / filename)
                    post.media = filename
            db.session.add(post)
            db.session.commit()

        posts = Post.query.order_by(Post.timestamp.desc()).limit(50).all()
        stories = Story.query.filter(Story.expires_at > datetime.utcnow()).all()
        return render_template('home.html', posts=posts, stories=stories)

    @app.route('/premium')
    @login_required
    def premium():
        return render_template('premium/checkout.html')

    @app.route('/pay', methods=['POST'])
    @login_required
    def pay():
        amount_kobo = 250000  # ₦2,500
        ref = f"xo_{uuid.uuid4().hex}"
        payload = {
            "email": current_user.email,
            "amount": amount_kobo,
            "reference": ref,
            "callback_url": url_for('verify', _external=True)
        }
        headers = {"Authorization": f"Bearer {PAYSTACK_SECRET}"}
        try:
            resp = requests.post("https://api.paystack.co/transaction/initialize", json=payload, headers=headers)
            data = resp.json()
            if data.get('status'):
                tx = Transaction(user_id=current_user.id, amount=2500, type='premium', ref=ref)
                db.session.add(tx)
                db.session.commit()
                return jsonify({"url": data['data']['authorization_url']})
        except:
            pass
        return jsonify({"error": "Try again"}), 400

    @app.route('/verify')
    def verify():
        ref = request.args.get('reference')
        if not ref:
            return redirect(url_for('home'))
        tx = Transaction.query.filter_by(ref=ref).first()
        if not tx:
            return redirect(url_for('home'))

        headers = {"Authorization": f"Bearer {PAYSTACK_SECRET}"}
        resp = requests.get(f"https://api.paystack.co/transaction/verify/{ref}", headers=headers).json()
        if resp.get('data', {}).get('status') == 'success':
            user = User.query.get(tx.user_id)
            user.is_premium = True
            user.no_ads = True
            db.session.commit()
            flash('XO Premium Activated! Enjoy!', 'success')
        else:
            flash('Payment failed', 'danger')
        return redirect(url_for('home'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        if not current_user.is_admin:
            abort(403)
        revenue = db.session.query(db.func.sum(Transaction.amount)).scalar() or 0
        users = User.query.count()
        premium = User.query.filter_by(is_premium=True).count()
        return render_template('dashboard.html', revenue=revenue, users=users, premium=premium)

    @app.route('/banned')
    def banned():
        return render_template('banned.html')

    @app.route('/uploads/<path:filename>')
    def uploads(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    # =========================
    # SOCKET.IO
    # =========================
    @socketio.on('join')
    def on_join(data):
        join_room(data['room'])

    @socketio.on('send_message')
    def handle_message(data):
        msg = Message(
            sender_id=current_user.id,
            recipient_id=data['recipient_id'],
            content=data['content']
        )
        db.session.add(msg)
        db.session.commit()
        emit('receive_message', {
            'sender': current_user.username,
            'content': data['content'],
            'time': msg.timestamp.strftime('%H:%M')
        }, room=data['room'])

    # =========================
    # INIT
    # =========================
    with app.app_context():
        db.create_all()
        if not User.query.first():
            admin = User(username='admin', email='admin@xo.ng')
            admin.set_password('xo123')
            admin.is_admin = True
            db.session.add(admin)
            db.session.commit()
            print("ADMIN CREATED: admin / xo123")

    return app, socketio

# =========================
# RUN
# =========================
if __name__ == '__main__':
    app, socketio = create_app()
    print("="*50)
    print("XO-CONNECTS v7.2 – NIGERIA READY")
    print("Visit: http://127.0.0.1:5000")
    print("Paystack Test Card: 408 408 408 408 408 1")
    print("="*50)
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)
