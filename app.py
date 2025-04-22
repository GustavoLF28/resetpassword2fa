import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import pyotp 
import qrcode
from io import BytesIO
import base64
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder='templates')
app.secret_key = 'SUA_CHAVE_MUITO_SECRETA_AQUI_123!@#'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    secret_2fa = db.Column(db.String(32))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('verify_2fa'))
        flash('Email ou senha inválidos!', 'danger')
    return render_template('login.html')

# Rota para solicitar redefinição
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            session['reset_email'] = email  # Armazena o email temporariamente
            return redirect(url_for('reset_password'))
        
        flash('Email não encontrado!', 'danger')
    return render_template('reset_request.html')

# Rota para definir nova senha

@app.route('/reset-password-confirm', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        return redirect(url_for('reset_password_request'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('Senhas não coincidem!', 'danger')
        else:
            user = User.query.filter_by(email=session['reset_email']).first()
            user.password = generate_password_hash(new_password)
            db.session.commit()
            
            session.pop('reset_email', None)  # Limpa a sessão
            flash('Senha alterada com sucesso!', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_confirm.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email já registrado!', 'danger')
            return redirect(url_for('register'))
        
        secret_2fa = pyotp.random_base32()
        hashed_pw = generate_password_hash(password)
        
        # Gera QR Code
        uri = pyotp.totp.TOTP(secret_2fa).provisioning_uri(email, issuer_name="MeuApp")
        img = qrcode.make(uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        new_user = User(email=email, password=hashed_pw, secret_2fa=secret_2fa)
        db.session.add(new_user)
        db.session.commit()
        
        return render_template('register.html', 
                           qrcode_img=img_str,
                           secret_2fa=secret_2fa)
    
    return render_template('register.html')

# No arquivo app.py, atualize a verificação 2FA:
@app.route('/verify-2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    secret = current_user.secret_2fa
    totp = pyotp.TOTP(secret, interval=30)  # Intervalo de 30 segundos
    
    if request.method == 'POST':
        user_code = request.form.get('code').strip()
        
        # Verifica o código atual e o anterior (tolerância de 30s)
        if totp.verify(user_code, valid_window=1):
            session['2fa_passed'] = True
            return redirect(url_for('dashboard'))
        
        flash('Código inválido! Dica: ' + totp.now(), 'danger')  # Debug
    
    return render_template('verify_2fa.html')
@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('2fa_passed'):  # ← Agora session está definido
        flash('Complete a verificação 2FA primeiro', 'warning')
        return redirect(url_for('verify_2fa'))
    
    return render_template('dashboard.html')
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
