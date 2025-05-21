# FILE APP.PY
# DI BUAT 95% OLEH KECERDASAN BUATAN

from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_session import Session
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from random import randint
import random
import base64
from uuid import uuid4
import logging
import requests
import sqlite3
import string
import math

import qrcode
import io

from authlib.integrations.flask_client import OAuth
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'static/konfigurasi'))

from config import EMAIL_API_TOKEN, G_CLIENT_ID, G_CLIENT_SECRET, admin_mail, panel_cpu, panel_ram, panel_disk
from pterodactyl import create_user, create_server, PTERODACTYL_URL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Konfigurasi SQLite
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data_user.db"  # Database utama untuk User
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_BINDS"] = {
    'data_panel': 'sqlite:///data_panel.db'
}

db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(100))
    bio = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    login_google = db.Column(db.Boolean, default=False)
    photo_url = db.Column(db.String(255))
    server = db.Column(db.Integer, default=0)
    cpu = db.Column(db.Integer, default=0)
    ram = db.Column(db.Integer, default=0)
    disk = db.Column(db.Integer, default=0)

class Server(db.Model):
    __bind_key__ = 'data_panel'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    server = db.Column(db.Integer, default=0)
    cpu = db.Column(db.Integer, default=0)
    ram = db.Column(db.Integer, default=0)
    disk = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
with app.app_context():
    db.create_all()

# Setup logging
logging.basicConfig(level=logging.INFO)

# Konfigurasi OAuth Google
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id= G_CLIENT_ID,
    client_secret= G_CLIENT_SECRET,
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'openid email profile',
    },
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Tentukan folder upload dan extension yang diizinkan
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Fungsi untuk memeriksa apakah file yang diupload valid (hanya gambar)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
def get_profile_photo(user):
    if user.photo_url:
        return url_for('static', filename=user.photo_url)
    else:
        inisial = user.nama[0].upper()
        return f"https://ui-avatars.com/api/?name={inisial}&background=random&color=fff"

def send_verification_email(email_penerima, kode):
    RESEND_API_KEY = EMAIL_API_TOKEN  # Ganti dengan API Key kamu
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "from": "Kocheng App <noreply@kocheng.biz.id>",
        "to": email_penerima,  # Ganti dengan target email
        "subject": "Kode untuk proses verifikasi",
        "text": f"Kode verifikasi Anda adalah: {kode}"
    }

    response = requests.post(url, headers=headers, json=data)

    print("Status:", response.status_code)
    print("Respon:", response.text)
    

#------ HALAMAN DASHBOARD UTAMA------#
@app.route("/")
def awal():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('Main-Page/landing-page.html', panel_cpu=panel_cpu, panel_ram=panel_ram, panel_disk=panel_disk)
    
@app.route("/login")
def halaman_login():
    return render_template('Main-Page/login-page.html')
    
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    
    user = User.query.get(session['user_id'])

    try:
        photo = get_profile_photo(user)
        return render_template('Main-Page/dashboard.html', user=user, photo=photo, admin_mail=admin_mail, panel_cpu=panel_cpu, panel_ram=panel_ram, panel_disk=panel_disk)
    except Exception as e:
        logging.error(f"Error bg: {str(e)}")
        session.pop('user_id', None)
        return redirect('/')  # Tambahkan redirect atau response yang sesuai
 
#------ PROFILE AREA ------#

@app.route('/profil')
def profil():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/')

    user = User.query.get(user_id)
    if not user:
        return "User tidak ditemukan", 404

    photo = get_profile_photo(user)
    return render_template('Main-Page/profile.html', user=user, photo=photo)

@app.route('/profil/edit-profil', methods=['GET', 'POST'])
def edit_profil():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/')

    user = User.query.get(user_id)
    if not user:
        return "User tidak ditemukan", 404

    message = None

    if request.method == 'POST':
        nama = request.form.get('nama', '').strip()
        bio = request.form.get('bio', '').strip()
        password = request.form.get('password_hash', '').strip()
        password_ip_page = request.form.get('password_ip_page', '').strip()
        new_email = request.form.get('email', '').strip()

        if not nama or not bio or not new_email:
            message = "Nama, bio, dan email harus diisi."
            return render_template('Main-Page/edit_profile.html', user=user, message=message)

        # Proses jika email berbeda
        if new_email != user.email:
            existing_user = User.query.filter(User.email == new_email, User.id != user.id).first()
            if existing_user:
                message = "Email ini sudah digunakan oleh akun lain!"
                return render_template('Main-Page/edit_profile.html', user=user, message=message)

            if not user.login_google:
                otp_kode = str(randint(100000, 999999))
                pending = {
                    'nama': nama,
                    'bio': bio,
                    'password_hash': password,
                    'password_ip_page': password_ip_page,
                    'new_email': new_email,
                    'otp': otp_kode
                }

                if 'photo' in request.files:
                    file = request.files['photo']
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        pending['photo_url'] = f'uploads/{filename}'

                session['pending_update'] = pending
                session['terakhir_kirim_kode_mail'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                send_verification_email(new_email, otp_kode)

                flash('Kode OTP sudah dikirim ke email baru Anda.')
                return redirect(url_for('verifikasi_edit_email'))

        # Jika tidak mengubah email atau user Google
        user.nama = nama
        user.bio = bio

        if not user.login_google and new_email == user.email:
            user.email = new_email

        if password:
            user.password_hash = generate_password_hash(password)

        if password_ip_page:
            user.password_ip_page = password_ip_page

        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                user.photo_url = f'uploads/{filename}'

        db.session.commit()
        return redirect('/profil?ubah=success')

    return render_template('Main-Page/edit_profile.html', user=user, message=message)
        
@app.route('/profil/verifikasi/new-email', methods=['GET', 'POST'])
def verifikasi_edit_email():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/')

    pending = session.get('pending_update')
    if not pending:
        return redirect('/profil/edit-profil')

    if request.method == 'POST':
        input_kode = request.form.get('kode', '').strip()
        if input_kode == pending.get('otp'):
            user = User.query.get(user_id)
            if not user:
                return "User tidak ditemukan", 404

            user.nama = pending.get('nama', '')
            user.bio = pending.get('bio', '')
            user.email = pending.get('new_email', '')

            pw = pending.get('password_hash', '')
            if pw:
                user.password_hash = generate_password_hash(pw)

            if 'photo_url' in pending:
                user.photo_url = pending['photo_url']

            db.session.commit()
            session.pop('pending_update', None)
            return redirect('/profil?ubahmail=success')
        else:
            flash("Kode verifikasi salah. Silakan coba lagi.", "warning")

    return render_template('Login-Daftar-Page/verifikasi-ubah-mail.html')

@app.route('/profil/verifikasi/new-code', methods=['POST'])
def kirim_ulang_mail_code():
    pending = session.get('pending_update')
    if not pending or 'new_email' not in pending:
        return redirect('/profil/edit-profil')

    now = datetime.utcnow()
    terakhir_kirim_new = session.get('terakhir_kirim_kode_mail')

    if terakhir_kirim_new:
        terakhir_kirim_dt = datetime.strptime(terakhir_kirim_new, "%Y-%m-%d %H:%M:%S")
        if now < terakhir_kirim_dt + timedelta(seconds=60):
            flash("Tunggu sebentar sebelum mengirim ulang kode.")
            return redirect('/profil/verifikasi/new-email')

    # Kirim ulang kode
    kode_baru = str(randint(100000, 999999))
    pending['otp'] = kode_baru
    session['pending_update'] = pending
    session['terakhir_kirim_kode_mail'] = now.strftime("%Y-%m-%d %H:%M:%S")
    send_verification_email(pending['new_email'], kode_baru)

    flash("Kode verifikasi baru telah dikirim.")
    return redirect('/profil/verifikasi/new-email')

    
#------ REGISTRASI AREA ------#
@app.route('/daftar/email', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nama = request.form['nama']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            return render_template("Login-Daftar-Page/register.html", message="Email sudah terdaftar!")

        # Simpan data sementara di session
        session['pending_nama'] = nama
        session['pending_email'] = email
        session['pending_password'] = generate_password_hash(password)

        # Kirim kode verifikasi
        kode = str(randint(100000, 999999))
        session['kode_verifikasi'] = kode
        session['email_verifikasi'] = email

        send_verification_email(email, kode)
        return redirect('/daftar/email/verifikasi')

    return render_template('Login-Daftar-Page/register.html')

@app.route('/login/email', methods=['GET', 'POST'])
def login2():
    message = None

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user:
            if user.password_hash:
                if check_password_hash(user.password_hash, password):
                    session['user_id'] = user.id

                    if not user.is_verified:
                        # Kirim kode verifikasi
                        kode = str(randint(100000, 999999))
                        session['kode_verifikasi'] = kode
                        session['email_verifikasi'] = email
                        send_verification_email(email, kode)

                        return redirect('/daftar/email/verifikasi')
                    else:
                        return redirect('/dashboard?login=success')
                else:
                    message = "Password salah!"
            else:
                message = "Akun ini terdaftar lewat Google. Silakan login menggunakan Google."
        else:
            message = "Email tidak ditemukan!"

    return render_template("Login-Daftar-Page/login-email.html", message=message)

@app.route('/daftar/email/verifikasi', methods=['GET', 'POST'])
def verifikasi():
    if request.method == 'POST':
        input_kode = request.form['kode']
        if input_kode == session.get('kode_verifikasi'):
            # Ambil data dari session
            nama = session.get('pending_nama')
            email = session.get('pending_email')
            password_hash = session.get('pending_password')

            if not User.query.filter_by(email=email).first():
                new_user = User(nama=nama, email=email, password_hash=password_hash, is_verified=True)
                db.session.add(new_user)
                db.session.commit()
                session['user_id'] = new_user.id

            # Bersihkan session sementara
            session.pop('pending_nama', None)
            session.pop('pending_email', None)
            session.pop('pending_password', None)
            session.pop('kode_verifikasi', None)

            return redirect('/dashboard?daftar=success')
        else:
            flash("Kode verifikasi salah. Silakan coba lagi.", "warning")
            return redirect('/daftar/email/verifikasi')

    return render_template("Login-Daftar-Page/verifikasi.html")

    
@app.route('/daftar/email/verifikasi/new-code', methods=['POST'])
def kirim_ulang():
    email = session.get('email_verifikasi')
    if not email:
        return redirect('/login/email')

    # Cek cooldown 60 detik
    now = datetime.utcnow()
    terakhir_kirim = session.get('terakhir_kirim_kode')  # timestamp string

    if terakhir_kirim:
        terakhir_kirim_dt = datetime.strptime(terakhir_kirim, "%Y-%m-%d %H:%M:%S")
        if now < terakhir_kirim_dt + timedelta(seconds=60):
            flash("Tunggu sebentar sebelum mengirim ulang kode.")
            return redirect('/daftar/email/verifikasi')

    # Lanjutkan pengiriman ulang
    kode = str(randint(100000, 999999))
    session['kode_verifikasi'] = kode
    session['terakhir_kirim_kode'] = now.strftime("%Y-%m-%d %H:%M:%S")
    send_verification_email(email, kode)

    flash("Kode verifikasi baru telah dikirim.")
    return redirect('/daftar/email/verifikasi')
    
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login/email?logout=success')
    
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google')
def authorize_google():
    # Cek kalau user cancel atau terjadi error saat authorize
    if 'error' in request.args:
        error_description = request.args.get('error_description', 'Authorization failed or was cancelled.')
        logging.error(f"Google OAuth error: {error_description}")
        return redirect('/')

    try:
        token = google.authorize_access_token()
    except Exception as e:
        logging.error(f"Exception during Google OAuth: {str(e)}")
        return redirect(url_for('awal'))  # fallback redirect ke "/"

    user_info = google.get('userinfo').json()

    email = user_info['email']
    nama = user_info.get('name', '')

    existing_user = db.session.query(User).filter_by(email=email).first()

    if not existing_user:
        new_user = User(email=email, nama=nama, login_google=True)
        db.session.add(new_user)
        db.session.commit()
        user = new_user
    else:
        user = existing_user

    session['user_id'] = user.id
    session['email'] = user.email
    session['nama'] = user.nama

    return redirect('/dashboard?login=success')    

#------ ADMIN AREA ------#
@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User berhasil dihapus.", "success")
    return redirect('/admin/list/user?delete=success')

@app.route('/admin/list/user')
def admin_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.id.desc()).paginate(page=page, per_page=10)
    return render_template('Main-Page/admin-listuser.html', users=users)
    
@app.route('/admin/list/server')
def admin_servers():
    page = request.args.get('page', 1, type=int)
    servers = Server.query.order_by(Server.created_at.desc()).paginate(page=page, per_page=10)
    return render_template('Main-Page/admin-listserver.html', servers=servers, panel_url=PTERODACTYL_URL)
    
@app.route('/admin/server/delete/<int:server_id>', methods=['POST'])
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    user = User.query.get(server.user_id)

    try:
        db.session.delete(server)
        user.server = 0
        user.cpu = 0
        user.ram = 0
        user.disk = 0
        db.session.commit()
        flash('Server berhasil dihapus.', 'success')
    except SQLAlchemyError:
        db.session.rollback()
        flash('Gagal menghapus server.', 'error')

    return redirect('/admin/list/server?delete=success')
    
    
#------ CREATE PANEL PTERODACTYL OTOMATIS AREA ------#
@app.route("/panel/detail")
def detail_akun():
    email = request.args.get("email")
    username = request.args.get("username")

    if not email or not username:
        flash("Data akun tidak valid.", "error")
        return redirect("/dashboard")

    account = {
        "email": email,
        "username": username,
        "panel_url": f"{PTERODACTYL_URL}"  # atau langsung ke login: f"{PANEL_URL}/auth/login"
    }

    return render_template("Panel-Page/account_details.html", account=account)

# Route halaman form
@app.route("/panel/create", methods=["GET", "POST"])
def order_hosting():
    user = User.query.get(session.get('user_id'))
    if not user:
        flash("User tidak ditemukan.", "error")
        return redirect("/login")

    # Jika user sudah punya server, langsung redirect ke halaman detail
    if user.server == 1:
        user_email = user.email
        username = user_email.split("@")[0]
        flash("Kamu sudah memiliki server!", "has_server")
        return redirect(f"/panel/detail?email={user_email}&username={username}")

    if request.method == "POST":
        print("POST request diterima")

        server_name = request.form.get("server_name")
        egg_id = request.form.get("egg")
        node_id = request.form.get("node")

        print("server_name:", server_name)
        print("egg_id:", egg_id)
        print("node_id:", node_id)

        if not all([server_name, egg_id, node_id]):
            flash("Data form tidak lengkap", "error")
            return redirect("/panel/create")

        user_email = user.email
        username = user_email.split("@")[0]

        # Create atau ambil user dari Pterodactyl
        ptero_user = create_user(user_email, username)
        print("Hasil create_user:", ptero_user)

        if not ptero_user or "id" not in ptero_user:
            flash("Gagal membuat atau mendapatkan user Pterodactyl.", "error")
            return redirect("/panel/create")

        # Ambil ID dari user Pterodactyl
        ptero_user_id = ptero_user["id"]

        # Buat server di Pterodactyl
        success = create_server(
            user_id=ptero_user_id,
            name=server_name,
            egg_id=int(egg_id),
            node_id=int(node_id),
            cpu=panel_cpu,
            ram=panel_ram,
            disk=panel_disk
        )

        print("Hasil create_server:", success)

        if success and 'attributes' in success:
            server_id = success['attributes']['id']

            # Simpan ke database internal
            panelS = Server(
                id=server_id,
                name=server_name,
                uuid=str(uuid4()),
                user_id=user.id,
                server=1,
                cpu=panel_cpu,
                ram=panel_ram,
                disk=panel_disk
            )
            db.session.add(panelS)

            user.server = 1
            user.cpu = panel_cpu
            user.ram = panel_ram
            user.disk = panel_disk

            db.session.commit()
            flash("Berhasil Membuat Server Panel!", "server_created")
            return redirect(f"/panel/detail?email={user_email}&username={username}")
        else:
            flash("Gagal membuat server.", "error")

    return render_template("Panel-Page/pterodactyl.html")

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)