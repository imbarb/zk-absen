from flask import Flask, render_template, request, redirect, flash , url_for
from flask_sqlalchemy import SQLAlchemy
from zk import ZK, const
import mysql.connector
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = "secret_zk_key"

# Konfigurasi Database MySQL
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://imbar:4Dm1n1mb%4012@10.3.142.158/qrcode_absen'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:Ict34003@localhost/db_bst'
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Model Karyawan
class Karyawan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(20), unique=True)
    nama = db.Column(db.String(100))
    privilege = db.Column(db.Integer, default=0) # 0 = User, 14 = Admin
    fingerprint_template = db.Column(db.LargeBinary, nullable=True)
    finger_index = db.Column(db.Integer, default=0) 

# Konfigurasi Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# Daftar IP Mesin Absensi
DAFTAR_MESIN = ['10.3.142.30']

@app.route('/')
@login_required
def index():
    karyawan_list = Karyawan.query.all()
    return render_template('index.html', karyawan=karyawan_list, mesin=DAFTAR_MESIN)

@app.route('/sync', methods=['POST'])
def sync_to_machine():
    users = Karyawan.query.all()
    status_report = []

    for ip in DAFTAR_MESIN:
        zk = ZK(ip, port=4370, timeout=5)
        conn = None
        try:
            conn = zk.connect()
            conn.disable_device()
            for u in users:
                conn.set_user(uid=u.id, name=u.nama, privilege=u.privilege, user_id=u.user_id)
            conn.enable_device()
            status_report.append(f"Sukses: {ip}")
        except Exception as e:
            status_report.append(f"Gagal {ip}: {str(e)}")
        finally:
            if conn: conn.disconnect()
    
    flash(", ".join(status_report))
    return redirect('/')

@app.route('/pull-finger/<user_id>')
def pull_finger(user_id):
    # Logika untuk menarik sidik jari dari mesin master (192.168.1.201)
    # Gunakan fungsi get_templates() lalu simpan ke database
    # Tutorial sebelumnya telah menjelaskan detail save_user_template()
    flash(f"Mencoba menarik data sidik jari untuk ID {user_id}...")
    return redirect('/')

from zk import ZK

def backup_finger_to_db(ip_mesin):
    zk = ZK(ip_mesin, port=4370)
    conn = zk.connect()
    templates = conn.get_templates() # Ambil semua jari di mesin
    
    for temp in templates:
        karyawan = Karyawan.query.filter_by(user_id=temp.user_id).first()
        if karyawan:
            karyawan.fingerprint_template = temp.template # Simpan data biner
            karyawan.finger_index = temp.temp_id
    db.session.commit()

def restore_to_machines(ip_mesin):
    zk = ZK(ip_mesin, port=4370)
    conn = zk.connect()
    users = Karyawan.query.all()
    
    for u in users:
        # 1. Buat Usernya dulu
        conn.set_user(uid=u.id, name=u.nama, user_id=u.user_id, privilege=u.privilege)
        
        # 2. Kirim Sidik Jarinya jika ada
        if u.fingerprint_template:
            conn.save_user_template(u, [u.fingerprint_template]) 

@app.route('/enroll-finger/<user_id>/<int:uid>')
def enroll_finger(user_id, uid):
    IP_MASTER = '10.3.142.30' 
    zk = ZK(IP_MASTER, port=4370, timeout=10 , force_udp=True) # Timeout lebih lama untuk proses scan
    conn = None
    
    try:
        conn = zk.connect()
        # 1. Pemicu mode scan di mesin (Jari indeks 0)
        # Program akan menunggu (block) sampai user selesai menempelkan jari 3x di mesin
        conn.enroll_user(uid=uid, temp_id=0, user_id=user_id)
        
        # 2. Ambil semua template dari mesin setelah scan sukses
        all_templates = conn.get_templates()
        
        # 3. Cari template milik user yang baru saja discan
        #user_temp = next((t for t in all_templates if t.user_id == user_id), None)
        user_temp = None
        for t in all_templates:
            if str(t.uid) == str(user_id):
                user_temp = t
                break

        if user_temp:
            # 4. Update Database MySQL
            karyawan = Karyawan.query.get(uid)
            if karyawan:
                karyawan.fingerprint_template = user_temp.template
                karyawan.finger_index = user_temp.temp_id
                db.session.commit()
                flash(f"Berhasil! Sidik jari {karyawan.nama} tersimpan di Database.")
        else:
            flash("Scan selesai, tapi data gagal ditarik dari mesin.")

    except Exception as e:
        flash(f"Proses Gagal atau Timeout: {str(e)}")
    finally:
        if conn:
            conn.disconnect()
            
    return redirect('/')

@app.route('/delete-user/<user_id>/<int:uid>')
def delete_from_machines(user_id, uid):
    status_report = []
    
    for ip in DAFTAR_MESIN:
        zk = ZK(ip, port=4370, timeout=5)
        conn = None
        try:
            conn = zk.connect()
            conn.disable_device()
            
            # Menghapus user berdasarkan UID dan User_ID
            conn.delete_user(uid=uid, user_id=user_id)
            
            conn.enable_device()
            status_report.append(f"Sukses di {ip}")
        except Exception as e:
            status_report.append(f"Gagal di {ip}: {str(e)}")
        finally:
            if conn:
                conn.disconnect()
    
    # Opsi: Hapus juga dari Database MySQL jika diinginkan
    # k = Karyawan.query.get(uid)
    # db.session.delete(k)
    # db.session.commit()

    flash(", ".join(status_report))
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Admin.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Username atau Password salah!')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, port=8000)
