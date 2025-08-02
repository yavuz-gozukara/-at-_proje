from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from models import User, Akademisyen, Student, PasswordResetToken, Ders, CourseStudent
import uuid
from datetime import datetime, timedelta
from utils.auth import send_password_reset_email
from werkzeug.security import generate_password_hash, check_password_hash  # check_password_hash eklenmeli

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_academician():
            return redirect(url_for('academic.dashboard'))
        elif current_user.is_student():
            # DÜZELTME: Yönlendirmeden önce öğrenci detaylarını kontrol et
            if hasattr(current_user, 'student_details') and current_user.student_details:
                return redirect(url_for('student.student_dashboard'))
            else:
                flash('Öğrenci profiliniz bulunamadı.', 'danger')
                return redirect(url_for('home'))
    if request.method == 'POST':
        email_or_no = request.form.get('email_or_no')  # Form ismi güncellendi
        password = request.form.get('password')
        
        user = User.query.filter(
            (User.Email == email_or_no) | 
            (User.OgrenciNo == email_or_no)
        ).first()
        if user and user.is_active_user and user.verify_password(password):
            login_user(user)
            flash('Başarıyla giriş yaptınız.', 'success')
            if user.is_academician():
                return redirect(url_for('academic.dashboard'))
            elif user.is_student():
                return redirect(url_for('student.student_dashboard'))
        else:
            flash('Geçersiz e-posta/öğrenci no veya şifre.', 'danger')
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.is_academician():
            return redirect(url_for('dashboard'))
        elif current_user.is_student():
            return redirect(url_for('student_dashboard'))

    if request.method == 'POST':
        user_type = request.form.get('user_type')
        ad = request.form.get('ad')
        soyad = request.form.get('soyad')
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        ogrenci_no = request.form.get('ogrenci_no')
        
        if len(password) < 6:
            flash('Şifreniz en az 6 karakter uzunluğunda olmalıdır.', 'danger')
            return render_template('register.html')
        
        if password != password2:
            flash('Şifreler uyuşmuyor.', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)

        if user_type == 'academician':
            existing_user = User.query.filter_by(Email=email).first()
            if existing_user:
                flash('Bu e-posta adresi ile zaten bir kullanıcı kaydı mevcut.', 'danger')
                return redirect(url_for('auth.register'))

            new_user = User(
                Email=email,
                SifreHash=hashed_password,
                UserType='academician',
                Isim=ad,
                Soyisim=soyad,
                is_active_user=True
            )
            db.session.add(new_user)
            db.session.commit()

            new_academician = Akademisyen(
                UserID=new_user.id
            )
            db.session.add(new_academician)
            db.session.commit()
            flash('Akademisyen kaydınız başarıyla oluşturuldu! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('auth.login'))

        elif user_type == 'student':
            if not ogrenci_no:
                flash('Öğrenci numarası boş bırakılamaz.', 'danger')
                return redirect(url_for('auth.register'))

            existing_user_by_no = User.query.filter_by(OgrenciNo=ogrenci_no).first()

            if existing_user_by_no and not existing_user_by_no.is_active_user:
                # Pasif öğrenci kaydını aktifleştirme ve şifre belirleme
                existing_user_by_no.SifreHash = hashed_password
                existing_user_by_no.Isim = ad
                existing_user_by_no.Soyisim = soyad
                existing_user_by_no.Email = email
                existing_user_by_no.is_active_user = True

                db.session.commit()
                flash('Hesabınız başarıyla aktifleştirildi! Şimdi giriş yapabilirsiniz.', 'success')
                return redirect(url_for('auth.login'))

            elif existing_user_by_no and existing_user_by_no.is_active_user:
                flash('Bu öğrenci numarası ile zaten aktif bir öğrenci kaydı mevcut.', 'danger')
                return redirect(url_for('auth.register'))

            else:
                # Yeni öğrenci hesabı oluşturma (aktif)
                if email:
                    existing_user_by_email = User.query.filter_by(Email=email).first()
                    if existing_user_by_email:
                        flash('Bu e-posta adresi ile zaten bir kullanıcı kaydı mevcut.', 'danger')
                        return redirect(url_for('auth.register'))

                new_user = User(
                    OgrenciNo=ogrenci_no,
                    Email=email,
                    SifreHash=hashed_password,
                    UserType='student',
                    Isim=ad,           # <-- EKLE
                    Soyisim=soyad,     # <-- EKLE
                    is_active_user=True
                )
                db.session.add(new_user)
                db.session.commit()

                new_student = Student(
                    UserID=new_user.id,
                    OgrenciNo=ogrenci_no
                )
                db.session.add(new_student)
                db.session.commit()
                flash('Öğrenci kaydınız başarıyla oluşturuldu! Şimdi giriş yapabilirsiniz.', 'success')
                return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_type', None)
    flash('Başarıyla çıkış yapıldı.', 'info')
    return redirect(url_for('home'))

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email_or_no = request.form.get('email_or_no')
        user = User.query.filter((User.Email == email_or_no) | (User.OgrenciNo == email_or_no)).first()

        if user:
            # Önceki tokenları temizle
            PasswordResetToken.query.filter_by(user_id=user.id).delete()
            db.session.commit()

            # Yeni bir token oluştur
            token = str(uuid.uuid4())
            expiration_time = datetime.utcnow() + timedelta(minutes=30)
            
            reset_token = PasswordResetToken(user_id=user.id, token=token, expiration_time=expiration_time)
            db.session.add(reset_token)
            db.session.commit()

            reset_link = url_for('auth.reset_password', token=token, _external=True)
            send_password_reset_email(user.Email or user.OgrenciNo, reset_link)
            flash('Şifre sıfırlama linki e-posta adresinize gönderildi. Lütfen spam klasörünüzü de kontrol edin.', 'info')
            return redirect(url_for('auth.login'))
        else:
            flash('Girilen e-posta veya öğrenci numarasına sahip bir kullanıcı bulunamadı.', 'danger')
            return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    reset_token = PasswordResetToken.query.filter_by(token=token).first()

    if not reset_token or reset_token.expiration_time < datetime.utcnow():
        flash('Geçersiz veya süresi dolmuş bir şifre sıfırlama linki.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Lütfen tüm alanları doldurun.', 'danger')
            return render_template('reset_password.html', token=token)

        if new_password != confirm_password:
            flash('Şifreler uyuşmuyor.', 'danger')
            return render_template('reset_password.html', token=token)

        # Şifre karmaşıklığı kontrolü
        if len(new_password) < 6:
            flash('Şifre en az 6 karakter uzunluğunda olmalıdır.', 'danger')
            return render_template('reset_password.html', token=token)

        user = User.query.get(reset_token.user_id)
        if user:
            user.SifreHash = generate_password_hash(new_password)
            db.session.delete(reset_token) # Tokenı kullanıldıktan sonra sil
            db.session.commit()
            flash('Şifreniz başarıyla sıfırlandı. Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Kullanıcı bulunamadı.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)

# Şifre sıfırlama işlemi için örnek kod (bu kodu doğrudan çalıştırmayın, sadece referans için)
# from werkzeug.security import generate_password_hash
# from extensions import db
# from models import User

# user = User.query.filter_by(Email='akademisyen_mail_adresiniz').first()
# user.SifreHash = generate_password_hash('şifreniz')
# db.session.commit()

