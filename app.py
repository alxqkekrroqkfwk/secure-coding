import sqlite3
import uuid
import bcrypt
import time
from datetime import datetime
import pytz
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_socketio import SocketIO, send
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import re
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 실제 운영에서는 환경변수로 관리
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 세션 30분 유지
app.config['SESSION_COOKIE_SECURE'] = False  # 개발 환경에서는 False로 설정
app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript에서 쿠키 접근 방지
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 방지
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # 파일 업로드 경로 설정
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 최대 16MB 파일 크기 제한
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
DATABASE = 'market.db'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 보안 관련 상수
MIN_PASSWORD_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT = 300  # 5분

# 로그인 시도 횟수 추적
login_attempts = {}

# 한국 시간대 설정
korea_tz = pytz.timezone('Asia/Seoul')

# 한국 시간대 설정
KST = pytz.timezone('Asia/Seoul')
app.jinja_env.globals.update(
    format_datetime=lambda dt: dt.astimezone(KST).strftime('%Y년 %m월 %d일 %H:%M'),
    format_date=lambda dt: dt.astimezone(KST).strftime('%Y년 %m월 %d일')
)

# 인증이 필요하지 않은 라우트 목록
PUBLIC_ROUTES = ['login', 'register', 'static', 'index']

@app.before_request
def check_auth():
    # 현재 요청의 엔드포인트 확인
    endpoint = request.endpoint
    
    # 현재 사용자 정보를 g 객체에 저장
    g.user = None
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user_data = cursor.fetchone()
        if user_data:
            g.user = User(user_data['id'], user_data['username'], user_data['password'])
            g.user.is_admin = bool(user_data['is_admin'])
    
    # PUBLIC_ROUTES에 포함되지 않은 모든 라우트에 대해 인증 체크
    if endpoint and endpoint not in PUBLIC_ROUTES and 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                profile_image TEXT DEFAULT NULL,
                report_count INTEGER DEFAULT 0,
                is_dormant BOOLEAN DEFAULT FALSE,
                balance INTEGER DEFAULT 0,
                is_admin BOOLEAN DEFAULT FALSE
            )
        """)
        
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                image_path TEXT,
                seller_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                report_count INTEGER DEFAULT 0,
                FOREIGN KEY (seller_id) REFERENCES user(id)
            )
        """)
        
        # 채팅방 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id TEXT NOT NULL,
                user2_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user1_id) REFERENCES user(id),
                FOREIGN KEY (user2_id) REFERENCES user(id)
            )
        """)
        
        # 채팅 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_room_id INTEGER NOT NULL,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (chat_room_id) REFERENCES chat_rooms(id),
                FOREIGN KEY (sender_id) REFERENCES user(id)
            )
        """)
        
        # 상품 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id TEXT NOT NULL,
                reporter_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES product(id),
                FOREIGN KEY (reporter_id) REFERENCES user(id),
                UNIQUE(product_id, reporter_id)
            )
        """)
        
        # 사용자 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reported_user_id TEXT NOT NULL,
                reporter_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reported_user_id) REFERENCES user(id),
                FOREIGN KEY (reporter_id) REFERENCES user(id),
                UNIQUE(reported_user_id, reporter_id)
            )
        """)
        
        # 전체 소통방 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS public_chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES user(id)
            )
        """)
        
        db.commit()

# 업로드 폴더가 없으면 생성
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 비밀번호 해싱 함수
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# 비밀번호 검증 함수
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# 입력 검증 함수
def validate_input(data, field_type):
    if field_type == 'username':
        return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', data))
    elif field_type == 'password':
        return len(data) >= MIN_PASSWORD_LENGTH
    elif field_type == 'email':
        return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data))
    return True

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 권한 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# SQL 인젝션 방지 함수
def sanitize_input(input_str):
    return input_str.replace("'", "''").replace('"', '""')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 입력 검증
        if not validate_input(username, 'username'):
            flash('유효하지 않은 사용자명입니다.')
            return redirect(url_for('register'))
        if not validate_input(password, 'password'):
            flash('비밀번호는 최소 8자 이상이어야 합니다.')
            return redirect(url_for('register'))
            
        db = get_db()
        cursor = db.cursor()
        
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
            
        # 비밀번호 해싱
        hashed_password = hash_password(password)
        user_id = str(uuid.uuid4())
        
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                      (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        
        # 로그인 시도 제한 확인
        if ip_address in login_attempts:
            if login_attempts[ip_address]['count'] >= MAX_LOGIN_ATTEMPTS:
                if login_attempts[ip_address]['time'] + LOGIN_TIMEOUT > time.time():
                    flash('너무 많은 로그인 시도가 있었습니다. 잠시 후 다시 시도해주세요.')
                    return redirect(url_for('login'))
                else:
                    del login_attempts[ip_address]
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and verify_password(password, user['password']):
            # 휴면 계정 체크
            if user['is_dormant']:
                flash('신고 누적으로 인해 휴면 상태로 전환된 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
                
            # 로그인 성공 시 시도 횟수 초기화
            if ip_address in login_attempts:
                del login_attempts[ip_address]
                
            session.clear()
            session['user_id'] = user['id']
            session.permanent = True
            flash('로그인 성공!')
            
            # 세션 저장 확인
            db.commit()
            
            return redirect(url_for('dashboard'))
        else:
            # 로그인 실패 시 시도 횟수 증가
            if ip_address not in login_attempts:
                login_attempts[ip_address] = {'count': 1, 'time': time.time()}
            else:
                login_attempts[ip_address]['count'] += 1
                
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    
    # 상품 목록의 created_at을 datetime 객체로 변환
    products = []
    for product in all_products:
        product = dict(product)
        product['created_at'] = datetime.strptime(product['created_at'], '%Y-%m-%d %H:%M:%S')
        products.append(product)
    
    return render_template('dashboard.html', products=products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@app.route('/profile/<username>', methods=['GET', 'POST'])
@login_required
def profile(username=None):
    db = get_db()
    cursor = db.cursor()
    
    # username이 제공된 경우 (판매자 프로필 보기)
    if username:
        cursor.execute("""
            SELECT u.id, u.username, u.bio, u.profile_image, 
                   CASE WHEN u.id = ? THEN u.balance ELSE NULL END as balance,
                   (SELECT COUNT(*) FROM product WHERE seller_id = u.id) as product_count
            FROM user u 
            WHERE u.username = ?
        """, (session.get('user_id'), username))
        user = cursor.fetchone()
        
        if not user:
            flash('사용자를 찾을 수 없습니다.')
            return redirect(url_for('dashboard'))
            
        # 판매자의 상품 목록 가져오기
        cursor.execute("""
            SELECT * FROM product 
            WHERE seller_id = ? 
            ORDER BY created_at DESC
        """, (user['id'],))
        products = cursor.fetchall()
        products = [dict(p) for p in products]
        for product in products:
            product['created_at'] = datetime.strptime(product['created_at'], '%Y-%m-%d %H:%M:%S')
        
        return render_template('profile.html', user=user, products=products, is_viewer=True)
    
    # 자신의 프로필 페이지 (username이 없는 경우)
    cursor.execute("""
        SELECT u.id, u.username, u.bio, u.profile_image, u.balance,
               (SELECT COUNT(*) FROM product WHERE seller_id = u.id) as product_count
        FROM user u 
        WHERE u.id = ?
    """, (session['user_id'],))
    user = cursor.fetchone()
    
    # 자신의 상품 목록 가져오기
    cursor.execute("""
        SELECT * FROM product 
        WHERE seller_id = ? 
        ORDER BY created_at DESC
    """, (session['user_id'],))
    products = cursor.fetchall()
    products = [dict(p) for p in products]
    for product in products:
        product['created_at'] = datetime.strptime(product['created_at'], '%Y-%m-%d %H:%M:%S')
    
    # 편집 모드 여부 확인
    edit_mode = request.args.get('edit') == 'true'
    
    return render_template('profile.html', user=user, products=products, is_viewer=False, edit_mode=edit_mode)

# 프로필 수정
@app.route('/profile/<username>/edit', methods=['POST'])
@login_required
def edit_profile(username):
    if not g.user or g.user.username != username:
        flash('자신의 프로필만 수정할 수 있습니다.', 'danger')
        return redirect(url_for('profile', username=username))

    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    
    if not user_data:
        flash('사용자를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('profile', username=username))

    # 프로필 이미지 처리
    if 'profile_image' in request.files:
        file = request.files['profile_image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cursor.execute("UPDATE user SET profile_image = ? WHERE id = ?", 
                         (filename, user_data['id']))

    # 소개글 업데이트
    bio = request.form.get('bio', '')
    cursor.execute("UPDATE user SET bio = ? WHERE id = ?", 
                  (bio, user_data['id']))

    # 비밀번호 변경 처리
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if current_password and new_password and confirm_password:
        if not verify_password(current_password, user_data['password']):
            flash('현재 비밀번호가 일치하지 않습니다.', 'danger')
            return redirect(url_for('profile', edit='true'))
        
        if new_password != confirm_password:
            flash('새 비밀번호가 일치하지 않습니다.', 'danger')
            return redirect(url_for('profile', edit='true'))
        
        if len(new_password) < 8:
            flash('비밀번호는 최소 8자 이상이어야 합니다.', 'danger')
            return redirect(url_for('profile', edit='true'))
        
        # 새 비밀번호 해싱 및 업데이트
        hashed_password = hash_password(new_password)
        cursor.execute("UPDATE user SET password = ? WHERE id = ?", 
                      (hashed_password, user_data['id']))
        flash('비밀번호가 성공적으로 변경되었습니다.', 'success')

    db.commit()
    flash('프로필이 성공적으로 수정되었습니다.', 'success')
    return redirect(url_for('profile'))

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        image = request.files['image']
        
        if not title or not description or not price:
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('new_product'))
            
        # 현재 로그인한 사용자 정보 확인
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, username FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
        
        if not current_user:
            flash('사용자 정보를 찾을 수 없습니다.')
            return redirect(url_for('login'))
            
        if image:
            filename = secure_filename(image.filename)
            # 이미지 파일 확장자 확인
            if not filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                flash('지원하지 않는 이미지 형식입니다.')
                return redirect(url_for('new_product'))
                
            # 업로드 폴더가 없으면 생성
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
                
            # 파일 저장 경로 설정
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            image_path = os.path.join('uploads', filename)  # 웹에서 접근할 경로
        else:
            image_path = None
            
        product_id = str(uuid.uuid4())
        
        # 한국 시간으로 현재 시간 저장
        current_time = datetime.now(korea_tz).strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute("""
            INSERT INTO product (id, title, description, price, image_path, seller_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (product_id, title, description, price, image_path, current_user['id'], current_time))
        
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
        
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 현재 로그인한 사용자 정보 가져오기
    current_user = {'id': None}
    if 'user_id' in session:
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
    
    cursor.execute("""
        SELECT p.*, u.username as seller_username, u.profile_image as seller_profile_image, u.id as seller_id
        FROM product p 
        LEFT JOIN user u ON p.seller_id = u.id 
        WHERE p.id = ?
    """, (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 상품 정보를 딕셔너리로 변환하고 created_at을 datetime 객체로 변환
    product = dict(product)
    product['created_at'] = datetime.strptime(product['created_at'], '%Y-%m-%d %H:%M:%S')
        
    # 판매자 정보가 없으면 알 수 없음으로 설정
    if not product['seller_username']:
        product = dict(product)
        product['seller_username'] = '알 수 없음'
        seller = {
            'profile_image': None,
            'username': '알 수 없음',
            'id': None
        }
    else:
        # 판매자 정보 설정
        seller = {
            'profile_image': product['seller_profile_image'],
            'username': product['seller_username'],
            'id': product['seller_id']
        }
        
    return render_template('product.html', product=product, seller=seller, current_user=current_user)

# 상품 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 가져오기
    cursor.execute("""
        SELECT * FROM product 
        WHERE id = ?
    """, (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
        
    # 권한 확인
    if product['seller_id'] != session['user_id']:
        flash('상품을 수정할 권한이 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        image = request.files.get('image')
        
        if not title or not description or not price:
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
            
        # 이미지 업로드 처리
        if image and image.filename:
            filename = secure_filename(image.filename)
            if not filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                flash('지원하지 않는 이미지 형식입니다.')
                return redirect(url_for('edit_product', product_id=product_id))
                
            # 기존 이미지 삭제
            if product['image_path']:
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(product['image_path']))
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            
            # 새 이미지 저장
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            image_path = os.path.join('uploads', filename)
        else:
            image_path = product['image_path']
        
        # 상품 정보 업데이트
        cursor.execute("""
            UPDATE product 
            SET title = ?, description = ?, price = ?, image_path = ?
            WHERE id = ?
        """, (title, description, price, image_path, product_id))
        
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
        
    return render_template('edit_product.html', product=product)

# 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 가져오기
    cursor.execute("""
        SELECT * FROM product 
        WHERE id = ?
    """, (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
        
    # 권한 확인
    if product['seller_id'] != session['user_id']:
        flash('상품을 삭제할 권한이 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 이미지 파일 삭제
    if product['image_path']:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(product['image_path']))
        if os.path.exists(image_path):
            os.remove(image_path)
    
    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

# 상품 신고
@app.route('/report/product/<product_id>', methods=['POST'])
@login_required
def report_product(product_id):
    if not request.form.get('reason'):
        flash('신고 사유를 입력해주세요.')
        return redirect(url_for('view_product', product_id=product_id))

    db = get_db()
    cursor = db.cursor()
    
    # 상품 존재 여부 확인
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('dashboard'))
        
    # 자신의 상품은 신고할 수 없음
    if product['seller_id'] == session['user_id']:
        flash('자신의 상품은 신고할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    try:
        # 신고 기록 추가
        cursor.execute("""
            INSERT INTO product_reports (product_id, reporter_id, reason)
            VALUES (?, ?, ?)
        """, (product_id, session['user_id'], request.form['reason']))
        
        # 신고 횟수 증가
        cursor.execute("""
            UPDATE product 
            SET report_count = report_count + 1
            WHERE id = ?
        """, (product_id,))
        
        # 신고 횟수 확인
        cursor.execute("SELECT report_count FROM product WHERE id = ?", (product_id,))
        report_count = cursor.fetchone()['report_count']
        
        # 5회 이상 신고된 상품 삭제
        if report_count >= 5:
            cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
            flash('신고가 누적되어 상품이 삭제되었습니다.')
            db.commit()
            return redirect(url_for('dashboard'))
            
        db.commit()
        flash('상품이 신고되었습니다.')
        
    except sqlite3.IntegrityError:
        flash('이미 신고한 상품입니다.')
        
    return redirect(url_for('view_product', product_id=product_id))

# 사용자 신고
@app.route('/report/user/<user_id>', methods=['POST'])
@login_required
def report_user(user_id):
    if not request.form.get('reason'):
        flash('신고 사유를 입력해주세요.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    
    # 사용자 존재 여부 확인
    cursor.execute("SELECT id, username FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('dashboard'))
        
    # 자기 자신은 신고할 수 없음
    if user['id'] == session['user_id']:
        flash('자기 자신은 신고할 수 없습니다.')
        return redirect(url_for('profile', username=user['username']))
    
    try:
        # 신고 기록 추가
        cursor.execute("""
            INSERT INTO user_reports (reported_user_id, reporter_id, reason)
            VALUES (?, ?, ?)
        """, (user['id'], session['user_id'], request.form['reason']))
        
        # 신고 횟수 증가
        cursor.execute("""
            UPDATE user 
            SET report_count = report_count + 1
            WHERE id = ?
        """, (user['id'],))
        
        # 신고 횟수 확인 (10회 이상이면 휴면 계정으로 전환)
        cursor.execute("SELECT report_count FROM user WHERE id = ?", (user['id'],))
        report_count = cursor.fetchone()['report_count']
        
        if report_count >= 10:
            cursor.execute("""
                UPDATE user 
                SET is_dormant = TRUE
                WHERE id = ?
            """, (user['id'],))
            flash('해당 사용자가 신고 누적으로 휴면 계정으로 전환되었습니다.')
        
        db.commit()
        flash('사용자가 신고되었습니다.')
        
    except sqlite3.IntegrityError:
        flash('이미 신고한 사용자입니다.')
        
    return redirect(url_for('profile', username=user['username']))

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = False

    def get_id(self):
        return self.id

    def check_password(self, password):
        return verify_password(password, self.password_hash)

    def set_password(self, password):
        return hash_password(password)

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password'])
    return None

@app.route('/chat/list')
@login_required
def chat_list():
    db = get_db()
    cursor = db.cursor()
    
    # 사용자가 참여한 모든 채팅방 조회
    cursor.execute("""
        SELECT r.*, 
               CASE 
                   WHEN r.user1_id = ? THEN u2.username 
                   ELSE u1.username 
               END as other_username,
               CASE 
                   WHEN r.user1_id = ? THEN u2.id 
                   ELSE u1.id 
               END as other_user_id
        FROM chat_rooms r
        JOIN user u1 ON r.user1_id = u1.id
        JOIN user u2 ON r.user2_id = u2.id
        WHERE r.user1_id = ? OR r.user2_id = ?
    """, (session['user_id'], session['user_id'], session['user_id'], session['user_id']))
    
    rooms = cursor.fetchall()
    chat_data = []
    
    for room in rooms:
        # 마지막 메시지 조회
        cursor.execute("""
            SELECT * FROM chat_messages 
            WHERE chat_room_id = ? 
            ORDER BY created_at DESC LIMIT 1
        """, (room['id'],))
        last_message = cursor.fetchone()
        
        # 읽지 않은 메시지 수 조회
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM chat_messages 
            WHERE chat_room_id = ? 
            AND sender_id != ? 
            AND is_read = FALSE
        """, (room['id'], session['user_id']))
        unread = cursor.fetchone()
        
        # 마지막 메시지가 있는 경우 datetime 객체로 변환
        if last_message:
            created_at = datetime.strptime(last_message['created_at'], '%Y-%m-%d %H:%M:%S')
            last_message = dict(last_message)
            last_message['created_at'] = created_at
        
        chat_data.append({
            'room_id': room['id'],
            'other_user': {
                'id': room['other_user_id'],
                'username': room['other_username']
            },
            'last_message': last_message,
            'unread_count': unread['count']
        })
    
    return render_template('chat/list.html', chats=chat_data)

@app.route('/chat/start/<user_id>', methods=['POST'])
@login_required
def start_chat(user_id):
    if user_id == session['user_id']:
        flash('자신과는 채팅할 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 이미 존재하는 채팅방 확인
    cursor.execute("""
        SELECT id FROM chat_rooms 
        WHERE (user1_id = ? AND user2_id = ?) 
        OR (user1_id = ? AND user2_id = ?)
    """, (session['user_id'], user_id, user_id, session['user_id']))
    
    existing_room = cursor.fetchone()
    
    if existing_room:
        return redirect(url_for('chat_room', room_id=existing_room['id']))
    
    # 새 채팅방 생성
    cursor.execute("""
        INSERT INTO chat_rooms (user1_id, user2_id) 
        VALUES (?, ?)
    """, (session['user_id'], user_id))
    
    db.commit()
    new_room_id = cursor.lastrowid
    
    return redirect(url_for('chat_room', room_id=new_room_id))

@app.route('/chat/room/<int:room_id>')
@login_required
def chat_room(room_id):
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 정보 조회
    cursor.execute("""
        SELECT r.*, 
               CASE 
                   WHEN r.user1_id = ? THEN u2.username 
                   ELSE u1.username 
               END as other_username,
               CASE 
                   WHEN r.user1_id = ? THEN u2.id 
                   ELSE u1.id 
               END as other_user_id
        FROM chat_rooms r
        JOIN user u1 ON r.user1_id = u1.id
        JOIN user u2 ON r.user2_id = u2.id
        WHERE r.id = ?
    """, (session['user_id'], session['user_id'], room_id))
    
    room = cursor.fetchone()
    
    if not room:
        flash('존재하지 않는 채팅방입니다.')
        return redirect(url_for('chat_list'))
    
    # 권한 확인
    if session['user_id'] not in [room['user1_id'], room['user2_id']]:
        flash('접근 권한이 없습니다.')
        return redirect(url_for('chat_list'))
    
    # 메시지 목록 조회
    cursor.execute("""
        SELECT * FROM chat_messages 
        WHERE chat_room_id = ? 
        ORDER BY created_at
    """, (room_id,))
    messages = cursor.fetchall()
    
    # 메시지 날짜/시간 변환
    messages = [dict(msg) for msg in messages]
    for msg in messages:
        msg['created_at'] = datetime.strptime(msg['created_at'], '%Y-%m-%d %H:%M:%S')
    
    # 읽지 않은 메시지 읽음 처리
    cursor.execute("""
        UPDATE chat_messages 
        SET is_read = TRUE 
        WHERE chat_room_id = ? 
        AND sender_id != ? 
        AND is_read = FALSE
    """, (room_id, session['user_id']))
    
    db.commit()
    
    other_user = {
        'id': room['other_user_id'],
        'username': room['other_username']
    }
    
    return render_template('chat/room.html', room=room, messages=messages, other_user=other_user)

@app.route('/api/chat/unread')
@login_required
def get_unread_count():
    if 'user_id' not in session:
        return jsonify({'count': 0})
        
    db = get_db()
    cursor = db.cursor()
    
    try:
        # 채팅 메시지 테이블이 있는지 확인
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM chat_messages m
            JOIN chat_rooms r ON m.chat_room_id = r.id
            WHERE (r.user1_id = ? OR r.user2_id = ?)
            AND m.sender_id != ?
            AND m.is_read = FALSE
        """, (session['user_id'], session['user_id'], session['user_id']))
        
        result = cursor.fetchone()
        return jsonify({'count': result['count'] if result else 0})
    except sqlite3.OperationalError:
        # 테이블이 없는 경우
        return jsonify({'count': 0})

@app.route('/api/chat/send/<int:room_id>', methods=['POST'])
@login_required
def send_message(room_id):
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 존재 여부와 권한 확인
    cursor.execute("""
        SELECT * FROM chat_rooms 
        WHERE id = ? AND (user1_id = ? OR user2_id = ?)
    """, (room_id, session['user_id'], session['user_id']))
    
    room = cursor.fetchone()
    if not room:
        return jsonify({'error': '채팅방을 찾을 수 없거나 접근 권한이 없습니다.'}), 404
    
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': '메시지 내용이 필요합니다.'}), 400
    
    # 현재 시간을 한국 시간대로 설정
    now = datetime.now(korea_tz).strftime('%Y-%m-%d %H:%M:%S')
    
    # 메시지 저장
    cursor.execute("""
        INSERT INTO chat_messages (chat_room_id, sender_id, content, created_at) 
        VALUES (?, ?, ?, ?)
    """, (room_id, session['user_id'], data['message'], now))
    
    db.commit()
    message_id = cursor.lastrowid
    
    # 저장된 메시지 정보 조회
    cursor.execute("SELECT * FROM chat_messages WHERE id = ?", (message_id,))
    message = cursor.fetchone()
    message = dict(message)
    message['created_at'] = datetime.strptime(message['created_at'], '%Y-%m-%d %H:%M:%S')
    
    return jsonify({
        'id': message['id'],
        'content': message['content'],
        'sender_id': message['sender_id'],
        'created_at': message['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
        'is_read': message['is_read']
    })

@app.route('/api/chat/messages/<int:room_id>')
@login_required
def get_messages(room_id):
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 존재 여부와 권한 확인
    cursor.execute("""
        SELECT * FROM chat_rooms 
        WHERE id = ? AND (user1_id = ? OR user2_id = ?)
    """, (room_id, session['user_id'], session['user_id']))
    
    room = cursor.fetchone()
    if not room:
        return jsonify({'error': '채팅방을 찾을 수 없거나 접근 권한이 없습니다.'}), 404
    
    # 마지막으로 받은 메시지 ID 이후의 새 메시지만 조회
    last_id = request.args.get('last_id', type=int, default=0)
    cursor.execute("""
        SELECT * FROM chat_messages 
        WHERE chat_room_id = ? AND id > ? 
        ORDER BY created_at
    """, (room_id, last_id))
    
    messages = cursor.fetchall()
    messages = [dict(msg) for msg in messages]
    for msg in messages:
        msg['created_at'] = datetime.strptime(msg['created_at'], '%Y-%m-%d %H:%M:%S')
    
    # 받은 메시지를 읽음 처리
    cursor.execute("""
        UPDATE chat_messages 
        SET is_read = TRUE 
        WHERE chat_room_id = ? 
        AND sender_id != ? 
        AND is_read = FALSE
    """, (room_id, session['user_id']))
    
    db.commit()
    
    return jsonify([{
        'id': message['id'],
        'content': message['content'],
        'sender_id': message['sender_id'],
        'created_at': message['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
        'is_read': message['is_read']
    } for message in messages])

@app.template_filter('format_datetime')
def format_datetime(value):
    if value is None:
        return ""
    
    # 문자열인 경우 datetime 객체로 변환
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value  # 변환 실패 시 원본 값 반환
    
    # 한국 시간대로 변환
    korea_tz = pytz.timezone('Asia/Seoul')
    if not value.tzinfo:
        value = pytz.UTC.localize(value)
    korea_time = value.astimezone(korea_tz)
    return korea_time.strftime('%Y년 %m월 %d일 %H:%M')

@app.route('/transfer/<user_id>', methods=['POST'])
@login_required
def transfer_money(user_id):
    if user_id == session['user_id']:
        flash('자신에게는 송금할 수 없습니다.', 'error')
        return redirect(url_for('profile'))
    
    amount = request.form.get('amount', type=int)
    if not amount or amount <= 0:
        flash('올바른 송금 금액을 입력해주세요.', 'error')
        return redirect(url_for('profile'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 송금자의 잔액 확인
    cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
    sender = cursor.fetchone()
    
    if not sender or sender['balance'] < amount:
        flash('잔액이 부족합니다.', 'error')
        return redirect(url_for('profile'))
    
    # 수신자 확인
    cursor.execute("SELECT username FROM user WHERE id = ?", (user_id,))
    recipient = cursor.fetchone()
    
    if not recipient:
        flash('존재하지 않는 사용자입니다.', 'error')
        return redirect(url_for('profile'))
    
    try:
        # 트랜잭션 시작
        cursor.execute("BEGIN TRANSACTION")
        
        # 송금자 잔액 감소
        cursor.execute("""
            UPDATE user 
            SET balance = balance - ? 
            WHERE id = ? AND balance >= ?
        """, (amount, session['user_id'], amount))
        
        # 수신자 잔액 증가
        cursor.execute("""
            UPDATE user 
            SET balance = balance + ? 
            WHERE id = ?
        """, (amount, user_id))
        
        # 트랜잭션 커밋
        cursor.execute("COMMIT")
        
        flash(f'{recipient["username"]}님께 {amount:,}원을 송금했습니다.', 'success')
        
    except Exception as e:
        # 오류 발생 시 롤백
        cursor.execute("ROLLBACK")
        flash('송금 중 오류가 발생했습니다.', 'error')
        
    return redirect(url_for('profile'))

# 관리자 대시보드
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    
    # 전체 상품 목록
    cursor.execute("""
        SELECT p.*, u.username as seller_username, 
               (SELECT COUNT(*) FROM product_reports WHERE product_id = p.id) as product_report_count
        FROM product p
        LEFT JOIN user u ON p.seller_id = u.id
        ORDER BY p.created_at DESC
    """)
    products = cursor.fetchall()
    products = [dict(p) for p in products]
    for product in products:
        product['created_at'] = datetime.strptime(product['created_at'], '%Y-%m-%d %H:%M:%S')
    
    # 신고된 상품 목록
    cursor.execute("""
        SELECT p.*, u.username as seller_username, 
               COUNT(pr.id) as product_report_count
        FROM product p
        LEFT JOIN user u ON p.seller_id = u.id
        JOIN product_reports pr ON p.id = pr.product_id
        GROUP BY p.id, p.title, p.description, p.price, p.image_path, p.seller_id, p.created_at, 
                 p.report_count, u.username
        HAVING COUNT(pr.id) > 0
        ORDER BY COUNT(pr.id) DESC
    """)
    reported_products = cursor.fetchall()
    reported_products = [dict(p) for p in reported_products]
    for product in reported_products:
        product['created_at'] = datetime.strptime(product['created_at'], '%Y-%m-%d %H:%M:%S')
    
    # 신고된 사용자 목록
    cursor.execute("""
        SELECT u.*, 
               COUNT(ur.id) as user_report_count
        FROM user u
        JOIN user_reports ur ON u.id = ur.reported_user_id
        GROUP BY u.id, u.username, u.password, u.bio, u.profile_image, 
                 u.report_count, u.is_dormant, u.balance, u.is_admin
        HAVING COUNT(ur.id) > 0
        ORDER BY COUNT(ur.id) DESC
    """)
    reported_users = cursor.fetchall()
    
    return render_template('admin/dashboard.html', 
                         products=products,
                         reported_products=reported_products,
                         reported_users=reported_users)

# 상품 신고 내역 조회
@app.route('/admin/product/reports/<product_id>')
@admin_required
def admin_product_reports(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 조회
    cursor.execute("""
        SELECT p.*, u.username as seller_username
        FROM product p
        LEFT JOIN user u ON p.seller_id = u.id
        WHERE p.id = ?
    """, (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('admin_dashboard'))
    
    # 신고 내역 조회
    cursor.execute("""
        SELECT pr.*, u.username as reporter_username
        FROM product_reports pr
        JOIN user u ON pr.reporter_id = u.id
        WHERE pr.product_id = ?
        ORDER BY pr.created_at DESC
    """, (product_id,))
    reports = cursor.fetchall()
    
    return render_template('admin/product_reports.html', 
                         product=product,
                         reports=reports)

# 사용자 신고 내역 조회
@app.route('/admin/user/reports/<user_id>')
@admin_required
def admin_user_reports(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('admin_dashboard'))
    
    # 신고 내역 조회
    cursor.execute("""
        SELECT ur.*, u.username as reporter_username
        FROM user_reports ur
        JOIN user u ON ur.reporter_id = u.id
        WHERE ur.reported_user_id = ?
        ORDER BY ur.created_at DESC
    """, (user_id,))
    reports = cursor.fetchall()
    
    return render_template('admin/user_reports.html', 
                         user=user,
                         reports=reports)

# 관리자 상품 삭제
@app.route('/admin/product/delete/<product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('admin_dashboard'))
    
    # 이미지 파일 삭제
    if product['image_path']:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], 
                                os.path.basename(product['image_path']))
        if os.path.exists(image_path):
            os.remove(image_path)
    
    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

# 관리자 사용자 상태 변경 (차단/해제)
@app.route('/admin/user/toggle-status/<user_id>', methods=['POST'])
@admin_required
def admin_toggle_user_status(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 상태 조회
    cursor.execute("SELECT is_dormant FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('admin_dashboard'))
    
    # 상태 토글
    new_status = not user['is_dormant']
    cursor.execute("""
        UPDATE user 
        SET is_dormant = ?
        WHERE id = ?
    """, (new_status, user_id))
    
    db.commit()
    
    status_msg = '차단' if new_status else '해제'
    flash(f'사용자가 {status_msg}되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/charge_money', methods=['POST'])
@login_required
def charge_money():
    if not request.form.get('amount'):
        flash('충전할 금액을 입력해주세요.', 'error')
        return redirect(url_for('profile'))
    
    try:
        amount = int(request.form.get('amount'))
        if amount < 1000:
            flash('최소 충전 금액은 1,000원입니다.', 'error')
            return redirect(url_for('profile'))
            
        db = get_db()
        cursor = db.cursor()
        
        # 현재 사용자의 잔액을 가져옵니다
        cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
        current_balance = cursor.fetchone()[0] or 0
        
        # 새로운 잔액을 계산하고 업데이트합니다
        new_balance = current_balance + amount
        cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_balance, session['user_id']))
        db.commit()
        
        flash(f'{amount:,}원이 충전되었습니다.', 'success')
        return redirect(url_for('profile'))
        
    except ValueError:
        flash('올바른 금액을 입력해주세요.', 'error')
        return redirect(url_for('profile'))
    except Exception as e:
        db.rollback()
        flash('충전 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('profile'))

# 전체 소통방
@app.route('/public-chat')
@login_required
def public_chat():
    db = get_db()
    cursor = db.cursor()
    
    # 메시지 목록 조회 (최근 100개)
    cursor.execute("""
        SELECT m.*, u.username as sender_username
        FROM public_chat_messages m
        JOIN user u ON m.sender_id = u.id
        ORDER BY m.created_at DESC
        LIMIT 100
    """)
    messages = cursor.fetchall()
    messages = [dict(msg) for msg in messages]
    
    # created_at을 datetime 객체로 변환
    for msg in messages:
        msg['created_at'] = datetime.strptime(msg['created_at'], '%Y-%m-%d %H:%M:%S')
    
    # 최신 메시지가 아래에 오도록 역순 정렬
    messages.reverse()
    
    return render_template('public_chat.html', messages=messages)

@app.route('/api/public-chat/send', methods=['POST'])
@login_required
def send_public_message():
    db = get_db()
    cursor = db.cursor()
    
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': '메시지 내용이 필요합니다.'}), 400
    
    # 현재 시간을 한국 시간대로 설정
    now = datetime.now(korea_tz).strftime('%Y-%m-%d %H:%M:%S')
    
    # 메시지 저장
    cursor.execute("""
        INSERT INTO public_chat_messages (sender_id, content, created_at) 
        VALUES (?, ?, ?)
    """, (session['user_id'], data['message'], now))
    
    db.commit()
    message_id = cursor.lastrowid
    
    # 저장된 메시지 정보 조회
    cursor.execute("""
        SELECT m.*, u.username as sender_username
        FROM public_chat_messages m
        JOIN user u ON m.sender_id = u.id
        WHERE m.id = ?
    """, (message_id,))
    message = cursor.fetchone()
    message = dict(message)
    message['created_at'] = datetime.strptime(message['created_at'], '%Y-%m-%d %H:%M:%S')
    
    return jsonify({
        'id': message['id'],
        'content': message['content'],
        'sender_id': message['sender_id'],
        'sender_username': message['sender_username'],
        'created_at': message['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/api/public-chat/messages')
@login_required
def get_public_messages():
    db = get_db()
    cursor = db.cursor()
    
    # 마지막으로 받은 메시지 ID 이후의 새 메시지만 조회
    last_id = request.args.get('last_id', type=int, default=0)
    cursor.execute("""
        SELECT m.*, u.username as sender_username
        FROM public_chat_messages m
        JOIN user u ON m.sender_id = u.id
        WHERE m.id > ?
        ORDER BY m.created_at
    """, (last_id,))
    
    messages = cursor.fetchall()
    messages = [dict(msg) for msg in messages]
    for msg in messages:
        msg['created_at'] = datetime.strptime(msg['created_at'], '%Y-%m-%d %H:%M:%S')
    
    return jsonify([{
        'id': message['id'],
        'content': message['content'],
        'sender_id': message['sender_id'],
        'sender_username': message['sender_username'],
        'created_at': message['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    } for message in messages])

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)
