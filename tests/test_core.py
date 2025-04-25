import unittest
import sys
import os
import bcrypt
from datetime import datetime

# 현재 디렉토리를 Python 경로에 추가
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(current_dir)
from app.app import app, get_db, init_db, hash_password, verify_password

class TestCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['DATABASE'] = 'test_market.db'
        app.config['WTF_CSRF_ENABLED'] = False  # CSRF 보호 비활성화
        cls.app = app.test_client()
        
        # 템플릿 디렉토리 생성
        os.makedirs('app/templates/admin', exist_ok=True)
        
        # 기본 템플릿 생성
        with open('app/templates/base.html', 'w') as f:
            f.write("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{% block title %}{% endblock %}</title>
            </head>
            <body>
                {% block content %}{% endblock %}
            </body>
            </html>
            """)
            
        # 로그인 템플릿
        with open('app/templates/login.html', 'w') as f:
            f.write("""
            {% extends 'base.html' %}
            {% block content %}
            <form method="post">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
            {% endblock %}
            """)
            
        # 대시보드 템플릿
        with open('app/templates/dashboard.html', 'w') as f:
            f.write("""
            {% extends 'base.html' %}
            {% block content %}
            <h1>Dashboard</h1>
            <div class="products">
                {% for product in products %}
                <div class="product">
                    <h2>{{ product.title }}</h2>
                    <p>{{ product.description }}</p>
                    <p>{{ product.price }}</p>
                </div>
                {% endfor %}
            </div>
            {% endblock %}
            """)
            
        # 프로필 템플릿
        with open('app/templates/profile.html', 'w') as f:
            f.write("""
            {% extends 'base.html' %}
            {% block content %}
            <h1>Profile</h1>
            <div class="user-info">
                <h2>{{ user.username }}</h2>
            </div>
            <div class="products">
                {% for product in products %}
                <div class="product">
                    <h2>{{ product.title }}</h2>
                    <p>{{ product.description }}</p>
                    <p>{{ product.price }}</p>
                </div>
                {% endfor %}
            </div>
            {% endblock %}
            """)
            
        # 관리자 대시보드 템플릿
        with open('app/templates/admin/dashboard.html', 'w') as f:
            f.write("""
            {% extends 'base.html' %}
            {% block content %}
            <h1>Admin Dashboard</h1>
            <div class="reports">
                <h2>Reports</h2>
                <div class="user-reports">
                    {% for report in user_reports %}
                    <div class="report">
                        <p>Reporter: {{ report.reporter_username }}</p>
                        <p>Reported User: {{ report.reported_username }}</p>
                        <p>Reason: {{ report.reason }}</p>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endblock %}
            """)
            
        with app.app_context():
            init_db()
        
    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        self.db = get_db()
        # 테스트용 기본 사용자 생성
        cursor = self.db.cursor()
        # 기존 테스트 사용자가 있다면 삭제
        cursor.execute("DELETE FROM user WHERE username IN (?, ?, ?, ?)", 
                      ('testuser', 'newuser', 'admin', 'reported'))
        self.db.commit()
        
        # 새로운 테스트 사용자 생성
        hashed_password = hash_password('testpassword123')
        cursor.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            ('test-id', 'testuser', hashed_password)
        )
        self.db.commit()
            
    def tearDown(self):
        if hasattr(self, 'db'):
            self.db.close()
        self.ctx.pop()
        
    @classmethod
    def tearDownClass(cls):
        # 템플릿 파일 정리
        template_files = [
            'app/templates/base.html',
            'app/templates/login.html',
            'app/templates/dashboard.html',
            'app/templates/profile.html',
            'app/templates/admin/dashboard.html'
        ]
        for file in template_files:
            if os.path.exists(file):
                os.remove(file)
                
        # 템플릿 디렉토리 정리
        if os.path.exists('app/templates/admin'):
            os.rmdir('app/templates/admin')
            
        # 테스트 데이터베이스 삭제
        if os.path.exists('test_market.db'):
            os.remove('test_market.db')
        
    def test_password_hashing(self):
        """비밀번호 해싱 및 검증 테스트"""
        password = "testpassword123"
        hashed = hash_password(password)
        
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("wrongpassword", hashed))
        
    def test_user_registration(self):
        """사용자 등록 테스트"""
        response = self.app.post('/register', data={
            'username': 'newuser',
            'password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", ('newuser',))
        user = cursor.fetchone()
        self.assertIsNotNone(user)
        
    def test_user_login(self):
        """사용자 로그인 테스트"""
        response = self.app.post('/login', data={
            'username': 'testuser',
            'password': 'testpassword123'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        
    def test_product_creation(self):
        """상품 등록 테스트"""
        with self.app as client:
            with client.session_transaction() as session:
                session['user_id'] = 'test-id'
                session['username'] = 'testuser'
            
            response = client.post('/product/new', data={
                'title': 'Test Product',
                'description': 'Test Description',
                'price': '10000',
                'image': (None, '')
            }, follow_redirects=True)
            
            self.assertEqual(response.status_code, 200)
            
            cursor = self.db.cursor()
            cursor.execute("SELECT * FROM product WHERE title = ?", ('Test Product',))
            product = cursor.fetchone()
            self.assertIsNotNone(product)
            
    def test_admin_access(self):
        """관리자 접근 권한 테스트"""
        cursor = self.db.cursor()
        hashed_password = hash_password('adminpass123')
        cursor.execute(
            "INSERT INTO user (id, username, password, is_admin) VALUES (?, ?, ?, ?)",
            ('admin-id', 'admin', hashed_password, True)
        )
        self.db.commit()
        
        with self.app as client:
            # 일반 사용자로 접근
            with client.session_transaction() as session:
                session['user_id'] = 'test-id'
                session['username'] = 'testuser'
            response = client.get('/admin')
            self.assertEqual(response.status_code, 302)
            
            # 관리자로 접근
            with client.session_transaction() as session:
                session['user_id'] = 'admin-id'
                session['username'] = 'admin'
            response = client.get('/admin')
            self.assertEqual(response.status_code, 200)
            
    def test_user_report(self):
        """사용자 신고 기능 테스트"""
        cursor = self.db.cursor()
        cursor.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            ('reported-id', 'reported', hash_password('pass123'))
        )
        self.db.commit()
        
        with self.app as client:
            with client.session_transaction() as session:
                session['user_id'] = 'test-id'
                session['username'] = 'testuser'
            
            response = client.post('/report/user/reported-id', data={
                'reason': 'Test Report Reason'
            }, follow_redirects=True)
            
            self.assertEqual(response.status_code, 200)
            
            cursor = self.db.cursor()
            cursor.execute("""
                SELECT * FROM user_reports 
                WHERE reporter_id = ? AND reported_user_id = ?
            """, ('test-id', 'reported-id'))
            report = cursor.fetchone()
            self.assertIsNotNone(report)

if __name__ == '__main__':
    unittest.main() 