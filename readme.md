# 보안 코딩 프로젝트

소규모 중고 쇼핑 플랫폼입니다. 사용자 간의 안전한 거래와 커뮤니케이션을 위한 보안 기능이 구현되어 있습니다.

## 시스템 요구사항

- Python 3.8 이상
- Miniconda 또는 Anaconda

Miniconda가 설치되어 있지 않다면 다음 URL에서 설치할 수 있습니다:
- https://docs.anaconda.com/free/miniconda/index.html

## 설치 방법

1. 저장소 클론:
```bash
git clone https://github.com/ugonfor/secure-coding
cd secure-coding
```

2. 가상환경 생성 및 의존성 설치:
```bash
conda env create -f environments.yaml
```

3. 가상환경 활성화:
```bash
conda activate secure-coding
```

## 실행 방법

1. 서버 실행:
```bash
python app.py
```

2. 웹 브라우저에서 다음 URL로 접속:
- 로컬 접속: http://localhost:8080
- 네트워크 접속: http://<IP주소>:8080

## 주요 기능

- 사용자 인증 (회원가입/로그인)
- 상품 등록 및 관리
- 상품 검색 및 필터링
- 사용자 간 메시지 전송
- 신고 시스템
- 관리자 대시보드

## 보안 기능

- CSRF 보호
- XSS 방지
- SQL Injection 방지
- 안전한 파일 업로드
- 비밀번호 암호화
- 세션 관리
