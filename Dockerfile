# 사용할 파이썬 공식 이미지를 기반으로 설정합니다.
FROM python:3.9-slim

# 작업 디렉토리를 /app으로 설정합니다.
WORKDIR /app

# 애플리케이션 코드를 복사하기 전에 requirements.txt만 먼저 복사하여 종속성을 설치합니다.
# 이렇게 하면 requirements.txt가 변경되지 않는 한, 캐시를 활용하여 이미지 빌드 속도를 높일 수 있습니다.
COPY requirements.txt .

# 파이썬 패키지들을 설치합니다.
RUN pip install --no-cache-dir -r requirements.txt

# 나머지 애플리케이션 코드를 복사합니다.
COPY . .

# 컨테이너가 5000번 포트를 사용함을 알립니다.
EXPOSE 5001

# 컨테이너 시작 시 Gunicorn을 사용하여 Flask 애플리케이션을 실행합니다.
# 'app:app'은 'app.py' 파일 내의 'app' 변수를 의미합니다.
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--worker-class", "gevent", "--timeout", "120", "-w", "1", "app:app"]