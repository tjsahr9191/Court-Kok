FROM python:3.9-slim

WORKDIR /app

# ### ADDED: 빌드에 필요한 도구들을 설치하는 단계 추가 ###
# apt-get 패키지 목록을 업데이트하고, build-essential(gcc 등 포함)과
# 파이썬 개발 헤더 파일 등을 설치합니다.
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libffi-dev \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "-b", "0.0.0.0:5001", "app:app"]

# 나머지 애플리케이션 코드를 복사합니다.
COPY . .
COPY ./test /app/test

# 컨테이너가 5000번 포트를 사용함을 알립니다.
EXPOSE 5001

# 컨테이너 시작 시 Gunicorn을 사용하여 Flask 애플리케이션을 실행합니다.
# 'app:app'은 'app.py' 파일 내의 'app' 변수를 의미합니다.
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--worker-class", "gevent", "--timeout", "120", "-w", "1", "app:app"]