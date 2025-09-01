import os
from flask import Flask, render_template, jsonify, request
import requests
from pymongo import MongoClient

app = Flask(__name__)

# 환경 변수에서 MongoDB 호스트를 가져오도록 수정
MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
# 환경 변수를 사용하여 MongoDB에 접속
client = MongoClient(f'mongodb://{MONGO_HOST}:27017/')
db = client.court_kok

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)