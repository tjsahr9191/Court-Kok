import os
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from pymongo import MongoClient
import json
from datetime import datetime, timedelta
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Generate a strong, random secret key for session management
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# 환경 변수에서 MongoDB 호스트를 가져오도록 수정
MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
# 환경 변수를 사용하여 MongoDB에 접속
try:
    client = MongoClient(f'mongodb://{MONGO_HOST}:27017/')
    db = client.court_kok
    client.admin.command('ping') # Check connections
    print("Successfully connected to MongoDB.")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    client = None
    db = None

@app.route('/')
def home():
    """Renders the main index.html file for the frontend application."""
    return render_template('index.html')

@app.route('/test')
def test():
    db.test.insert_one({"name": "test"})
    return "hi world!!!"

@app.route('/api/signup', methods=['POST'])
def signup():
    """Handles user registration and stores credentials in MongoDB."""
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    
    data = request.json
    name = data.get('name')
    username = data.get('id')
    password = data.get('pw')
    email = data.get('email')
    phone = data.get('phone')

    # Hash the password for security
    hashed_password = generate_password_hash(password)

    # Check if user already exists
    if db.users.find_one({"id": username}):
        return jsonify({"status": "error", "message": "사용자 ID가 이미 존재합니다."}), 409
    
    try:
        user_info = {
            "name": name,
            "id": username,
            "password": hashed_password,
            "email": email,
            "phone": phone
        }
        db.users.insert_one(user_info)
        return jsonify({"status": "success", "message": "회원가입이 완료되었습니다."}), 201
    except Exception as e:
        print(f"Error during signup: {e}")
        return jsonify({"status": "error", "message": "회원가입 중 오류가 발생했습니다."}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticates user and creates a session upon successful login."""
    if not db:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    
    data = request.json
    username = data.get('id')
    password = data.get('pw')

    user = db.users.find_one({"id": username})
    
    if user and check_password_hash(user['password'], password):
        # Successful login, create session
        session['logged_in'] = True
        session['user_id'] = str(user['_id'])
        session['user_name'] = user['name']
        session['user_phone'] = user['phone']
        return jsonify({"status": "success", "message": "로그인 성공"}), 200
    else:
        return jsonify({"status": "error", "message": "아이디 또는 비밀번호가 잘못되었습니다."}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logs out the user by clearing the session."""
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_phone', None)
    return jsonify({"status": "success", "message": "로그아웃 성공"}), 200

@app.route('/api/user_info', methods=['GET'])
def get_user_info():
    """Returns the current user's information if a session exists."""
    if 'logged_in' in session:
        return jsonify({
            "status": "success",
            "userId": session.get('user_id'),
            "userName": session.get('user_name'),
            "userPhone": session.get('user_phone')
        }), 200
    return jsonify({"status": "error", "message": "사용자가 로그인되지 않았습니다."}), 401

@app.route('/api/reservations', methods=['GET'])
def get_reservations():
    """Fetches all court reservations."""
    if not db:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    
    reservations_data = list(db.reservations.find({}, {'_id': 0}))
    return jsonify({"status": "success", "data": reservations_data}), 200

@app.route('/api/reservations/create', methods=['POST'])
def create_reservation():
    """Creates a new reservation."""
    if 'logged_in' not in session:
        return jsonify({"status": "error", "message": "로그인이 필요합니다."}), 401

    if not db:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
        
    data = request.json
    slot_id = data.get('slotId')
    capacity = data.get('capacity')
    
    reservation = {
        "slotId": slot_id,
        "capacity": int(capacity),
        "creatorId": session['user_id'],
        "creatorName": session['user_name'],
        "creatorPhone": session['user_phone'],
        "participants": [session['user_id']],
        "createdAt": datetime.now()
    }
    db.reservations.insert_one(reservation)
    return jsonify({"status": "success", "message": "예약이 생성되었습니다."}), 201

@app.route('/api/reservations/update', methods=['POST'])
def update_reservation():
    """Adds or removes a user from a reservation."""
    if 'logged_in' not in session:
        return jsonify({"status": "error", "message": "로그인이 필요합니다."}), 401

    if not db:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
        
    data = request.json
    action = data.get('action') # 'join' or 'cancel'
    slot_id = data.get('slotId')
    
    reservation = db.reservations.find_one({"slotId": slot_id})
    if reservation is None:
        return jsonify({"status": "error", "message": "예약을 찾을 수 없습니다."}), 404

    user_id = session['user_id']
    
    if action == 'join':
        if len(reservation.get('participants', [])) >= reservation['capacity']:
            return jsonify({"status": "error", "message": "슬롯이 가득 찼습니다."}), 400
        if user_id not in reservation.get('participants', []):
            reservation['participants'].append(user_id)
    elif action == 'cancel':
        if user_id in reservation.get('participants', []):
            reservation['participants'].remove(user_id)
            if len(reservation['participants']) == 0:
                # If last person cancels, delete the reservation
                db.reservations.delete_one({"slotId": slot_id})
                return jsonify({"status": "success", "message": "예약이 취소되었습니다."}), 200
    
    db.reservations.update_one({"slotId": slot_id}, {"$set": {"participants": reservation['participants']}})
    return jsonify({"status": "success", "message": "예약이 업데이트되었습니다."}), 200

@app.route('/api/reservations/delete', methods=['POST'])
def delete_reservation():
    """Deletes a reservation, only if the user is the creator."""
    if 'logged_in' not in session:
        return jsonify({"status": "error", "message": "로그인이 필요합니다."}), 401

    if not db:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
        
    data = request.json
    slot_id = data.get('slotId')
    
    reservation = db.reservations.find_one({"slotId": slot_id})
    if not reservation:
        return jsonify({"status": "error", "message": "예약을 찾을 수 없습니다."}), 404

    if reservation.get('creatorId') != session['user_id']:
        return jsonify({"status": "error", "message": "예약 삭제 권한이 없습니다."}), 403

    db.reservations.delete_one({"slotId": slot_id})
    return jsonify({"status": "success", "message": "예약이 성공적으로 삭제되었습니다."}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)
