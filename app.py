import os
from flask import Flask, render_template, jsonify, request
from pymongo import MongoClient
from bson.objectid import ObjectId  # ObjectId를 사용하기 위해 import
import json
from datetime import datetime, timedelta
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity, get_jwt

app = Flask(__name__)

# --- JWT 설정 ---
# JWT를 위한 시크릿 키 설정 (실제 운영 환경에서는 더욱 복잡한 키를 사용하세요)
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)  # 토큰 만료 시간 설정
jwt = JWTManager(app)
# ---

# 환경 변수에서 MongoDB 호스트를 가져오도록 수정
MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
try:
    client = MongoClient(f'mongodb://{MONGO_HOST}:27017/')
    db = client.court_kok
    client.admin.command('ping')  # Check connections
    print("Successfully connected to MongoDB.")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    client = None
    db = None

# --- JWT 로그아웃 관리를 위한 블록리스트 ---
# 메모리에 블록리스트를 저장합니다. 운영 환경에서는 Redis 와 같은 DB 사용을 권장합니다.
BLOCKLIST = set()


@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in BLOCKLIST


# ---

@app.route('/')
def home():
    """Renders the main index.html file for the frontend application."""
    return render_template('index.html')


@app.route('/test')
def test():
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

    hashed_password = generate_password_hash(password)

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
    """Authenticates user and returns a JWT access token."""
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500

    data = request.json
    username = data.get('id')
    password = data.get('pw')

    user = db.users.find_one({"id": username})

    if user and check_password_hash(user['password'], password):
        # 인증 성공 시, 사용자 고유 ID(_id)를 identity로 사용하여 access token 생성
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify(access_token=access_token), 200

    return jsonify({"status": "error", "message": "아이디 또는 비밀번호가 잘못되었습니다."}), 401


@app.route('/api/logout', methods=['POST'])
@jwt_required()  # 로그아웃을 하려면 유효한 토큰이 필요
def logout():
    """Logs out the user by adding the token's JTI to the blocklist."""
    jti = get_jwt()["jti"]
    BLOCKLIST.add(jti)
    return jsonify({"status": "success", "message": "로그아웃 성공"}), 200


@app.route('/api/user_info', methods=['GET'])
@jwt_required()  # 이 엔드포인트는 유효한 토큰이 있어야만 접근 가능
def get_user_info():
    """Returns the current user's information from the JWT identity."""
    current_user_id = get_jwt_identity()
    user = db.users.find_one({"_id": ObjectId(current_user_id)})
    if user:
        return jsonify({
            "status": "success",
            "userId": str(user['_id']),
            "userName": user['name'],
            "userPhone": user['phone'],
            "userIdName": user['id']
        }), 200
    return jsonify({"status": "error", "message": "사용자를 찾을 수 없습니다."}), 404


@app.route('/api/reservations', methods=['GET'])
def get_reservations():
    """Fetches all court reservations."""
    if not db:
        return jsonify({"status": "error", "message": "Database not connected"}), 500

    reservations_data = list(db.reservations.find({}))
    # ObjectId를 문자열로 변환
    for res in reservations_data:
        res['_id'] = str(res['_id'])
        if 'createdAt' in res:
            res['createdAt'] = res['createdAt'].isoformat()
    return jsonify({"status": "success", "data": reservations_data}), 200


@app.route('/api/reservations/create', methods=['POST'])
@jwt_required()
def create_reservation():
    """Creates a new reservation."""
    current_user_id = get_jwt_identity()
    user = db.users.find_one({"_id": ObjectId(current_user_id)})

    if not user:
        return jsonify({"status": "error", "message": "사용자 정보를 찾을 수 없습니다."}), 404

    data = request.json
    slot_id = data.get('slotId')
    capacity = data.get('capacity')

    reservation = {
        "slotId": slot_id,
        "capacity": int(capacity),
        "creatorId": current_user_id,
        "creatorName": user['name'],
        "creatorPhone": user['phone'],
        "participants": [current_user_id],
        "createdAt": datetime.now()
    }
    db.reservations.insert_one(reservation)
    return jsonify({"status": "success", "message": "예약이 생성되었습니다."}), 201


@app.route('/api/reservations/update', methods=['POST'])
@jwt_required()
def update_reservation():
    """Adds or removes a user from a reservation."""
    current_user_id = get_jwt_identity()

    data = request.json
    action = data.get('action')  # 'join' or 'cancel'
    slot_id = data.get('slotId')

    reservation = db.reservations.find_one({"slotId": slot_id})
    if reservation is None:
        return jsonify({"status": "error", "message": "예약을 찾을 수 없습니다."}), 404

    if action == 'join':
        if len(reservation.get('participants', [])) >= reservation['capacity']:
            return jsonify({"status": "error", "message": "슬롯이 가득 찼습니다."}), 400
        if current_user_id not in reservation.get('participants', []):
            db.reservations.update_one({"slotId": slot_id}, {"$push": {"participants": current_user_id}})
    elif action == 'cancel':
        if current_user_id in reservation.get('participants', []):
            participants = reservation['participants']
            participants.remove(current_user_id)
            if len(participants) == 0:
                db.reservations.delete_one({"slotId": slot_id})
                return jsonify({"status": "success", "message": "예약이 취소되었습니다."}), 200
            else:
                db.reservations.update_one({"slotId": slot_id}, {"$set": {"participants": participants}})

    return jsonify({"status": "success", "message": "예약이 업데이트되었습니다."}), 200


@app.route('/api/reservations/delete', methods=['POST'])
@jwt_required()
def delete_reservation():
    """Deletes a reservation, only if the user is the creator."""
    current_user_id = get_jwt_identity()

    data = request.json
    slot_id = data.get('slotId')

    reservation = db.reservations.find_one({"slotId": slot_id})
    if not reservation:
        return jsonify({"status": "error", "message": "예약을 찾을 수 없습니다."}), 404

    if reservation.get('creatorId') != current_user_id:
        return jsonify({"status": "error", "message": "예약 삭제 권한이 없습니다."}), 403

    db.reservations.delete_one({"slotId": slot_id})
    return jsonify({"status": "success", "message": "예약이 성공적으로 삭제되었습니다."}), 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)

