import os
from flask import Flask, render_template, jsonify, request, redirect, url_for
from pymongo import MongoClient
from bson.objectid import ObjectId
import json
from datetime import datetime, timedelta
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, jwt_required, JWTManager, get_jwt_identity,
    get_jwt, set_access_cookies, unset_jwt_cookies, verify_jwt_in_request
)

app = Flask(__name__)

# --- JWT 설정 ---
app.config["JWT_SECRET_KEY"] = "super-secret-key-for-dev"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  # 배포 시(https) True로 변경 권장
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # CSRF 보호 필요 시 True로 설정

jwt = JWTManager(app)

# --- Database 설정 ---
MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
MONGO_USER = os.environ.get('MONGO_USER')
MONGO_PASS = os.environ.get('MONGO_PASS')
try:
    client = MongoClient(f'mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:27017/')
    db = client.court_kok
    client.admin.command('ping')
    print("Successfully connected to MongoDB.")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    client = None
    db = None

# --- JWT 로그아웃 관리를 위한 블록리스트 ---
BLOCKLIST = set()


@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in BLOCKLIST


# ===============================================
# === HTML Page Rendering Routes ================
# ===============================================

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login')
def login_page():
    try:
        verify_jwt_in_request(optional=True)
        current_user = get_jwt_identity()
        if current_user:
            return redirect(url_for('home'))
    except Exception:  # 만료되거나 손상된 토큰은 무시
        pass
    return render_template('login.html')


@app.route('/signup')
def signup_page():
    try:
        verify_jwt_in_request(optional=True)
        current_user = get_jwt_identity()
        if current_user:
            return redirect(url_for('home'))
    except Exception:  # 만료되거나 손상된 토큰은 무시
        pass
    return render_template('signup.html')


@app.route('/my_registrations')
@jwt_required()
def my_registrations_page():
    current_user_id = get_jwt_identity()
    user_id_obj = ObjectId(current_user_id)

    created_events_cursor = db.events.find({"creator_id": user_id_obj}).sort("date", 1)
    created_events_list = []
    for event in created_events_cursor:
        participants_details = []
        for p_id in event.get('participants', []):
            user = db.users.find_one({"_id": p_id})
            if user:
                participants_details.append({
                    "name": user.get('name'), "id": user.get('id'), "phone": user.get('phone')
                })
        event['_id'] = str(event['_id'])
        event['participants_details'] = participants_details
        created_events_list.append(event)

    attended_events_cursor = db.events.find({
        "participants": user_id_obj, "creator_id": {"$ne": user_id_obj}
    }).sort("date", 1)
    attended_events_list = []
    for event in attended_events_cursor:
        creator = db.users.find_one({"_id": event['creator_id']})
        if creator:
            event['creator_details'] = {
                "name": creator.get('name'), "id": creator.get('id'), "phone": creator.get('phone')
            }
        event['_id'] = str(event['_id'])
        attended_events_list.append(event)

    return render_template(
        'my_registrations.html',
        created_events=created_events_list,
        attended_events=attended_events_list
    )


@app.route('/user_page')
@jwt_required()
def user_page():
    current_user_id = get_jwt_identity()
    user_data = db.users.find_one({"_id": ObjectId(current_user_id)})

    if not user_data:
        return "User not found!", 404

    return render_template('user_page.html', user=user_data)


# ===============================================
# ============ AUTH API Endpoints ===============
# ===============================================

@app.route('/api/signup', methods=['POST'])
def signup():
    if db is None: return jsonify({"status": "error", "message": "Database not connected"}), 500
    data = request.json
    name, username, password, email, phone = data.get('name'), data.get('id'), data.get('pw'), data.get(
        'email'), data.get('phone')

    if not all([name, username, password, email, phone]):
        return jsonify({"status": "error", "message": "모든 필드를 채워주세요."}), 400
    if db.users.find_one({"id": username}):
        return jsonify({"status": "error", "message": "사용자 ID가 이미 존재합니다."}), 409

    hashed_password = generate_password_hash(password)
    user_info = {"name": name, "id": username, "password": hashed_password, "email": email, "phone": phone}
    db.users.insert_one(user_info)
    return jsonify({"status": "success", "message": "회원가입이 완료되었습니다."}), 201


@app.route('/api/login', methods=['POST'])
def login():
    if db is None: return jsonify({"status": "error", "message": "Database not connected"}), 500
    data = request.json
    username, password = data.get('id'), data.get('pw')
    user = db.users.find_one({"id": username})
    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user['_id']))
        response = jsonify({"status": "success", "message": "로그인 성공"})
        set_access_cookies(response, access_token)
        return response, 200
    return jsonify({"status": "error", "message": "아이디 또는 비밀번호가 잘못되었습니다."}), 401


@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    BLOCKLIST.add(jti)
    response = jsonify({"status": "success", "message": "로그아웃 성공"})
    unset_jwt_cookies(response)
    return response, 200


@app.route('/api/user_info', methods=['GET'])
@jwt_required()
def get_user_info():
    current_user_id = get_jwt_identity()
    user = db.users.find_one({"_id": ObjectId(current_user_id)})
    if user:
        return jsonify({
            "status": "success", "userId": str(user['_id']), "userName": user['name'],
            "userPhone": user['phone'], "userIdName": user['id']
        }), 200
    return jsonify({"status": "error", "message": "사용자를 찾을 수 없습니다."}), 404


@app.route('/api/change_password', methods=['POST'])
@jwt_required()
def change_password():
    current_user_id = get_jwt_identity()
    user = db.users.find_one({"_id": ObjectId(current_user_id)})

    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not all([current_password, new_password, confirm_password]):
        return jsonify({"message": "모든 필드를 입력해주세요."}), 400
    if not check_password_hash(user['password'], current_password):
        return jsonify({"message": "현재 비밀번호가 일치하지 않습니다."}), 401
    if new_password != confirm_password:
        return jsonify({"message": "새 비밀번호가 일치하지 않습니다."}), 400
    if check_password_hash(user['password'], new_password):
        return jsonify({"message": "새 비밀번호는 현재 비밀번호와 달라야 합니다."}), 400

    new_hashed_password = generate_password_hash(new_password)
    db.users.update_one(
        {"_id": ObjectId(current_user_id)},
        {"$set": {"password": new_hashed_password}}
    )
    return jsonify({"message": "비밀번호가 성공적으로 변경되었습니다. 다시 로그인해주세요."}), 200


# ===============================================
# ======== EVENT/CALENDAR API Endpoints =========
# ===============================================

@app.route('/api/events', methods=['GET'])
@jwt_required()
def get_events():
    date_str = request.args.get('date')
    if not date_str:
        return jsonify({"status": "error", "message": "Date parameter is required"}), 400
    try:
        events_cursor = db.events.find({"date": date_str})
        events_list = []
        for event in events_cursor:
            creator_info = db.users.find_one({"_id": event['creator_id']}) or {}
            event_data = {
                "id": str(event['_id']), "time": event['time'], "duration": event['duration'],
                "min": event['min_participants'], "max": event['max_participants'],
                "current": len(event.get('participants', [])),
                "creator": {"id": creator_info.get('id', 'N/A'), "phone": creator_info.get('phone', 'N/A')}
            }
            events_list.append(event_data)
        return jsonify({"status": "success", "events": events_list}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/events', methods=['POST'])
@jwt_required()
def create_event():
    current_user_id = get_jwt_identity()
    user_id_obj = ObjectId(current_user_id)
    data = request.json

    date_str = data.get('date')
    time_str = data.get('time')
    duration = data.get('duration')
    min_participants = data.get('min_participants')
    max_participants = data.get('max_participants')

    if not all([date_str, time_str, duration, min_participants, max_participants]):
        return jsonify({"status": "error", "message": "All fields are required."}), 400

    new_event_start = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
    new_event_end = new_event_start + timedelta(minutes=int(duration))
    existing_events = db.events.find({"date": date_str})
    for event in existing_events:
        existing_start = datetime.strptime(f"{event['date']} {event['time']}", "%Y-%m-%d %H:%M")
        existing_end = existing_start + timedelta(minutes=int(event['duration']))
        if new_event_start < existing_end and new_event_end > existing_start:
            return jsonify({"status": "error", "message": "Time slot is already booked or overlaps."}), 409

    event_doc = {
        "date": date_str, "time": time_str, "duration": int(duration),
        "min_participants": int(min_participants), "max_participants": int(max_participants),
        "creator_id": user_id_obj, "participants": [user_id_obj],
        "created_at": datetime.utcnow()
    }
    db.events.insert_one(event_doc)
    return jsonify({"status": "success", "message": "Event created successfully."}), 201


@app.route('/api/events/<event_id>/signup', methods=['POST'])
@jwt_required()
def signup_for_event(event_id):
    current_user_id = get_jwt_identity()
    user_id_obj = ObjectId(current_user_id)
    try:
        event_id_obj = ObjectId(event_id)
    except:
        return jsonify({"status": "error", "message": "Invalid event ID format."}), 400

    event = db.events.find_one({"_id": event_id_obj})
    if not event:
        return jsonify({"status": "error", "message": "Event not found."}), 404
    if len(event.get('participants', [])) >= event['max_participants']:
        return jsonify({"status": "error", "message": "Event is already full."}), 409
    if user_id_obj in event.get('participants', []):
        return jsonify({"status": "error", "message": "You are already signed up for this event."}), 409

    db.events.update_one(
        {"_id": event_id_obj},
        {"$push": {"participants": user_id_obj}}
    )
    return jsonify({"status": "success", "message": "Successfully signed up for the event."}), 200


@app.route('/api/events/<event_id>/signup', methods=['DELETE'])
@jwt_required()
def cancel_event_signup(event_id):
    current_user_id = get_jwt_identity()
    user_id_obj = ObjectId(current_user_id)
    try:
        event_id_obj = ObjectId(event_id)
    except:
        return jsonify({"message": "Invalid event ID format."}), 400

    event = db.events.find_one({"_id": event_id_obj})
    if not event:
        return jsonify({"message": "Event not found."}), 404
    if event['creator_id'] == user_id_obj:
        return jsonify({"message": "You cannot cancel your own event. Please delete it instead."}), 403
    if user_id_obj not in event.get('participants', []):
        return jsonify({"message": "You are not signed up for this event."}), 400

    db.events.update_one(
        {"_id": event_id_obj},
        {"$pull": {"participants": user_id_obj}}
    )
    return jsonify({"message": "예약이 성공적으로 취소되었습니다."}), 200


@app.route('/api/events/<event_id>', methods=['DELETE'])
@jwt_required()
def delete_event(event_id):
    current_user_id = get_jwt_identity()
    user_id_obj = ObjectId(current_user_id)
    try:
        event_id_obj = ObjectId(event_id)
    except:
        return jsonify({"message": "Invalid event ID format."}), 400

    event = db.events.find_one({"_id": event_id_obj})
    if not event:
        return jsonify({"message": "Event not found."}), 404
    if event['creator_id'] != user_id_obj:
        return jsonify({"message": "You are not authorized to delete this event."}), 403

    db.events.delete_one({"_id": event_id_obj})
    return jsonify({"message": "모임이 성공적으로 삭제되었습니다."}), 200


# ===============================================
# ================ Main Run =====================
# ===============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)