import os
from flask import Flask, render_template, jsonify, request
from pymongo import MongoClient
from bson.objectid import ObjectId
import json
from datetime import datetime, timedelta
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity, get_jwt, decode_token

from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Gauge
import time # time 모듈을 별도로 import 합니다.

from flask_sock import Sock

app = Flask(__name__)

# --- 프로메테우스 설정 ---
metrics = PrometheusMetrics(app)
connected_clients_gauge = Gauge('connected_clients', 'Number of currently connected WebSocket clients')

# --- JWT 설정 ---
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

# --- Database 설정 ---
MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
MONGO_USER = os.environ.get('MONGO_USER', 'root')
MONGO_PASS = os.environ.get('MONGO_PASS', 'password')

def connect_to_mongodb():
    try:
        client = MongoClient(f'mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:27017/',
                             serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("Successfully connected to MongoDB.")
        return client
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}.")
# def connect_to_mongodb():
#     try:
#         # Docker 외부에서 실행하므로 'mongodb' 대신 'localhost'를 사용합니다.
#         client = MongoClient(f'mongodb://root:password@localhost:27017/',
#                              serverSelectionTimeoutMS=5000)
#         client.admin.command('ping')
#         print("Successfully connected to MongoDB.")
#         return client
#     except Exception as e:
#         print(f"Failed to connect to MongoDB: {e}.")

client = connect_to_mongodb()
db = client.court_kok if client else None

# --- JWT 로그아웃 관리를 위한 블록리스트 ---
BLOCKLIST = set()

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in BLOCKLIST

# WebSocket 설정
sock = Sock(app)
clients = {} # {user_id: [websocket_instance, ...]}

def broadcast_event_update(event_id, message_type="event_update"):
    """특정 이벤트와 관련된 모든 클라이언트에게 변경 사항을 전송합니다."""
    # 모든 클라이언트에게 변경사항을 전파하여 UI를 업데이트하도록 함
    for user_id, user_clients in list(clients.items()):
        for ws in user_clients:
            try:
                ws.send(json.dumps({
                    "type": message_type,
                    "eventId": event_id,
                    "message": "Event updated"
                }))
            except Exception as e:
                print(f"Failed to send to client: {e}")
                user_clients.remove(ws)

# ===============================================
# === HTML Page Rendering Routes ================
# ===============================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/my_registrations')
@jwt_required()
def my_registrations_page():
    """
    my_registrations 페이지를 렌더링하고, 데이터는 웹소켓으로 받습니다.
    """
    return render_template('my_registrations.html')

@app.route('/user_page')
@jwt_required()
def user_page():
    # We will implement this page later
    return "<h1>User Page (To be implemented)</h1>"

# ===============================================
# ============ AUTH API Endpoints ===============
# ===============================================

@app.route('/api/signup', methods=['POST'])
def signup():
    if db is None: return jsonify({"status": "error", "message": "Database not connected"}), 500
    data = request.json
    name, username, password, email, phone = data.get('name'), data.get('id'), data.get('pw'), data.get('email'), data.get('phone')

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
        return jsonify(access_token=access_token), 200
    return jsonify({"status": "error", "message": "아이디 또는 비밀번호가 잘못되었습니다."}), 401

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    BLOCKLIST.add(jti)
    return jsonify({"status": "success", "message": "로그아웃 성공"}), 200

# ===============================================
# ========= WEBSOCKET API Endpoints =============
# ===============================================

@sock.route('/ws')
def websocket_api(ws):
    # JWT 토큰을 쿼리 파라미터에서 가져옴
    token = request.args.get('token')
    if not token:
        ws.close()
        return

    # 데이터베이스 연결 상태 확인
    if db is None:
        print("Database not connected, cannot handle WebSocket request.")
        ws.close()
        return

    try:
        # JWT 토큰 디코딩 및 검증
        decoded_token = decode_token(token)
        current_user_id = decoded_token['sub']
        user_id_obj = ObjectId(current_user_id)
    except Exception as e:
        print(f"Token validation failed: {e}")
        ws.close()
        return

    # 이후 로직은 기존과 동일
    if current_user_id not in clients:
        clients[current_user_id] = []
    clients[current_user_id].append(ws)

    try:
        # 연결 직후 사용자 정보 전송
        user = db.users.find_one({"_id": user_id_obj})
        if user:
            user_info = {
                "type": "user_info",
                "userId": str(user['_id']),
                "userName": user['name'],
                "userPhone": user['phone'],
                "userIdName": user['id']
            }
            ws.send(json.dumps(user_info))

        while True:
            try:
                message = ws.receive()
                if message is None:
                    continue

                data = json.loads(message)
                action = data.get('action')

                if action == 'get_events':
                    date_str = data.get('date')
                    if not date_str:
                        ws.send(json.dumps({"type": "error", "message": "Date parameter is required"}))
                        continue
                    try:
                        events_cursor = db.events.find({"date": date_str})
                        events_list = []
                        for event in events_cursor:
                            creator_info = db.users.find_one({"_id": event['creator_id']})
                            event_data = {
                                "id": str(event['_id']),
                                "time": event['time'],
                                "duration": event['duration'],
                                "min": event['min_participants'],
                                "max": event['max_participants'],
                                "current": len(event['participants']),
                                "creator": {
                                    "id": creator_info.get('id', 'N/A'),
                                    "phone": creator_info.get('phone', 'N/A')
                                }
                            }
                            events_list.append(event_data)
                        ws.send(json.dumps({"type": "events_list", "events": events_list}))
                    except Exception as e:
                        ws.send(json.dumps({"type": "error", "message": str(e)}))

                elif action == 'create_event':
                    date_str = data.get('date')
                    time_str = data.get('time')
                    duration = data.get('duration')
                    min_participants = data.get('min_participants')
                    max_participants = data.get('max_participants')

                    if not all([date_str, time_str, duration, min_participants, max_participants]):
                        ws.send(json.dumps({"type": "error", "message": "모든 필드를 채워주세요."}))
                        continue

                    new_event_start = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
                    new_event_end = new_event_start + timedelta(minutes=duration)

                    existing_events = db.events.find({"date": date_str})
                    is_overlap = False
                    for event in existing_events:
                        existing_start = datetime.strptime(f"{event['date']} {event['time']}", "%Y-%m-%d %H:%M")
                        existing_end = existing_start + timedelta(minutes=event['duration'])
                        if new_event_start < existing_end and new_event_end > existing_start:
                            is_overlap = True
                            break
                    if is_overlap:
                        ws.send(json.dumps({"type": "error", "message": "시간대가 이미 예약되었거나 다른 이벤트와 겹칩니다."}))
                        continue

                    event_doc = {
                        "date": date_str,
                        "time": time_str,
                        "duration": duration,
                        "min_participants": min_participants,
                        "max_participants": max_participants,
                        "creator_id": user_id_obj,
                        "participants": [user_id_obj],
                        "created_at": datetime.utcnow()
                    }
                    result = db.events.insert_one(event_doc)
                    ws.send(json.dumps({"type": "success", "message": "이벤트가 성공적으로 생성되었습니다."}))
                    broadcast_event_update(str(result.inserted_id))

                elif action == 'signup_for_event':
                    event_id = data.get('eventId')
                    try:
                        event_id_obj = ObjectId(event_id)
                    except:
                        ws.send(json.dumps({"type": "error", "message": "유효하지 않은 이벤트 ID입니다."}))
                        continue

                    event = db.events.find_one({"_id": event_id_obj})
                    if not event:
                        ws.send(json.dumps({"type": "error", "message": "이벤트를 찾을 수 없습니다."}))
                        continue

                    if len(event['participants']) >= event['max_participants']:
                        ws.send(json.dumps({"type": "error", "message": "이벤트가 이미 가득 찼습니다."}))
                        continue
                    if user_id_obj in event['participants']:
                        ws.send(json.dumps({"type": "error", "message": "이미 이 이벤트에 참여 중입니다."}))
                        continue

                    db.events.update_one(
                        {"_id": event_id_obj},
                        {"$push": {"participants": user_id_obj}}
                    )
                    ws.send(json.dumps({"type": "success", "message": "이벤트에 성공적으로 참여했습니다."}))
                    broadcast_event_update(event_id)

                elif action == 'get_my_registrations':
                    # '내 등록' 페이지 로드 시 호출
                    created_events_cursor = db.events.find({"creator_id": user_id_obj}).sort("date", 1)
                    created_events_list = []
                    for event in created_events_cursor:
                        participants_details = []
                        for p_id in event.get('participants', []):
                            user = db.users.find_one({"_id": p_id})
                            if user:
                                participants_details.append({
                                    "name": user.get('name'),
                                    "id": user.get('id'),
                                    "phone": user.get('phone')
                                })
                        event['_id'] = str(event['_id'])
                        event['creator_id'] = str(event['creator_id'])
                        event['participants'] = [str(p_id) for p_id in event['participants']]
                        event['participants_details'] = participants_details
                        created_events_list.append(event)

                    attended_events_cursor = db.events.find({
                        "participants": user_id_obj,
                        "creator_id": {"$ne": user_id_obj}
                    }).sort("date", 1)
                    attended_events_list = []
                    for event in attended_events_cursor:
                        creator = db.users.find_one({"_id": event['creator_id']})
                        if creator:
                            event['creator_details'] = {
                                "name": creator.get('name'),
                                "id": creator.get('id'),
                                "phone": creator.get('phone')
                            }
                        event['_id'] = str(event['_id'])
                        event['creator_id'] = str(event['creator_id'])
                        event['participants'] = [str(p_id) for p_id in event['participants']]
                        attended_events_list.append(event)

                    ws.send(json.dumps({
                        "type": "my_registrations_data",
                        "created_events": created_events_list,
                        "attended_events": attended_events_list
                    }))

            except Exception as e:
                print(f"Error processing WebSocket message: {e}")
                # 메시지 처리 중 오류가 발생하면 연결을 종료합니다.
                ws.close()
                break

    except Exception as e:
        print(f"WebSocket Loop Error for user {current_user_id}: {e}")
    finally:
        if current_user_id in clients and ws in clients[current_user_id]:
            clients[current_user_id].remove(ws)
            if not clients[current_user_id]:
                del clients[current_user_id]
        print(f"Connection closed for user {current_user_id}. Active users: {len(clients)}")

# ===============================================
# ===============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    # debug=True는 개발용이며, 웹소켓과 함께 사용할 때 문제가 될 수 있습니다.
    # production 환경에서는 False로 설정하세요.
    app.run(host='0.0.0.0', port=port, debug=True)