import os
from flask import Flask, render_template, jsonify, request, redirect, url_for
from prometheus_client import Gauge
from prometheus_flask_exporter import PrometheusMetrics
from pymongo import MongoClient, ReturnDocument
from bson.objectid import ObjectId
import json
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, jwt_required, JWTManager, get_jwt_identity,
    get_jwt, set_access_cookies, unset_jwt_cookies, verify_jwt_in_request
)
from flask_sock import Sock
import math

app = Flask(__name__)
metrics = PrometheusMetrics(app)
connected_clients_gauge = Gauge(
    'connected_clients',
    'Number of currently connected WebSocket clients'
)

# --- JWT 설정 (쿠키 기반) ---
app.config["JWT_SECRET_KEY"] = "super-secret-key-for-dev"  # TODO: prod에서는 환경변수 사용
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False          # prod: True (HTTPS)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False    # prod: True 권장
app.config["JWT_COOKIE_SAMESITE"] = "Lax"        # 기본값이지만 명시

jwt = JWTManager(app)

# --- WebSocket 설정 ---
sock = Sock(app)
# 접속 중인 클라이언트: {user_id(str): [ws1, ws2, ...]}
clients = {}

# --- Database 설정 ---
MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
MONGO_USER = os.environ.get('MONGO_USER', 'root')
MONGO_PASS = os.environ.get('MONGO_PASS', 'password')
try:
    client = MongoClient(
        f'mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:27017/',
        serverSelectionTimeoutMS=5000
    )
    db = client.court_kok
    client.admin.command('ping')
    print("Successfully connected to MongoDB.")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    client = None
    db = None

# --- JWT 블록리스트 (단일 프로세스용) ---
BLOCKLIST = set()


@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in BLOCKLIST


# --- Notification Helper ---
def create_notification(user_id, event, category):
    """Generates a notification for a user related to an event."""
    if db is None: return
    # Prevent duplicate reminders
    if category == 'reminder':
        if db.notifications.find_one({"user_id": user_id, "event_id": event['_id'], "category": "reminder"}):
            return

    notif = {
        "user_id": user_id,
        "event_id": event['_id'],
        "category": category, # 'cancellation', 'full', 'reminder'
        "event_details": { # Denormalize for performance
            "date": event['date'],
            "time": event['time'],
            "duration": event['duration'],
            "max_participants": event['max_participants']
        },
        "created_at": datetime.utcnow(),
        "is_read": False,
    }
    db.notifications.insert_one(notif)


def get_weekday_korean(date_obj):
    return "월화수목금토일"[date_obj.weekday()]


def format_notification_data(notif):
    """Formats a raw notification document for the frontend."""
    try:
        details = notif['event_details']
        dt_obj = datetime.strptime(f"{details['date']} {details['time']}", '%Y-%m-%d %H:%M')
        end_dt_obj = dt_obj + timedelta(minutes=details['duration'])

        # Format: {month.date(day) startinghour - endinghour}
        event_time_str = f"{dt_obj.month}.{dt_obj.day}({get_weekday_korean(dt_obj)}) {dt_obj.strftime('%H:%M')} - {end_dt_obj.strftime('%H:%M')}"
        # Format: {eventName}
        event_name_str = f"{dt_obj.month}.{dt_obj.day}({get_weekday_korean(dt_obj)}) {dt_obj.strftime('%H:%M')} 모임"

        data = {
            "_id": str(notif['_id']),
            "relative_time": humanize_time(notif['created_at'])
        }

        if notif['category'] == 'cancellation':
            data.update({
                "color": "red",
                "line1_prefix": event_time_str, "line1_suffix": "있던",
                "line2_prefix": event_name_str, "line2_suffix": "이(가) 취소되었습니다."
            })
        elif notif['category'] == 'full':
            data.update({
                "color": "blue",
                "line1_prefix": event_time_str, "line1_suffix": "있는",
                "line2_prefix": event_name_str, "line2_suffix": f"의 최대인원 {details['max_participants']}명이 모두 모였습니다!"
            })
        elif notif['category'] == 'reminder':
            data.update({
                "color": "green",
                "line1_prefix": event_time_str, "line1_suffix": "있는",
                "line2_prefix": event_name_str, "line2_suffix": "이(가) 하루 남았습니다!"
            })
        return data
    except (KeyError, ValueError, TypeError) as e:
        # If a notification is malformed, log the error and skip it
        print(f"Error formatting notification {notif.get('_id')}: {e}")
        return None

def humanize_time(dt):
    """Returns a human-friendly relative time string."""
    now = datetime.utcnow()
    diff = now - dt
    seconds = diff.total_seconds()

    if seconds < 60: return "방금 전"
    minutes = math.floor(seconds / 60)
    if minutes < 60: return f"{minutes}분 전"
    hours = math.floor(minutes / 60)
    if hours < 24: return f"{hours}시간 전"
    days = math.floor(hours / 24)
    if days < 7: return f"{days}일 전"
    weeks = math.floor(days / 7)
    if weeks < 5: return f"{weeks}주 전"
    return dt.strftime('%Y년 %m월 %d일')

# --- WebSocket Helper ---
def broadcast_event_update(event_date):
    """이벤트 변경사항을 모든 연결된 클라이언트에 브로드캐스트"""
    message = json.dumps({
        "type": "event_update",
        "date": event_date,
        "message": f"Schedule for {event_date} has been updated."
    })
    # 리스트 복사본으로 안전하게 순회
    for user_id, sockets in list(clients.items()):
        for ws in list(sockets):
            try:
                ws.send(message)
            except Exception as e:
                print(f"Failed to send broadcast to {user_id}: {e}")
                try:
                    sockets.remove(ws)
                except ValueError:
                    pass
        if not sockets:
            clients.pop(user_id, None)


def serialize_created_event(ev, users_coll):
    """내가 만든 모임 카드에 필요한 필드 직렬화"""
    participants_details = []
    for p_id in ev.get('participants', []):
        u = users_coll.find_one({"_id": p_id})
        if u:
            participants_details.append({
                "name": u.get('name'),
                "id": u.get('id'),
                "phone": u.get('phone')
            })
    return {
        "_id": str(ev["_id"]),
        "date": ev.get("date"),
        "time": ev.get("time"),
        "duration": ev.get("duration"),
        "participants": [str(x) for x in ev.get("participants", [])],
        "max_participants": ev.get("max_participants"),
        "participants_details": participants_details
    }


def serialize_attended_event(ev, users_coll):
    """내가 참여할 모임 카드에 필요한 필드 직렬화"""
    creator = users_coll.find_one({"_id": ev.get("creator_id")})
    creator_details = None
    if creator:
        creator_details = {
            "name": creator.get("name"),
            "id": creator.get("id"),
            "phone": creator.get("phone"),
        }
    return {
        "_id": str(ev["_id"]),
        "date": ev.get("date"),
        "time": ev.get("time"),
        "duration": ev.get("duration"),
        "participants": [str(x) for x in ev.get("participants", [])],
        "max_participants": ev.get("max_participants"),
        "creator_details": creator_details
    }


# --- JWT 인증 실패 시 처리 로직 ---
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    if request.path.startswith('/api/'):
        return jsonify(message="로그인이 필요합니다."), 401
    else:
        return redirect(url_for('login_page'))


# ===============================================
# === Page Rendering Routes (SSR) ===============
# ===============================================

@app.route('/')
@jwt_required()
def home():
    return render_template('index.html')


@app.route('/login')
def login_page():
    try:
        verify_jwt_in_request(optional=True)
        if get_jwt_identity():
            return redirect(url_for('home'))
    except Exception:
        pass
    return render_template('login.html')


@app.route('/signup')
def signup_page():
    try:
        verify_jwt_in_request(optional=True)
        if get_jwt_identity():
            return redirect(url_for('home'))
    except Exception:
        pass
    return render_template('signup.html')


@app.route('/my_registrations')
@jwt_required()
def my_registrations_page():
    if db is None:
        return "Database not connected", 500
    current_user_id = get_jwt_identity()
    user_id_obj = ObjectId(current_user_id)

    created_events_cursor = db.events.find({"creator_id": user_id_obj}).sort("date", 1)
    created_events_list = []
    for event in created_events_cursor:
        created_events_list.append(serialize_created_event(event, db.users))

    attended_events_cursor = db.events.find(
        {"participants": user_id_obj, "creator_id": {"$ne": user_id_obj}}
    ).sort("date", 1)
    attended_events_list = []
    for event in attended_events_cursor:
        attended_events_list.append(serialize_attended_event(event, db.users))

    return render_template('my_registrations.html',
                           created_events=created_events_list,
                           attended_events=attended_events_list)


@app.route('/user_page')
@jwt_required()
def user_page():
    if db is None:
        return "Database not connected", 500
    current_user_id = get_jwt_identity()
    user_data = db.users.find_one({"_id": ObjectId(current_user_id)})
    if not user_data:
        return "User not found!", 404
    return render_template('user_page.html', user=user_data)


@app.route('/notifications')
@jwt_required()
def notifications_page():
    if db is None:
        return "Database not connected", 500

    current_user_id = get_jwt_identity()
    user_id_obj = ObjectId(current_user_id)

    notifications_cursor = db.notifications.find({"user_id": user_id_obj}).sort("created_at", -1)

    # Filter out notifications that failed to format
    notifications_list = [
        formatted_notif for n in notifications_cursor
        if (formatted_notif := format_notification_data(n)) is not None
    ]

    return render_template('notifications.html', notifications=notifications_list)

# ===============================================
# ======== WebSocket Endpoint ===================
# ===============================================

@sock.route('/ws')
def websocket_api(ws):
    current_user_id = None
    try:
        # 핸드셰이크 시 쿠키 기반 JWT 검사
        verify_jwt_in_request(locations=["cookies"])
        current_user_id = get_jwt_identity()
    except Exception as e:
        print(f"[WS] Rejected: {type(e).__name__}: {e}")
        ws.close()
        return

    connected_clients_gauge.inc()
    clients.setdefault(current_user_id, []).append(ws)
    print(f"[WS] Connected: {current_user_id}. Total clients: {sum(len(v) for v in clients.values())}")

    try:
        while True:
            message = ws.receive()
            if message is None:
                break

            # --- 액션 처리 ---
            try:
                payload = json.loads(message)
            except Exception:
                continue

            action = payload.get("action")

            if action == "get_my_registrations" and db is not None:
                try:
                    user_id_obj = ObjectId(current_user_id)

                    # 내가 만든 모임
                    created_events_cursor = db.events.find({"creator_id": user_id_obj}).sort("date", 1)
                    created_events_list = [
                        serialize_created_event(ev, db.users) for ev in created_events_cursor
                    ]

                    # 내가 참여(주최자 제외)
                    attended_events_cursor = db.events.find({
                        "participants": user_id_obj,
                        "creator_id": {"$ne": user_id_obj}
                    }).sort("date", 1)
                    attended_events_list = [
                        serialize_attended_event(ev, db.users) for ev in attended_events_cursor
                    ]

                    outgoing = {
                        "type": "my_registrations_data",
                        "created_events": created_events_list,
                        "attended_events": attended_events_list,
                    }
                    ws.send(json.dumps(outgoing))
                except Exception as e:
                    print(f"[WS] get_my_registrations failed: {e}")
                    ws.send(json.dumps({"type": "error", "message": "Failed to load registrations"}))
            else:
                # 필요 시 다른 액션 추가
                pass

    except Exception as e:
        print(f"[WS] Closed for {current_user_id}: {e}")
    finally:
        # 연결 해제 정리
        sockets = clients.get(current_user_id, [])
        connected_clients_gauge.dec()
        try:
            if ws in sockets:
                sockets.remove(ws)
        except ValueError:
            pass
        if not sockets:
            clients.pop(current_user_id, None)
        print(f"[WS] Disconnected: {current_user_id}. Total clients: {sum(len(v) for v in clients.values())}")


# ===============================================
# ============ AUTH API Endpoints ===============
# ===============================================

@app.route('/api/signup', methods=['POST'])
def signup():
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    data = request.json or {}
    if db.users.find_one({"id": data.get('id')}):
        return jsonify({"message": "사용자 ID가 이미 존재합니다."}), 409
    hashed_password = generate_password_hash(data.get('pw'))
    user_info = {
        "name": data.get('name'),
        "id": data.get('id'),
        "password": hashed_password,
        "email": data.get('email'),
        "phone": data.get('phone')
    }
    db.users.insert_one(user_info)
    return jsonify({"message": "회원가입이 완료되었습니다."}), 201


@app.route('/api/login', methods=['POST'])
def login():
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    data = request.json or {}
    user = db.users.find_one({"id": data.get('id')})
    if user and check_password_hash(user['password'], data.get('pw')):
        access_token = create_access_token(identity=str(user['_id']))
        response = jsonify({
            "status": "success",
            "message": "로그인 성공",
            "access_token": access_token  # k6를 위한 access_token
        })
        set_access_cookies(response, access_token)
        return response, 200
    return jsonify({"message": "아이디 또는 비밀번호가 잘못되었습니다."}), 401


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
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    current_user_id = get_jwt_identity()
    user = db.users.find_one({"_id": ObjectId(current_user_id)})
    if user:
        unread_count = db.notifications.count_documents({
            "user_id": ObjectId(current_user_id),
            "is_read": False
        })
        return jsonify({
            "status": "success",
            "userName": user['name'],
            "notificationCount": unread_count
        }), 200
    return jsonify({"status": "error", "message": "사용자를 찾을 수 없습니다."}), 404


@app.route('/api/change_password', methods=['POST'])
@jwt_required()
def change_password():
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    current_user_id = get_jwt_identity()
    user = db.users.find_one({"_id": ObjectId(current_user_id)})
    data = request.json or {}
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    if not check_password_hash(user['password'], current_password):
        return jsonify({"message": "현재 비밀번호가 일치하지 않습니다."}), 401
    if check_password_hash(user['password'], new_password):
        return jsonify({"message": "새 비밀번호는 현재 비밀번호와 달라야 합니다."}), 400
    new_hashed_password = generate_password_hash(new_password)
    db.users.update_one(
        {"_id": ObjectId(current_user_id)},
        {"$set": {"password": new_hashed_password}}
    )
    return jsonify({"message": "비밀번호가 성공적으로 변경되었습니다. 다시 로그인해주세요."}), 200

# ===============================================
# ====== NOTIFICATION API Endpoints =============
# ===============================================

@app.route('/api/notifications/<notification_id>', methods=['DELETE'])
@jwt_required()
def delete_notification(notification_id):
    if db is None: return jsonify({"message": "Database not connected"}), 500

    user_id_obj = ObjectId(get_jwt_identity())
    notif_id_obj = ObjectId(notification_id)

    result = db.notifications.delete_one({
        "_id": notif_id_obj,
        "user_id": user_id_obj # Ensure user can only delete their own
    })

    if result.deleted_count == 1:
        return jsonify({"message": "알림이 삭제되었습니다."}), 200
    else:
        return jsonify({"message": "알림을 찾을 수 없거나 삭제할 권한이 없습니다."}), 404


@app.route('/api/notifications/mark_read', methods=['POST'])
@jwt_required()
def mark_notifications_as_read():
    if db is None: return jsonify({"message": "Database not connected"}), 500
    user_id_obj = ObjectId(get_jwt_identity())
    db.notifications.update_many(
        {"user_id": user_id_obj, "is_read": False},
        {"$set": {"is_read": True}}
    )
    return jsonify({"message": "모든 알림을 읽음으로 표시했습니다."}), 200

# ===============================================
# ======== EVENT API Endpoints ==================
# ===============================================

@app.route('/api/events', methods=['GET'])
@jwt_required()
def get_events():
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    date_str = request.args.get('date')
    events_cursor = db.events.find({"date": date_str})
    events_list = []
    for event in events_cursor:
        creator_info = db.users.find_one({"_id": event['creator_id']}) or {}
        event_data = {
            "id": str(event['_id']),
            "time": event['time'],
            "duration": event['duration'],
            "min": event['min_participants'],
            "max": event['max_participants'],
            "current": len(event.get('participants', [])),
            "creator": {
                "id": creator_info.get('id', 'N/A'),
                "phone": creator_info.get('phone', 'N/A')
            }
        }
        events_list.append(event_data)
    return jsonify({"status": "success", "events": events_list}), 200


@app.route('/api/events', methods=['POST'])
@jwt_required()
def create_event():
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    data = request.json or {}
    # TODO: 충돌/중복 방지 로직 추가 가능
    event_doc = {
        "date": data.get('date'),
        "time": data.get('time'),
        "duration": int(data.get('duration')),
        "min_participants": int(data.get('min_participants')),
        "max_participants": int(data.get('max_participants')),
        "creator_id": ObjectId(get_jwt_identity()),
        "participants": [ObjectId(get_jwt_identity())],
        "created_at": datetime.utcnow(),
        "reminder_sent": False
    }
    db.events.insert_one(event_doc)
    broadcast_event_update(data.get('date'))
    return jsonify({"message": "모임이 성공적으로 생성되었습니다."}), 201

# <============= 동시성 제어 X ================>
# @app.route('/api/events/<event_id>/signup', methods=['POST'])
# @jwt_required()
# def signup_for_event(event_id):
#     if db is None:
#         return jsonify({"status": "error", "message": "Database not connected"}), 500
#     event_id_obj = ObjectId(event_id)
#     user_id_obj = ObjectId(get_jwt_identity())
#     event = db.events.find_one({"_id": event_id_obj})
#
#     if not event:
#         return jsonify({"message": "Event not found."}), 404
#     if len(event.get('participants', [])) >= event['max_participants']:
#         return jsonify({"message": "인원이 가득 찼습니다."}), 409
#     if user_id_obj in event.get('participants', []):
#         return jsonify({"message": "이미 참여 중인 모임입니다."}), 409
#
#     db.events.update_one({"_id": event_id_obj}, {"$push": {"participants": user_id_obj}})
#     broadcast_event_update(event['date'])
#     return jsonify({"message": "참가 신청이 완료되었습니다."}), 200
# <============= 동시성 제어 X ================>

@app.route('/api/events/<event_id>/signup', methods=['POST'])
@jwt_required()
def signup_for_event_atomic(event_id):
    event_id_obj = ObjectId(event_id)
    user_id_obj = ObjectId(get_jwt_identity())

    updated_event = db.events.find_one_and_update(
        {
            "_id": event_id_obj,
            "participants": {"$ne": user_id_obj},
            "$expr": {"$lt": [{"$size": "$participants"}, "$max_participants"]}
        },
        {
            "$push": {"participants": user_id_obj}
        },
        return_document=ReturnDocument.AFTER
    )

    if updated_event:
        broadcast_event_update(updated_event['date'])
        return jsonify({"message": "참가 신청이 완료되었습니다."}), 200
    else:
        return jsonify({"message": "인원이 가득 찼거나 이미 참여 중인 모임입니다."}), 409


@app.route('/api/events/<event_id>/signup', methods=['DELETE'])
@jwt_required()
def cancel_event_signup(event_id):
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    event_id_obj = ObjectId(event_id)
    user_id_obj = ObjectId(get_jwt_identity())
    event = db.events.find_one({"_id": event_id_obj})

    if not event:
        return jsonify({"message": "Event not found."}), 404
    if event['creator_id'] == user_id_obj:
        return jsonify({"message": "주최자는 예약을 취소할 수 없습니다. 모임을 삭제해주세요."}), 403
    if user_id_obj not in event.get('participants', []):
        return jsonify({"message": "참여 중인 모임이 아닙니다."}), 400

    db.events.update_one({"_id": event_id_obj}, {"$pull": {"participants": user_id_obj}})
    broadcast_event_update(event['date'])
    return jsonify({"message": "예약이 성공적으로 취소되었습니다."}), 200


@app.route('/api/events/<event_id>', methods=['DELETE'])
@jwt_required()
def delete_event(event_id):
    if db is None:
        return jsonify({"status": "error", "message": "Database not connected"}), 500
    event_id_obj = ObjectId(event_id)
    user_id_obj = ObjectId(get_jwt_identity())
    event = db.events.find_one({"_id": event_id_obj})

    if not event:
        return jsonify({"message": "Event not found."}), 404
    if event['creator_id'] != user_id_obj:
        return jsonify({"message": "모임을 삭제할 권한이 없습니다."}), 403

    # Send cancellation notifications to participants
    participants = event.get('participants', [])
    for p_id in participants:
        if p_id != user_id_obj: # Don't notify the creator
            create_notification(p_id, event, 'cancellation')

    db.events.delete_one({"_id": event_id_obj})
    broadcast_event_update(event['date'])
    return jsonify({"message": "모임이 성공적으로 삭제되었습니다."}), 200


# ===============================================
# ===== Background Task (Requires Scheduler) ====
# ===============================================

def send_event_reminders():
    """
    Finds events starting in the next 24 hours and sends reminders.
    !!! IMPORTANT !!!
    This function should be run periodically by a background task scheduler
    (e.g., a cron job running a script, APScheduler, Celery).
    For example, run this every hour.
    """
    if db is None:
        print("[Scheduler] Database not connected. Skipping reminders.")
        return

    now = datetime.now(timezone.utc)
    # KST is UTC+9. We need to parse DB dates as KST then compare to now.
    # A simpler approach for local time is to use server's local time if it's set to KST.
    # For this example, we'll use a naive datetime approach assuming server runs in KST.

    now_local = datetime.now()
    tomorrow_local = now_local + timedelta(days=1)

    query = {
        "reminder_sent": {"$ne": True},
    }

    events_to_remind = []
    for event in db.events.find(query):
        try:
            event_dt = datetime.strptime(f"{event['date']} {event['time']}", '%Y-%m-%d %H:%M')
            if now_local <= event_dt < tomorrow_local:
                events_to_remind.append(event)
        except (ValueError, KeyError):
            continue

    if not events_to_remind:
        print(f"[{datetime.now()}] No event reminders to send.")
        return

    for event in events_to_remind:
        print(f"Sending reminders for event: {event['_id']}")
        for p_id in event.get('participants', []):
            create_notification(p_id, event, 'reminder')

        db.events.update_one(
            {"_id": event['_id']},
            {"$set": {"reminder_sent": True}}
        )
    print(f"[{datetime.now()}] Sent reminders for {len(events_to_remind)} events.")


# ===============================================
# ================ Main Run =====================
# ===============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)