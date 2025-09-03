import unittest
import requests
import threading
import time
from pymongo import MongoClient

# --- 💡 중요 설정: 자신의 환경에 맞게 수정하세요 ---
BASE_URL = "http://127.0.0.1:5001"
MONGO_URI = "mongodb://root:password@mongodb:27017/?authSource=admin"
DB_NAME = "court_kok"
NUM_USERS = 500
EVENT_MAX_PARTICIPANTS = 20
# --- 설정 끝 ---

# --- Helper Functions (클래스 외부에 정의) ---
def create_and_login_user(session, username):
    """테스트용 사용자를 생성하고 로그인하여 인증된 세션을 반환합니다."""
    signup_url = f"{BASE_URL}/api/signup"
    login_url = f"{BASE_URL}/api/login"
    user_payload = {"name": username, "id": username, "pw": "password123", "email": f"{username}@test.com", "phone": "01012345678"}
    try:
        session.post(signup_url, json=user_payload)
    except requests.exceptions.RequestException:
        pass # 이미 존재하면 무시
    login_payload = {"id": username, "pw": "password123"}
    response = session.post(login_url, json=login_payload)
    if response.status_code == 200:
        return session
    return None

def worker_signup(session, event_id, results_list, lock):
    """한 명의 사용자가 모임에 참가를 신청하는 스레드 워커 함수."""
    try:
        signup_url = f"{BASE_URL}/api/events/{event_id}/signup"
        response = session.post(signup_url)
        with lock:
            results_list.append(response.status_code)
    except requests.exceptions.RequestException as e:
        with lock:
            results_list.append(str(e))

# --- Test Case Class ---
class TestConcurrency(unittest.TestCase):

    # 클래스 변수: 테스트 전체에서 공유될 데이터
    db = None
    creator_user = None
    event_id = None
    authed_sessions = []
    results = []
    lock = threading.Lock()

    @classmethod
    def setUpClass(cls):
        """ 모든 테스트 시작 전 1회 실행: 테스트 환경 준비 """
        print("="*70)
        print("Setting up test environment (this may take a moment)...")

        client = MongoClient(MONGO_URI)
        cls.db = client[DB_NAME]

        # 1. 이전 테스트 데이터 정리
        print("  - Cleaning up previous test data...")
        cls.db.users.delete_many({"id": {"$regex": "^unittest_user_"}})
        creator = cls.db.users.find_one({"id": "unittest_creator"})
        if creator:
            cls.db.events.delete_many({"creator_id": creator['_id']})
            cls.db.users.delete_one({"id": "unittest_creator"})

        # 2. 모임 생성자 준비 및 로그인
        print("  - Preparing event creator...")
        creator_session = requests.Session()
        create_and_login_user(creator_session, "unittest_creator")
        cls.creator_user = cls.db.users.find_one({"id": "unittest_creator"})

        # 3. 테스트용 참가자 사용자 준비 (생성자와 분리)
        participant_sessions = []
        print(f"  - Preparing {NUM_USERS} concurrent users...")
        for i in range(NUM_USERS):
            session = requests.Session()
            authed_session = create_and_login_user(session, f"unittest_user_{i}")
            if authed_session:
                participant_sessions.append(authed_session)
        cls.authed_sessions = participant_sessions

        # 4. 모임 생성 (참가자는 생성자 1명으로 시작)
        print("  - Creating test event...")
        event_payload = {
            "date": "2025-11-11", "time": "11:00", "duration": 60,
            "min_participants": 2, "max_participants": EVENT_MAX_PARTICIPANTS
        }
        response = creator_session.post(f"{BASE_URL}/api/events", json=event_payload)
        if response.status_code != 201:
            raise Exception("Failed to create test event in setUpClass")

        created_event = cls.db.events.find_one({"creator_id": cls.creator_user['_id']}, sort=[("created_at", -1)])
        cls.event_id = created_event['_id']

        print(f"Setup complete. Event ID: {cls.event_id}, Creator: {cls.creator_user['id']}, Participants ready: {len(cls.authed_sessions)}")
        print("="*70)


    def test_signup_race_condition(self):
        """ 500명의 사용자가 동시에 참가를 신청하여 경쟁 상태(Race Condition)를 테스트합니다. """
        print(f"\nRunning test: Simulating {NUM_USERS} concurrent signups...")

        threads = []
        start_time = time.time()

        for session in self.__class__.authed_sessions:
            thread = threading.Thread(
                target=worker_signup,
                args=(session, self.__class__.event_id, self.__class__.results, self.__class__.lock)
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end_time = time.time()

        elapsed_time = end_time - start_time
        total_requests = len(self.__class__.results)
        success_count = self.__class__.results.count(200)
        tps = total_requests / elapsed_time if elapsed_time > 0 else 0

        print("\n--- Performance Results ---")
        print(f"  - Total time for {total_requests} concurrent requests: {elapsed_time:.4f} seconds.")
        print(f"  - Transactions Per Second (TPS): {tps:.2f} req/s")
        print("---------------------------")

        final_event_state = self.__class__.db.events.find_one({"_id": self.__class__.event_id})
        final_participants_count = len(final_event_state.get("participants", []))

        print(f"\n--- Verification Results ---")
        print(f"  - Max participants allowed: {EVENT_MAX_PARTICIPANTS}")
        print(f"  - Successful requests (200 OK): {success_count}")
        print(f"  - Final participant count in DB: {final_participants_count}")
        print("----------------------------")

        # 검증 1: 최종 참가자 수가 최대 정원을 절대 넘지 않아야 함
        self.assertLessEqual(
            final_participants_count,
            EVENT_MAX_PARTICIPANTS,
            msg=f"🔴 RACE CONDITION DETECTED: Final count ({final_participants_count}) exceeded max ({EVENT_MAX_PARTICIPANTS})!"
        )

        # 검증 2: (최대 정원 - 생성자 1명) 만큼만 신청에 성공해야 함
        expected_success_count = EVENT_MAX_PARTICIPANTS - 1
        self.assertEqual(
            success_count,
            expected_success_count,
            msg=f"🟡 DATA INCONSISTENCY: Expected {expected_success_count} successes, but got {success_count}."
        )

        # 검증 3: 최종 참가자 수는 정확히 최대 정원과 같아야 함
        self.assertEqual(
            final_participants_count,
            EVENT_MAX_PARTICIPANTS,
            msg=f"🟡 DATA INCONSISTENCY: Expected final count to be {EVENT_MAX_PARTICIPANTS}, but got {final_participants_count}."
        )


    @classmethod
    def tearDownClass(cls):
        """ 모든 테스트 종료 후 1회 실행: 테스트 데이터 정리 """
        print("\n" + "="*70)
        print("Tearing down test environment...")

        # 'if cls.db:' 대신 'is not None'으로 명확하게 비교해야 합니다.
        if cls.db is not None:
            # 테스트에 사용된 모든 가상 사용자 삭제
            cls.db.users.delete_many({"id": {"$regex": "^unittest_user_"}})

            # 모임 생성자 정보가 있을 경우, 해당 생성자가 만든 모임과 생성자 계정 삭제
            if cls.creator_user:
                cls.db.events.delete_many({"creator_id": cls.creator_user['_id']})
                cls.db.users.delete_one({"id": "unittest_creator"})

            print("  - Test data cleaned up.")

        print("="*70)

if __name__ == '__main__':
    unittest.main()