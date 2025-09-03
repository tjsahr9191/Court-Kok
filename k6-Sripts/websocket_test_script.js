import http from 'k6/http';
import ws from 'k6/ws';
import { check, group, sleep } from 'k6';
import { Counter } from 'k6/metrics';

// --- 설정 ---
const SERVER_URL = 'http://3.37.124.150:5001'; // EC2 서버의 Public IP
const USER_PREFIX = `testuser_${__ENV.K6_ENV || 'local'}`;
const USER_PASSWORD = 'password123';
const MAX_TEST_USERS = 50; // 테스트할 동시 접속자 수

// --- 메트릭 ---
const wsSuccess = new Counter('websocket_successful_connections');
const wsFail = new Counter('websocket_failed_connections');
const apiErrors = new Counter('api_errors');
const eventCreations = new Counter('event_creations');
const eventSignups = new Counter('event_signups');

// --- 시나리오 옵션 ---
export const options = {
    scenarios: {
        realistic_user_flow: {
            executor: 'constant-vus',
            vus: MAX_TEST_USERS,
            duration: '5m', // 5분 동안 테스트
        },
    },
};

// --- 1. 테스트 사용자 사전 생성 ---
export function setup() {
    console.log(`Setting up ${MAX_TEST_USERS} test users...`);
    for (let i = 1; i <= MAX_TEST_USERS; i++) {
        const signupPayload = JSON.stringify({
            name: `Test User ${i}`, id: `${USER_PREFIX}${i}`, pw: USER_PASSWORD,
            email: `${USER_PREFIX}${i}@test.com`, phone: '01000000000'
        });
        http.post(`${SERVER_URL}/api/signup`, signupPayload, { headers: { 'Content-Type': 'application/json' } });
    }
    console.log('User setup complete.');
}

// --- 2. 메인 테스트 로직 ---
export default function () {
    const vuId = __VU;
    const userCredentials = { id: `${USER_PREFIX}${vuId}`, pw: USER_PASSWORD };

    // 2-1. 로그인하여 세션 쿠키 획득
    const loginRes = http.post(`${SERVER_URL}/api/login`, JSON.stringify(userCredentials), {
        headers: { 'Content-Type': 'application/json' },
    });

    check(loginRes, { 'Login successful': (r) => r.status === 200 });
    if (loginRes.status !== 200) {
        apiErrors.add(1);
        return; // 로그인 실패 시 VU 종료
    }
    const accessTokenCookie = loginRes.cookies.access_token_cookie[0].value;

    // 2-2. 쿠키를 사용하여 웹소켓 연결 (세션 동안 유지)
    const wsUrl = `${SERVER_URL.replace('http', 'ws')}/ws`;
    const params = { headers: { 'Cookie': `access_token_cookie=${accessTokenCookie}`, 'Origin': SERVER_URL } };

    const res = ws.connect(wsUrl, params, function (socket) {
        socket.on('open', () => {
            wsSuccess.add(1);
            console.log(`VU ${vuId}: WebSocket connected.`);

            // 5~10초마다 랜덤한 행동을 하도록 설정
            socket.setInterval(() => {
                group('User Actions', function() {
                    // 행동 1: 특정 날짜의 일정 조회
                    const randomDate = new Date();
                    randomDate.setDate(randomDate.getDate() + Math.floor(Math.random() * 30));
                    const dateStr = randomDate.toISOString().split('T')[0];

                    const eventsRes = http.get(`${SERVER_URL}/api/events?date=${dateStr}`);
                    check(eventsRes, { 'Get events successful': (r) => r.status === 200 });

                    const events = eventsRes.json('events') || [];

                    const actionChance = Math.random();
                    if (actionChance < 0.15 && events.length > 0) {
                        // 15% 확률로 기존 이벤트에 참가 신청
                        const availableEvents = events.filter(e => e.current < e.max);
                        if (availableEvents.length > 0) {
                            const eventToSignup = availableEvents[Math.floor(Math.random() * availableEvents.length)];
                            const signupRes = http.post(`${SERVER_URL}/api/events/${eventToSignup.id}/signup`);
                            check(signupRes, { 'Signup successful': (r) => r.status === 200 || r.status === 409 });
                            if(signupRes.status === 200) eventSignups.add(1);
                        }
                    } else if (actionChance < 0.30) {
                        // 15% 확률로 새 이벤트 생성 (총 30%)
                        const createPayload = JSON.stringify({
                            date: dateStr, time: "14:00", duration: 120,
                            min_participants: 2, max_participants: 4
                        });
                        const createRes = http.post(`${SERVER_URL}/api/events`, createPayload, { headers: { 'Content-Type': 'application/json' } });
                        check(createRes, { 'Create event successful': (r) => r.status === 201 });
                        if(createRes.status === 201) eventCreations.add(1);
                    }
                    // 나머지 70%는 일정 조회만 함
                });
            }, 5000 + Math.random() * 5000); // 5-10초 간격
        });

        socket.on('message', (data) => {
            // 서버로부터 event_update 메시지를 받는지 확인
            console.log(`VU ${vuId}: Received broadcast: ${data}`);
        });

        socket.on('close', () => {
            console.log(`VU ${vuId}: WebSocket disconnected.`);
        });

        socket.on('error', (e) => {
            wsFail.add(1);
            console.error(`VU ${vuId}: WebSocket Error: ${e.error()}`);
        });

        // VU의 세션은 45~60초 동안 지속
        socket.setTimeout(() => {
            socket.close();
        }, 45000 + Math.random() * 15000);
    });

    check(res, { 'WebSocket handshake successful': (r) => r && r.status === 101 });
    if (!res || res.status !== 101) {
        wsFail.add(1);
    }
}