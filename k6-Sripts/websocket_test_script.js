import http from 'k6/http';
import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

// ====================================================================================
// --- 설정 ---
// ====================================================================================
const SERVER_URL = 'http://3.37.124.150:5001';
const USER_PREFIX = `testuser_${__ENV.K6_ENV || 'local'}`;
const USER_PASSWORD = 'password123';

// 중요: options의 target과 이 값을 일치시켜야 합니다.
const MAX_TEST_USERS = 5000;
// 테스트 시간 (예: 10분)
const RAMP_UP_DURATION = '10m';

// ====================================================================================
// --- 메트릭 ---
// ====================================================================================
const wsSuccess = new Counter('websocket_successful_connections');
const wsFail = new Counter('websocket_failed_connections');
const apiErrors = new Counter('api_errors');

// ====================================================================================
// --- 테스트 시나리오 옵션 ---
// ====================================================================================
export const options = {
    // setup 함수의 최대 실행 시간을 15분으로 늘려줍니다.
    setupTimeout: '15m', // <--- 이 라인을 추가하세요.

    scenarios: {
        breakpoint_test: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: RAMP_UP_DURATION, target: MAX_TEST_USERS },
            ],
            gracefulRampDown: '30s',
        },
    },
};

// ====================================================================================
// --- 1. 테스트 준비 단계 (Setup) ---
// ====================================================================================
export function setup() {
    console.log(`Setting up ${MAX_TEST_USERS} test users for breakpoint test...`);
    // 모든 사용자를 미리 생성해 둡니다.
    for (let i = 1; i <= MAX_TEST_USERS; i++) {
        const signupPayload = JSON.stringify({
            name: `Test User ${i}`, id: `${USER_PREFIX}${i}`, pw: USER_PASSWORD,
            email: `${USER_PREFIX}${i}@test.com`, phone: '01000000000'
        });
        http.post(`${SERVER_URL}/api/signup`, signupPayload, { headers: { 'Content-Type': 'application/json' } });
    }
    console.log('User setup complete.');
}

// ====================================================================================
// --- 2. 메인 테스트 로직 (Default Function) ---
// ====================================================================================
export default async function () {
    const vuId = __VU;
    const userCredentials = { id: `${USER_PREFIX}${vuId}`, pw: USER_PASSWORD };

    // 2-1. 로그인
    const loginRes = http.post(`${SERVER_URL}/api/login`, JSON.stringify(userCredentials), {
        headers: { 'Content-Type': 'application/json' },
    });

    if (loginRes.status !== 200) {
        apiErrors.add(1);
        return;
    }
    const accessToken = loginRes.json('access_token');

    // 2-2. 웹소켓 연결 후 테스트가 끝날 때까지 유지
    const wsUrl = `${SERVER_URL.replace('http', 'ws')}/ws`;
    const params = { headers: { 'Authorization': `Bearer ${accessToken}`, 'Origin': SERVER_URL } };

    await new Promise((resolve, reject) => {
        const res = ws.connect(wsUrl, params, function (socket) {
            socket.on('open', () => {
                wsSuccess.add(1);
            });

            socket.on('close', () => {
                resolve();
            });

            socket.on('error', (e) => {
                wsFail.add(1);
                console.error(`VU ${vuId}: WebSocket Error: ${e.error()}`);
                reject(e);
            });

            // 테스트 시간(10분)보다 약간 짧은 시간(9분 30초) 동안 연결을 유지하도록 설정
            // 이렇게 하면 대부분의 VU가 테스트 내내 연결을 유지하게 됩니다.
            socket.setTimeout(() => {
                socket.close();
            }, 570000); // 9분 30초 = 570,000ms
        });

        if (!res || res.status !== 101) {
            wsFail.add(1);
            reject('WebSocket handshake failed');
        }
    });
}