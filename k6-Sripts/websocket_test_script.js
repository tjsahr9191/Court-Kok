import ws from 'k6/ws';
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter } from 'k6/metrics';

// ====================================================================================
// 테스트 설정 (여기를 수정하여 테스트 환경을 구성하세요)
// ====================================================================================

// 테스트할 서버의 주소
// const SERVER_URL = 'http://3.37.124.150:5001';
const SERVER_URL = 'http://localhost:5001';
// 테스트에 사용할 사용자 계정 접두사
const USER_PREFIX = `testuser_${__ENV.K6_ENV || 'local'}`;
// 테스트할 최대 사용자 수 (options의 max VUs와 맞추는 것이 좋습니다)
const MAX_TEST_USERS = 6000;
// 기본 비밀번호
const USER_PASSWORD = 'password123';

// ====================================================================================
// 사용자 정의 메트릭
// ====================================================================================
const wsSuccess = new Counter('websocket_successful_connections');
const wsFail = new Counter('websocket_failed_connections');
const eventCreationSuccess = new Counter('event_creation_success');
const eventSignupSuccess = new Counter('event_signup_success');
const apiErrors = new Counter('api_errors');

// ====================================================================================
// 부하 테스트 시나리오 옵션
// ====================================================================================
export const options = {
    // 10분 동안 가상 사용자(VU)를 6000명까지 점진적으로 늘리고,
    // 3분 30초 동안 유지한 뒤, 30초에 걸쳐 종료합니다.
    // 참고: 6000 VUs는 매우 높은 부하입니다. 서버 사양에 맞춰 조절하세요.
    stages: [
        { duration: '10m', target: 6000 }, // Ramp-up
    ]
};

// ====================================================================================
// 테스트 준비 단계 (모든 VU 시작 전 1회 실행)
// ====================================================================================
export function setup() {
    console.log(`Setting up ${MAX_TEST_USERS} test users...`);
    // 테스트에 필요한 사용자 계정을 미리 생성합니다.
    for (let i = 1; i <= MAX_TEST_USERS; i++) {
        const signupPayload = JSON.stringify({
            name: `Test User ${i}`,
            id: `${USER_PREFIX}${i}`,
            pw: USER_PASSWORD,
            email: `${USER_PREFIX}${i}@test.com`,
            phone: '01000000000'
        });
        const res = http.post(`${SERVER_URL}/api/signup`, signupPayload, {
            headers: { 'Content-Type': 'application/json' },
            // 태그를 사용하여 나중에 결과를 필터링하기 용이하게 만듭니다.
            tags: { name: 'Signup' }
        });
        // 100명마다 로그 출력
        if (i % 100 === 0) {
            console.log(`Created user ${i}/${MAX_TEST_USERS}. Status: ${res.status}`);
        }
    }
    console.log('User setup complete.');
}


// ====================================================================================
// 각 가상 사용자(VU)가 실행할 메인 함수
// ====================================================================================
export default function () {
    // 각 VU는 고유한 ID를 가집니다. (__VU는 k6에서 제공하는 고유 ID)
    const vuId = __VU;
    const userCredentials = {
        id: `${USER_PREFIX}${vuId}`,
        pw: USER_PASSWORD
    };

    // 1. HTTP를 통해 로그인하고 JWT 토큰 받기
    let accessToken;
    group('User Authentication', function () {
        const loginPayload = JSON.stringify(userCredentials);
        const res = http.post(`${SERVER_URL}/api/login`, loginPayload, {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'Login' }
        });

        check(res, {
            'Login successful (status 200)': (r) => r.status === 200,
            'Access token received': (r) => r.json('access_token') !== undefined,
        });

        if (res.status !== 200) {
            apiErrors.add(1);
            console.error(`VU ${vuId}: Login failed! Status: ${res.status}, Body: ${res.body}`);
            // 로그인 실패 시, 이 VU는 이번 이터레이션을 종료합니다.
            return;
        }
        accessToken = res.json('access_token');
    });

    if (!accessToken) {
        // 토큰이 없으면 웹소켓 연결을 시도하지 않습니다.
        return;
    }

    // 2. 웹소켓 연결 및 사용자 시나리오 수행
    const wsUrl = `${SERVER_URL.replace('http', 'ws')}/ws?token=${accessToken}`;

    group('WebSocket Interaction', function () {
        const res = ws.connect(wsUrl, {}, function (socket) {
            socket.on('open', () => {
                wsSuccess.add(1);
                // console.log(`VU ${vuId}: WebSocket connection established.`);

                // 오늘로부터 30일 이내의 랜덤한 날짜 선택
                const randomDate = new Date();
                randomDate.setDate(randomDate.getDate() + Math.floor(Math.random() * 30));
                const dateStr = randomDate.toISOString().split('T')[0];

                // 연결 직후, 선택된 날짜의 이벤트 목록 요청
                socket.send(JSON.stringify({
                    action: 'get_events',
                    date: dateStr
                }));
            });

            socket.on('message', (message) => {
                const data = JSON.parse(message);

                if (data.type === 'events_list') {
                    const events = data.events;
                    const date = data.date; // 서버에서 받은 날짜 사용

                    // 20% 확률로 새 이벤트 생성, 80% 확률로 기존 이벤트 참여 시도
                    if (Math.random() < 0.2) { // Create a new event
                        socket.send(JSON.stringify({
                            action: 'create_event',
                            date: date,
                            time: `${Math.floor(Math.random() * 10) + 9}:00`, // 09:00 ~ 18:00
                            duration: (Math.random() < 0.5 ? 60 : 120), // 60분 또는 120분
                            min_participants: 2,
                            max_participants: 4
                        }));
                    } else if (events && events.length > 0) { // Sign up for an existing event
                        const randomEvent = events[Math.floor(Math.random() * events.length)];
                        // 참여 가능한 이벤트인지 확인 (선택 사항)
                        if (randomEvent.current < randomEvent.max) {
                            socket.send(JSON.stringify({
                                action: 'signup_for_event',
                                eventId: randomEvent.id
                            }));
                        }
                    }
                } else if (data.type === 'success') {
                    if (data.message.includes('성공적으로 생성')) {
                        eventCreationSuccess.add(1);
                    } else if (data.message.includes('성공적으로 참여')) {
                        eventSignupSuccess.add(1);
                    }
                } else if (data.type === 'error') {
                    // console.error(`VU ${vuId}: Received error from server: ${data.message}`);
                    apiErrors.add(1);
                }
            });

            socket.on('close', () => {
                // console.log(`VU ${vuId}: WebSocket connection closed.`);
            });

            socket.on('error', (e) => {
                wsFail.add(1);
                console.error(`VU ${vuId}: WebSocket Error: ${e.error()}`);
            });

            // 15~30초 사이의 랜덤한 시간 동안 연결 유지 후 종료
            socket.setTimeout(() => {
                socket.close();
            }, 15000 + Math.random() * 15000);
        });

        check(res, {
            'WebSocket connection successful (status 101)': (r) => r && r.status === 101
        });
        if (!res || res.status !== 101) {
            wsFail.add(1);
        }
    });

    // 한 시나리오가 끝난 후 1~3초간 대기
    sleep(1 + Math.random() * 2);
}

// ====================================================================================
// 테스트 종료 단계 (모든 VU 종료 후 1회 실행)
// ====================================================================================
/*
// 참고: k6 자체는 외부 DB에 직접 접근할 수 없습니다.
// 테스트 데이터를 정리하려면, 별도의 API 엔드포인트를 만들거나 외부 스크립트를 사용해야 합니다.
export function teardown(data) {
    console.log('Tearing down test data...');
    // 예시: 삭제 API가 있다면 아래와 같이 호출할 수 있습니다.
    // for (let i = 1; i <= MAX_TEST_USERS; i++) {
    //     http.del(`${SERVER_URL}/api/test_users/${USER_PREFIX}${i}`);
    // }
    console.log('Teardown complete.');
}
*/