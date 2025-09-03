import ws from 'k6/ws';
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

// 접속할 서버 주소 (k6 옵션으로 환경 변수처럼 사용 가능)
const SERVER_URL = 'http://3.37.124.150:5001';
// const SERVER_URL = 'http://localhost:5001';

// 웹소켓 연결 성공/실패 횟수 카운터
const wsSuccess = new Counter('websocket_success');
const wsFail = new Counter('websocket_fail');

// 부하 테스트 시나리오
export const options = {
    // 5초에 100명까지 VUs(가상 사용자)를 늘리고, 10분간 유지 후 서서히 감소
    stages: [
        { duration: '10m', target: 6000 },
        { duration: '30s', target: 50 },
        { duration: '3m', target: 50 },
        { duration: '30s', target: 0 },
    ],
    // 모든 VUs에 대해 한 번만 실행되는 설정
    ext: {
        loadimpact: {
            // 이메일, 비밀번호 등 사용자 정보
            staticData: {
                users: [
                    { id: 'user1', pw: 'pw1' },
                    { id: 'user2', pw: 'pw2' },
                    { id: 'user3', pw: 'pw3' },
                    // 더 많은 사용자 추가 가능
                ]
            }
        }
    }
};

// VUs 실행 전에 한 번만 실행되는 함수: JWT 토큰 발급
export function setup() {
    const loginPayload = JSON.stringify({
        id: 'testuser',
        pw: 'testpassword'
    });

    // 유저가 없다면 회원가입 먼저 시도
    http.post(`${SERVER_URL}/api/signup`, JSON.stringify({
        name: 'Test User',
        id: 'testuser',
        pw: 'testpassword',
        email: 'test@test.com',
        phone: '01012345678'
    }), {
        headers: { 'Content-Type': 'application/json' }
    });

    const res = http.post(`${SERVER_URL}/api/login`, loginPayload, {
        headers: { 'Content-Type': 'application/json' }
    });

    check(res, {
        'Login successful': (r) => r.status === 200,
        'Access token received': (r) => r.json().access_token !== undefined,
    });

    // JWT 토큰 반환
    return { token: res.json().access_token };
}

// 각 가상 사용자(VU)가 실행할 메인 함수
export default function (data) {
    const wsUrl = `${SERVER_URL.replace('http', 'ws')}/ws?token=${data.token}`;

    // 30초 동안 웹소켓 연결 유지
    const res = ws.connect(wsUrl, null, function (socket) {
        let events = [];
        let eventIdToSignup = null;

        socket.on('open', () => {
            wsSuccess.add(1);
            console.log('Successfully connected to WebSocket');

            // 1. 이벤트 목록 요청
            socket.send(JSON.stringify({
                action: 'get_events',
                date: '2025-01-01' // 적절한 날짜로 수정
            }));

            // 2. 10초마다 이벤트 참여 시도 (실제 상황 시뮬레이션)
            socket.setInterval(() => {
                if (eventIdToSignup) {
                    socket.send(JSON.stringify({
                        action: 'signup_for_event',
                        eventId: eventIdToSignup
                    }));
                }
            }, 10000);
        });

        socket.on('message', (message) => {
            const data = JSON.parse(message);

            // 2-1. 이벤트 목록 수신
            if (data.type === 'events_list') {
                events = data.events;
                if (events.length > 0) {
                    // 무작위 이벤트 선택하여 참여 준비
                    eventIdToSignup = events[Math.floor(Math.random() * events.length)].id;
                    console.log(`Will attempt to sign up for event: ${eventIdToSignup}`);
                }
            }

            // 3. 이벤트 참여 결과 수신
            if (data.type === 'success' && data.message.includes('성공적으로 참여')) {
                console.log('Successfully signed up for an event!');
                // 참여 후 내 등록 목록 조회
                socket.send(JSON.stringify({
                    action: 'get_my_registrations'
                }));
            }

            // 4. 내 등록 목록 수신
            if (data.type === 'my_registrations_data') {
                console.log(`Received my registrations: ${data.attended_events.length} attended, ${data.created_events.length} created.`);
            }
        });

        socket.on('close', () => {
            console.log('WebSocket connection closed.');
        });

        socket.on('error', (e) => {
            wsFail.add(1);
            console.error(`WebSocket Error: ${e.error()}`);
        });

        // 30초 후 연결 종료
        socket.setTimeout(() => {
            socket.close();
        }, 30000);
    });

    check(res, {
        'WebSocket connection status is 101': (r) => r && r.status === 101
    });
}