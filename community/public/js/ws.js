// public/js/ws.js

// WebSocket 인스턴스를 저장할 전역 변수
export let ws;

// WebSocket 초기화: onOpen, onMessage 콜백 등록
export function initWebSocket(onOpen, onMessage) {
  ws = new WebSocket(`ws://${location.host}`);
  ws.addEventListener('open',    () => onOpen());
  ws.addEventListener('message', e => onMessage(JSON.parse(e.data)));
  ws.addEventListener('error',   e => console.error('WS error', e));
  ws.addEventListener('close',   () => console.log('WS closed'));
}

// WebSocket으로 메시지 전송
export function send(type, payload = {}) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type, ...payload }));
  } else {
    console.warn('WS not open, cannot send:', type, payload);
  }
}

