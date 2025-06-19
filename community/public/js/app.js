// public/js/app.js
import { initWebSocket, send } from './ws.js';
import {
  bindLogin,
  bindChat,
  bindChannelModal,
  handleCreateChannel,
  renderChannelItem,
  renderExploreItem,
  renderMessage,
  showApp,
  showModalStep
} from './ui.js';

let currentRoom = 1;
const loginForm    = document.getElementById('login-form');
const signupForm   = document.getElementById('signup-form');
const toSignupLink = document.getElementById('to-signup');
const toLoginLink  = document.getElementById('to-login');
const authTitle    = document.getElementById('auth-title');
const authError    = document.getElementById('auth-error');

/** 방 전환: UI 초기화 + 서버에 join 요청 */
function joinRoom(roomId) {
  console.log('[app] joinRoom', roomId, 'currentRoom:', currentRoom);
  if (roomId === currentRoom) return;
  const chatEl = document.getElementById('chat');
  if (chatEl) chatEl.innerHTML = '';
  send('join', { room_id: roomId });
  currentRoom = roomId;
}
// init 단계에서 한 번만 실행
function bindAuthToggle() {
  // 초기엔 로그인 폼만 보이도록
  loginForm.classList.remove('hidden');
  signupForm.classList.add('hidden');
  toSignupLink.classList.remove('hidden');
  toLoginLink.classList.add('hidden');
  authTitle.innerText = '로그인';

  // 토글 클릭
  toSignupLink.addEventListener('click', () => {
    loginForm.classList.add('hidden');
    signupForm.classList.remove('hidden');
    toSignupLink.classList.add('hidden');
    toLoginLink.classList.remove('hidden');
    authTitle.innerText = '회원가입';
    authError.innerText = '';
  });
  toLoginLink.addEventListener('click', () => {
    signupForm.classList.add('hidden');
    loginForm.classList.remove('hidden');
    toLoginLink.classList.add('hidden');
    toSignupLink.classList.remove('hidden');
    authTitle.innerText = '로그인';
    authError.innerText = '';
  });
}

function bindAuthSubmit() {
  // 로그인
  loginForm.addEventListener('submit', e => {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    send('login', {username: username, password: password});
  });

  // 회원가입
  signupForm.addEventListener('submit', e => {
    e.preventDefault();
    const username = document.getElementById('signup-username').value.trim();
    const password = document.getElementById('signup-password').value;
    const email    = document.getElementById('signup-email').value.trim();
    send('signup', {username: username, password: password, email: email});
  });
}

/** WebSocket 연결 완료 시 초기화 */
function handleOpen() {
  console.log('[app] WS open');
  bindLogin((user, pass) => send('login', { username: user, password: pass }));
  bindChat();
  bindChannelModal();

  // 채널 생성 버튼 바인딩
  const createBtn = document.getElementById('submit-create-btn');
  if (createBtn) createBtn.addEventListener('click', handleCreateChannel);

  // 기본 General 채널 클릭 바인딩
  const generalLi = document.querySelector('#channel-list li[data-room="1"]');
  if (generalLi) generalLi.addEventListener('click', () => joinRoom(1));
}

/** 수신된 WebSocket 메시지 처리 */
function handleMessage(data) {
  console.log('[app] recv', data);
  switch (data.type) {
    case 'login_result':
      if (data.success) {
        showApp(data.user);
        joinRoom(currentRoom);
      } else {
        document.getElementById('login-error').textContent = data.reason;
        authError.style.color = 'red';
        authError.innerText = '잘못된 비밀번호입니다.';
      }
      break;
      
    case 'signup_result':
     if (data.success) {
       authError.style.color = 'green';
       authError.innerText = '회원가입 성공! 로그인해주세요.';
       // 자동으로 로그인 폼으로 돌아가기
       toLoginLink.click();
     } else {
       authError.style.color = 'red';
       authError.innerText = `회원가입 실패: ${msg.error}`;
     }
     break;
      
    case 'join':
      console.log('[app] join ACK', data);
      if (!data.ok) {
        document.getElementById('notifications').textContent = data.reason;
      }
      break;

    case 'msg':
      const who = data.nick;
      const line = document.createElement('div');
      line.className = data.from === data.user_id ? 'my-msg' : 'other-msg';
      line.innerHTML = `<span class="msg-author">${who}</span>: ${data.text}`;
      chat.appendChild(line);
      chat.scrollTop = chat.scrollHeight;
      break;

    case 'create_channel':
      if (data.ok) {
        renderChannelItem(data.id, data.name, data.invite_token, joinRoom);
      } else {
        document.getElementById('notifications').textContent = data.reason;
      }
      break;

    case 'list_channels':
      console.log('[app] list_channels data.channels.length=', data.channels.length);

      // 1) Open the modal and switch to the "explore" pane
      const modalElem = document.getElementById('modal');
      if (modalElem) modalElem.style.display = 'flex';
      showModalStep('explore');

      // 2) Clear the explore list container
      const exploreListElem = document.getElementById('explore-list');
      if (exploreListElem) exploreListElem.innerHTML = '';

      // 3) Render each channel into the explore list
      data.channels.forEach(ch => {
      console.log('[app] renderExploreItem for', ch.name);
      renderExploreItem(ch.id, ch.name, ch.invite_token, (id, name, token) => {
      // When the user clicks an explore item:
      renderChannelItem(id, name, token, joinRoom);
      joinRoom(id);
	      // Close the modal and reset to the select step
      const m = document.getElementById('modal');
      if (m) m.style.display = 'none';
      showModalStep('select');
      	  });
      });
      break;
    
    // 1) 유저 정보 응답 처리
    case 'user_info':
      // 서버로부터 받은 user 객체를 폼에 채워넣기
      // data.user: { id, username, email, nickname, created_at }
      document.getElementById('account-username').value = data.user.username || '';
      document.getElementById('account-email').value    = data.user.email || '';
      document.getElementById('account-nickname').value = data.user.nickname || '';
      break;

    // 2) 닉네임 변경 결과 처리
    case 'update_nickname_result':
      if (data.success) {
        alert('닉네임이 변경되었습니다.');
        document.getElementById('account-modal').classList.add('hidden');
      } else {
        alert('변경 실패: ' + data.error);
      }
      break;

    default:
      console.warn('[app] Unknown type', data.type);
  }
}

// 초기화
document.addEventListener('DOMContentLoaded', () => {
  initWebSocket(handleOpen, handleMessage);
  bindAuthToggle();
  bindAuthSubmit();
});

