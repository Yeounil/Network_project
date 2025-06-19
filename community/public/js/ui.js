import { send } from './ws.js';

// --- 로그인 바인딩 ---
export function bindLogin(onLogin) {
  const loginBtn = document.getElementById('login-btn');
  if (!loginBtn) return;
  loginBtn.addEventListener('click', () => {
    const user = document.getElementById('username').value.trim();
    const pass = document.getElementById('password').value;
    const errEl = document.getElementById('login-error');
    if (!user || !pass) {
      errEl.textContent = '아이디와 비밀번호를 입력하세요.';
      return;
    }
    errEl.textContent = '';
    onLogin(user, pass);
  });
}

// --- 채팅 전송 바인딩 ---
export function bindChat() {
  const sendBtn = document.getElementById('send');
  const msgInput = document.getElementById('msg');
  if (!sendBtn || !msgInput) return;
  const sendMessage = () => {
    const text = msgInput.value.trim();
    if (!text) return;
    send('msg', { text });
    renderMessage('나', text);
    msgInput.value = '';
  };
  sendBtn.addEventListener('click', sendMessage);
  msgInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') sendMessage();
  });
}

// --- 모달 스텝 전환 헬퍼 ---
export function showModalStep(step) {
  ['select', 'explore', 'create'].forEach(s => {
    const el = document.getElementById(`modal-step-${s}`);
    if (el) el.style.display = s === step ? 'block' : 'none';
  });
}

// --- 채널 모달 바인딩 ---
export function bindChannelModal() {
  const modal         = document.getElementById('modal');
  const openBtns      = [
    document.getElementById('open-channel-modal'),
    document.getElementById('add-channel-btn')
  ].filter(Boolean);
  const exploreBtn    = document.getElementById('explore-channel-btn');
  const createBtn     = document.getElementById('modal-create-btn');
  const backSelectBtn = document.getElementById('back-select-btn');
  const backExploreBtn= document.getElementById('back-select-from-explore-btn');
  const ulExplore     = document.getElementById('explore-list');

  if (!modal || openBtns.length === 0) return;
  // 헬퍼: 모달 닫기 로직
  const closeModal = () => {
    modal.style.display = 'none';
    showModalStep('select');
    if (ulExplore) ulExplore.innerHTML = '';
  };
  
  // 모달 열기 및 초기화
  openBtns.forEach(btn => btn.addEventListener('click', () => {
    modal.style.display = 'flex';
    showModalStep('select');
    if (ulExplore) ulExplore.innerHTML = '';
  }));
  
  // 배경 클릭으로 닫기
  modal.addEventListener('click', e => {
    if (e.target === modal) {
      closeModal();
    }
  });
  
  // ESC 키로 닫기
  window.addEventListener('keydown', e => {
    if (e.key === 'Escape' && modal.style.display === 'flex') {
      closeModal();
    }
  });

  // 채널 탐색 단계
  exploreBtn?.addEventListener('click', () => {
    if (ulExplore) ulExplore.innerHTML = '';
    showModalStep('explore');
    send('list_channels', {});
  });

  // 채널 생성 단계
  createBtn?.addEventListener('click', () => showModalStep('create'));

  // 뒤로가기 버튼
  backSelectBtn?.addEventListener('click', () => showModalStep('select'));
  backExploreBtn?.addEventListener('click', () => {
    if (ulExplore) ulExplore.innerHTML = '';
    showModalStep('select');
  });

}

export function bindUserMenu() {
  // --- 1. 디버깅: 어떤 요소가 null인지 찍어보기 ---
  [
    'user-btn',
    'user-dropdown',
    'menu-account',
    'close-account',
    'account-modal',
    'account-form',
    'account-nickname'
  ].forEach(id => {
    console.log(`[DEBUG] "${id}" →`, document.getElementById(id));
  });

  // --- 2. 필수 요소 없으면 함수 중단 ---
  const userBtn      = document.getElementById('user-btn');
  const dropdown     = document.getElementById('user-dropdown');
  const menuAccount  = document.getElementById('menu-account');
  const closeAcc     = document.getElementById('close-account');
  const accountModal = document.getElementById('account-modal');
  const acctForm     = document.getElementById('account-form');
  const nickInput    = document.getElementById('account-nickname');
  if (!userBtn || !dropdown || !menuAccount || !closeAcc || !accountModal || !acctForm || !nickInput) {
    console.error('❌ bindUserMenu: 필요한 요소 중 하나 이상을 찾지 못했습니다. 위 DEBUG 로그를 확인하세요.');
    return;
  }

  // --- 3. 기존 바인딩 로직 ---
  userBtn.addEventListener('click', e => {
    console.log('👤 userBtn click event');
    e.stopPropagation();
    dropdown.classList.toggle('hidden');
  });
  document.addEventListener('click', () => dropdown.classList.add('hidden'));
  dropdown.addEventListener('click', e => e.stopPropagation());

  menuAccount.addEventListener('click', () => {
    console.log('▶ “내 계정” 메뉴 클릭됨');
    showAccountModal();
  });
  
  closeAcc.addEventListener('click', () => toggleModal('account-modal', true));

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
      dropdown.classList.add('hidden');
    }
  });

  acctForm.addEventListener('submit', e => {
    e.preventDefault();
    const newNick = nickInput.value.trim();
    console.log('✏️ 닉네임 변경 요청:', newNick);
    send('update_nickname', {nickname: newNick});
  });
}

// 모달 토글 헬퍼
function toggleModal(id, hide) {
  const m = document.getElementById(id);
  if (!m) return;
  m.classList.toggle('hidden', hide);
}

// “내 계정” 모달 열 때 서버에 정보 요청
function showAccountModal() {
  toggleModal('account-modal', false);
  console.log(
    'account-modal 엘리먼트:', document.getElementById('account-modal'),
    'classList:', document.getElementById('account-modal').classList,
    'computed display:', window.getComputedStyle(document.getElementById('account-modal')).display
  );
  send('get_user_info');
}

// --- 채널 생성 핸들러 ---
export function handleCreateChannel() {
  const nameEl   = document.getElementById('create-channel-name');
  const maxEl    = document.getElementById('max-members');
  const typeEls  = document.getElementsByName('channel-type');
  const nameErr  = document.getElementById('channel-name-error');
  const maxErr   = document.getElementById('max-members-error');
  if (!nameEl || !maxEl || !typeEls) return;

  const name = nameEl.value.trim();
  const validName = /^[A-Za-z0-9_-]{3,20}$/.test(name);
  nameErr.textContent = validName ? '' : '영문/숫자/_/- 3~20자 입력하세요.';

  const max = parseInt(maxEl.value, 10);
  const validMax = !isNaN(max) && max >= 2 && max <= 100;
  maxErr.textContent = validMax ? '' : '2~100 사이 숫자를 입력하세요.';

  if (!validName || !validMax) return;
  let channelType = 'public';
  for (const r of typeEls) {
    if (r.checked) { channelType = r.value; break; }
  }
  const token = Math.random().toString(36).substr(2, 8);

  send('create_channel', {
    name,
    channel_type: channelType,
    max_members: max,
    invite_token: token
  });

  modal.style.display = 'none';
  showModalStep('select');
}

// --- 사이드바 채널 렌더링 ---
export function renderChannelItem(id, name, inviteToken, onClickJoin) {
  const ul = document.getElementById('channel-list');
  if (!ul || ul.querySelector(`li[data-room=\"${id}\"]`)) return;

  const li = document.createElement('li');
  li.dataset.room = id;
  li.className = 'channel-item';
  li.addEventListener('click', () => onClickJoin(id));

  const span = document.createElement('span');
  span.textContent = name;
  li.appendChild(span);
  
  const btn = document.createElement('button');
  btn.textContent = '🔗';
  btn.title = '초대 링크 복사';
  btn.addEventListener('click', e => {
    e.stopPropagation();
    const link = `${location.origin}/invite/${inviteToken}`;
    copyToClipboard(link)
      .then(() => alert('초대 링크 복사됨: ' + link))
      .catch(() => prompt('초대 링크:', link));
  });
  li.appendChild(btn);

  ul.appendChild(li);
}

// 유틸: 클립보드 복사 폴백
function copyToClipboard(text) {
  if (navigator.clipboard && location.protocol === 'https:') {
    return navigator.clipboard.writeText(text);
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); }
  finally { document.body.removeChild(ta); }
  return Promise.resolve();
}

function renderUserList(users) {
  const ul = document.getElementById('user-list');
  ul.innerHTML = users.map(u =>
    `<li data-id="${u.id}">${u.nickname} (${u.username})</li>`
  ).join('');
}

// --- 탐색 리스트 렌더링 ---
export function renderExploreItem(id, name, inviteToken, onSelect) {
  const ul = document.getElementById('explore-list');
  if (!ul) return;
  if (ul.querySelector(`li[data-id=\"${id}\"]`)) return;

  const li = document.createElement('li');
  li.className = 'channel-item';
  li.dataset.id    = id;
  li.dataset.token = inviteToken;
  li.textContent   = name;
  li.tabIndex      = 0;
  li.setAttribute('role', 'option');
  li.style.cursor  = 'pointer';

  if (typeof onSelect === 'function') {
    li.addEventListener('click', () => {
      try {
        onSelect(id, name, inviteToken);
      } catch (err) {
        console.error('onSelect 에러:', err);
      }
    });
  }
  ul.appendChild(li);
}

// 2) WebSocket 메시지 핸들러에 아래 케이스 추가
export function handleServerMessage(raw) {
  const data = JSON.parse(raw);
  switch (data.type) {

    case 'user_info':
      // server → { type:'user_info', user:{ id, username, email, nickname, created_at } }
      document.getElementById('account-username').value = data.user.username;
      document.getElementById('account-email').value    = data.user.email;
      document.getElementById('account-nickname').value = data.user.nickname;
      break;

    case 'update_nickname_result':
      if (data.success) {
        alert('닉네임이 변경되었습니다.');
        toggleModal('account-modal', true);
      } else {
        alert('변경 실패: ' + data.error);
      }
      break;

    // …기존 메시지 핸들링…
  }
}

// --- 채팅 메시지 렌더링 ---
export function renderMessage(nick, text) {
  const chat = document.getElementById('chat');
  if (!chat) return;
  const p = document.createElement('p');
  p.innerHTML = `<strong>${nick}</strong>: ${text}`;
  chat.appendChild(p);
  chat.scrollTop = chat.scrollHeight;
}

// --- 로그인 후 화면 전환 ---
export function showApp(user) {
  const login = document.getElementById('login-container');
  const app   = document.getElementById('app');
  if (login) login.style.display = 'none';
  if (app)   app.style.display   = 'grid';
  const nameEl = document.getElementById('user-name');
  if (nameEl) nameEl.textContent = user;
  // 기본 채널 'General' 자동 가입
  renderChannelItem(1, 'General', '', id => send('join', { room_id: id }));
}

document.addEventListener('DOMContentLoaded', () => {
  bindUserMenu();
  handleCreateChannel();
});

