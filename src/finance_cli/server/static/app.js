/* Finance web app shell: access, profiles, areas, navigation and job plumbing.
   The business profile is per tab (sessionStorage) and never a server-wide choice. */
import {api, ApiError, follow, submit, TERMINAL} from './api.js';
import * as ui from './ui.js';
import {actions, views} from './views.js';

export const AREAS = {
  banking: {name: '하나개인뱅킹', service: '개인 계좌·거래·이체', home: 'accounts', icon: 'accounts', items: [
    ['accounts', '내 계좌', '계좌', 'accounts', 'hana-accounts'], ['history', '거래 내역', '거래', 'history', 'hana-history'],
    ['transfer', '이체', '이체', 'transfer', 'hana-transfer'], ['inquiry', '이체 내역', '이체 내역', 'history', 'hana-inquiry'],
    ['security', '보안매체·한도', '보안', 'shield', 'hana-security']]},
  corporate: {name: '하나기업뱅킹', service: '기업 계좌·거래·이체', home: 'corporate-accounts', icon: 'business', items: [
    ['corporate-accounts', '기업 계좌', '계좌', 'accounts', 'corporate-accounts'],
    ['corporate-history', '기업 거래내역', '거래', 'history', 'corporate-history'],
    ['corporate-transfer', '기업 이체', '이체', 'transfer', 'corporate-transfer']]},
  giro: {name: '지로', service: '모바일지로', home: 'giro-live', icon: 'bill', items: [
    ['giro-live', '고지 조회', '고지 조회', 'bill', 'giro-live'],
    ['giro-pay', '지로 납부', '납부', 'transfer', 'giro-pay'],
    ['giro-receipts', '납부내역', '납부내역', 'history', 'giro-receipts'],
    ['giro-accounts', '등록계좌', '등록계좌', 'accounts', 'giro-accounts'],
    ['bills', '고지서 자료', '자료 해석', 'bill', 'giro-bills'], ['deadlines', '납부 기한', '기한', 'calendar', 'giro-bills'],
    ['girostatus', '연결 준비', '연결', 'shield', 'giro-readiness']]},
  tax: {name: '세금', service: '홈택스', home: 'taxhome', icon: 'tax', items: [
    ['taxhome', '세금 요약', '요약', 'tax', 'hometax-tax'], ['invoices', '전자세금계산서', '계산서', 'invoice', 'hometax-invoice-query'],
    ['returns', '신고 내역', '신고 내역', 'history', 'hometax-returns'], ['dues', '납부할 세액', '납부할 세액', 'accounts', 'hometax-tax'],
    ['payments', '납부 내역', '납부 내역', 'check', 'hometax-tax'], ['refunds', '환급금', '환급금', 'transfer', 'hometax-tax'],
    ['notices', '전자고지', '전자고지', 'bill', 'hometax-tax'], ['reports', '보고서·접수증', '보고서', 'report', 'hometax-reports'],
    ['tax-file', '세금 신고', '신고', 'invoice', 'hometax-file-pay'], ['tax-pay', '세금 납부', '납부', 'transfer', 'hometax-file-pay']]},
};
const COMMON = [['activity', '전체 작업 기록', '작업', 'activity'], ['settings', '연결·인증서', '설정', 'shield'],
  ['coverage', '전체 기능·지원 상태', '전체 기능', 'grid']];
const HIDDEN = {invoiceform: 'tax'};

function stored(key, fallback) {
  try { return JSON.parse(sessionStorage.getItem('finance.' + key)) ?? fallback; } catch (error) { return fallback; }
}
function store(key, value) {
  try { sessionStorage.setItem('finance.' + key, JSON.stringify(value)); } catch (error) { /* per-tab convenience only */ }
}

export const state = {
  server: null, profiles: [], logins: [], targets: [], credentials: [], capabilities: null,
  profileId: stored('profile', 'all'), mode: stored('mode', 'tax'), view: null, lastViews: stored('views', {}),
  token: 0, cache: new Map(), params: {}, rows: {}, hidden: false, vaults: {},
};

const main = () => document.querySelector('#main');

export function feature(id) {
  return state.capabilities?.features.find(f => f.id === id) || null;
}

function navigation(mode) {
  return AREAS[mode].items.map(([id, name, short, iconName, featureId]) => {
    const status = feature(featureId)?.status;
    return {id, name, short, icon: iconName, feature: featureId, available: status === 'available' || status === 'setup_required'};
  });
}

export function profile() {
  return state.profileId === 'all' ? null : state.profiles.find(p => p.id === state.profileId) || null;
}

/* Targets and logins visible in this tab's profile. "전체" shows everything. */
export function scopeTargets(kinds) {
  const current = profile();
  return state.targets.filter(t => !t.disabled && (!kinds || kinds.includes(t.kind))
    && (!current || current.target_ids.includes(t.id)));
}
export function scopeLogins(institution) {
  const current = profile();
  const ids = new Set(scopeTargets().map(t => t.login_id));
  return state.logins.filter(l => l.institution === institution && !l.disabled && (!current || ids.has(l.id)));
}
export function login(id) { return state.logins.find(l => l.id === id) || null; }
export function target(id) { return state.targets.find(t => t.id === id) || null; }

function viewKey() { return `${state.profileId}:${state.mode}`; }

export async function refreshModel() {
  const [profiles, , targets, capabilities, vaults] = await Promise.all([
    api.get('/profiles'), refreshLogins(), api.get('/targets'), api.get('/capabilities'), api.get('/vaults')]);
  state.vaults = Object.fromEntries(vaults.vaults.map(v => [v.name, v.unlocked]));
  state.profiles = profiles.profiles;
  state.targets = targets.targets;
  state.capabilities = capabilities;
  if (state.profileId !== 'all' && !state.profiles.some(p => p.id === state.profileId && !p.disabled)) setProfile('all');
}

async function refreshLogins() {
  const value = await api.get('/logins');
  state.logins = value.logins;
  state.sessionClock = {server: value.server_time, local: Date.now() / 1000};
  return value;
}

export function bankSessionExpired(row) {
  if (row?.institution !== 'hana' || !row.session?.idle_expires_at) return false;
  const clock = state.sessionClock;
  const at = clock?.server === undefined ? Date.now() / 1000 : clock.server + Date.now() / 1000 - clock.local;
  return at >= row.session.idle_expires_at;
}

export async function expiredBankLogin(ctx, id) {
  ui.toast(ui.message('session_idle_expired'));
  await actions.login(ctx, {dataset: {login: id, reason: 'session_idle_expired'}});
}

export async function ensureBankSession(ctx, id) {
  if (!bankSessionExpired(login(id))) return true;
  // Another tab may have used this session. This is local metadata, no bank request.
  await refreshLogins();
  if (!bankSessionExpired(login(id))) return true;
  await expiredBankLogin(ctx, id);
  return false; // Logging in never replays the interrupted operation.
}

function usesBankSession(name) {
  return name.startsWith('hana.') && !['hana.login', 'hana.onesign.login',
    'hana.history.export', 'hana.onesign.history.export'].includes(name);
}

export function setProfile(id) {
  state.profileId = id;
  store('profile', id);
  state.token += 1;  // Late answers for the previous profile are dropped.
}

function title() {
  const entry = [...Object.values(AREAS).flatMap(a => a.items), ...COMMON].find(i => i[0] === state.view);
  return entry ? entry[1] : state.view === 'invoiceform' ? '계산서 작성' : 'Finance';
}

function renderChrome() {
  const area = AREAS[state.mode];
  const items = navigation(state.mode);
  document.querySelectorAll('.mode-control').forEach(target => {
    target.innerHTML = `<button class="workspace-switch" data-ui="choose-mode" aria-label="업무 영역 변경: ${ui.esc(area.name)}" aria-haspopup="dialog"><span class="workspace-icon">${ui.icon(area.icon)}</span><span><strong>${ui.esc(area.name)}</strong><small>${ui.esc(area.service)}</small></span>${ui.icon('chevrons')}</button>`;
  });
  document.querySelector('.workspace-label').textContent = area.service;
  const item = (entry, mobile = false) => `<button class="nav-item ${state.view === entry.id ? 'active' : ''} ${entry.available ? '' : 'unavailable'}" ${entry.available ? `data-view="${entry.id}"` : 'disabled aria-disabled="true"'} ${state.view === entry.id ? 'aria-current="page"' : ''}>${ui.icon(entry.icon)}<span>${ui.esc(mobile ? entry.short : entry.name)}</span>${entry.available ? '' : '<small class="soon-label">준비 중</small>'}</button>`;
  document.querySelector('.main-nav').innerHTML = items.map(e => item(e)).join('');
  document.querySelector('.common-nav').innerHTML = COMMON.map(([id, name, , iconName]) => item({id, name, icon: iconName, available: true})).join('');
  document.querySelector('.bottom-nav').innerHTML = items.filter(e => e.available).slice(0, 3).map(e => item(e, true)).join('')
    + `<button class="nav-item" data-ui="more" aria-haspopup="dialog">${ui.icon('grid')}<span>전체 메뉴</span></button>`;
  const common = COMMON.some(([id]) => id === state.view);
  document.querySelector('#breadcrumb-mode').textContent = common ? '공통' : area.name;
  document.querySelector('#breadcrumb-title').textContent = title();
  document.querySelector('#stage').dataset.workspace = state.mode;
  const current = profile();
  const name = current ? current.name : '전체';
  const kind = current ? (ui.KIND[current.kind] || '유형 미설정') : '모든 대상';
  document.querySelector('.profile-switch').innerHTML = `<span class="profile-mark">${ui.esc([...name][0] || 'F')}</span><span><strong>${ui.esc(name)}</strong><small>${ui.esc(kind)}</small></span>${ui.icon('chevrons')}`;
  document.querySelector('.profile-switch').setAttribute('aria-label', `업무 프로필 변경: ${name} · ${kind}`);
  document.querySelector('#server-mode').textContent = state.server?.mode === 'proxy' ? '원격' : '로컬';
  document.querySelector('#footer').textContent = '업무는 서버의 작업으로 실행되며, 연결이 끊겨도 작업은 취소되지 않아요.';
  document.title = `Finance — ${title()}`;
}

export async function render() {
  const token = ++state.token;
  renderChrome();
  const view = views[state.view];
  if (!view) return;
  const context = makeContext(token);
  try {
    const html = await view(context);
    if (token !== state.token) return;
    main().innerHTML = html;
    context.after.forEach(fn => fn());
  } catch (error) {
    if (token !== state.token) return;
    main().innerHTML = ui.heading(title(), '') + ui.note(ui.message(error.code || 'local_processing_error'));
  }
}

export function changeView(view, params = {}) {
  const owner = Object.keys(AREAS).find(mode => AREAS[mode].items.some(i => i[0] === view)) || HIDDEN[view];
  const entry = navigation(owner || state.mode).find(i => i.id === view);
  if (entry && !entry.available) return;
  if (!owner && !COMMON.some(([id]) => id === view)) return;
  if (owner) {
    state.mode = owner;
    store('mode', owner);
    state.lastViews[viewKey()] = view;
    store('views', state.lastViews);
  }
  state.view = view;
  state.params = params;
  ui.closeDialog();
  render().then(() => {
    document.querySelector('.main-shell').scrollTo({top: 0});
    main().focus({preventScroll: true});
  });
}

function changeMode(mode) {
  state.mode = mode;
  store('mode', mode);
  ui.closeDialog();
  changeView(state.lastViews[viewKey()] || AREAS[mode].home);
}

/* The OneSign store a login uses (for transfers, its transfer signing store). */
export function onesignStore(row, transfer = false) {
  if (!row || row.method !== 'onesign') return null;
  return (transfer && row.signing?.transfer_sign?.ref) || row.credential?.ref || null;
}

/* Fields still to ask: a store unlocked in the server's memory needs no passphrase. */
export function secretFields(fields, store) {
  return fields.filter(([name]) => !(name === 'vault_passphrase' && store && state.vaults[store]));
}

export function rememberField(fields, store) {
  return store && fields.some(([name]) => name === 'vault_passphrase')
    ? `<label class="check"><input type="checkbox" name="remember_vault" checked> 서버를 끌 때까지 이 저장소 암호 기억 (서버 메모리에만, 이체 포함)</label>` : '';
}

/* Unlock in server memory when asked; the passphrase is then not sent with the job. */
export async function applyRemember(values, store) {
  const remember = values.remember_vault === 'on';
  delete values.remember_vault;
  if (!remember || !store || !values.vault_passphrase) return values;
  await api.post(`/vaults/${encodeURIComponent(store)}/unlock`, {passphrase: values.vault_passphrase});
  state.vaults[store] = true;
  delete values.vault_passphrase;
  return values;
}

/* Secrets: collected in a dialog, returned once, never stored in the browser or logged. */
export function askSecrets(title, allFields, description = '', {store = null} = {}) {
  const fields = secretFields(allFields, store);
  if (!fields.length) return Promise.resolve({});
  return new Promise(resolve => {
    const body = `<form id="secret-form" autocomplete="off">${description ? `<p class="dialog-note">${description}</p>` : ''}${fields.map(([name, label, pattern]) => `<div class="field"><label for="secret-${name}">${ui.esc(label)}</label><input id="secret-${name}" name="${name}" type="password" required autocomplete="off" ${pattern ? `inputmode="numeric" pattern="${pattern}"` : ''}></div>`).join('')}${rememberField(fields, store)}<p class="dialog-note">입력한 값은 이 작업의 해당 단계에만 전달하고 저장하지 않아요.</p><p class="form-error" id="secret-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">확인</button></div></form>`;
    ui.showDialog(title, body);
    const form = document.querySelector('#secret-form');
    const dialog = document.querySelector('#detail-dialog');
    const done = value => { dialog.removeEventListener('close', cancel); resolve(value); };
    const cancel = () => done(null);
    dialog.addEventListener('close', cancel);
    form.addEventListener('submit', async event => {
      event.preventDefault();
      let value = Object.fromEntries(new FormData(form).entries());
      try {
        value = await applyRemember(value, store);
      } catch (error) {
        document.querySelector('#secret-error').textContent = ui.message(error.code);
        return;
      }
      form.reset();
      dialog.removeEventListener('close', cancel);
      ui.closeDialog();
      done(value);
    });
  });
}

export const SECRET_LABELS = {
  login_password: ['login_password', '기업 로그인 비밀번호'],
  otp: ['otp', '일반 OTP 6자리', '[0-9]{6}'],
  certificate_password: ['certificate_password', '인증서 비밀번호'],
  vault_passphrase: ['vault_passphrase', '하나인증서 저장소 암호'],
  pin: ['pin', '하나인증서 PIN 6자리', '[0-9]{6}'],
  account_password: ['account_password', '출금 계좌 비밀번호 4자리', '[0-9]{4}'],
};

function makeContext(token) {
  const context = {
    state, token, after: [], params: state.params,
    current: () => token === state.token,
    later: fn => context.after.push(fn),
    render, changeView, scopeTargets, scopeLogins, login, target, profile, feature, askSecrets,
    async refresh() { await refreshModel(); await render(); },
    /* Submit a job and follow it; progress goes to the element with the given id. */
    async run(name, fields, {panel, key, onDone, secrets} = {}) {
      let job;
      try {
        if (usesBankSession(name) && !await ensureBankSession(context, fields.login_id)) return null;
        job = await submit(name, {...fields, ...(secrets ? {secrets} : {}), profile_id: profile()?.id || undefined});
      } catch (error) {
        if (error.code === 'session_idle_expired') {
          await expiredBankLogin(context, fields.login_id);
          return null;
        }
        const message = error.code === 'capability_unavailable' && error.reasons?.length
          ? error.reasons.map(ui.message).join(' ') : ui.message(error.code);
        if (document.getElementById(panel)) document.getElementById(panel).innerHTML = jobState(null, message);
        ui.toast(message);
        return null;
      }
      return context.track(job, {panel, key, onDone});
    },
    async track(job, {panel, key, onDone} = {}) {
      if (key) state.cache.set(key, job);
      const update = value => {
        if (key) state.cache.set(key, value);
        const target = document.getElementById(panel);
        if (target && context.current()) target.innerHTML = jobState(value);
      };
      update(job);
      const final = await follow(job.id, update, () => true).catch(error => {
        ui.toast(ui.message(error.code));
        return null;
      });
      if (final?.name?.startsWith('hana.') && final.login_id) {
        await refreshLogins().catch(() => {}); // A display refresh cannot change the job's outcome.
        if (final.local?.stopped === 'session_idle_expired' && context.current()) {
          await expiredBankLogin(context, final.login_id);
          return null;
        }
      }
      if (final && context.current()) await onDone?.(final);
      return final;
    },
  };
  return context;
}

export function jobState(job, error = '') {
  if (!job) return `<div class="job-state">${ui.tag('접수 안 됨', 'danger')}<span>${error}</span></div>`;
  const busy = job.status === 'queued' || job.status === 'running';
  const fixed = job.fixed?.target ? `${ui.esc(job.fixed.target.display_name)} · ` : '';
  const stopped = job.local?.stopped ? ` · ${ui.message(job.local.stopped)}` : '';
  const saved = job.local && job.local.session_saved === false ? ' · 세션 저장 확인 안 됨' : '';
  return `<div class="job-state">${busy ? '<span class="spinner" aria-hidden="true"></span>' : ''}${ui.statusTags(job)}${ui.verification(job.verification)}<span>${fixed}${ui.ORIGIN[job.origin] || ''} 요청 · ${job.observed_at ? '조회 ' + ui.time(job.observed_at) : '접수 ' + ui.time(job.created_at)}${stopped}${saved}</span><button class="text-button" data-action="job-detail" data-job="${ui.esc(job.id)}">작업 상세 ${ui.icon('arrow')}</button></div>`;
}

/* Job detail with the institution verdict, reconciliation and local state kept apart. */
export async function showJob(id) {
  let job;
  try { job = await api.get('/jobs/' + encodeURIComponent(id)); } catch (error) { ui.toast(ui.message(error.code)); return; }
  const fixed = job.fixed || {};
  const lines = [
    ['작업', job.title], ['상태', ui.STATUS[job.status]?.[0] || job.status],
    ['업무 결과 요약', ui.OUTCOME[job.outcome]?.[0] || job.outcome], ['요청 출처', ui.ORIGIN[job.origin] || job.origin],
    ['로그인', fixed.login?.display_name], ['대상', fixed.target ? `${fixed.target.display_name} (${ui.KIND[fixed.target.kind] || fixed.target.kind})` : null],
    ['프로필', fixed.profile?.name], ['접수', ui.time(job.created_at)], ['관측', ui.time(job.observed_at)],
  ].filter(([, v]) => v);
  const artifacts = (job.artifacts || []).map(a => `<div class="setting-row"><span>${ui.esc(a.filename)}${a.complete === 0 ? ' · 확인 필요' : a.complete === 1 ? ' · 완전' : ''}</span><span class="row-actions">${a.media_type.startsWith('text/html') ? `<button class="text-button" data-action="preview-artifact" data-artifact="${ui.esc(a.id)}">보기</button>` : ''}<a class="text-button" href="/api/v1/artifacts/${encodeURIComponent(a.id)}">${ui.icon('download')}저장</a></span></div>`).join('');
  const cancellable = (job.status === 'queued' || job.status === 'awaiting_input') && !job.attempt?.sent;
  const reconcile = job.name === 'hana.transfer.prepare' && job.status === 'finished' && job.attempt?.sent && ['execute', 'execute_pin'].includes(job.step);
  ui.showDialog('작업 상세', `<div class="summary-lines">${lines.map(([k, v]) => `<div class="summary-line"><span>${ui.esc(k)}</span><strong>${ui.esc(v)}</strong></div>`).join('')}</div>${job.local?.stopped ? `<p class="dialog-note">${ui.message(job.local.stopped)}</p>` : ''}${ui.verification(job.verification)}${ui.details('기관 판정 (원문 필드)', job.service_verdict)}${ui.details('결과 재조회', job.reconciliation)}${ui.details('로컬 처리 상태', job.local)}${ui.details('처리 순서', job.events?.map(e => ({시각: ui.time(e.at), 단계: e.kind, ...e.detail})))}${artifacts ? `<div class="settings-body">${artifacts}</div>` : ''}<div class="dialog-actions">${cancellable ? `<button class="button secondary" data-action="cancel-job" data-job="${ui.esc(job.id)}">작업 취소</button>` : ''}${job.name === 'giro.payment.prepare' ? `<button class="button secondary" data-action="giro-payment-open" data-job="${ui.esc(job.id)}">${job.status === 'awaiting_input' ? '납부 내용 확인' : '납부 결과 보기'}</button>` : ''}${job.name === 'hana.corporate.transfer.prepare' ? `<button class="button secondary" data-action="corporate-transfer-open" data-job="${ui.esc(job.id)}">${job.status === 'awaiting_input' ? '이체 이어하기' : '이체 결과 보기'}</button>` : ''}${reconcile ? `<button class="button secondary" data-action="reconcile" data-job="${ui.esc(job.id)}">이체 결과 조회</button>` : ''}<button class="button primary" data-ui="close">닫기</button></div>`, {wide: true});
}

function chooseMode() {
  ui.showDialog('어떤 업무를 볼까요?', `<div class="mode-options">${Object.entries(AREAS).map(([key, mode]) => `<button data-mode="${key}" class="mode-option ${key === state.mode ? 'selected' : ''}"><span class="workspace-icon">${ui.icon(mode.icon)}</span><span><strong>${mode.name}</strong><small>${mode.service}</small></span>${key === state.mode ? ui.icon('check') : ui.icon('arrow')}</button>`).join('')}</div><p class="dialog-note">영역을 바꿔도 프로필별로 각 영역에서 보던 화면을 유지해요.</p>`);
}

function chooseProfile() {
  const option = (id, name, kind) => `<button data-profile="${ui.esc(id)}" class="mode-option ${id === state.profileId ? 'selected' : ''}"><span class="workspace-icon">${ui.icon(id === 'all' ? 'grid' : 'business')}</span><span><strong>${ui.esc(name)}</strong><small>${ui.esc(kind)}</small></span>${id === state.profileId ? ui.icon('check') : ui.icon('arrow')}</button>`;
  ui.showDialog('업무 프로필', `<div class="mode-options">${option('all', '전체', '모든 대상')}${state.profiles.filter(p => !p.disabled).map(p => option(p.id, p.name, ui.KIND[p.kind] || '유형 미설정')).join('')}</div><p class="dialog-note">프로필 전환은 이 탭의 표시 대상만 바꿔요. 다른 탭·기기와 진행 중인 작업은 그대로예요.</p><div class="dialog-actions"><button class="button secondary" data-view="settings">프로필 관리</button></div>`);
}

function moreMenu() {
  const items = navigation(state.mode);
  ui.showDialog(`${AREAS[state.mode].name} 메뉴`, `<div class="menu-sheet">${items.map(item => `<button ${item.available ? `data-view="${item.id}"` : 'disabled aria-disabled="true"'}>${ui.icon(item.icon)}${ui.esc(item.name)}${item.available ? ui.icon('arrow') : '<span class="soon-label">준비 중</span>'}</button>`).join('')}<hr>${COMMON.map(([id, name, , iconName]) => `<button data-view="${id}">${ui.icon(iconName)}${ui.esc(name)}${ui.icon('arrow')}</button>`).join('')}</div>`);
}

function enrollScreen() {
  const target = document.querySelector('#enroll');
  target.hidden = false;
  document.querySelector('#stage').hidden = true;
  target.innerHTML = `<div class="enroll-screen"><div class="enroll-card"><div class="brand"><span class="brand-mark">f</span>finance<span class="brand-dot">.</span></div><h1>이 브라우저 등록</h1><p>서버에서 <span class="code">fin server enroll</span>를 실행해 일회성 코드를 만든 뒤 입력하세요. 코드는 10분 뒤 만료되고 한 번만 쓸 수 있어요.</p><p>웹앱 접속은 은행·홈택스 로그인과 별개예요. 이 등록으로 기관에 접속하지 않아요.</p><form id="enroll-form"><div class="field"><label for="enroll-code">등록 코드</label><input id="enroll-code" name="code" autocomplete="one-time-code" required maxlength="11" placeholder="XXXXX-XXXXX"></div><div class="field"><label for="enroll-name">기기 이름 (선택)</label><input id="enroll-name" name="name" maxlength="60" placeholder="예: 내 휴대폰"></div><div class="form-actions"><button class="button primary" type="submit">등록</button><p class="form-error" id="enroll-error" role="alert"></p></div></form></div></div>`;
}

async function boot() {
  let server;
  try { server = await api.state(); } catch (error) {
    document.body.innerHTML = `<div class="enroll-screen"><div class="enroll-card"><h1>서버에 연결할 수 없어요</h1><p>${ui.message(error.code)}</p></div></div>`;
    return;
  }
  state.server = server;
  if (!server.enrolled) { enrollScreen(); return; }
  document.querySelector('#enroll').hidden = true;
  document.querySelector('#stage').hidden = false;
  try { await refreshModel(); } catch (error) {
    if (error.code === 'access_required') { enrollScreen(); return; }
    throw error;
  }
  if (!AREAS[state.mode]) state.mode = 'tax';
  const start = state.lastViews[viewKey()] || AREAS[state.mode].home;
  changeView(navigation(state.mode).find(i => i.id === start)?.available === false ? 'coverage' : start);
}

document.addEventListener('click', async event => {
  const target = event.target.closest('button,a,tr[data-row]');
  if (!target || target.disabled) return;
  if (target.dataset.view) {
    event.preventDefault();
    changeView(target.dataset.view === 'home' ? AREAS[state.mode].home : target.dataset.view);
    return;
  }
  if (target.dataset.mode) { changeMode(target.dataset.mode); return; }
  if (target.dataset.profile) {
    setProfile(target.dataset.profile);
    ui.closeDialog();
    changeView(state.lastViews[viewKey()] || state.view || AREAS[state.mode].home);
    return;
  }
  switch (target.dataset.ui) {
    case 'close': ui.closeDialog(); return;
    case 'choose-mode': chooseMode(); return;
    case 'choose-profile': chooseProfile(); return;
    case 'more': moreMenu(); return;
  }
  const action = target.dataset.action || (target.dataset.row ? 'row' : null);
  if (action === 'job-detail') { showJob(target.dataset.job); return; }
  if (action && actions[action]) {
    if (target.tagName === 'BUTTON') target.disabled = true;
    try { await actions[action](makeContext(state.token), target, event); }
    finally { if (target.isConnected && target.tagName === 'BUTTON') target.disabled = false; }
  }
});

document.addEventListener('keydown', event => {
  if (event.target.matches?.('tr[data-row]') && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault();
    event.target.click();
  }
});

document.addEventListener('submit', async event => {
  const form = event.target;
  if (form.id === 'enroll-form') {
    event.preventDefault();
    const data = new FormData(form);
    try {
      await api.enroll(String(data.get('code')), String(data.get('name') || ''));
      form.reset();
      await boot();
    } catch (error) {
      document.querySelector('#enroll-error').textContent = ui.message(error.code);
    }
    return;
  }
  const name = form.dataset.submit;
  if (name && actions[name]) {
    event.preventDefault();
    const button = form.querySelector('button[type="submit"]');
    if (button) button.disabled = true;
    try { await actions[name](makeContext(state.token), form, event); }
    finally { if (button?.isConnected) button.disabled = false; }
  }
});

document.addEventListener('change', event => {
  const name = event.target.dataset.change;
  if (name && actions[name]) actions[name](makeContext(state.token), event.target, event);
});

document.querySelector('#detail-dialog').addEventListener('click', event => {
  const dialog = event.currentTarget;
  if (event.target === dialog) {
    const rect = dialog.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) ui.closeDialog();
  }
});

export {api, submit, follow, TERMINAL, ApiError};
boot();
