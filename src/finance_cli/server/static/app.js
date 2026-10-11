/* Finance web app shell: access, profiles, areas, navigation and job plumbing.
   The business profile is per tab (sessionStorage) and never a server-wide choice. */
import {api, ApiError, follow, submit, TERMINAL} from './api.js';
import * as busy from './busy.js';
import * as ui from './ui.js';
import {actions, views} from './views.js';

export const AREAS = {
  banking: {name: '하나개인뱅킹', short: '개인뱅킹', institution: 'hana', service: '개인 계좌·거래·이체', home: 'accounts', icon: 'accounts',
    guide: '로그인하면 계좌와 거래 내역을 조회하고 이체할 수 있어요.', items: [
    ['accounts', '내 계좌', '계좌', 'accounts', 'hana-accounts'], ['history', '거래 내역', '거래', 'history', 'hana-history'],
    ['transfer', '이체', '이체', 'transfer', 'hana-transfer'], ['inquiry', '이체 내역', '이체 내역', 'history', 'hana-inquiry'],
    ['security', '보안매체·한도', '보안', 'shield', 'hana-security']]},
  corporate: {name: '하나기업뱅킹', short: '기업뱅킹', institution: 'hana_corporate', service: '기업 계좌·거래·이체', home: 'corporate-accounts', icon: 'business',
    guide: '로그인하면 기업 계좌와 거래내역을 조회하고 이체할 수 있어요.', items: [
    ['corporate-accounts', '기업 계좌', '계좌', 'accounts', 'corporate-accounts'],
    ['corporate-history', '기업 거래내역', '거래', 'history', 'corporate-history'],
    ['corporate-transfer', '기업 이체', '이체', 'transfer', 'corporate-transfer']]},
  giro: {name: '지로', short: '지로', institution: 'giro', service: '모바일지로', home: 'giro-live', icon: 'bill',
    guide: '로그인하면 고지를 조회하고 납부할 수 있어요.', items: [
    ['giro-live', '고지·납부', '고지·납부', 'bill', 'giro-live'],
    ['giro-receipts', '납부내역', '납부내역', 'history', 'giro-receipts'],
    ['giro-accounts', '등록계좌', '등록계좌', 'accounts', 'giro-accounts'],
    ['girostatus', '도구·상태', '도구', 'shield', 'giro-readiness']]},
  tax: {name: '세금', short: '세금', institution: 'hometax', service: '홈택스', home: 'taxhome', icon: 'tax',
    guide: '로그인하면 세금·전자세금계산서·신고 내역을 조회할 수 있어요.', items: [
    ['taxhome', '세금 요약', '요약', 'tax', 'hometax-tax'], ['invoices', '전자세금계산서', '계산서', 'invoice', 'hometax-invoice-query'],
    ['returns', '신고·증빙', '신고', 'history', 'hometax-returns'], ['dues', '납부·환급', '납부·환급', 'accounts', 'hometax-tax'],
    ['notices', '전자고지', '전자고지', 'bill', 'hometax-tax']]},
};
const COMMON = [['activity', '전체 작업 기록', '작업', 'activity'], ['settings', '연결·인증서', '설정', 'shield'],
  ['coverage', '전체 기능·지원 상태', '전체 기능', 'grid']];
/* Screens opened from another screen's tabs or buttons: [area, the menu entry they sit under, title]. */
const NESTED = {invoiceform: ['tax', 'invoices', '계산서 작성'], payments: ['tax', 'dues', '납부 내역'], refunds: ['tax', 'dues', '환급금'],
  reports: ['tax', 'returns', '저장한 문서'], bills: ['giro', 'girostatus', '고지서 자료'], deadlines: ['giro', 'girostatus', '납부 기한'],
  'giro-pay': ['giro', 'giro-receipts', '납부내역']};
const common = view => COMMON.some(([id]) => id === view);
/* Area screens that work without an institution session: offline Giro tools and saved documents. */
const NO_SESSION = ['girostatus', 'bills', 'deadlines', 'reports'];
const known = view => common(view) || view in NESTED || Object.values(AREAS).some(a => a.items.some(i => i[0] === view));

function stored(key, fallback) {
  try { return JSON.parse(sessionStorage.getItem('finance.' + key)) ?? fallback; } catch (error) { return fallback; }
}
function store(key, value) {
  try { sessionStorage.setItem('finance.' + key, JSON.stringify(value)); } catch (error) { /* per-tab convenience only */ }
}
/* A choice that holds for this browser, across its tabs and restarts. */
function storedLocal(key, fallback) {
  try { return JSON.parse(localStorage.getItem('finance.' + key)) ?? fallback; } catch (error) { return fallback; }
}
function storeLocal(key, value) {
  try { localStorage.setItem('finance.' + key, JSON.stringify(value)); } catch (error) { /* the choice then lasts for this page only */ }
}

export const state = {
  server: null, profiles: [], logins: [], targets: [], credentials: [], capabilities: null,
  profileId: stored('profile', 'all'), mode: stored('mode', 'tax'), view: null, lastViews: stored('views', {}),
  token: 0, cache: new Map(), params: {}, rows: {}, hidden: false, vaults: {},
  autoExtend: storedLocal('autoExtend', false) === true,
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
  scheduleExtensions();
}

async function refreshLogins() {
  const value = await api.get('/logins');
  state.logins = value.logins;
  state.sessionClock = {server: value.server_time, local: Date.now() / 1000};
  renderTabs();
  renderLoginNotice();
  scheduleExtensions();
  return value;
}

function serverNow() {
  const clock = state.sessionClock;
  return clock?.server === undefined ? Date.now() / 1000 : clock.server + Date.now() / 1000 - clock.local;
}

/* Institutions whose sessions follow the local idle limit; the server sends each deadline. */
const IDLE_INSTITUTIONS = ['hana', 'hana_corporate', 'giro', 'hometax'];
const LISTS = ['accounts', 'settings', 'corporate-accounts', 'giro-live', 'giro-receipts', 'giro-accounts'];

export function bankSessionExpired(row) {
  if (!IDLE_INSTITUTIONS.includes(row?.institution) || !row.session?.idle_expires_at) return false;
  return serverNow() >= row.session.idle_expires_at;
}

function areaLogins(mode) {
  const institution = AREAS[mode].institution;
  return institution === 'giro' ? state.logins.filter(l => l.institution === 'giro' && !l.disabled) : scopeLogins(institution);
}

/* Logins of an area whose recorded session is usable (or query-only) and inside the local
   bank idle limit. This reads local metadata only; the institution is not asked. */
function liveLogins(mode) {
  return areaLogins(mode).filter(l => ['ready', 'query_only'].includes(l.readiness) && !bankSessionExpired(l));
}

/* A work screen of an area whose logins are all logged out says so under its heading and offers
   the login there, by the same local records as the tab mark. An area with no connection yet
   keeps its screens' own first-connection guidance. */
function loginNotice() {
  if (!state.view || common(state.view) || NO_SESSION.includes(state.view)) return '';
  const area = AREAS[state.mode], rows = areaLogins(state.mode);
  if (!rows.length || liveLogins(state.mode).length) return '';
  const buttons = rows.map(row => ui.button(rows.length > 1 ? `${row.display_name} 로그인` : '로그인',
    `data-action="login" data-login="${ui.esc(row.id)}"`, 'primary')).join('');
  return `<div class="login-notice" role="status">${ui.icon('info')}<p><strong>${ui.esc(ui.INSTITUTION[area.institution])}에 로그인되어 있지 않아요.</strong> ${area.guide}</p><div class="login-notice-actions">${buttons}</div></div>`;
}

/* A work screen of an area with a live login offers a new login beside its heading: the one place
   for it on every screen, as the notice under the heading is the one place for a logged-out area. */
function sessionActions() {
  if (!state.view || common(state.view) || NO_SESSION.includes(state.view)) return '';
  const rows = liveLogins(state.mode);
  return rows.map(row => ui.button(rows.length > 1 ? `${row.display_name} 다시 로그인` : '다시 로그인',
    `data-action="login" data-login="${ui.esc(row.id)}"`)).join('');
}

/* A tab keeps running the files it was loaded with. Once the server answers from a newer copy the
   screen says so and leaves the reload to the person, who may be in the middle of typing. */
function outdatedNotice() {
  if (!state.outdated) return '';
  return `<div class="login-notice outdated" role="status">${ui.icon('refresh')}<p><strong>새 버전이 배포됐어요.</strong> 이 탭은 이전 화면으로 동작하고 있어요. 입력하던 내용을 마친 뒤 새로고침하세요.</p><div class="login-notice-actions">${ui.button('새로고침', 'data-ui="reload"', 'primary')}</div></div>`;
}

export function outdated() {
  state.outdated = true;
  renderLoginNotice();
}

/* Drawn apart from the screen itself, so a logout shows at once without redrawing a form. */
export function renderLoginNotice() {
  const page = main();
  if (!page) return;
  page.querySelectorAll('.login-notice,.session-actions').forEach(node => node.remove());
  const heading = page.querySelector('.page-heading');
  const html = outdatedNotice() + loginNotice();
  if (html) { if (heading) heading.insertAdjacentHTML('afterend', html); else page.insertAdjacentHTML('afterbegin', html); }
  const actions = sessionActions(), slot = heading?.querySelector('.heading-actions');
  if (actions && slot) slot.insertAdjacentHTML('beforeend', `<span class="session-actions">${actions}</span>`);
}

let tabTimer = null;
let countdownTimer = null;

/* Time left until a tab's nearest idle limit, as m:ss. Text only; the tabs are not redrawn. */
function tick() {
  const nodes = document.querySelectorAll('.tab-countdown');
  if (!nodes.length) { clearInterval(countdownTimer); countdownTimer = null; return; }
  for (const node of nodes) {
    const left = Math.max(0, Math.ceil(Number(node.dataset.deadline) - serverNow()));
    node.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
    node.classList.toggle('soon', left <= EXTEND_LEAD);
  }
}

/* The idle limit passed with no request: from here on the session counts as logged out. */
async function sessionLapsed() {
  renderTabs();
  renderLoginNotice();
  await refreshLogins().catch(() => {});
  ui.toast('유휴 제한 시간 동안 요청이 없어 로그아웃 처리됐어요. 계속하려면 다시 로그인하세요.');
  // Screens that list sessions show it at once; a screen with a form or an open dialog is left as it
  // is, and so is one held by a running request, whose own completion draws it.
  if (LISTS.includes(state.view) && !document.querySelector('#detail-dialog')?.open && !busy.blocking()) render();
}

/* Area tabs at the top of the main page; an area with a live login has a lit icon
   with a check, a state of the tab itself rather than a notification badge, and a small
   countdown to the nearest idle limit of its sessions. */
export function renderTabs() {
  const target = document.querySelector('.area-tabs');
  if (!target) return;
  const expiries = [];
  target.innerHTML = Object.entries(AREAS).map(([key, area]) => {
    const rows = liveLogins(key);
    const limits = rows.map(l => l.session?.idle_expires_at).filter(Boolean);
    expiries.push(...limits);
    const countdown = limits.length ? `<small class="tab-countdown" data-deadline="${Math.min(...limits)}" title="세션 만료까지 남은 시간"></small>` : '';
    const live = rows.length ? ' · 로그인됨' : '';
    return `<button class="area-tab${rows.length ? ' live' : ''}" data-mode="${key}" ${key === state.mode && !common(state.view) ? 'aria-current="true"' : ''} aria-label="${ui.esc(area.name + live)}" title="${ui.esc(area.service + live)}"><span class="workspace-icon">${ui.icon(area.icon)}${rows.length ? `<i class="session-mark">${ui.icon('check')}</i>` : ''}</span><span class="full">${ui.esc(area.name)}</span><span class="short">${ui.esc(area.short)}</span>${countdown}</button>`;
  }).join('');
  tick();
  if (expiries.length && !countdownTimer) countdownTimer = setInterval(tick, 1000);
  clearTimeout(tabTimer);
  // The bank idle limit passes without any request; drop the mark when it does.
  if (expiries.length) tabTimer = setTimeout(sessionLapsed, Math.max(0, Math.min(...expiries) - serverNow()) * 1000 + 500);
}

/* Automatic login extension. A per-browser choice: while this app is open, a login whose
   session has a local idle limit is extended once, shortly before the limit, with the
   institution's own extension job. Nothing is retried: an extension that is refused or does not
   succeed stops the automatic extension of that session, which then ends at its limit. */
const EXTEND_LEAD = 90;            // seconds before the idle limit
const extendTimers = new Map();    // login id -> timer
const extending = new Set();       // login ids with an extension in flight
const extendStopped = new Map();   // session id -> why its automatic extension stopped
const extendAfter = new Map();     // login id -> do not try again before (ms)

/* The extension job of a login, by the naming rule <module>.session.extend; null while the
   institution module has no extension request. */
export function extensionJob(row) {
  const module = {hometax: 'hometax', hana: row?.method === 'onesign' ? 'hana.onesign' : 'hana',
    hana_corporate: 'hana.corporate', giro: 'giro'}[row?.institution];
  const name = module + '.session.extend';
  return module && state.capabilities?.jobs?.includes(name) ? name : null;
}

/* What the automatic extension means for one login right now: 'none' (no session with an idle
   limit), 'unsupported', 'off', 'stopped', 'locked' (its OneSign store is not remembered) or 'on'. */
export function extensionState(row) {
  if (!row?.session?.idle_expires_at || bankSessionExpired(row) || !['ready', 'query_only'].includes(row.readiness)) return 'none';
  if (!extensionJob(row)) return 'unsupported';
  if (!state.autoExtend) return 'off';
  if (extendStopped.has(row.current_session_id)) return 'stopped';
  if (needsStore(row) && !state.vaults[onesignStore(row)]) return 'locked';
  return 'on';
}

/* Only a personal OneSign extension opens the sealed store; its passphrase must be remembered. */
const needsStore = row => row.institution === 'hana' && row.method === 'onesign';

export function setAutoExtend(on) {
  state.autoExtend = Boolean(on);
  storeLocal('autoExtend', state.autoExtend);
  if (state.autoExtend) { extendStopped.clear(); extendAfter.clear(); }  // turning it on is a new, explicit choice
  scheduleExtensions();
}

function scheduleExtensions() {
  for (const timer of extendTimers.values()) clearTimeout(timer);
  extendTimers.clear();
  if (!state.autoExtend) return;
  for (const row of state.logins) {
    if (extending.has(row.id) || extensionState(row) !== 'on') continue;
    const due = (row.session.idle_expires_at - EXTEND_LEAD - serverNow()) * 1000;
    const wait = Math.max(0, due, (extendAfter.get(row.id) || 0) - Date.now());
    extendTimers.set(row.id, setTimeout(() => extendLogin(row.id), wait));
  }
}

/* Only one tab of this browser sends the extension of a session. */
function claimExtension(row) {
  const key = 'finance.extending:' + row.current_session_id;
  try {
    const held = Number(localStorage.getItem(key));
    if (held && Date.now() - held < 60000) return false;
    localStorage.setItem(key, String(Date.now()));
  } catch (error) { /* without shared storage each tab decides alone */ }
  return true;
}

function stopExtension(row, reason) {
  extendStopped.set(row.current_session_id, reason);
  ui.toast(`${row.display_name}: 자동 로그인 연장이 되지 않았어요 (${reason}). 다시 시도하지 않으며, 이 세션은 만료 시각에 로그아웃 처리돼요.`);
  if (LISTS.includes(state.view) && !document.querySelector('#detail-dialog')?.open && !busy.blocking()) render();
}

export async function extendLogin(id) {
  if (extending.has(id)) return;
  extending.add(id);
  try {
    // Another tab or a query may have moved the limit: decide on the server's current record.
    await refreshLogins().catch(() => {});
    const row = login(id);
    if (!row || extensionState(row) !== 'on') return;
    if (row.session.idle_expires_at - serverNow() > EXTEND_LEAD + 5) return;
    if (!claimExtension(row)) { extendAfter.set(id, Date.now() + 20000); return; }
    let job;
    try {
      // A remembered OneSign store passphrase is supplied by the server, never by the browser.
      // Nobody asked for this request at the screen, so it does not hold the screen.
      job = await submit(extensionJob(row), {login_id: id, ...(needsStore(row) ? {secrets: {}} : {})}, {hold: false});
    } catch (error) {
      // Busy: another job is using this session right now, and its own request moves the limit.
      if (error.code === 'resource_busy') extendAfter.set(id, Date.now() + 20000);
      else if (error.code !== 'session_idle_expired') stopExtension(row, ui.message(error.code));
      return;
    }
    const final = await follow(job.id, null).catch(() => null);
    await refreshLogins().catch(() => {});
    // A Hometax command saves its session under a new id: stop the session the login points to now.
    const current = login(id);
    if (final?.outcome !== 'success')
      stopExtension(current?.current_session_id ? current : row, final ? ui.OUTCOME[final.outcome]?.[0] || final.status : '결과 미확인');
  } finally {
    extending.delete(id);
    scheduleExtensions();
  }
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

/* Jobs that send on an existing session of an idle-limited institution. A login makes a new
   session and a local step sends nothing, so an expired session stops neither. */
function usesBankSession(name) {
  if (!/^(hana|giro|hometax)\./.test(name)) return false;
  return !/(^|\.)login(-[a-z]+)?$/.test(name) && !name.endsWith('.history.export')
    && !['giro.bills.parse', 'giro.readiness', 'hometax.report.resave'].includes(name);
}

export function setProfile(id) {
  state.profileId = id;
  store('profile', id);
  state.token += 1;  // Late answers for the previous profile are dropped.
}

function title() {
  const entry = [...Object.values(AREAS).flatMap(a => a.items), ...COMMON].find(i => i[0] === state.view);
  return entry ? entry[1] : NESTED[state.view]?.[2] || 'Finance';
}

function renderChrome() {
  const area = AREAS[state.mode];
  const items = navigation(state.mode);
  renderTabs();
  // A shared screen belongs to no area; the menu beside it is the area last worked in.
  document.querySelector('.workspace-label').textContent = common(state.view) ? `최근 영역 · ${area.short}` : area.service;
  const here = entry => state.view === entry.id || NESTED[state.view]?.[1] === entry.id;
  const item = (entry, mobile = false) => `<button class="nav-item ${here(entry) ? 'active' : ''} ${entry.available ? '' : 'unavailable'}" ${entry.available ? `data-view="${entry.id}"` : 'disabled aria-disabled="true"'} ${here(entry) ? 'aria-current="page"' : ''}>${ui.icon(entry.icon)}<span>${ui.esc(mobile ? entry.short : entry.name)}</span>${entry.available ? '' : '<small class="soon-label">준비 중</small>'}</button>`;
  document.querySelector('.main-nav').innerHTML = items.map(e => item(e)).join('');
  document.querySelector('.common-nav').innerHTML = COMMON.map(([id, name, , iconName]) => item({id, name, icon: iconName, available: true})).join('');
  document.querySelector('.bottom-nav').innerHTML = items.filter(e => e.available).slice(0, 4).map(e => item(e, true)).join('')
    + `<button class="nav-item" data-ui="more" aria-haspopup="dialog">${ui.icon('grid')}<span>전체 메뉴</span></button>`;
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

/* `by` is the context of the action that asks for this redraw. It stays current, so the next step
   of that action still reaches the screen; a context whose screen was already left is not revived. */
export async function render(by = null) {
  const own = by?.current?.();
  const token = ++state.token;
  if (own) by.token = token;
  renderChrome();
  const view = views[state.view];
  if (!view) return;
  const context = makeContext(token);
  try {
    const html = await view(context);
    if (token !== state.token) return;
    main().innerHTML = html;
    renderLoginNotice();
    context.after.forEach(fn => fn());
  } catch (error) {
    if (token !== state.token) return;
    main().innerHTML = ui.heading(title(), '') + ui.note(ui.message(error.code || 'local_processing_error'));
    renderLoginNotice();
  }
}

export function changeView(view, params = {}, {push = true} = {}) {
  const owner = Object.keys(AREAS).find(mode => AREAS[mode].items.some(i => i[0] === view)) || NESTED[view]?.[0];
  const entry = navigation(owner || state.mode).find(i => i.id === view);
  if (entry && !entry.available) return;
  if (!owner && !common(view)) return;
  if (owner) {
    state.mode = owner;
    store('mode', owner);
    state.lastViews[viewKey()] = view;
    store('views', state.lastViews);
  }
  // The browser's back button returns to the previous screen instead of leaving the app.
  if (push && view !== state.view) history.pushState({view}, '', '#' + view);
  state.view = view;
  state.params = params;
  ui.closeDialog();
  busy.during('화면을 불러오고 있어요', render(), {quiet: true}).then(() => {
    // A wide screen scrolls the page itself; a narrow one scrolls the shell.
    for (const box of [document.scrollingElement, document.querySelector('.main-shell')]) box?.scrollTo?.({top: 0});
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

/* Remembering opens the store for every later job, transfers included, so a login, query or
   transfer dialog leaves it to the user. The issuance wizard asks for the passphrase at each of
   its steps and offers it already chosen (`chosen`). */
export function rememberField(fields, store, {chosen = false} = {}) {
  return store && fields.some(([name]) => name === 'vault_passphrase')
    ? `<label class="check"><input type="checkbox" name="remember_vault"${chosen ? ' checked' : ''}> 서버를 끌 때까지 이 저장소 암호 기억 (서버 메모리에만, 이체 포함)</label>` : '';
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

/* The name a job is shown under before the server has answered. */
function jobTitle(name) {
  return state.capabilities?.features?.flatMap(f => f.jobs || []).find(j => j.name === name)?.title || '';
}

function makeContext(token) {
  const context = {
    state, token, after: [], params: state.params,
    current: () => context.token === state.token,
    later: fn => context.after.push(fn),
    render, changeView, scopeTargets, scopeLogins, login, target, profile, feature, askSecrets,
    async refresh() { await refreshModel(); await render(); },
    /* Submit a job and follow it. The screen is held from the press until the job is over or waits
       for the user; the job's own line also goes to the element with the given id. */
    async run(name, fields, {panel, key, onDone, secrets} = {}) {
      let job, held;
      try {
        if (usesBankSession(name) && !await ensureBankSession(context, fields.login_id)) return null;
        held = busy.hold(jobTitle(name));
        held.update('접수 중');
        job = await submit(name, {...fields, ...(secrets ? {secrets} : {}), profile_id: profile()?.id || undefined});
      } catch (error) {
        held?.release();
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
      return context.track(job, {panel, key, onDone, held});
    },
    /* Follow a job to its end. `hold: true` holds the screen for a job the user just sent on (a
       confirmation); a job a screen merely finds running is shown without holding anything. */
    async track(job, {panel, key, onDone, held, hold} = {}) {
      if (hold && !held) held = busy.hold(job.title || jobTitle(job.name));
      if (key) state.cache.set(key, job);
      const update = value => {
        if (key) state.cache.set(key, value);
        held?.update(ui.STATUS[value.status]?.[0], value.title);
        const target = document.getElementById(panel);
        if (target && context.current()) target.innerHTML = jobState(value);
      };
      update(job);
      const final = await follow(job.id, update, () => true).catch(error => {
        ui.fail(ui.message(error.code));
        return null;
      });
      const bank = /^(hana|giro|hometax)\./.test(final?.name || '') && final.login_id;
      if (bank) await refreshLogins().catch(() => {}); // A display refresh cannot change the job's outcome.
      // The screen opens before anything that follows asks the user for more.
      held?.release();
      if (bank && final.local?.stopped === 'session_idle_expired' && context.current()) {
        await expiredBankLogin(context, final.login_id);
        return null;
      }
      if (final && context.current()) await onDone?.(final);
      // Its screen was left meanwhile: the result is still said, and the screen shows it when reopened.
      else if (final && held) ui.toast(`${final.title || final.name}: ${ui.outcomeLabel(final)[0]}`);
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
  // A plain success needs no badge. Every other status or verdict stays in view; the
  // support level and the request origin are in the job detail.
  const plain = job.status === 'finished' && job.outcome === 'success';
  const when = job.observed_at ? ui.time(job.observed_at) + ' 조회' : ui.time(job.created_at) + ' 접수';
  const origin = job.origin && job.origin !== 'web' ? ` · ${ui.ORIGIN[job.origin] || ui.esc(job.origin)} 요청` : '';
  return `<div class="job-state">${busy ? '<span class="spinner" aria-hidden="true"></span>' : ''}${plain ? '' : ui.statusTags(job)}<span>${fixed}${when}${origin}${stopped}${saved}</span><button class="text-button" data-action="job-detail" data-job="${ui.esc(job.id)}">작업 상세 ${ui.icon('arrow')}</button></div>`;
}

/* Job detail with the institution verdict, reconciliation and local state kept apart. */
export async function showJob(id) {
  let job;
  try { job = await busy.during('작업 상세를 불러오고 있어요', api.get('/jobs/' + encodeURIComponent(id)), {quiet: true}); }
  catch (error) { ui.fail(ui.message(error.code)); return; }
  const fixed = job.fixed || {};
  const lines = [
    ['작업', job.title], ['진행 상태', ui.STATUS[job.status]?.[0] || job.status],
    ['업무 결과', ui.outcomeLabel(job)[0]], ['요청한 곳', ui.ORIGIN[job.origin] || job.origin],
    ['로그인', fixed.login?.display_name], ['대상', fixed.target ? `${fixed.target.display_name} (${ui.KIND[fixed.target.kind] || fixed.target.kind})` : null],
    ['프로필', fixed.profile?.name], ['접수 시각', ui.time(job.created_at)], ['기관 응답 시각', ui.time(job.observed_at)],
    ['지원 상태', ui.VERIFICATION[job.verification]?.[0]],
  ].filter(([, v]) => v);
  const artifacts = (job.artifacts || []).map(a => `<div class="setting-row"><span>${ui.esc(a.filename)}${a.complete === 0 ? ' · 확인 필요' : a.complete === 1 ? ' · 완전' : ''}</span><span class="row-actions">${a.media_type.startsWith('text/html') ? `<button class="text-button" data-action="preview-artifact" data-artifact="${ui.esc(a.id)}">보기</button>` : ''}<a class="text-button" href="/api/v1/artifacts/${encodeURIComponent(a.id)}">${ui.icon('download')}저장</a></span></div>`).join('');
  const cancellable = (job.status === 'queued' || job.status === 'awaiting_input') && !job.attempt?.sent;
  const reconcile = job.name === 'hana.transfer.prepare' && job.status === 'finished' && job.attempt?.sent && ['execute', 'execute_pin'].includes(job.step);
  // A prepared transfer is confirmed on the login session it was prepared in, not after a newer login.
  const resume = job.name === 'hana.transfer.prepare' && job.status === 'awaiting_input' && job.session_id === login(job.login_id)?.current_session_id;
  ui.showDialog('작업 상세', `<div class="summary-lines">${lines.map(([k, v]) => `<div class="summary-line"><span>${ui.esc(k)}</span><strong>${ui.esc(v)}</strong></div>`).join('')}</div>${job.local?.stopped ? `<p class="dialog-note">${ui.message(job.local.stopped)}</p>` : ''}${ui.details('기관 판정 (원문 필드)', job.service_verdict)}${ui.details('결과 재조회', job.reconciliation)}${ui.details('로컬 처리 상태', job.local)}${ui.details('처리 순서', job.events?.map(e => ({시각: ui.time(e.at), 단계: e.kind, ...e.detail})))}${artifacts ? `<div class="settings-body">${artifacts}</div>` : ''}<div class="dialog-actions">${cancellable ? `<button class="button secondary" data-action="cancel-job" data-job="${ui.esc(job.id)}">작업 취소</button>` : ''}${job.name === 'giro.payment.prepare' ? `<button class="button secondary" data-action="giro-payment-open" data-job="${ui.esc(job.id)}">${job.status === 'awaiting_input' ? '납부 내용 확인' : '납부 결과 보기'}</button>` : ''}${job.name === 'hana.corporate.transfer.prepare' ? `<button class="button secondary" data-action="corporate-transfer-open" data-job="${ui.esc(job.id)}">${job.status === 'awaiting_input' ? '이체 이어하기' : '이체 결과 보기'}</button>` : ''}${resume ? `<button class="button secondary" data-action="transfer-open" data-job="${ui.esc(job.id)}">이체 이어하기</button>` : ''}${reconcile ? `<button class="button secondary" data-action="reconcile" data-job="${ui.esc(job.id)}">이체 결과 조회</button>` : ''}<button class="button primary" data-ui="close">닫기</button></div>`, {wide: true});
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
  // An address with a screen name opens that screen. With nothing connected yet, start at the
  // connection screen and its first-time steps rather than an empty work screen.
  const asked = decodeURIComponent(location.hash.slice(1));
  const start = known(asked) ? asked : !state.logins.length ? 'settings' : state.lastViews[viewKey()] || AREAS[state.mode].home;
  const first = navigation(state.mode).find(i => i.id === start)?.available === false ? 'coverage' : start;
  history.replaceState({view: first}, '', '#' + first);
  changeView(first, {}, {push: false});
}

window.addEventListener('popstate', event => {
  const view = event.state?.view || decodeURIComponent(location.hash.slice(1));
  if (known(view) && document.querySelector('#stage') && !document.querySelector('#stage').hidden) changeView(view, {}, {push: false});
});

/* Whatever an action could not handle itself is said on the screen, never lost. */
function report(error) {
  if (!error?.code) console.error(error);
  ui.fail(ui.message(error?.code || 'screen_processing_error'));
}

document.addEventListener('click', async event => {
  const target = event.target.closest('button,a,tr[data-row]');
  if (!target || target.disabled) return;
  if (target.dataset.view) {
    event.preventDefault();
    changeView(target.dataset.view === 'home' ? AREAS[state.mode].home : target.dataset.view);
    return;
  }
  // Only an area tab switches area; other buttons may carry their own mode value for an action.
  if (target.matches('.area-tab') && AREAS[target.dataset.mode]) { changeMode(target.dataset.mode); return; }
  if (target.dataset.profile) {
    setProfile(target.dataset.profile);
    ui.closeDialog();
    changeView(state.lastViews[viewKey()] || state.view || AREAS[state.mode].home);
    return;
  }
  switch (target.dataset.ui) {
    case 'close': ui.closeDialog(); return;
    case 'choose-profile': chooseProfile(); return;
    case 'more': moreMenu(); return;
    case 'reload': location.reload(); return;
  }
  const action = target.dataset.action || (target.dataset.row ? 'row' : null);
  if (action === 'job-detail') { showJob(target.dataset.job); return; }
  if (action && actions[action]) {
    if (target.tagName === 'BUTTON') target.disabled = true;
    try { await actions[action](makeContext(state.token), target, event); }
    catch (error) { report(error); }
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
    catch (error) { report(error); }
    finally { if (button?.isConnected) button.disabled = false; }
  }
});

document.addEventListener('change', event => {
  const name = event.target.dataset.change;
  if (!name || !actions[name]) return;
  try { Promise.resolve(actions[name](makeContext(state.token), event.target, event)).catch(report); }
  catch (error) { report(error); }
});

document.querySelector('#detail-dialog').addEventListener('click', event => {
  const dialog = event.currentTarget;
  // A dialog that holds a form closes only through its own buttons, so a stray click outside
  // cannot throw away what was typed.
  if (event.target === dialog && !dialog.querySelector('form')) {
    const rect = dialog.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) ui.closeDialog();
  }
});

/* A table that does not fit its panel is drawn as labelled rows instead of being cut off at the
   edge: always on a narrow screen and, on a wider one, whenever its columns overflow. A table is
   measured once as it arrives, before it is painted, and again when the window changes size. */
function fitTables(again = false) {
  const narrow = (document.querySelector('#stage')?.clientWidth || 0) <= 700;
  for (const wrap of document.querySelectorAll(again ? '.table-wrap' : '.table-wrap:not([data-fit])')) {
    wrap.dataset.fit = '1';
    wrap.classList.remove('stacked');
    if (narrow || wrap.scrollWidth > wrap.clientWidth + 1) wrap.classList.add('stacked');
  }
}
// The server names its copy of the app on every answer; a tab that comes back into view asks once.
api.onOutdated?.(outdated);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && !state.outdated && state.server?.enrolled) api.get('/auth/state').catch(() => {});
});

const arriving = new MutationObserver(() => fitTables());
for (const box of [main(), document.querySelector('#dialog-content')]) if (box) arriving.observe(box, {childList: true, subtree: true});
window.addEventListener('resize', () => fitTables(true));

export {api, submit, follow, TERMINAL, ApiError};
boot();
