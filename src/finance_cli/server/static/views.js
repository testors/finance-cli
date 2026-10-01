/* Screens. Every institution request is a server job; results show their fixed
   target, observation time and the institution's own verdict. Nothing here
   infers success, due dates, balances or payment state that the job did not return. */
import {api, submit} from './api.js';
import * as ui from './ui.js';
import {certificateActions} from './certificates.js';
import {applyRemember, askSecrets, bankSessionExpired, changeView, ensureBankSession, expiredBankLogin, jobState, login, onesignStore, profile, refreshModel, rememberField,
  render, scopeLogins, scopeTargets, SECRET_LABELS, secretFields, showJob, state, target} from './app.js';

const {esc, icon, tag, note, heading, money} = ui;

const REASONS = {hometax_runtime_not_installed: '홈택스 실행 환경 미설치 (서버에서 fin runtime install hometax)',
  node_not_found: '서버에 Node 없음', jdk_17_or_later_required: '계산서 서명용 JDK 17 이상 필요',
  web_job_not_implemented: '웹 작업 미구현'};
const BANKS = [['081', '하나은행'], ['004', 'KB국민은행'], ['088', '신한은행'], ['020', '우리은행'], ['011', 'NH농협은행'],
  ['003', 'IBK기업은행'], ['023', 'SC제일은행'], ['027', '한국씨티은행'], ['031', '대구은행'], ['032', '부산은행'],
  ['034', '광주은행'], ['035', '제주은행'], ['037', '전북은행'], ['039', '경남은행'], ['045', '새마을금고'], ['048', '신협'],
  ['071', '우체국'], ['089', '케이뱅크'], ['090', '카카오뱅크'], ['092', '토스뱅크']];

function setupNotice(featureId) {
  const item = state.capabilities?.features.find(f => f.id === featureId);
  if (!item || item.status !== 'setup_required') return '';
  return note('설정이 필요해요: ' + item.reasons.map(r => esc(REASONS[r] || r)).join(', '));
}

function canQuery(row) { return ['ready', 'query_only'].includes(row.readiness); }

function readiness(row) {
  if (bankSessionExpired(row)) return tag('세션 만료 · 다시 로그인', 'warning');
  const value = row.readiness;
  return value === 'query_only' ? tag('조회용 세션 있음', '') : value === 'ready' ? tag('세션 있음', '') : value === 'login_disabled' ? tag('사용 중지', 'neutral') : tag('로그인 필요', 'warning');
}

const key = (name, fields = {}) => [name, fields.login_id || '', fields.target_id || '', fields.parent || ''].join('|');

/* The latest job for a name and fixed login/target, from this tab or the server. */
async function latest(name, fields = {}) {
  const cached = state.cache.get(key(name, fields));
  if (cached) return cached.result === undefined && cached.status === 'finished' ? api.get('/jobs/' + cached.id) : cached;
  const listing = await api.get('/jobs?limit=200');
  const match = listing.jobs.find(j => j.name === name && (!fields.login_id || j.login_id === fields.login_id)
    && (!fields.target_id || j.target_id === fields.target_id));
  if (!match) return null;
  const job = await api.get('/jobs/' + match.id);
  state.cache.set(key(name, fields), job);
  return job;
}

function panel(id, job) {
  return `<div id="${id}" class="job-panel">${job ? jobState(job) : ''}</div>`;
}

function empty(text, actions = '') {
  return `<section class="panel"><div class="empty-state">${text}${actions ? `<div class="section-actions">${actions}</div>` : ''}</div></section>`;
}

function outcomeNote(job, zeroText = '조회 결과가 0건이에요.') {
  if (!job || job.status !== 'finished') return '';
  const verdict = job.service_verdict || {};
  if (job.outcome === 'unknown') return note(`기관의 최종 판정을 확인하지 못했어요${verdict.reason ? ` (${esc(verdict.reason)})` : ''}. 서비스 이용 불가 시간대일 수 있으며, 0건이나 실패로 처리하지 않았어요.`);
  if (job.outcome === 'rejected') return note(`기관이 실패로 판정했어요${verdict.reason ? ` (${esc(verdict.reason)})` : ''}.`);
  if (job.outcome === 'not_started') return note(ui.message(job.local?.stopped) || '업무를 실행하지 않았어요.');
  if (job.outcome === 'partial_success') return note('일부만 성공했어요. 받은 부분만 표시하며 나머지는 확인이 필요해요.');
  return '';
}

function rememberRows(group, rows, extra = {}) {
  state.rows[group] = {rows: rows || [], ...extra};
}

// Tax ------------------------------------------------------------------------

function taxTargets() {
  return scopeTargets(['personal', 'business']).filter(t => login(t.login_id)?.institution === 'hometax');
}

function taxTarget() {
  const list = taxTargets();
  let id;
  try { id = sessionStorage.getItem('finance.taxTarget:' + state.profileId); } catch (error) { id = null; }
  return list.find(t => t.id === id) || list[0] || null;
}

function targetBar(list, current) {
  const owner = current ? login(current.login_id) : null;
  return `<div class="target-bar"><div>${icon('business')}<span>조회 대상</span><label class="sr-only" for="tax-target">홈택스 사용자·사업장 선택</label><select id="tax-target" data-change="choose-tax-target">${list.map(t => `<option value="${esc(t.id)}" ${t.id === current?.id ? 'selected' : ''}>${esc(t.display_name)} · ${esc(ui.KIND[t.kind])} (${esc(login(t.login_id)?.display_name)})</option>`).join('')}</select></div><div>${owner ? readiness(owner) : ''}<button class="text-button" data-view="settings">대상·로그인 관리 ${icon('arrow')}</button></div></div>`;
}

function noTaxTarget() {
  return empty('이 프로필에 홈택스 대상이 없어요. 연결·인증서에서 홈택스 로그인 후 사용자·사업장을 확인해 등록하고 프로필에 넣으세요.',
    `<button class="button primary" data-view="settings">연결·인증서</button>`);
}

const TAX = {
  dues: {name: 'hometax.tax.dues', title: '납부할 세액', sub: '홈택스의 납부할 세액을 조회해요.', fields: []},
  payments: {name: 'hometax.tax.payments', title: '납부 내역', sub: '기간별 납부 내역을 조회해요.', fields: ['period', 'pages',
    ['payment_type', '납부 구분', [['', '전체(기본)'], ['03', '홈택스 납부']]]]},
  refunds: {name: 'hometax.tax.refunds', title: '환급금', sub: '환급금 지급 상태를 조회해요.', fields: ['period', 'pages',
    ['refund_status', '지급 상태', [['', '전체'], ['1', '지급 완료'], ['2', '미수령'], ['3', '1년 경과 미수령']]]]},
  notices: {name: 'hometax.tax.notices', title: '전자고지', sub: '전자고지를 조회해요. 열람 상태는 서비스 기준이에요.', fields: ['period',
    ['notice_type', '고지 유형', [['', '서비스 기본'], ['01', '고지서'], ['02', '독촉장']]],
    ['read_status', '열람 상태', [['', '미열람(기본)'], ['all', '전체'], ['01', '열람']]]]},
};

function queryForm(view, spec) {
  const today = new Date().toISOString().slice(0, 10);
  const start = new Date(Date.now() - 1000 * 86400 * 180).toISOString().slice(0, 10);
  const fields = spec.fields.map(field => {
    if (field === 'period') return `<label class="field-inline">시작일<input type="date" name="from" value="${start}"></label><label class="field-inline">종료일<input type="date" name="to" value="${today}"></label>`;
    if (field === 'pages') return `<label class="field-inline check"><input type="checkbox" name="all_pages">전체 페이지</label>`;
    const [name, label, options] = field;
    return `<label class="field-inline">${esc(label)}<select name="${name}">${options.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('')}</select></label>`;
  }).join('');
  return `<form class="filter-bar" data-submit="tax-query" data-view="${view}">${fields}<button class="button primary" type="submit">${icon('refresh')}조회</button></form>`;
}

function formInput(form) {
  const data = new FormData(form);
  const value = {};
  for (const [k, v] of data.entries()) {
    if (v === '' || v === null) continue;
    value[k] = v === 'on' ? true : v;
  }
  for (const checkbox of form.querySelectorAll('input[type=checkbox]')) value[checkbox.name] = checkbox.checked;
  return value;
}

function taxResults(job, group) {
  if (!job) return '<div class="empty-state">아직 조회하지 않았어요. 조회를 누르면 서버 작업으로 실행해요.</div>';
  if (job.status !== 'finished') return '';
  const items = job.result?.items;
  rememberRows(group, items, {job});
  const pagination = job.result?.pagination;
  return outcomeNote(job) + (items ? ui.rowsTable(items, {group}) : '') +
    (pagination ? `<div class="list-footer">${items?.length ?? 0}건 · ${pagination.complete ? '마지막 페이지까지 확인' : '페이지 확인 필요'}${pagination.reason ? ' · ' + esc(pagination.reason) : ''}</div>` : '');
}

async function taxList(ctx, view) {
  const spec = TAX[view];
  const list = taxTargets();
  const current = taxTarget();
  if (!current) return heading(spec.title, spec.sub) + setupNotice('hometax-tax') + noTaxTarget();
  const job = await latest(spec.name, {target_id: current.id});
  if (job && !['finished', 'cancelled', 'expired', 'awaiting_input'].includes(job.status)) ctx.later(() => follow(ctx, job, view));
  return heading(spec.title, spec.sub) + setupNotice('hometax-tax') + targetBar(list, current) +
    (view === 'dues' ? note('납부 실행은 지원하지 않아요. 서비스 중지 시간(00:00–06:59, 23:30–23:59)의 응답은 0건과 구별해 표시해요.') : '') +
    `<section class="panel"><div class="panel-heading"><h2>${esc(spec.title)}</h2>${ui.verification('live_untested')}</div>${queryForm(view, spec)}${panel('job-panel', job)}<div id="results">${taxResults(job, view)}</div></section>`;
}

function follow(ctx, job, group, renderer = taxResults) {
  return ctx.track(job, {panel: 'job-panel', key: key(job.name, {target_id: job.target_id, login_id: job.login_id}),
    onDone: done => { const box = document.getElementById('results'); if (box) box.innerHTML = renderer(done, group); }});
}

async function runTax(ctx, name, input, group, renderer = taxResults) {
  const current = taxTarget();
  if (!current) return null;
  const box = document.getElementById('results');
  if (box) box.innerHTML = '';
  return ctx.run(name, {login_id: current.login_id, target_id: current.id, input}, {
    panel: 'job-panel', key: key(name, {target_id: current.id, login_id: current.login_id}),
    onDone: job => { const target = document.getElementById('results'); if (target) target.innerHTML = renderer(job, group); }});
}

async function taxHome(ctx) {
  const current = taxTarget();
  if (!current) return heading('세금 요약', '홈택스 대상별 세금과 증빙을 확인해요.') + setupNotice('hometax-tax') + noTaxTarget();
  const [dues, refunds, invoices] = await Promise.all([latest('hometax.tax.dues', {target_id: current.id}),
    latest('hometax.tax.refunds', {target_id: current.id}), latest('hometax.invoice.list', {target_id: current.id})]);
  const metric = (label, job, view) => {
    const value = job?.status === 'finished' && job.outcome === 'success' ? `${job.result?.items?.length ?? 0}건` : job ? (ui.OUTCOME[job.outcome]?.[0] || ui.STATUS[job.status]?.[0]) : '미조회';
    return `<button class="panel metric" data-view="${view}"><span>${esc(label)}</span><strong class="number">${esc(value)}</strong><small>${job?.observed_at ? '조회 ' + ui.time(job.observed_at) : '조회 기록 없음'}${icon('arrow')}</small></button>`;
  };
  return heading('세금 요약', `${esc(current.display_name)}의 세금과 증빙을 한곳에서 확인하세요.`) + setupNotice('hometax-tax') + targetBar(taxTargets(), current) +
    `<div class="metric-grid">${metric('납부할 세액', dues, 'dues')}${metric('환급금', refunds, 'refunds')}${metric('전자세금계산서', invoices, 'invoices')}</div>` +
    `<div class="workspace-grid tax-workspace"><section class="panel quick-transfer"><h2>조회는 대상별 작업으로 실행돼요</h2><p>대상 선택·확인·조회를 서버가 한 번에 직렬로 실행하고, 결과에는 확인한 대상을 표시해요. 요약 숫자는 마지막 조회 결과의 건수이며 금액을 추정해 합산하지 않아요.</p>${ui.button('납부할 세액 조회', 'data-view="dues"', 'primary')}</section><div class="tax-shortcuts"><section class="panel quick-transfer"><h2>전자세금계산서</h2><p>작성한 내용을 확인한 뒤 발급해요.</p>${ui.button('새 계산서 작성', 'data-action="invoice-new"', 'primary')}${ui.button('매출·매입 조회', 'data-view="invoices"')}</section><section class="panel quick-transfer"><h2>신고 자료</h2><p>신고 내역과 접수증을 확인하세요.</p>${ui.button('신고 내역 보기', 'data-view="returns"')}</section></div></div>`;
}

async function returnsView(ctx) {
  const current = taxTarget();
  if (!current) return heading('신고 내역', '접수 결과·제출서식·신고서를 확인하세요.') + noTaxTarget();
  const mode = state.params.mode || 'list';
  const name = mode === 'list' ? 'hometax.returns.list' : 'hometax.returns.status';
  const job = await latest(name, {target_id: current.id});
  const year = new Date().getFullYear();
  const form = mode === 'list'
    ? `<form class="filter-bar" data-submit="returns-query" data-mode="list"><label class="field-inline">시작일<input type="date" name="from"></label><label class="field-inline">종료일<input type="date" name="to"></label><label class="field-inline">세목 코드<input name="tax_code" maxlength="10" placeholder="생략 시 종합소득세"></label><label class="field-inline check"><input type="checkbox" name="all_pages">전체 페이지</label><button class="button primary" type="submit">${icon('refresh')}조회</button></form>`
    : `<form class="filter-bar" data-submit="returns-query" data-mode="status"><label class="field-inline">연도<input type="number" name="year" min="2000" max="2100" value="${year}"></label><label class="field-inline">월<input type="number" name="month" min="1" max="12" value="${new Date().getMonth() + 1}"></label><label class="field-inline check"><input type="checkbox" name="all_pages">전체 페이지</label><button class="button primary" type="submit">${icon('refresh')}조회</button></form>`;
  return heading('신고 내역', '제출된 신고의 조회 화면이에요. 새 신고 제출은 지원하지 않아요.') + targetBar(taxTargets(), current) +
    `<section class="panel"><div class="panel-heading"><div class="segmented" aria-label="조회 기준">${[['list', '신고 내역'], ['status', '접수 결과']].map(([k, l]) => `<button data-action="returns-mode" data-mode="${k}" class="${mode === k ? 'active' : ''}" aria-pressed="${mode === k}">${l}</button>`).join('')}</div>${ui.verification('live_untested')}</div>${form}${panel('job-panel', job)}<div id="results">${taxResults(job, 'returns')}</div><div class="list-footer">행을 누르면 제출서식 조회, 접수증·신고서 저장을 할 수 있어요.</div></section>`;
}

async function reportsView(ctx) {
  const listing = await api.get('/artifacts?kind=hometax_report' + (profile() ? '&profile_id=' + encodeURIComponent(profile().id) : ''));
  const rows = listing.artifacts;
  return heading('보고서·접수증', '저장한 문서의 내용과 완전성 상태를 확인하세요. 문서는 스크립트 없이 격리해 보여줘요.') +
    `<section class="panel">${rows.length ? `<div class="document-list">${rows.map(a => `<article class="document-row"><span class="record-icon">${icon('report')}</span><div class="record-main"><h3>${esc(a.filename)}</h3><p>${ui.time(a.created_at)} · ${esc(a.target_name || '')} · ${esc(a.job_title)}</p></div>${a.complete === 1 ? tag('완전') : a.complete === 0 ? tag('확인 필요', 'warning') : tag('완전성 미표시', 'neutral')}<div class="row-actions"><button class="button secondary" data-action="preview-artifact" data-artifact="${esc(a.id)}">보기</button><a class="text-button" href="/api/v1/artifacts/${encodeURIComponent(a.id)}">${icon('download')}HTML 저장</a>${a.document ? `<button class="text-button" data-action="report-resave" data-job="${esc(a.job_id)}" data-document="${a.document}">다시 저장</button>` : ''}</div></article>`).join('')}</div>` : '<div class="empty-state">저장한 문서가 없어요. 신고 내역에서 접수증이나 신고서를 저장하세요.</div>'}</section>`;
}

async function invoicesView(ctx) {
  const current = taxTarget();
  if (!current) return heading('전자세금계산서', '조회, 초안 작성, 수정 발급') + setupNotice('hometax-invoice-query') + noTaxTarget();
  const direction = state.params.direction || 'sales';
  const job = await latest('hometax.invoice.list', {target_id: current.id});
  const today = new Date().toISOString().slice(0, 10);
  const first = today.slice(0, 8) + '01';
  return heading('전자세금계산서', `${esc(current.display_name)} · 조회, 초안 작성, 수정 발급`, ui.button('새 계산서 작성', 'data-action="invoice-new"', 'primary')) +
    setupNotice('hometax-invoice-issue') + targetBar(taxTargets(), current) +
    `<section class="panel"><div class="panel-heading"><div class="segmented" aria-label="계산서 구분">${[['sales', '매출'], ['purchases', '매입']].map(([k, l]) => `<button data-action="invoice-direction" data-direction="${k}" class="${direction === k ? 'active' : ''}" aria-pressed="${direction === k}">${l}</button>`).join('')}</div>${ui.verification('live_untested')}</div><form class="filter-bar" data-submit="invoice-query"><input type="hidden" name="direction" value="${direction}"><label class="field-inline">시작일<input type="date" name="from" value="${first}"></label><label class="field-inline">종료일<input type="date" name="to" value="${today}"></label><label class="field-inline">유형<select name="invoice_type"><option value="">전자세금계산서(기본)</option><option value="03">전자계산서</option></select></label><label class="field-inline check"><input type="checkbox" name="all_pages">전체 페이지</label><button class="button primary" type="submit">${icon('refresh')}조회</button></form>${panel('job-panel', job)}<div id="results">${taxResults(job, 'invoices')}</div></section>` +
    note('계산서 발급은 초안 확인과 별도 단계예요. 같은 초안으로는 한 번만 발급을 시도하며, 결과가 불확실하면 다시 발급하지 말고 목록으로 확인하세요.');
}

function invoiceFormView(ctx) {
  const current = taxTarget();
  const amend = state.params.amend;
  if (!current) return heading('계산서 작성', '') + noTaxTarget();
  const owner = login(current.login_id);
  const signing = current.signing?.invoice_sign || owner?.signing?.invoice_sign;
  const party = (prefix, title, fields, required = []) => `<div class="form-section"><h2>${title}</h2><div class="form-grid">${fields.map(([name, label, extra = '']) => `<div class="field"><label for="${prefix}-${name}">${label}${required.includes(name) ? '' : ' (선택)'}</label><input id="${prefix}-${name}" name="${prefix}.${name}" ${required.includes(name) && !amend ? 'required' : ''} ${extra}></div>`).join('')}</div></div>`;
  const common = [['name', '상호', 'maxlength="60"'], ['representative', '대표자', 'maxlength="30"'], ['address', '주소', 'maxlength="150"'],
    ['business_type', '업태', 'maxlength="40"'], ['business_item', '종목', 'maxlength="40"'], ['email', '이메일', 'type="email" maxlength="80"']];
  const items = [0, 1, 2, 3].map(i => `<div class="item-editor"><div class="form-grid"><div class="field span"><label for="item-${i}-name">품목 ${i + 1}${i ? ' (선택)' : ''}</label><input id="item-${i}-name" name="items.${i}.name" maxlength="100" ${i || amend ? '' : 'required'}></div><div class="field"><label for="item-${i}-month">월</label><input id="item-${i}-month" name="items.${i}.month" maxlength="2" inputmode="numeric"></div><div class="field"><label for="item-${i}-day">일</label><input id="item-${i}-day" name="items.${i}.day" maxlength="2" inputmode="numeric"></div><div class="field"><label for="item-${i}-quantity">수량</label><input id="item-${i}-quantity" name="items.${i}.quantity" type="number" step="1"></div><div class="field"><label for="item-${i}-unit">단가</label><input id="item-${i}-unit" name="items.${i}.unit_price" type="number" step="1"></div><div class="field"><label for="item-${i}-supply">공급가액</label><input id="item-${i}-supply" name="items.${i}.supply_amount" type="number" step="1"></div><div class="field"><label for="item-${i}-tax">세액</label><input id="item-${i}-tax" name="items.${i}.tax_amount" type="number" step="1"></div></div></div>`).join('');
  return heading(amend ? '수정 계산서 작성' : '전자세금계산서 작성', '일반 과세 · 사업자 간 거래 · 서비스 미리보기까지 준비하고, 확인 후 발급해요.', ui.button('목록으로', 'data-view="invoices"')) +
    targetBar(taxTargets(), current) +
    (signing ? note(`발급용 인증서: <strong>${esc(signing.ref)}</strong>. 로그인용 인증서로 대신 발급하지 않아요.`) : note('발급용 인증서가 지정되지 않았어요. 연결·인증서에서 이 로그인이나 사업장에 발급용 인증서를 지정하세요.')) +
    `<form class="panel invoice-form" data-submit="invoice-prepare" data-amend="${esc(amend || '')}">` +
    (amend ? `<div class="form-section"><h2>수정 사유</h2><div class="form-grid"><div class="field"><label>당초 승인번호</label><input value="${esc(amend)}" readonly></div><div class="field"><label for="amend-reason">수정 사유</label><select id="amend-reason" name="reason">${[['correction', '기재사항 착오정정 (취소·재발급 2건)'], ['amount-change', '공급가액 변동'], ['return', '환입'], ['cancellation', '계약의 해제'], ['local-credit', '내국신용장 사후개설 (2건)'], ['duplicate', '착오에 의한 이중발급']].map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select></div></div><p class="field-help">바꿀 항목만 입력하세요. 서비스 화면에서 잠긴 항목은 바꾸지 않아요.</p></div>` : '') +
    party('supplier', '공급자 (비우면 서비스 기본값)', common) +
    party('buyer', '공급받는 자', [['business_number', '사업자등록번호', 'maxlength="12" inputmode="numeric" placeholder="123-45-67890"'], ...common], ['business_number']) +
    `<div class="form-section"><h2>공급 내용</h2><div class="form-grid"><div class="field"><label for="invoice-date">작성일</label><input id="invoice-date" type="date" name="date" ${amend ? '' : 'required'}></div><div class="field"><label for="invoice-remark">비고 (선택)</label><input id="invoice-remark" name="remark" maxlength="150"></div></div>${items}</div>` +
    `<div class="form-section"><h2>결제 구분</h2><div class="form-grid"><div class="field"><label for="settlement-type">청구·영수</label><select id="settlement-type" name="settlement.type"><option value="">서비스 기본</option><option value="claim">청구</option><option value="receipt">영수</option></select></div><div class="field"><label for="settlement-credit">외상미수금 (선택)</label><input id="settlement-credit" name="settlement.credit" inputmode="numeric"></div><div class="field"><label for="settlement-cash">현금 (선택)</label><input id="settlement-cash" name="settlement.cash" inputmode="numeric"></div><div class="field"><label for="settlement-check">수표 (선택)</label><input id="settlement-check" name="settlement.check" inputmode="numeric"></div></div></div>` +
    `<div class="form-actions"><button class="button primary" type="submit">초안 확인 ${icon('arrow')}</button><p class="field-help">서비스 미리보기까지 진행하고 발급하지 않아요. 다음 화면에서 내용을 확인한 뒤 발급을 결정해요. 세액은 입력한 값 그대로 들어가며 반올림하지 않아요.</p></div></form>${panel('job-panel', null)}`;
}

function draftInput(form) {
  const value = {};
  for (const [name, raw] of new FormData(form).entries()) {
    if (raw === '' || name === 'reason') continue;
    const parts = name.split('.');
    let node = value;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      const next = /^\d+$/.test(parts[i + 1]) ? [] : {};
      node[part] = node[part] ?? next;
      node = node[part];
    }
    const last = parts[parts.length - 1];
    node[last] = ['quantity', 'unit_price', 'supply_amount', 'tax_amount'].includes(last) ? Number(raw) : raw;
  }
  if (value.items) value.items = value.items.filter(Boolean);
  return value;
}

function draftPreview(preview) {
  const d = preview?.draft || {};
  const line = (label, v) => v === undefined || v === null || v === '' ? '' : `<div class="summary-line"><span>${esc(label)}</span><strong>${typeof v === 'number' ? money(v) : esc(v)}</strong></div>`;
  return `<div class="summary-lines">${line('공급자', d.supplier?.splrTnmNm)}${line('공급자 사업자번호', d.supplier?.splrTxprDscmNo)}${line('공급받는 자', d.buyer?.dmnrTnmNm)}${line('공급받는 자 사업자번호', d.buyer?.dmnrTxprDscmNo)}${line('작성일', d.totals?.wrtDt)}${(d.items || []).map((i, n) => line(`품목 ${n + 1}`, `${i.lsatNm ?? ''} · 공급가액 ${i.lsatSplCft ?? '—'} · 세액 ${i.lsatTxamt ?? '—'}`)).join('')}${line('공급가액 합계', d.totals?.splCft)}${line('세액 합계', d.totals?.txamt)}${line('합계', d.totals?.sumAmt)}${line('청구·영수 코드', d.settlement?.recApeClCd)}${line('발급 문서 수', preview?.document_count ? preview.document_count + '건' : null)}${line('당초 승인번호', preview?.original_approval_number)}</div>${ui.details('서비스 초안 필드 (허용 목록)', d)}`;
}

function transferPreview(preview) {
  const bank = BANKS.find(b => b[0] === preview.recipient_bank_code)?.[1] || preview.recipient_bank_code;
  const line = (label, v) => `<div class="summary-line"><span>${esc(label)}</span><strong>${esc(v ?? '—')}</strong></div>`;
  return `<div class="summary-lines">${line('받는 분 (은행 응답)', preview.recipient_name)}${line('받는 계좌', `${bank} ${preview.recipient_account}`)}${line('출금 계좌', preview.source_account)}${line('수수료', money(preview.fee_krw) + '원')}<div class="summary-line total"><span>보낼 금액</span><strong>${money(preview.amount_krw)}원</strong></div>${line('출금 합계', money(preview.total_krw) + '원')}</div>`;
}

/* Confirmation: shows exactly what was prepared, its fixed target and the verification level. */
function confirmDialog(ctx, job) {
  const awaiting = job.awaiting || {};
  const transfer = job.name === 'hana.transfer.prepare';
  const fixed = job.fixed || {};
  const store = onesignStore(login(job.login_id), true);
  const fields = secretFields((awaiting.requires || []).map(name => SECRET_LABELS[name]).filter(Boolean), store);
  const expires = awaiting.expires_at ? `<p class="dialog-note">확인 기한: <span class="countdown" data-deadline="${awaiting.expires_at}"></span> 남음. 기한이 지나면 새 로그인부터 다시 준비해요.</p>` : '';
  const body = `<p class="pill-row">${ui.verification(awaiting.verification)}${tag('되돌릴 수 없음', 'danger')}</p>` +
    `<div class="summary-lines"><div class="summary-line"><span>프로필</span><strong>${esc(fixed.profile?.name || '전체')}</strong></div><div class="summary-line"><span>로그인</span><strong>${esc(fixed.login?.display_name)}</strong></div><div class="summary-line"><span>대상</span><strong>${esc(fixed.target?.display_name)}</strong></div>${awaiting.signing_credential ? `<div class="summary-line"><span>발급용 인증서</span><strong>${esc(awaiting.signing_credential)}</strong></div>` : ''}</div>` +
    (transfer ? transferPreview(awaiting.preview || {}) : draftPreview(awaiting.preview)) + expires +
    `<form id="confirm-form" autocomplete="off">${fields.map(([name, label, pattern]) => `<div class="field"><label for="confirm-${name}">${esc(label)}</label><input id="confirm-${name}" name="${name}" type="password" required autocomplete="off" ${pattern ? `inputmode="numeric" pattern="${pattern}"` : ''}></div>`).join('')}${rememberField(fields, store)}<p class="dialog-note">${transfer ? '확인하면 이체를 한 번만 전송해요. 응답을 받지 못해도 자동으로 다시 보내지 않고 결과 조회로 확인해요.' : '확인하면 이 초안으로 발급을 한 번만 시도해요. 결과가 불확실하면 다시 발급하지 말고 목록으로 확인하세요.'}</p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">나중에</button><button type="button" class="button secondary" data-action="cancel-job" data-job="${esc(job.id)}">준비 취소</button><button class="button primary" type="submit">${transfer ? `이체 ${money(awaiting.preview?.amount_krw)}원` : '발급'}</button></div></form>`;
  ui.showDialog(transfer ? '이 내용으로 보낼까요?' : '발급 전 초안 확인', body, {wide: !transfer});
  const timer = setInterval(() => {
    const clock = document.querySelector('.countdown');
    if (!clock) { clearInterval(timer); return; }
    const left = Math.max(0, Math.round(Number(clock.dataset.deadline) - Date.now() / 1000));
    clock.textContent = `${Math.floor(left / 60)}분 ${String(left % 60).padStart(2, '0')}초`;
    if (!left) clearInterval(timer);
  }, 500);
  document.querySelector('#confirm-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.target;
    form.querySelector('button[type=submit]').disabled = true;
    try {
      if (transfer && !await ensureBankSession(ctx, job.login_id)) return;
      const secrets = await applyRemember(Object.fromEntries(new FormData(form).entries()), store);
      form.reset();
      await api.post(`/jobs/${encodeURIComponent(job.id)}/confirm`, {confirmation: awaiting.digest, secrets});
    } catch (error) {
      if (error.code === 'session_idle_expired') {
        clearInterval(timer);
        await expiredBankLogin(ctx, job.login_id);
        return;
      }
      ui.toast(ui.message(error.code));
      form.querySelector('button[type=submit]').disabled = false;
      return;
    }
    clearInterval(timer);
    ui.closeDialog();
    const final = await ctx.track({...job, status: 'queued'}, {panel: 'job-panel'});
    if (final) resultDialog(final);
  });
}

function resultDialog(job) {
  const transfer = job.name === 'hana.transfer.prepare';
  const verdict = job.service_verdict || {};
  const [label, tone] = ui.OUTCOME[job.outcome] || [job.outcome, 'neutral'];
  const approval = job.result?.approval_number || job.result?.replacement_approval_number;
  const extra = transfer
    ? `<p class="success-copy">은행 실행 응답: ${esc(verdict.execution_result ? (verdict.execution_result.accepted === true ? '접수' : verdict.execution_result.accepted === false ? '거절' : '미확인') : '없음')}. 이체 확정은 결과 조회로 따로 확인해요.</p>`
    : `<p class="success-copy">${approval ? `승인번호 ${esc(approval)}` : '승인번호를 받지 못했어요.'}${verdict.reason ? ` · ${esc(verdict.reason)}` : ''}</p>`;
  ui.showDialog(transfer ? '이체 결과' : '발급 결과', `<div class="success-symbol">${icon(job.outcome === 'success' ? 'check' : 'info')}</div><h3 class="success-title">${esc(label)}</h3>${extra}${job.outcome === 'unknown' || job.outcome === 'partial_success' ? `<p class="dialog-note">${transfer ? '같은 이체를 다시 보내지 말고 결과 조회로 확인하세요.' : '다시 발급하지 말고 계산서 목록이나 상세로 승인번호를 확인하세요.'}</p>` : ''}${ui.verification(job.verification)}<div class="dialog-actions">${transfer && job.attempt?.sent ? `<button class="button secondary" data-action="reconcile" data-job="${esc(job.id)}">이체 결과 조회</button>` : ''}<button class="button secondary" data-action="job-detail" data-job="${esc(job.id)}">작업 상세</button><button class="button primary" data-ui="close">확인</button></div>`);
  if (tone === 'danger' && job.local?.stopped) ui.toast(ui.message(job.local.stopped));
}

// Banking ------------------------------------------------------------------

function accountTargets(method) {
  return scopeTargets(['account']).filter(t => login(t.login_id)?.institution === 'hana' && (!method || login(t.login_id)?.method === method));
}

function accountSelect(list, id = 'account', label = '계좌') {
  return `<label class="field-inline">${esc(label)}<select name="target_id" id="${id}" required>${list.map(t => `<option value="${esc(t.id)}">${esc(t.display_name)} · ${esc(t.identity?.account_number || '')} (${esc(login(t.login_id)?.display_name)})</option>`).join('')}</select></label>`;
}

// Bank query dates follow Korea time even before 09:00 KST or from an overseas browser.
const bankDate = (daysAgo = 0) => new Date(Date.now() + 9 * 3600000 - daysAgo * 86400000).toISOString().slice(0, 10);

function loginButton(row, primary = false) {
  if (row.disabled) return '';
  return ui.button(row.current_session_id ? '다시 로그인' : '로그인',
    `data-action="login" data-login="${esc(row.id)}"`, primary ? 'primary' : 'secondary');
}

function accountsJobName(row) { return row.method === 'onesign' ? 'hana.onesign.accounts' : 'hana.accounts.list'; }

async function runHanaQuery(ctx, suffix, fields, options) {
  if (suffix !== 'history.export' && !await ensureBankSession(ctx, fields.login_id)) return;
  const owner = login(fields.login_id);
  const onesign = owner?.method === 'onesign';
  const secrets = onesign ? await askSecrets(suffix === 'security.query' ? '보안매체·한도 조회' : '내역 조회', [SECRET_LABELS.vault_passphrase],
    '로그인한 세션으로 조회해요.', {store: onesignStore(owner)}) : {};
  if (secrets === null) return;
  return ctx.run(`hana.${onesign ? 'onesign.' : ''}${suffix}`, fields, {...options, secrets});
}

async function accountsView(ctx) {
  const logins = scopeLogins('hana');
  if (!logins.length) {
    return heading('내 계좌', '은행 로그인별 계좌와 조회 시각을 확인해요.') + setupNotice('hana-accounts') +
      empty(profile() ? '이 프로필에 하나은행 계좌가 없어요. 전체에서 조회한 계좌를 선택해 프로필에 넣을 수 있어요.' : '하나은행 로그인이 없어요. 연결·인증서에서 추가하세요.',
        '<button class="button primary" data-view="settings">연결·인증서</button>');
  }
  const jobs = await Promise.all(logins.map(row => latest(accountsJobName(row), {login_id: row.id})));
  const current = profile();
  const allowed = new Set(scopeTargets(['account']).map(t => t.id));
  let total = 0, counted = 0, unknown = 0;
  const panels = logins.map((row, index) => {
    const job = jobs[index];
    const verification = state.capabilities?.features.find(f => f.id === 'hana-accounts')?.jobs
      .find(j => j.name === accountsJobName(row))?.verification || job?.verification || 'live_untested';
    const mapping = job?.result?.candidate_targets || {};
    const rows = (job?.status === 'finished' && job.outcome === 'success' ? job.result?.accounts || [] : [])
      .filter(a => !current || allowed.has(mapping[a.ref]));
    if (!rows.length) unknown += 1;
    for (const account of rows) if (typeof account.balance === 'number') { total += account.balance; counted += 1; }
    const sameSession = job && job.session_id && job.session_id === row.current_session_id && row.method === 'joint_certificate';
    return `<section class="panel"><div class="panel-heading"><div><h2>${esc(row.display_name)}</h2><p class="meta">${esc(ui.METHOD[row.method])} · ${job?.observed_at ? '조회 ' + ui.time(job.observed_at) : '미조회'}</p></div><div class="pill-row">${readiness(row)}${ui.verification(verification)}</div></div>${panel('job-' + row.id, job && (job.status !== 'finished' || job.outcome !== 'success') ? job : null)}${rows.length ? `<div class="table-wrap"><table class="table data"><thead><tr><th>계좌</th><th>번호</th><th>통화</th><th class="num">잔액</th></tr></thead><tbody>${rows.map(a => `<tr><td>${esc(a.label)}</td><td>${esc(a.account_number)}</td><td>${esc(a.currency)}</td><td class="num">${state.hidden ? '••••••' : money(a.balance)}</td></tr>`).join('')}</tbody></table></div>` : `<div class="empty-state">${job ? outcomeNote(job) || '표시할 계좌가 없어요.' : '아직 조회하지 않았어요.'}</div>`}<div class="section-actions">${canQuery(row) && !sameSession ? ui.button('잔액 조회', `data-action="accounts-query" data-login="${esc(row.id)}"`, 'primary', 'refresh') : ''}${loginButton(row, !canQuery(row) || sameSession)}${sameSession ? '<span class="muted-block">이 세션의 계좌 조회는 이미 기록했어요. 새로 로그인하면 다시 조회할 수 있어요.</span>' : ''}</div></section>`;
  }).join('');
  return heading('내 계좌', '은행 로그인별로 모아 보고, 로그인 상태와 조회 시각을 구별해요.') + setupNotice('hana-accounts') +
    `<section class="balance-overview"><div><div class="balance-label">조회한 계좌 잔액 합계<button class="icon-button" data-action="privacy" aria-label="${state.hidden ? '잔액 표시' : '잔액 숨기기'}">${icon('eye')}</button></div><div class="total-balance number">${counted ? (state.hidden ? '••••••' : money(total)) : '—'}<small>원</small></div><div class="balance-meta"><span>${counted}개 계좌 합산</span>${unknown ? `<span>미조회 ${unknown}곳은 합계에서 제외</span>` : ''}</div></div><div class="overview-side"><p>필요할 때, 바로 이체하세요.</p><button class="button on-dark" data-view="transfer">이체하기 ${icon('transfer')}</button></div></section><div class="stack">${panels}</div>`;
}

async function historyView(ctx) {
  const list = accountTargets();
  if (!list.length) return heading('거래 내역', '계좌별 입출금 내역을 조회해요.') + setupNotice('hana-history') + empty('조회한 계좌가 없어요. 내 계좌에서 계좌를 조회하면 바로 사용할 수 있어요.', '<button class="button primary" data-view="accounts">내 계좌</button>');
  const today = bankDate();
  const week = bankDate(6);
  return heading('거래 내역', '계좌별 입출금 내역을 조회해요. 다음 페이지는 직접 요청해야 가져와요.') + setupNotice('hana-history') +
    `<section class="panel"><form class="filter-bar" data-submit="history-query">${accountSelect(list)}<label class="field-inline">시작일<input type="date" name="start_date" value="${week}" required></label><label class="field-inline">종료일<input type="date" name="end_date" value="${today}" required></label><label class="field-inline">구분<select name="direction"><option value="all">전체</option><option value="deposit">입금</option><option value="withdrawal">출금</option></select></label><label class="field-inline">정렬<select name="order"><option value="desc">최신순</option><option value="asc">과거순</option></select></label><label class="field-inline">검색<input name="search" maxlength="25"></label><button class="button primary" type="submit">${icon('refresh')}조회</button><button class="button secondary" type="button" data-action="account-login">다시 로그인</button></form>${panel('job-panel', null)}<div id="results"><div class="empty-state">계좌와 기간을 정해 조회하세요. 이 세션에서 계좌 조회를 먼저 해야 해요.</div></div></section>`;
}

function historyRows(job, append = false) {
  const previous = append ? state.rows.history?.rows || [] : [];
  const rows = [...previous, ...(job.result?.rows || [])];
  rememberRows('history', rows, {job, pages: [...(append ? state.rows.history?.pages || [] : []), job.id]});
  const mapped = rows.map(r => ({일자: r.date, 시각: r.time, 구분: r.type, 내용: r.name, 금액: r.amount, 잔액: r.balance, 메모: r.memo}));
  return outcomeNote(job) + (job.result?.rows ? ui.rowsTable(mapped, {group: 'history', keys: ['일자', '시각', '구분', '내용', '금액', '잔액']}) : '') +
    `<div class="list-footer">${rows.length}건 · ${job.result?.more_available ? '다음 페이지 있음' : job.result?.pagination_complete ? '조회 범위 끝' : '페이지 상태 확인 필요'}</div><div class="section-actions">${job.result?.more_available ? ui.button('다음 페이지', `data-action="history-more" data-job="${esc(job.id)}"`) : ''}${job.outcome === 'success' ? ui.button('내역 저장 (JSON·CSV)', `data-action="history-export" data-job="${esc(job.id)}"`, 'secondary', 'download') : ''}</div>`;
}

async function transferView(ctx) {
  const list = accountTargets('onesign');
  const presets = [10000, 50000, 100000];
  if (!list.length) return heading('이체', '보내기 전에 받는 분과 금액을 확인하세요.') + setupNotice('hana-transfer') + empty('하나인증서로 로그인하고 계좌를 조회하면 출금 계좌를 선택할 수 있어요.', '<button class="button primary" data-view="settings">연결·인증서</button>');
  return heading('이체', '보내기 전에 받는 분과 금액을 확인하세요.') + setupNotice('hana-transfer') +
    `<div class="steps"><span class="active"><b>1</b>정보 입력</span><i></i><span><b>2</b>내용 확인</span><i></i><span><b>3</b>완료</span></div>` +
    note('하나인증서 로그인 한 번으로 잔액·거래 내역·이체 내역을 조회하고 이체할 수 있어요. 이체 후에도 조회는 계속 가능해요. 다음 이체를 준비할 때는 새 로그인이 필요해요. 이 기능은 실서버 미검증이에요.') +
    `<div class="transfer-layout"><form class="panel form-panel" data-submit="transfer-prepare"><div class="field"><label for="source-account">어느 계좌에서 보낼까요?</label><select id="source-account" name="target_id">${list.map(t => `<option value="${esc(t.id)}">${esc(t.display_name)} · ${esc(t.identity?.account_number)} (${esc(login(t.login_id)?.display_name)} · ${esc(login(t.login_id)?.readiness === 'ready' ? '세션 있음' : '새 이체 로그인 필요')})</option>`).join('')}</select></div><div class="field"><label for="recipient-account">받는 계좌</label><div class="field-row"><select id="recipient-bank" name="bank" aria-label="받는 은행">${BANKS.map(([code, name]) => `<option value="${code}">${name}</option>`).join('')}</select><input id="recipient-account" name="account" inputmode="numeric" autocomplete="off" required pattern="[0-9-]{8,30}" placeholder="숫자만 입력"></div></div><div class="field"><label for="transfer-amount">얼마를 보낼까요?</label><div class="amount-input"><input id="transfer-amount" name="amount" inputmode="numeric" autocomplete="off" required pattern="[0-9,]+"><span>원</span></div><div class="amount-presets">${presets.map(v => `<button type="button" data-action="amount-add" data-add="${v}">+${money(v / 10000)}만</button>`).join('')}<button type="button" data-action="amount-clear">지우기</button></div></div><div class="form-actions"><button class="button primary" type="submit">이체 내용 확인 ${icon('arrow')}</button><button class="button secondary" type="button" data-action="account-login">다시 로그인</button><p class="field-help">다음 단계에서 저장소 암호와 출금 계좌 비밀번호를 받아 은행의 확인 화면까지 준비해요. 이때는 이체하지 않아요.</p></div></form><aside class="panel transfer-summary"><h2>진행 방식</h2><div class="info-block">${icon('shield')} 1) 준비: 받는 분 이름·수수료를 은행에서 확인<br>2) 확인: 내용을 보고 PIN(필요한 경우)과 함께 실행 예약<br>3) 실행: 한 번만 전송, 자동 재전송 없음<br>4) 결과 조회: 이체 내역으로 따로 대조</div></aside></div>${panel('job-panel', null)}`;
}

async function inquiryView(ctx) {
  const list = accountTargets();
  if (!list.length) return heading('이체 내역', '이체 결과를 확인하세요.') + setupNotice('hana-inquiry') + empty('조회한 계좌 대상이 없어요.', '<button class="button primary" data-view="accounts">내 계좌</button>');
  const today = bankDate();
  const month = bankDate(30);
  return heading('이체 내역', '완료된 이체와 처리 결과를 확인하세요.') + setupNotice('hana-inquiry') +
    `<section class="panel"><form class="filter-bar" data-submit="inquiry-query">${accountSelect(list)}<label class="field-inline">시작일<input type="date" name="start_date" value="${month}" required></label><label class="field-inline">종료일<input type="date" name="end_date" value="${today}" required></label><button class="button primary" type="submit">${icon('refresh')}조회</button><button class="button secondary" type="button" data-action="account-login">다시 로그인</button></form>${panel('job-panel', null)}<div id="results"></div><div class="list-footer">행을 누르면 이체 상세를 조회해요.</div></section>`;
}

async function securityView(ctx) {
  const logins = scopeLogins('hana').filter(l => ['joint_certificate', 'onesign'].includes(l.method));
  if (!logins.length) return heading('보안매체·한도', '등록된 보안매체와 한도 상태를 조회하세요.') + setupNotice('hana-security') + empty('연결된 하나은행 로그인이 없어요.', '<button class="button primary" data-view="settings">연결·인증서</button>');
  const kinds = [['limits', '이체한도'], ['limit-exception', '한도 예외'], ['security-media', '보안매체'], ['otp', 'OTP'], ['otp-accident', 'OTP 사고'], ['mobile-otp', '모바일 OTP']];
  return heading('보안매체·한도', '상태를 조회만 해요. OTP 발급이나 한도 변경은 제공하지 않아요.') + setupNotice('hana-security') +
    `<section class="panel"><form class="filter-bar" data-submit="security-query"><label class="field-inline">로그인<select name="login_id">${logins.map(l => `<option value="${esc(l.id)}">${esc(l.display_name)}</option>`).join('')}</select></label><label class="field-inline">조회 항목<select name="kind">${kinds.map(([k, l]) => `<option value="${k}">${l}</option>`).join('')}</select></label><button class="button primary" type="submit">${icon('refresh')}조회</button><button class="button secondary" type="button" data-action="security-login">다시 로그인</button></form>${panel('job-panel', null)}<div id="results"></div></section>`;
}

// Giro -----------------------------------------------------------------------

async function billsView(ctx, due = false) {
  const today = new Date().toISOString().slice(0, 10);
  return heading(due ? '납부 기한' : '고지서 자료', due ? '자료에 적힌 납부 기한을 기준일과 비교해요.' : '확보해 둔 고지 자료를 읽고 항목을 확인해요.') +
    note('모바일지로는 현재 자료 해석만 지원해요. 실시간 고지 조회, 로그인, 납부 실행은 준비 중이에요. 자료에 없는 기한이나 납부 완료 여부는 추정하지 않아요.') +
    `<section class="panel"><form class="filter-bar" data-submit="bills-parse" data-mode="${due ? 'due' : 'list'}"><label class="field-inline">고지 자료 (JSON)<input type="file" name="file" accept=".json,.txt,application/json" required></label><label class="field-inline">구분<select name="tax_type"><option value="national">국세</option><option value="local">지방세</option><option value="customs">관세</option></select></label>${due ? `<label class="field-inline">기준일<input type="date" name="today" value="${today}"></label><label class="field-inline">기간(일)<input type="number" name="within_days" value="7" min="0" max="36500"></label><label class="field-inline check"><input type="checkbox" name="include_overdue">기한 경과 포함</label>` : ''}<button class="button primary" type="submit">해석</button></form>${panel('job-panel', null)}<div id="results"></div></section>`;
}

function billsResult(job) {
  const result = job.result || {};
  const bills = result.bills;
  const rows = (bills || []).filter(Boolean).map(b => ({기관: b.issuer, 세목: b.tax_name, 금액: b.amount ?? b.amount_raw, 납부기한: b.due_date ?? `확인 불가 (${b.due_date_raw ?? '없음'})`, ...(b.days_until_due !== undefined && b.days_until_due !== null ? {'남은 일수': b.days_until_due} : {}), 전자납부번호: b.electronic_number}));
  rememberRows('bills', rows, {job});
  return outcomeNote(job) + `<div class="list-footer">입력 자료 ${esc(result.input?.upload_id || '')} · ${esc(result.input?.tax_type || '')} · 처리 ${esc(result.processed_at || '')}${result.as_of ? ' · 기준일 ' + esc(result.as_of) : ''} · ${result.complete ? '자료 완전' : '자료 확인 필요'}${result.unparsed_count ? ` · 기한 해석 불가 ${result.unparsed_count}건 제외` : ''}</div>` +
    (bills === null ? '<div class="empty-state">자료에 고지 목록이 없어요.</div>' : ui.rowsTable(rows, {group: 'bills', keys: ['기관', '세목', '금액', '납부기한', ...(result.as_of ? ['남은 일수'] : []), '전자납부번호']})) +
    (result.issues?.length ? ui.details(`확인 필요 사항 ${result.issues.length}건`, result.issues) : '');
}

async function giroStatusView(ctx) {
  const job = await latest('giro.readiness');
  const result = job?.result;
  return heading('지로 연결 준비', '현재 지원하는 기능과 남은 연결 단계를 확인하세요.') +
    `<section class="panel"><div class="panel-heading"><h2>모바일지로 지원 상태</h2>${tag('로그인 미지원', 'warning')}</div><div class="settings-body">${[['고지서 항목·납기 해석', '로컬 자료 해석 지원'], ['인증·조회 요청 계획', '오프라인 준비 지원'], ['인증서·암호 처리 점검', '서버에서 관리'], ['초기 연결 점검', '서버에서 관리 · 로그인·납부 기능 아님'], ['실제 로그인·실시간 조회·납부', '준비 중']].map(([l, v]) => `<div class="setting-row"><span>${l}</span><strong>${v}</strong></div>`).join('')}</div></section>` +
    `<section class="panel"><div class="panel-heading"><h2>인증·조회 요청 계획</h2>${ui.button('계획 불러오기', 'data-action="giro-readiness"', 'secondary', 'refresh')}</div>${panel('job-panel', job)}<div id="results">${result ? giroPlan(result) : ''}</div></section>`;
}

function giroPlan(result) {
  return `<div class="settings-body"><div class="setting-row"><span>실제 로그인 준비</span><strong>${result.live_login_ready ? '준비됨' : '아니요'}</strong></div>${(result.steps || []).map(s => `<div class="setting-row"><span>${esc(s.endpoint || s.operation)}</span><strong>${esc(s.mode || '')} ${esc(s.effect || '')}</strong></div>`).join('')}${(result.blockers || []).map(b => `<div class="setting-row"><span>남은 단계</span><strong>${esc(typeof b === 'string' ? b : JSON.stringify(b))}</strong></div>`).join('')}</div>`;
}

// Common -----------------------------------------------------------------------

async function activityView(ctx) {
  const scope = state.params.scope || (profile() ? 'profile' : 'all');
  const query = scope === 'profile' && profile() ? '?profile_id=' + encodeURIComponent(profile().id) : '';
  const listing = await api.get('/jobs' + query + (query ? '&' : '?') + 'limit=200');
  const areaIcon = {banking: 'accounts', tax: 'tax', giro: 'bill'};
  return heading('전체 작업 기록', '웹·CLI·에이전트의 작업과 결과를 함께 확인하세요.', profile() ? `<div class="segmented">${[['profile', '현재 프로필'], ['all', '전체']].map(([k, l]) => `<button data-action="activity-scope" data-scope="${k}" class="${scope === k ? 'active' : ''}" aria-pressed="${scope === k}">${l}</button>`).join('')}</div>` : '') +
    `<section class="panel">${listing.jobs.length ? `<ul class="operation-list">${listing.jobs.map(job => `<li class="operation-row"><span class="workspace-icon">${icon(areaIcon[job.area] || 'activity')}</span><div class="operation-body"><h3>${esc(job.title)}</h3><p>${esc([job.fixed?.target?.display_name, job.fixed?.login?.display_name, ui.ORIGIN[job.origin]].filter(Boolean).join(' · '))} · ${ui.time(job.created_at)}${job.command ? ' · ' + esc(job.command.join(' ')) : ''}</p></div>${ui.statusTags(job)}<button class="text-button" data-action="job-detail" data-job="${esc(job.id)}">상세 ${icon('arrow')}</button></li>`).join('')}</ul>` : '<div class="empty-state">작업 기록이 없어요.</div>'}</section>`;
}

/* Connections screen. One card per institution login; its verified targets sit
   under it because that is where they belong. The primary action follows the
   user's next step (login → verify → done); everything else is behind "더보기".
   Identifiers such as revisions and fingerprints stay out of the main view. */
const SESSION_LABEL = {usable: '사용 가능', consumed: '세션 사용함', expired: '세션 만료', stale: '세션 재확인 필요'};

function loginStatus(row) {
  if (row.disabled) return tag('사용 중지', 'neutral');
  if (row.readiness === 'query_only') return tag('조회용 세션 있음', '') + '<span class="meta">새 이체 시 로그인 필요</span>';
  if (row.readiness === 'ready') return tag('로그인됨', '') + (row.session?.checked_at ? `<span class="meta">확인 ${ui.time(row.session.checked_at)}</span>` : '');
  const session = row.session;
  if (!session) return tag('로그인 필요', 'warning');
  return tag(session.state === 'stale' ? '재확인 필요' : '로그인 필요', 'warning') + `<span class="meta">${esc(SESSION_LABEL[session.state] || session.state)} · 마지막 로그인 ${ui.time(session.created_at)}</span>`;
}

function verifyAction(row) {
  return row.institution === 'hometax' ? ['discover', '사용자·사업장 확인'] : ['accounts-query', '계좌 조회'];
}

/* The one button the user most likely needs next. */
function primaryAction(row, targets) {
  if (row.disabled) return '';
  const attrs = `data-login="${esc(row.id)}"`;
  if (!canQuery(row)) return loginButton(row, true);
  const relogin = row.institution === 'hana' ? loginButton(row) : '';
  if (!targets.length) { const [action, label] = verifyAction(row); return ui.button(label, `data-action="${action}" ${attrs}`, 'primary') + relogin; }
  return relogin;
}

function signingLines(row) {
  const lines = [];
  if (row.institution === 'hometax') lines.push(['계산서 발급 인증서', row.signing?.invoice_sign?.ref, 'signing']);
  if (row.method === 'onesign') {
    if (row.signing?.transfer_sign?.ref && row.signing.transfer_sign.ref !== row.credential?.ref)
      lines.push(['별도 이체 인증서', row.signing.transfer_sign.ref, 'signing']);
    const store = row.credential?.ref;
    if (store) lines.push(['저장소 암호', state.vaults[store] ? '서버 메모리에 기억 중' : '잠김 · 작업마다 입력', state.vaults[store] ? 'lock-vault' : 'unlock-vault', store]);
  }
  if (row.institution === 'hana' && row.method !== 'onesign') {
    const reg = row.registration || {};
    lines.push(['앱 등록 정보', reg.app_profile?.configured && reg.login_input?.configured ? '연결됨' : '서버에서 연결 필요', null]);
  }
  return lines.map(([label, value, action, store]) => `<div class="connection-setting"><span>${esc(label)}</span><strong>${value ? esc(value) : '<em>미지정</em>'}</strong>${action ? `<button type="button" class="text-button" data-action="${action}" data-login="${esc(row.id)}" ${store ? `data-store="${esc(store)}"` : ''}>${action === 'unlock-vault' ? '잠금 해제' : action === 'lock-vault' ? '잠그기' : '변경'}</button>` : ''}</div>`).join('');
}

function targetRow(t) {
  const identity = Object.values(t.identity || {}).find(v => typeof v === 'string' && v.trim()) || '';
  return `<div class="target-row ${t.disabled ? 'disabled' : ''}"><div class="target-symbol">${icon(t.kind === 'account' ? 'accounts' : t.kind === 'business' ? 'business' : 'shield')}</div><div class="target-text"><strong>${esc(t.display_name)}</strong><span class="meta">${esc(ui.KIND[t.kind] || t.kind)}${identity ? ' · ' + esc(identity) : ''} · 확인 ${ui.time(t.verified_at)}${t.signing?.invoice_sign ? ' · 발급용 ' + esc(t.signing.invoice_sign.ref) : ''}</span></div>${t.disabled ? tag('사용 중지', 'neutral') : ''}<button type="button" class="icon-button" data-action="target-menu" data-target="${esc(t.id)}" aria-label="${esc(t.display_name)} 관리">${icon('more')}</button></div>`;
}

function connectionCard(row) {
  const targets = state.targets.filter(t => t.login_id === row.id);
  const [verify, verifyLabel] = verifyAction(row);
  const symbol = row.institution === 'hometax' ? '稅' : row.institution === 'hana' ? '하' : '지';
  const addTarget = canQuery(row) && !row.disabled && targets.length
    ? `<button type="button" class="text-button" data-action="${verify}" data-login="${esc(row.id)}">${verifyLabel} ${icon('arrow')}</button>` : '';
  const emptyTargets = row.disabled ? '' : !canQuery(row)
    ? `<p class="target-empty">${row.institution === 'hana' ? '로그인 후 계좌를 조회하면 자동으로 연결돼요.' : '로그인하면 사용자·사업장을 확인해 선택할 수 있어요.'}</p>`
    : `<p class="target-empty">${row.institution === 'hana' ? '아직 조회한 계좌가 없어요. 계좌를 조회하면 바로 사용할 수 있어요.' : '사용자·사업장 확인을 실행하고 결과에서 선택하세요.'}</p>`;
  return `<section class="panel connection-card ${row.disabled ? 'disabled' : ''}" aria-labelledby="login-${esc(row.id)}">
    <div class="connection-head"><div class="bank-symbol">${symbol}</div><div class="connection-title"><h2 id="login-${esc(row.id)}">${esc(row.display_name)}</h2><p class="meta">${esc(ui.INSTITUTION[row.institution])} · ${esc(ui.METHOD[row.method])}${row.credential?.ref ? ' · ' + esc(row.credential.ref) : ''}</p></div><div class="login-status">${loginStatus(row)}</div><div class="connection-actions">${primaryAction(row, targets)}<button type="button" class="icon-button" data-action="login-menu" data-login="${esc(row.id)}" aria-label="${esc(row.display_name)} 더보기">${icon('more')}</button></div></div>
    ${row.institution === 'hometax' ? setupNotice('hometax-login') : ''}
    <div class="connection-targets"><div class="connection-subhead"><h3>${row.institution === 'hana' ? '계좌' : '대상'} ${targets.length ? `<span class="count">${targets.length}</span>` : ''}</h3>${addTarget}</div>${targets.length ? targets.map(targetRow).join('') : emptyTargets}</div>
    ${signingLines(row) ? `<div class="connection-settings">${signingLines(row)}</div>` : ''}
    <div id="job-${esc(row.id)}"></div></section>`;
}

function onboarding() {
  const steps = [['인증서 발급·가져오기', '공동인증서를 가져오거나 하나인증서를 신규 발급해 보관해요. 금융인증서 발급은 아직 미지원이에요.'],
    ['기관 연결 추가', '기관·로그인 방법·인증서를 골라요. 저장만 하고 기관에는 접속하지 않아요.'],
    ['로그인하고 조회', '은행 계좌는 조회하면 자동으로 연결돼요. 홈택스는 사용자·사업장을 확인해 선택하세요. 업무 프로필은 필요할 때만 만들면 돼요.']];
  return `<section class="panel onboarding"><div class="panel-heading"><div><h2>처음 연결하기</h2><p class="meta">세 단계면 업무를 시작할 수 있어요.</p></div></div><ol class="onboarding-steps">${steps.map(([t, d], i) => `<li><b>${i + 1}</b><div><strong>${t}</strong><p>${d}</p></div></li>`).join('')}</ol><div class="onboarding-actions">${ui.button('인증서 발급·가져오기', 'data-action="certificate-add"')}${ui.button('기관 연결 추가', 'data-action="add-login-dialog"', 'primary')}<p class="field-help">기존 CLI 인증서 프로필이 있으면 서버에서 <span class="code">fin server import-profiles</span>로 가져올 수 있어요.</p></div></section>`;
}

function profileCard(p) {
  const targets = p.target_ids.map(id => target(id)).filter(Boolean);
  return `<button type="button" class="profile-card ${p.disabled ? 'disabled' : ''}" data-action="edit-profile" data-profile-id="${esc(p.id)}"><span class="profile-card-head"><strong>${esc(p.name)}</strong>${tag(ui.KIND[p.kind] || '유형 미설정', p.kind ? '' : 'neutral')}${p.disabled ? tag('사용 중지', 'neutral') : ''}</span><span class="meta">${targets.length ? targets.map(t => esc(t.display_name)).join(', ') : '대상이 없어요'}</span></button>`;
}

async function settingsView(ctx) {
  await refreshModel();
  const [credentials, devices, saved] = await Promise.all([api.get('/credentials'), api.get('/auth/devices'), api.get('/id-cards')]);
  state.credentials = credentials.credentials;
  const cards = saved.id_cards;
  const logins = [...state.logins].sort((a, b) => Number(a.disabled) - Number(b.disabled));
  const usage = c => {
    const names = [...new Set((c.in_use || []).map(r => r.source === 'target_signing' ? `${r.login_name} › ${r.name}` : r.name))];
    return names.length ? tag(`연결 ${names.length}개 사용 중`, 'info') + `<span class="meta">${esc(names.join(', '))}</span>` : tag('미사용', 'neutral');
  };
  const credentialRows = state.credentials.map(c => `<div class="setting-row"><span><strong>${esc(c.ref)}</strong><span class="meta">${esc(c.type === 'joint' ? '공동인증서' : '하나인증서 저장소')}${c.type === 'joint' ? ' · ' + esc(String(c.format).toUpperCase()) : ''}${c.fingerprint ? ' · 지문 ' + esc(c.fingerprint.slice(0, 8)) : ''}</span><span class="credential-usage">${usage(c)}</span></span><div class="row-actions">${c.type === 'onesign' ? (state.vaults[c.ref] ? tag('암호 기억 중') + ui.button('잠그기', `data-action="lock-vault" data-store="${esc(c.ref)}"`) : tag('잠김', 'neutral') + ui.button('잠금 해제', `data-action="unlock-vault" data-store="${esc(c.ref)}"`)) : ''}${ui.button('이름 변경', `data-action="rename-credential" data-kind="${esc(c.type)}" data-ref="${esc(c.ref)}"`)}${ui.button('삭제', `data-action="remove-credential" data-kind="${esc(c.type)}" data-ref="${esc(c.ref)}"`, 'secondary danger-text')}</div></div>`).join('');
  const cardRows = cards.map(c => `<div class="setting-row"><span><strong>${esc(c.name)}</strong><span class="meta">${c.kind === 'driver' ? '운전면허증' : '주민등록증'} · 발급일 ${esc(c.issue_date)} · 보관 ${ui.time(c.saved_at)}</span></span><div class="row-actions">${ui.button('이름 변경', `data-action="rename-credential" data-kind="idcard" data-ref="${esc(c.name)}"`)}${ui.button('삭제', `data-action="remove-credential" data-kind="idcard" data-ref="${esc(c.name)}"`, 'secondary danger-text')}</div></div>`).join('');
  const deviceRows = devices.devices.map(d => `<div class="setting-row"><span><strong>${esc(d.name)}</strong><span class="meta">등록 ${ui.time(d.created_at)} · 마지막 사용 ${ui.time(d.last_seen_at)}${d.active ? '' : ' · 비활성'}</span></span><div class="row-actions">${d.current ? tag('현재 브라우저') : ''}${d.active ? ui.button(d.current ? '로그아웃' : '접속 해제', `data-action="revoke-device" data-device="${esc(d.id)}" data-current="${d.current}"`) : ''}</div></div>`).join('');
  return heading('연결·인증서', '기관 로그인과 업무 대상, 프로필을 관리해요.', ui.button('인증서 발급·가져오기', 'data-action="certificate-add"', 'secondary', 'plus') + (logins.length ? ui.button('기관 연결 추가', 'data-action="add-login-dialog"', 'primary', 'plus') : '')) +
    `<div class="connection-list">${logins.length ? logins.map(connectionCard).join('') : onboarding()}</div>` +
    `<section class="section-block"><div class="section-head"><div><h2>업무 프로필</h2><p class="meta">대상을 묶어 개인·사업장·법인별로 보는 이름표예요. 권한이나 명의 확인 근거는 아니에요.</p></div>${ui.button('프로필 추가', 'data-action="new-profile"', 'secondary', 'plus')}</div><div class="profile-grid">${state.profiles.map(profileCard).join('') || '<p class="field-help">프로필 없이 전체에서 바로 사용할 수 있어요. 필요한 경우에만 계좌·사업장을 묶으세요.</p>'}</div></section>` +
    `<details class="advanced-block"><summary><span>인증서·신분증 보관함과 접속 기기</span><span class="meta">인증서 ${state.credentials.length} · 신분증 ${cards.length} · 기기 ${devices.devices.filter(d => d.active).length}</span>${icon('arrow')}</summary><div class="settings-grid"><section class="panel"><div class="panel-heading"><h2>인증서</h2>${ui.button('발급·가져오기', 'data-action="certificate-add"', 'primary')}</div><div class="settings-body">${credentialRows || '<p class="field-help">보관한 인증서가 없어요.</p>'}<p class="field-help">사용하지 않는 인증서는 여기서 이름을 바꾸거나 삭제할 수 있어요. 공동인증서 가져오기·하나인증서 신규 발급은 위 버튼에서 진행해요. 공동·금융인증서 신규 발급은 미지원이에요. 내보내기·설정 추출·기기 등록 파일은 서버에서 관리해요: <span class="code">fin cert joint import|export</span>, <span class="code">fin hana onesign init|export-identity</span>, <span class="code">fin server registration</span>. 연결이 쓰고 있는 인증서는 먼저 그 연결을 해제해야 이름 변경·삭제가 돼요.</p></div></section><section class="panel"><div class="panel-heading"><h2>신분증</h2>${ui.button('신분증 보관', 'data-action="idcard-add"', 'primary')}</div><div class="settings-body">${cardRows || '<p class="field-help">보관한 신분증이 없어요.</p>'}<p class="field-help">신분증 사진과 확인한 정보를 보관 암호로 암호화해 두고, 하나인증서 발급의 신분증 확인 단계에서 골라 써요. 이름과 주민번호·사진은 암호화되어 이 목록에는 종류와 발급일만 보여요. 내보내기는 서버에서 <span class="code">fin idcard export</span>로 해요.</p></div></section><section class="panel"><div class="panel-heading"><h2>웹앱 접속 기기</h2></div><div class="settings-body">${deviceRows}<p class="field-help">새 기기는 서버에서 <span class="code">fin server enroll</span>로 만든 일회성 코드로 등록해요. 기관 세션과는 별개예요.</p></div></section></div></details>`;
}

/* Add-login dialog: method and credential options follow the chosen institution. */
function loginFormBody(institution, method) {
  const methods = institution === 'hana' ? [['joint_certificate', '공동인증서 (앱 인증 필요)'], ['onesign', '하나인증서']] : [['joint_certificate', '공동인증서']];
  const chosen = methods.some(([m]) => m === method) ? method : methods[0][0];
  const kind = chosen === 'onesign' ? 'onesign' : 'joint';
  const options = state.credentials.filter(c => c.type === kind);
  const help = options.length ? '' : `<p class="field-help">보관한 ${kind === 'onesign' ? '하나인증서 저장소' : '공동인증서'}가 없어요. 서버에서 <span class="code">${kind === 'onesign' ? 'fin hana onesign init' : 'fin cert joint import'}</span>으로 보관하거나 ${ui.button('발급·가져오기', 'data-action="certificate-add"')}를 선택하세요.</p>`;
  return `<div class="field"><label for="login-institution">기관</label><select id="login-institution" name="institution" data-change="login-form-change"><option value="hometax" ${institution === 'hometax' ? 'selected' : ''}>홈택스</option><option value="hana" ${institution === 'hana' ? 'selected' : ''}>하나은행</option></select></div>
    <div class="field"><label for="login-method">로그인 방법</label><select id="login-method" name="method" data-change="login-form-change">${methods.map(([v, l]) => `<option value="${v}" ${v === chosen ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
    <div class="field"><label for="login-credential">${kind === 'onesign' ? '하나인증서 저장소' : '공동인증서'}</label><select id="login-credential" name="credential" ${options.length ? '' : 'disabled'}>${options.map(c => `<option value="${esc(c.ref)}">${esc(c.ref)}${c.fingerprint ? ' · ' + esc(c.fingerprint.slice(0, 8)) : ''}</option>`).join('')}</select>${help}</div>
    <div class="field"><label for="login-name">표시 이름</label><input id="login-name" name="name" required maxlength="60" value="${esc(ui.INSTITUTION[institution])} ${institution === 'hana' && chosen === 'onesign' ? '하나인증서' : '개인'}"></div><p class="dialog-note">저장만 하고 기관에는 접속하지 않아요. 명의·사업장은 로그인 후 확인 결과에서 등록해요.</p><div class="login-fields-end"></div>`;
}

async function coverageView(ctx) {
  const capabilities = state.capabilities;
  const groups = [['banking', '뱅킹 · 하나은행'], ['tax', '세금 · 홈택스'], ['giro', '지로 · 모바일지로'], ['common', '공통 · 인증서와 운영']];
  const label = f => f.status === 'available' ? tag(f.placement_label) : f.status === 'setup_required' ? tag('설정 필요', 'warning')
    : f.status === 'local_only' ? tag('서버에서 관리', 'info') : tag('준비 중', 'neutral');
  return heading('전체 기능·지원 상태', 'finance-cli의 기능을 업무·공통 설정·서버 관리에 나누어 연결해요.') +
    note(`실사용 확인은 기록에서 성공 응답을 확인한 경로를 뜻해요. 일부 확인은 로그인 방식·세부 기능별 차이가 있으니 설명을 확인하세요. 현재 로그인 상태나 모든 인증 분기의 성공을 보장하지 않아요.${capabilities.verification_reviewed_at ? ' 확인 기준: ' + esc(capabilities.verification_reviewed_at) + '.' : ''}`) +
    `<div class="capability-grid">${groups.map(([area, title]) => `<section class="panel"><div class="panel-heading"><h2>${title}</h2></div><div class="capability-list">${capabilities.features.filter(f => f.area === area).map(f => `<button ${f.status === 'planned' ? 'disabled aria-disabled="true"' : `data-action="feature-info" data-feature="${esc(f.id)}"`}><span>${esc(f.title)}${f.verification_note ? `<small class="meta">${esc(f.verification_note)}</small>` : ''}${f.reasons.length ? `<small class="meta">${f.reasons.map(r => esc(REASONS[r] || r)).join(', ')}</small>` : ''}</span><span class="pill-row">${label(f)}${f.status !== 'planned' && f.status !== 'local_only' ? ui.verification(f.verification) : ''}</span>${icon('arrow')}</button>`).join('')}</div></section>`).join('')}</div>`;
}

export const views = {
  taxhome: taxHome, dues: ctx => taxList(ctx, 'dues'), payments: ctx => taxList(ctx, 'payments'),
  refunds: ctx => taxList(ctx, 'refunds'), notices: ctx => taxList(ctx, 'notices'), returns: returnsView,
  reports: reportsView, invoices: invoicesView, invoiceform: invoiceFormView,
  accounts: accountsView, history: historyView, transfer: transferView, inquiry: inquiryView, security: securityView,
  bills: ctx => billsView(ctx), deadlines: ctx => billsView(ctx, true), girostatus: giroStatusView,
  activity: activityView, settings: settingsView, coverage: coverageView,
};

// Actions ------------------------------------------------------------------

function loginSecrets(row) {
  if (row.method === 'onesign') return [SECRET_LABELS.vault_passphrase, SECRET_LABELS.pin];
  return [SECRET_LABELS.certificate_password];
}

function loginJob(row) {
  return row.institution === 'hometax' ? 'hometax.login' : row.method === 'onesign' ? 'hana.onesign.login' : 'hana.login';
}

async function afterModel(ctx) { await refreshModel(); await render(); }

function candidatesDialog(ctx, job, loginId) {
  const candidates = job.result?.candidates || job.result?.accounts || [];
  const mapping = job.result?.candidate_targets || {};
  if (!candidates.length) { ui.showDialog('확인 결과', outcomeNote(job) || '<p class="dialog-note">등록할 수 있는 대상이 없어요.</p>'); return; }
  ui.showDialog('기관이 확인한 대상', `<p class="dialog-note">기관 응답에서 확인한 항목만 등록할 수 있어요. 등록한 대상은 프로필에 넣어 볼 수 있어요.</p><div class="settings-body">${candidates.map(c => `<div class="setting-row"><span>${esc(c.label)}<span class="meta">${esc(ui.KIND[c.kind] || c.kind)} · ${esc([c.tin, c.business_number, c.account_number].filter(Boolean).join(' · '))}</span></span>${mapping[c.ref] ? tag('등록됨') : ui.button('등록', `data-action="register-candidate" data-job="${esc(job.id)}" data-login="${esc(loginId)}" data-ref="${esc(c.ref)}"`, 'primary')}</div>`).join('')}</div><div class="dialog-actions"><button class="button primary" data-ui="close">닫기</button></div>`);
}

async function runForLogin(ctx, name, row, extra = {}, {secrets, onDone} = {}) {
  const panelId = document.getElementById('job-' + row.id) ? 'job-' + row.id : 'job-panel';
  return ctx.run(name, {login_id: row.id, ...extra}, {panel: panelId, secrets, key: key(name, {login_id: row.id}), onDone});
}

async function artifactPreview(id) {
  ui.showDialog('문서 보기', `<iframe class="artifact-frame" sandbox referrerpolicy="no-referrer" title="격리된 문서 미리보기" src="/api/v1/artifacts/${encodeURIComponent(id)}?disposition=inline"></iframe><p class="dialog-note">문서는 스크립트와 동일 출처 권한 없이 격리해 보여줘요.</p><div class="dialog-actions"><a class="button secondary" href="/api/v1/artifacts/${encodeURIComponent(id)}">${icon('download')}HTML 저장</a><button class="button primary" data-ui="close">닫기</button></div>`, {wide: true});
}

function approvalIn(row) {
  return Object.values(row || {}).find(v => typeof v === 'string' && /^\d{8}-?[0-9A-Za-z]{8}-?[0-9A-Za-z]{8}$/.test(v)) || null;
}

export const actions = {
  ...certificateActions,
  'choose-tax-target': (ctx, select) => {
    try { sessionStorage.setItem('finance.taxTarget:' + state.profileId, select.value); } catch (error) { /* per-tab only */ }
    render();
  },
  'tax-query': (ctx, form) => runTax(ctx, TAX[form.dataset.view].name, formInput(form), form.dataset.view),
  'returns-mode': (ctx, button) => changeView('returns', {mode: button.dataset.mode}),
  'returns-query': (ctx, form) => runTax(ctx, form.dataset.mode === 'list' ? 'hometax.returns.list' : 'hometax.returns.status',
    Object.fromEntries(Object.entries(formInput(form)).map(([k, v]) => [k, ['year', 'month'].includes(k) ? Number(v) : v])), 'returns'),
  'invoice-direction': (ctx, button) => changeView('invoices', {direction: button.dataset.direction}),
  'invoice-query': (ctx, form) => runTax(ctx, 'hometax.invoice.list', formInput(form), 'invoices'),
  'invoice-new': () => changeView('invoiceform', {}),
  'invoice-prepare': async (ctx, form) => {
    const current = taxTarget();
    const amend = form.dataset.amend;
    const draft = draftInput(form);
    const input = amend ? {approval_number: amend, reason: new FormData(form).get('reason'), ...(Object.keys(draft).length ? {changes: draft} : {})} : draft;
    await ctx.run(amend ? 'hometax.invoice.amend' : 'hometax.invoice.prepare', {login_id: current.login_id, target_id: current.id, input}, {
      panel: 'job-panel', onDone: job => job.status === 'awaiting_input' ? confirmDialog(ctx, job) : ui.showDialog('초안 준비 결과', outcomeNote(job) + (job.result ? draftPreview(job.result) : '') + `<div class="dialog-actions"><button class="button primary" data-ui="close">확인</button></div>`)});
  },
  row: (ctx, row) => {
    const [group, index] = row.dataset.row.split(':');
    const entry = state.rows[group];
    const item = entry?.rows?.[Number(index)];
    if (!item) return;
    let buttons = '';
    if (group === 'returns' && item.rtnCvaId) {
      const source = entry.job?.name === 'hometax.returns.status' ? 'status' : 'list';
      const attrs = `data-return="${esc(item.rtnCvaId)}" data-source="${source}"`;
      buttons = ui.button('제출서식 조회', `data-action="return-forms" ${attrs}`) + ui.button('접수증 저장', `data-action="return-receipt" ${attrs}`) + ui.button('신고서 저장 (전체 서식)', `data-action="return-document" ${attrs}`, 'primary');
    }
    if (group === 'invoices') {
      const approval = approvalIn(item);
      if (approval) buttons = ui.button('상세 조회', `data-action="invoice-detail" data-approval="${esc(approval)}"`) + (entry.job?.input?.direction !== 'purchases' ? ui.button('수정 계산서 작성', `data-action="invoice-amend" data-approval="${esc(approval)}"`, 'primary') : '');
    }
    if (group === 'history') buttons = ui.button('거래 상세 조회', `data-action="history-detail" data-index="${Number(index)}"`);
    if (group === 'inquiry') buttons = ui.button('이체 상세 조회', `data-action="inquiry-detail" data-index="${Number(index)}"`);
    ui.showDialog('상세', `${ui.fieldsList(item)}<p class="dialog-note">기관 응답의 필드명을 그대로 보여줘요. 식별번호류는 가려서 표시해요.</p><div class="dialog-actions">${buttons}<button class="button primary" data-ui="close">닫기</button></div>`);
  },
  'return-forms': (ctx, button) => { ui.closeDialog(); return runTax(ctx, 'hometax.returns.forms', {return_id: button.dataset.return, query_source: button.dataset.source}, 'forms', job => outcomeNote(job) + ui.rowsTable(job.result?.items || [], {group: 'forms'})); },
  'return-receipt': (ctx, button) => { ui.closeDialog(); return runTax(ctx, 'hometax.returns.receipt', {return_id: button.dataset.return, query_source: button.dataset.source}, 'reports', reportResult); },
  'return-document': (ctx, button) => { ui.closeDialog(); return runTax(ctx, 'hometax.returns.document', {return_id: button.dataset.return, query_source: button.dataset.source, all_forms: true}, 'reports', reportResult); },
  'invoice-detail': (ctx, button) => { ui.closeDialog(); return runTax(ctx, 'hometax.invoice.detail', {approval_number: button.dataset.approval}, 'invoice', job => outcomeNote(job) + (job.result?.invoice ? ui.fieldsList(job.result.invoice) : '') + ui.rowsTable(job.result?.items || [], {group: 'invoice-items'})); },
  'invoice-amend': (ctx, button) => changeView('invoiceform', {amend: button.dataset.approval}),
  'preview-artifact': (ctx, button) => artifactPreview(button.dataset.artifact),
  'report-resave': async (ctx, button) => {
    const parent = await api.get('/jobs/' + encodeURIComponent(button.dataset.job));
    await ctx.run('hometax.report.resave', {login_id: parent.login_id, parent_job_id: parent.id, input: {document: Number(button.dataset.document)}}, {panel: 'job-panel', onDone: job => { ui.toast(ui.OUTCOME[job.outcome]?.[0] || job.status); render(); }});
  },
  // Banking
  privacy: () => { state.hidden = !state.hidden; render(); },
  login: async (ctx, button) => {
    const row = login(button.dataset.login);
    const reason = button.dataset.reason === 'session_idle_expired' ? ui.message('session_idle_expired') + ' ' : '';
    const secrets = await askSecrets(`${row.display_name} 로그인`, loginSecrets(row), reason + (row.institution === 'hometax' ? '공동인증서로 홈택스에 로그인해요.' : row.method === 'onesign' ? '하나인증서로 새 로그인 세션을 만들어요.' : '앱 인증과 공동인증서 로그인을 진행해요.'), {store: onesignStore(row)});
    if (!secrets) return;
    await runForLogin(ctx, loginJob(row), row, {}, {secrets, onDone: job => { ui.toast(ui.OUTCOME[job.outcome]?.[0] || ''); if (job.local?.stopped) ui.toast(ui.message(job.local.stopped)); return afterModel(ctx); }});
  },
  'session-check': async (ctx, button) => {
    const row = login(button.dataset.login);
    await runForLogin(ctx, 'hometax.session.refresh', row, {input: {mode: 'resume'}}, {onDone: job => { ui.toast(ui.OUTCOME[job.outcome]?.[0] || ''); return afterModel(ctx); }});
  },
  discover: async (ctx, button) => {
    const row = login(button.dataset.login);
    await runForLogin(ctx, 'hometax.targets.discover', row, {}, {onDone: job => candidatesDialog(ctx, job, row.id)});
  },
  'accounts-query': async (ctx, button) => {
    if (!await ensureBankSession(ctx, button.dataset.login)) return;
    const row = login(button.dataset.login);
    let secrets;
    if (row.method === 'onesign') {
      secrets = await askSecrets('계좌 조회', [SECRET_LABELS.vault_passphrase], '', {store: onesignStore(row)});
      if (!secrets) return;
    }
    await runForLogin(ctx, accountsJobName(row), row, {}, {secrets, onDone: async job => {
      if (job.local?.account_linking_failed) ui.toast('은행 조회는 완료됐지만 계좌를 연결하지 못했어요. 저장소 상태를 확인하세요.');
      await afterModel(ctx);
    }});
  },
  extend: async (ctx, button) => {
    const row = login(button.dataset.login);
    await runForLogin(ctx, 'hana.session.extend', row, {}, {onDone: job => ui.toast(job.outcome === 'success' ? '로그인 연장 요청이 접수되었어요. 현재 세션 상태는 다음 조회에서 확인해요.' : ui.OUTCOME[job.outcome]?.[0])});
  },
  'register-candidate': async (ctx, button) => {
    try {
      const registered = await api.post(`/logins/${encodeURIComponent(button.dataset.login)}/targets`, {job_id: button.dataset.job, candidate: button.dataset.ref});
      const current = profile();
      if (current && !current.target_ids.includes(registered.id)) {
        await api.patch('/profiles/' + encodeURIComponent(current.id), {target_ids: [...current.target_ids, registered.id]});
      }
      ui.toast(current ? `등록하고 ${current.name} 프로필에 넣었어요.` : '대상을 등록했어요.');
      button.replaceWith(Object.assign(document.createElement('span'), {className: 'status-pill', textContent: '등록됨'}));
      await refreshModel();
      if (state.view !== 'settings') render();
    } catch (error) { ui.toast(ui.message(error.code)); }
  },
  'account-login': (ctx, button) => {
    const chosen = target(new FormData(button.closest('form')).get('target_id'));
    return actions.login(ctx, {dataset: {login: chosen.login_id}});
  },
  'history-query': async (ctx, form) => {
    const input = formInput(form);
    const chosen = target(input.target_id);
    delete input.target_id;
    await runHanaQuery(ctx, 'history.list', {login_id: chosen.login_id, target_id: chosen.id, input}, {panel: 'job-panel', onDone: job => { document.getElementById('results').innerHTML = historyRows(job); }});
  },
  'history-more': async (ctx, button) => {
    const parent = state.rows.history?.job;
    await runHanaQuery(ctx, 'history.more', {login_id: parent.login_id, target_id: parent.target_id, parent_job_id: button.dataset.job}, {panel: 'job-panel', onDone: job => { document.getElementById('results').innerHTML = historyRows(job, true); }});
  },
  'history-detail': async (ctx, button) => {
    const entry = state.rows.history;
    const index = Number(button.dataset.index);
    const page = entry.pages.length > 1 ? null : entry.job.id;
    ui.closeDialog();
    if (!page) { ui.toast('상세 조회는 첫 페이지 조회 직후에만 지원해요.'); return; }
    await runHanaQuery(ctx, 'history.detail', {login_id: entry.job.login_id, target_id: entry.job.target_id, parent_job_id: page, input: {row: index + 1}}, {panel: 'job-panel', onDone: job => ui.showDialog('거래 상세', outcomeNote(job) + ui.fieldsList(job.result?.detail) + `<p class="dialog-note">${job.result?.source === 'saved_ledger_row' ? '저장된 거래 행에서 보여줘요. 은행에 요청하지 않았어요.' : '은행 상세 조회 결과예요.'}</p><div class="dialog-actions"><button class="button primary" data-ui="close">닫기</button></div>`)});
  },
  'history-export': async (ctx, button) => {
    const entry = state.rows.history;
    await runHanaQuery(ctx, 'history.export', {login_id: entry.job.login_id, target_id: entry.job.target_id, parent_job_id: button.dataset.job}, {panel: 'job-panel', onDone: job => ui.showDialog('내역 저장', `${(job.artifacts || []).map(a => `<div class="setting-row"><span>${esc(a.filename)}</span><a class="text-button" href="/api/v1/artifacts/${encodeURIComponent(a.id)}">${icon('download')}저장</a></div>`).join('') || outcomeNote(job)}<div class="dialog-actions"><button class="button primary" data-ui="close">닫기</button></div>`)});
  },
  'inquiry-query': async (ctx, form) => {
    const input = formInput(form);
    const chosen = target(input.target_id);
    delete input.target_id;
    await runHanaQuery(ctx, 'inquiry.history', {login_id: chosen.login_id, target_id: chosen.id, input}, {panel: 'job-panel', onDone: job => {
      rememberRows('inquiry', job.result?.rows, {job});
      document.getElementById('results').innerHTML = outcomeNote(job) + ui.rowsTable(job.result?.rows, {group: 'inquiry'});
    }});
  },
  'inquiry-detail': async (ctx, button) => {
    const entry = state.rows.inquiry;
    ui.closeDialog();
    await runHanaQuery(ctx, 'inquiry.detail', {login_id: entry.job.login_id, target_id: entry.job.target_id, parent_job_id: entry.job.id, input: {row: Number(button.dataset.index) + 1}}, {panel: 'job-panel', onDone: job => ui.showDialog('이체 상세', outcomeNote(job) + (job.result?.rows || []).map(r => ui.fieldsList(r)).join('') + `<p class="dialog-note">이체 확정 여부는 따로 판단하지 않아요.</p><div class="dialog-actions"><button class="button primary" data-ui="close">닫기</button></div>`)});
  },
  'security-query': async (ctx, form) => {
    const input = formInput(form);
    const loginId = input.login_id;
    delete input.login_id;
    await runHanaQuery(ctx, 'security.query', {login_id: loginId, input}, {panel: 'job-panel', onDone: job => {
      const observation = job.result?.observation;
      const result = !observation ? '' : input.kind === 'limits' ? ui.transferLimits(observation)
        : (observation.fields ? `<div class="settings-body">${ui.fieldsList({...observation.fields, ...observation.display})}</div>` : '') + ui.rowsTable(observation.rows, {group: 'security'});
      document.getElementById('results').innerHTML = outcomeNote(job) + result + ui.details('진단', observation?.diagnostics);
    }});
  },
  'security-login': (ctx, button) => actions.login(ctx,
    {dataset: {login: button.closest('form').querySelector('[name="login_id"]').value}}),
  'amount-add': (ctx, button) => {
    const input = document.querySelector('#transfer-amount');
    const value = Number(String(input.value).replace(/\D/g, '')) || 0;
    input.value = money(value + Number(button.dataset.add));
  },
  'amount-clear': () => { document.querySelector('#transfer-amount').value = ''; },
  'transfer-prepare': async (ctx, form) => {
    const data = new FormData(form);
    const source = target(data.get('target_id'));
    if (!await ensureBankSession(ctx, source.login_id)) return;
    const owner = login(source.login_id);
    if (owner.readiness !== 'ready') { ui.toast('하나인증서로 새로 로그인한 뒤 준비하세요.'); return; }
    const amount = Number(String(data.get('amount')).replace(/\D/g, ''));
    if (!amount) { ui.toast('보낼 금액을 입력하세요.'); return; }
    const secrets = await askSecrets('이체 준비', [SECRET_LABELS.vault_passphrase, SECRET_LABELS.account_password], '은행의 확인 화면까지 준비해요. 이 단계에서는 이체하지 않아요.', {store: onesignStore(owner, true)});
    if (!secrets) return;
    await ctx.run('hana.transfer.prepare', {login_id: source.login_id, target_id: source.id, input: {
      recipient_bank_code: data.get('bank'), recipient_account_number: String(data.get('account')).replace(/\s/g, ''), amount_krw: amount}}, {
      panel: 'job-panel', secrets, onDone: job => job.status === 'awaiting_input' ? confirmDialog(ctx, job) : ui.showDialog('이체 준비 결과', outcomeNote(job) + (job.local?.authentication_not_supported ? note('은행이 이 CLI가 지원하지 않는 추가 인증을 요구해 멈췄어요. 이체는 실행하지 않았어요.') : '') + `<div class="dialog-actions"><button class="button primary" data-ui="close">확인</button></div>`)});
    await refreshModel();
  },
  reconcile: async (ctx, button) => {
    const parent = await api.get('/jobs/' + encodeURIComponent(button.dataset.job));
    if (!await ensureBankSession(ctx, parent.login_id)) return;
    const secrets = await askSecrets('이체 결과 조회', [SECRET_LABELS.vault_passphrase], '같은 이체를 다시 보내지 않고 이체 내역에서 결과를 대조해요.', {store: onesignStore(login(parent.login_id), true)});
    if (!secrets) return;
    await ctx.run('hana.transfer.reconcile', {login_id: parent.login_id, target_id: parent.target_id, parent_job_id: parent.id}, {
      panel: 'job-panel', secrets, onDone: job => {
        const r = job.reconciliation || {};
        ui.showDialog('이체 결과 조회', `<div class="summary-lines"><div class="summary-line"><span>결과 조회</span><strong>${r.queried ? '조회함' : '조회 못 함'}</strong></div><div class="summary-line"><span>계좌·금액 일치 후보</span><strong>${r.candidate_complete ? '있음' : '없음'}</strong></div><div class="summary-line"><span>준비한 거래와의 연결 확인</span><strong>${r.transfer_confirmed ? '확인' : '확인 안 됨'}</strong></div></div><p class="dialog-note">결과 조회는 실행 판정과 따로 기록해요. 후보 일치만으로 이체 성공을 확정하지 않아요.</p><div class="dialog-actions"><button class="button primary" data-ui="close">확인</button></div>`);
      }});
  },
  // Giro
  'bills-parse': async (ctx, form) => {
    const data = new FormData(form);
    const file = data.get('file');
    if (!(file instanceof File) || !file.size) { ui.toast('고지 자료 파일을 선택하세요.'); return; }
    let upload;
    try { upload = await api.upload('giro_bills', file); } catch (error) { ui.toast(ui.message(error.code)); return; }
    const input = {upload_id: upload.id, tax_type: data.get('tax_type'), mode: form.dataset.mode};
    if (form.dataset.mode === 'due') Object.assign(input, {today: data.get('today') || undefined, within_days: Number(data.get('within_days') || 7), include_overdue: form.querySelector('[name=include_overdue]').checked});
    await ctx.run('giro.bills.parse', {input}, {panel: 'job-panel', onDone: job => { document.getElementById('results').innerHTML = billsResult(job); }});
  },
  'giro-readiness': ctx => ctx.run('giro.readiness', {}, {panel: 'job-panel', key: key('giro.readiness'), onDone: job => { document.getElementById('results').innerHTML = job.result ? giroPlan(job.result) : outcomeNote(job); }}),
  // Common
  'activity-scope': (ctx, button) => changeView('activity', {scope: button.dataset.scope}),
  'cancel-job': async (ctx, button) => {
    try { await api.post(`/jobs/${encodeURIComponent(button.dataset.job)}/cancel`); ui.closeDialog(); ui.toast('작업을 취소했어요.'); render(); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'feature-info': (ctx, button) => {
    const item = state.capabilities.features.find(f => f.id === button.dataset.feature);
    const local = item.status === 'local_only';
    ui.showDialog(item.title, `<div class="summary-lines"><div class="summary-line"><span>제공 위치</span><strong>${esc(item.placement_label)}</strong></div><div class="summary-line"><span>상태</span><strong>${esc(item.status)}</strong></div>${item.jobs.map(j => `<div class="summary-line"><span>${esc(j.title)}${j.verification_note ? `<small class="meta">${esc(j.verification_note)}</small>` : ''}</span><strong>${ui.verification(j.verification)} ${esc(j.status)}${j.requires_confirmation ? ' · 확인 필요' : ''}${j.requires_input.length ? ' · 입력: ' + esc(j.requires_input.join(', ')) : ''}</strong></div>`).join('')}</div><p class="dialog-note">${item.verification_note ? esc(item.verification_note) + ' ' : ''}${item.verification_reviewed_at ? '확인 기준: ' + esc(item.verification_reviewed_at) + '. ' : ''}${local ? 'CLI나 로컬 라이브러리에는 있지만 원격 실행 경로가 없는 서버 관리 기능이에요.' : '사용 가능 표시는 현재 로그인이나 대상 확인을 보장하지 않아요.'}</p>${ui.verification(item.verification)}<div class="dialog-actions"><button class="button primary" data-ui="close">닫기</button></div>`);
  },
  'add-login-dialog': () => {
    ui.showDialog('기관 연결 추가', `<form data-submit="add-login" autocomplete="off"><div class="login-fields">${loginFormBody('hometax', 'joint_certificate')}</div><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">추가</button></div></form>`);
  },
  'login-form-change': (ctx, select) => {
    const form = select.closest('form');
    const data = new FormData(form);
    form.querySelector('.login-fields').innerHTML = loginFormBody(data.get('institution'), data.get('method'));
  },
  'add-login': async (ctx, form) => {
    const data = Object.fromEntries(new FormData(form).entries());
    if (!data.credential) { ui.toast('먼저 서버에 인증서를 보관하세요.'); return; }
    try { await api.post('/logins', {institution: data.institution, method: data.method, name: data.name, credential: data.credential}); ui.closeDialog(); ui.toast('연결을 추가했어요. 기관에는 접속하지 않았어요.'); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'login-menu': (ctx, button) => {
    const row = login(button.dataset.login);
    const hometax = row.institution === 'hometax';
    const onesign = row.method === 'onesign';
    const items = [];
    const item = (run, label, hint = '', tone = '') => items.push(`<button type="button" class="${tone}" data-action="menu-run" data-run="${run}" data-login="${esc(row.id)}"><span>${esc(label)}</span>${hint ? `<small>${esc(hint)}</small>` : ''}</button>`);
    if (!row.disabled) {
      item('login', row.current_session_id ? '다시 로그인' : '로그인', onesign ? '새 세션을 만들어요' : '');
      if (hometax) { item('session-check', '세션 확인', '저장된 세션이 아직 유효한지 확인해요'); item('discover', '사용자·사업장 확인', '대상을 추가로 등록해요'); }
      if (row.institution === 'hana') item('accounts-query', '계좌 조회', '조회된 계좌는 자동으로 연결돼요');
      if (row.institution === 'hana' && !onesign) item('extend', '로그인 연장');
      if (hometax) item('signing', '계산서 발급 인증서');
      if (onesign && row.signing?.transfer_sign?.ref && row.signing.transfer_sign.ref !== row.credential?.ref)
        item('signing', '별도 이체 인증서', '로그인 인증서 사용으로 되돌릴 수 있어요');
    }
    item('sessions', '세션 기록');
    item('rename-login', '이름 변경');
    item('toggle-login', row.disabled ? '다시 사용' : '사용 중지', row.disabled ? '' : '새 작업을 막고 기록은 남겨요', row.disabled ? '' : 'danger');
    item('remove-login', '연결 해제', '연결·대상·세션을 지우고 작업 기록은 남겨요', 'danger');
    ui.showDialog(row.display_name, `<p class="meta">${esc(ui.INSTITUTION[row.institution])} · ${esc(ui.METHOD[row.method])}</p><div class="menu-list">${items.join('')}</div>`);
  },
  'target-menu': (ctx, button) => {
    const item = target(button.dataset.target);
    const attrs = `data-action="menu-run" data-target="${esc(item.id)}"`;
    ui.showDialog(item.display_name, `<p class="meta">${esc(ui.KIND[item.kind] || item.kind)} · ${esc(login(item.login_id)?.display_name)}</p><div class="menu-list"><button type="button" ${attrs} data-run="rename-target"><span>이름 변경</span></button>${item.kind === 'business' ? `<button type="button" ${attrs} data-run="target-signing"><span>사업장 발급용 인증서</span><small>${esc(item.signing?.invoice_sign?.ref || '로그인 기본값')}</small></button>` : ''}<button type="button" class="${item.disabled ? '' : 'danger'}" ${attrs} data-run="toggle-target"><span>${item.disabled ? '다시 사용' : '사용 중지'}</span></button></div>`);
  },
  'menu-run': (ctx, button) => { ui.closeDialog(); return actions[button.dataset.run](ctx, button); },
  'remove-login': (ctx, button) => {
    const row = login(button.dataset.login);
    const targets = state.targets.filter(t => t.login_id === row.id);
    ui.showDialog(`${row.display_name} 연결 해제`, `<form data-submit="confirm-remove-login" data-login="${esc(row.id)}"><p class="dialog-note">이 서버에서 연결을 지워요. 다시 쓰려면 연결을 새로 추가하고 대상을 다시 확인해야 해요.</p><div class="summary-lines"><div class="summary-line"><span>지우는 것</span><strong>연결 설정, 대상 ${targets.length}개와 프로필 묶음, 이 서버가 만든 세션 파일</strong></div><div class="summary-line"><span>남기는 것</span><strong>작업 기록·저장 문서, 인증서와 하나인증서 저장소</strong></div></div><p class="dialog-note">확인을 기다리는 이체·계산서는 취소돼요. 실행 중인 작업이 있으면 해제하지 않아요. 기관에서 로그아웃하지는 않아요.</p><p class="form-error" id="remove-login-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">연결 해제</button></div></form>`);
  },
  'confirm-remove-login': async (ctx, form) => {
    const row = login(form.dataset.login);
    try {
      const result = await api.post(`/logins/${encodeURIComponent(row.id)}/remove`, {expected_revision: row.revision});
      ui.closeDialog();
      ui.toast(result.session_files_not_removed ? '연결을 해제했어요. 일부 세션 파일은 지우지 못했어요.' : '연결을 해제했어요.');
      await afterModel(ctx);
    } catch (error) { document.querySelector('#remove-login-error').textContent = ui.message(error.code); }
  },
  'rename-login': (ctx, button) => {
    const row = login(button.dataset.login);
    ui.showDialog('연결 이름', `<form data-submit="save-login-name" data-login="${esc(row.id)}"><div class="field"><label for="login-rename">표시 이름</label><input id="login-rename" name="name" value="${esc(row.display_name)}" required maxlength="60"></div><p class="dialog-note">이름은 표시용이에요. 실행 설정은 바뀌지 않아요.</p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">저장</button></div></form>`);
  },
  'save-login-name': async (ctx, form) => {
    const row = login(form.dataset.login);
    try { await api.patch('/logins/' + encodeURIComponent(row.id), {expected_revision: row.revision, name: new FormData(form).get('name')}); ui.closeDialog(); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'new-profile': () => {
    ui.showDialog('프로필 추가', `<form data-submit="add-profile"><div class="field"><label for="profile-new-name">이름</label><input id="profile-new-name" name="name" required maxlength="60" placeholder="예: A스튜디오"></div><div class="field"><label for="profile-new-kind">유형</label><select id="profile-new-kind" name="kind"><option value="">미설정</option><option value="personal">개인</option><option value="sole_proprietor">개인사업자</option><option value="corporation">법인</option></select></div>${state.targets.length ? `<div class="field"><label>대상</label><div class="check-list">${state.targets.map(t => `<label><input type="checkbox" name="targets" value="${esc(t.id)}"> ${esc(t.display_name)} <span class="meta">${esc(ui.KIND[t.kind] || t.kind)} · ${esc(login(t.login_id)?.display_name)}</span></label>`).join('')}</div></div>` : ''}<p class="dialog-note">이름·유형은 표시용이며 권한이나 명의 확인 근거가 아니에요.</p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">추가</button></div></form>`);
  },
  'add-profile': async (ctx, form) => {
    const data = new FormData(form);
    try { await api.post('/profiles', {name: data.get('name'), kind: data.get('kind') || null, target_ids: data.getAll('targets')}); ui.closeDialog(); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'edit-profile': (ctx, button) => {
    const item = state.profiles.find(p => p.id === button.dataset.profileId);
    ui.showDialog('프로필 편집', `<form data-submit="save-profile" data-profile-id="${esc(item.id)}"><div class="field"><label for="profile-name">이름</label><input id="profile-name" name="name" value="${esc(item.name)}" required maxlength="60"></div><div class="field"><label for="profile-kind">유형</label><select id="profile-kind" name="kind">${[['', '미설정'], ['personal', '개인'], ['sole_proprietor', '개인사업자'], ['corporation', '법인']].map(([v, l]) => `<option value="${v}" ${(item.kind || '') === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div><div class="field"><label>대상</label><div class="check-list">${state.targets.map(t => `<label><input type="checkbox" name="targets" value="${esc(t.id)}" ${item.target_ids.includes(t.id) ? 'checked' : ''}>${esc(t.display_name)} · ${esc(ui.KIND[t.kind])} (${esc(login(t.login_id)?.display_name)})</label>`).join('') || '<span class="field-help">등록한 대상이 없어요.</span>'}</div></div><label class="check"><input type="checkbox" name="disabled" ${item.disabled ? 'checked' : ''}> 사용 중지</label><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">저장</button></div></form>`);
  },
  'save-profile': async (ctx, form) => {
    const data = new FormData(form);
    try {
      await api.patch('/profiles/' + encodeURIComponent(form.dataset.profileId), {name: data.get('name'), kind: data.get('kind') || null, target_ids: data.getAll('targets'), disabled: data.get('disabled') === 'on'});
      ui.closeDialog(); await afterModel(ctx);
    } catch (error) { ui.toast(ui.message(error.code)); }
  },
  signing: (ctx, button) => {
    const row = login(button.dataset.login);
    const hometax = row.institution === 'hometax';
    const purpose = hometax ? 'invoice_sign' : 'transfer_sign';
    const kind = hometax ? 'joint' : 'onesign';
    ui.showDialog(hometax ? '발급용 인증서' : '이체 서명 수단', `<form data-submit="save-signing" data-login="${esc(row.id)}" data-purpose="${purpose}" data-method="${hometax ? 'joint_certificate' : 'onesign'}"><div class="field"><label for="signing-ref">자격 증명</label><select id="signing-ref" name="credential"><option value="">${hometax ? '지정 해제' : '로그인 인증서 사용'}</option>${state.credentials.filter(c => c.type === kind).map(c => `<option value="${esc(c.ref)}" ${row.signing?.[purpose]?.ref === c.ref ? 'selected' : ''}>${esc(c.ref)}</option>`).join('')}</select></div><p class="dialog-note">바꾸면 설정 revision이 올라가 세션 재확인이 필요하고, 확인 대기 중인 초안·이체는 무효가 돼요. 만료·실패 시 다른 인증서로 자동 전환하지 않아요.</p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">저장</button></div></form>`);
  },
  'save-signing': async (ctx, form) => {
    const row = login(form.dataset.login);
    const credential = new FormData(form).get('credential');
    const value = credential ? {method: form.dataset.method, credential} : null;
    try { await api.patch('/logins/' + encodeURIComponent(row.id), {expected_revision: row.revision, signing: {[form.dataset.purpose]: value}}); ui.closeDialog(); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'target-signing': (ctx, button) => {
    const item = target(button.dataset.target);
    ui.showDialog('사업장 발급용 인증서', `<form data-submit="save-target-signing" data-target="${esc(item.id)}"><div class="field"><label for="target-signing">공동인증서</label><select id="target-signing" name="credential"><option value="">로그인 기본값 사용</option>${state.credentials.filter(c => c.type === 'joint').map(c => `<option value="${esc(c.ref)}" ${item.signing?.invoice_sign?.ref === c.ref ? 'selected' : ''}>${esc(c.ref)}</option>`).join('')}</select></div><p class="dialog-note">사업장마다 발급용 인증서가 다르면 여기에서 지정해요. 대상 지정이 로그인 기본값보다 우선해요.</p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">저장</button></div></form>`);
  },
  'save-target-signing': async (ctx, form) => {
    const item = target(form.dataset.target);
    const credential = new FormData(form).get('credential');
    try { await api.patch('/targets/' + encodeURIComponent(item.id), {expected_revision: login(item.login_id).revision, signing: {invoice_sign: credential ? {method: 'joint_certificate', credential} : null}}); ui.closeDialog(); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'rename-target': (ctx, button) => {
    const item = target(button.dataset.target);
    ui.showDialog('대상 이름', `<form data-submit="save-target-name" data-target="${esc(item.id)}"><div class="field"><label for="target-name">표시 이름</label><input id="target-name" name="name" value="${esc(item.display_name)}" required maxlength="60"></div><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">저장</button></div></form>`);
  },
  'save-target-name': async (ctx, form) => {
    try { await api.patch('/targets/' + encodeURIComponent(form.dataset.target), {name: new FormData(form).get('name')}); ui.closeDialog(); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'toggle-target': async (ctx, button) => {
    const item = target(button.dataset.target);
    try { await api.patch('/targets/' + encodeURIComponent(item.id), {disabled: !item.disabled}); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'toggle-login': async (ctx, button) => {
    const row = login(button.dataset.login);
    try { await api.patch('/logins/' + encodeURIComponent(row.id), {expected_revision: row.revision, disabled: !row.disabled}); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  sessions: async (ctx, button) => {
    const value = await api.get(`/logins/${encodeURIComponent(button.dataset.login)}/sessions`);
    const labels = {usable: '사용 가능', consumed: '사용함·대체됨', expired: '만료', stale: '재확인 필요'};
    ui.showDialog('세션 기록', `<p class="dialog-note">저장된 성공 기록만으로 현재 유효성을 보장하지 않아요. 마지막 확인 시각을 함께 보세요.</p><div class="settings-body">${value.sessions.map(s => `<div class="setting-row"><span>${ui.time(s.created_at)}${s.id === value.current_session_id ? ' · 현재' : ''}<span class="meta">확인 ${ui.time(s.checked_at)}${s.note ? ' · ' + esc(s.note) : ''}</span></span>${tag(labels[s.state] || s.state, s.state === 'usable' ? '' : 'neutral')}</div>`).join('') || '<p class="field-help">세션이 없어요.</p>'}</div><div class="dialog-actions"><button class="button primary" data-ui="close">닫기</button></div>`);
  },
  'rename-credential': (ctx, button) => {
    const {kind, ref} = button.dataset;
    if (credentialInUse(kind, ref, '이름 변경')) return;
    ui.showDialog(`${ref} 이름 변경`, `<form data-submit="save-credential-name" data-kind="${esc(kind)}" data-ref="${esc(ref)}" autocomplete="off"><div class="field"><label for="credential-rename">새 이름</label><input id="credential-rename" name="new_name" value="${esc(ref)}" required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}" spellcheck="false"></div><p class="field-help">영문·숫자로 시작하고 영문·숫자·<span class="code">_ . -</span>만 쓸 수 있어요. ${kind === 'idcard' ? '이름만 바뀌고 보관한 신분증은 그대로예요.' : '이름만 바뀌고 인증서와 키는 그대로예요.'}${kind === 'onesign' ? ' 기억 중인 저장소 암호도 새 이름으로 이어져요.' : ''}</p><p class="form-error" id="credential-rename-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">저장</button></div></form>`);
  },
  'save-credential-name': async (ctx, form) => {
    const {kind, ref} = form.dataset;
    const newName = String(new FormData(form).get('new_name') || '').trim();
    try {
      await api.post(`${storePath(kind, ref)}/rename`, {new_name: newName});
      ui.closeDialog(); ui.toast(`${ref} → ${newName}로 바꿨어요.`); await afterModel(ctx);
    } catch (error) {
      document.querySelector('#credential-rename-error').textContent = error.code === 'credential_in_use'
        ? '그사이 이 인증서를 쓰는 연결이 생겼어요. 화면을 새로 고치세요.' : ui.message(error.code);
    }
  },
  'remove-credential': (ctx, button) => {
    const {kind, ref} = button.dataset;
    const label = {joint: '공동인증서', onesign: '하나인증서 저장소', idcard: '신분증'}[kind];
    if (credentialInUse(kind, ref, '삭제')) return;
    const backup = {joint: `fin cert export ${ref} --output …`, onesign: `fin hana onesign export-identity --name ${ref} --output …`,
      idcard: `fin idcard export ${ref} --output …`}[kind];
    ui.showDialog(`${ref} 삭제`, `<form data-submit="confirm-remove-credential" data-kind="${esc(kind)}" data-ref="${esc(ref)}" autocomplete="off"><p class="dialog-note danger-note">이 ${label}${kind === 'idcard' ? '을' : '를'} 이 서버에서 지워요. 되돌릴 수 없고, 백업이 없으면 ${kind === 'idcard' ? '사진과 정보를 다시 보관해야 해요.' : '다시 가져오거나 새로 발급해야 해요.'}${kind === 'onesign' ? ' 기기 식별자와 인증서 기록이 함께 지워지고, 기억 중인 저장소 암호도 잊어요.' : ''} 필요하면 먼저 서버에서 <span class="code">${esc(backup)}</span>로 백업하세요.</p><div class="field"><label for="remove-confirm">확인을 위해 이름 <strong>${esc(ref)}</strong>을 입력하세요</label><input id="remove-confirm" name="confirm" required autocomplete="off" spellcheck="false"></div><p class="form-error" id="remove-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">삭제</button></div></form>`);
  },
  'confirm-remove-credential': async (ctx, form) => {
    const {kind, ref} = form.dataset;
    const confirm = String(new FormData(form).get('confirm') || '');
    if (confirm !== ref) { document.querySelector('#remove-error').textContent = '입력한 이름이 달라요.'; return; }
    try {
      await api.post(`${storePath(kind, ref)}/remove`, {confirm});
      ui.closeDialog(); ui.toast(`${ref}을 삭제했어요.`); await afterModel(ctx);
    } catch (error) {
      document.querySelector('#remove-error').textContent = error.code === 'credential_in_use'
        ? '그사이 이 인증서를 쓰는 연결이 생겼어요. 화면을 새로 고치세요.' : ui.message(error.code);
    }
  },
  'unlock-vault': async (ctx, button) => {
    const store = button.dataset.store;
    ui.showDialog('하나인증서 저장소 잠금 해제', `<form data-submit="save-unlock" data-store="${esc(store)}" autocomplete="off"><p class="dialog-note">입력한 저장소 암호는 서버를 끌 때까지 서버 메모리에만 기억하고 디스크에는 저장하지 않아요. 그동안 이 저장소를 쓰는 로그인·조회·이체에서 저장소 암호를 묻지 않아요.</p><div class="field"><label for="unlock-passphrase">저장소 암호</label><input id="unlock-passphrase" name="passphrase" type="password" required autocomplete="off"></div><p class="form-error" id="unlock-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button class="button primary" type="submit">잠금 해제</button></div></form>`);
  },
  'save-unlock': async (ctx, form) => {
    const passphrase = new FormData(form).get('passphrase');
    try {
      await api.post(`/vaults/${encodeURIComponent(form.dataset.store)}/unlock`, {passphrase});
      form.reset(); ui.closeDialog(); ui.toast('서버를 끌 때까지 저장소 암호를 기억해요.'); await afterModel(ctx);
    } catch (error) { document.querySelector('#unlock-error').textContent = ui.message(error.code); }
  },
  'lock-vault': async (ctx, button) => {
    try { await api.post(`/vaults/${encodeURIComponent(button.dataset.store)}/lock`); ui.toast('저장소 암호를 서버 메모리에서 지웠어요.'); await afterModel(ctx); }
    catch (error) { ui.toast(ui.message(error.code)); }
  },
  'revoke-device': async (ctx, button) => {
    try {
      if (button.dataset.current === 'true') { await api.post('/auth/logout'); location.reload(); return; }
      await api.delete('/auth/devices/' + encodeURIComponent(button.dataset.device)); render();
    } catch (error) { ui.toast(ui.message(error.code)); }
  },
};

/* Saved ID cards have their own store; certificates share the credential endpoints. */
function storePath(kind, ref) {
  return kind === 'idcard' ? `/id-cards/${encodeURIComponent(ref)}` : `/credentials/${encodeURIComponent(kind)}/${encodeURIComponent(ref)}`;
}

/* A credential some connection or profile uses cannot be renamed or removed here. */
function credentialInUse(kind, ref, verb) {
  const item = state.credentials.find(c => c.type === kind && c.ref === ref);
  const uses = item?.in_use || [];
  if (!uses.length) return false;
  const names = [...new Set(uses.map(r => r.source === 'target_signing' ? `${r.login_name} › ${r.name}` : r.name))];
  ui.showDialog(`${ref} ${verb}`, `<p class="dialog-note">이 인증서를 쓰는 연결이 있어 ${verb}할 수 없어요. 먼저 아래 연결을 해제하세요. 연결은 해제한 뒤 인증서를 골라 다시 추가할 수 있어요.</p><div class="settings-body">${names.map(n => `<div class="setting-row"><span>${esc(n)}</span></div>`).join('')}</div><div class="dialog-actions"><button class="button primary" data-ui="close">확인</button></div>`);
  return true;
}

function reportResult(job) {
  const documents = job.result?.documents || [];
  return outcomeNote(job) + (documents.length ? `<div class="document-list">${documents.map(d => `<article class="document-row"><span class="record-icon">${icon('report')}</span><div class="record-main"><h3>${esc(d.form?.frmlNm || '접수증')}</h3><p>${esc(d.artifact?.page_count ?? '—')}쪽 · ${esc(d.reason || '')}</p></div>${d.artifact?.complete ? tag('완전') : tag('확인 필요', 'warning')}<div class="row-actions">${d.artifact_id ? `<button class="button secondary" data-action="preview-artifact" data-artifact="${esc(d.artifact_id)}">보기</button><a class="text-button" href="/api/v1/artifacts/${encodeURIComponent(d.artifact_id)}">${icon('download')}저장</a>` : ''}</div></article>`).join('')}</div>` : '<div class="empty-state">저장한 문서가 없어요.</div>');
}
