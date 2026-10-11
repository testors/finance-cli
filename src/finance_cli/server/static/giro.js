/* Giro uses the registered CLI device and asks for a PIN only at login/payment. */
import {api} from './api.js';
import * as ui from './ui.js';
import {state, login, askSecrets, refreshModel, render, changeView, jobState} from './app.js';

const {esc, button, heading, note} = ui;
export const TAXES = [['national', '국세'], ['local', '지방세'], ['customs', '관세'],
  ['env', '환경개선부담금'], ['nontax', '세외수입'], ['traffic', '경찰청범칙금'], ['penalty', '법무부국고금'],
  ['patent', '특허수수료'], ['marine', '항만수수료'], ['fund', '기금 및 기타국고'], ['water', '상하수도요금'],
  ['social', '통합사회보험료'], ['annuity', '국민연금 반납금·추납보험료'], ['employ', '고용보험 연납·분기납'],
  ['industry', '산재보험 연납·분기납'], ['kepco', '전기요금'], ['ktcomm', 'KT 통신요금'], ['tv', 'TV수신료'], ['giro', '일반지로']];
const PAYABLE = ['national', 'local', 'customs'];
const NUMBER_INPUTS = {water: [['elec_water_no', '전자수용가번호']], social: [['number', '전자납부번호']],
  annuity: [['number', '전자납부번호']], employ: [['insure_no', '보험관리번호']], industry: [['insure_no', '보험관리번호']],
  kepco: [['number', '고객번호']], ktcomm: [['number', '전자납부번호·전화번호']], tv: [['number', '관리번호 (10자리)']],
  giro: [['giro_no', '지로번호'], ['number', '전자납부번호']]};
const PIN = ['pin', '지로 로그인 간편비밀번호 6자리', '[0-9]{6}'];
const ACCOUNT = ['account_password', '출금 계좌 비밀번호 4자리', '[0-9]{4}'];
const connection = () => state.logins.find(r => r.institution === 'giro' && !r.disabled);
const money = value => /^\d+$/.test(String(value ?? '')) ? BigInt(value).toLocaleString('ko-KR') + '원' : String(value ?? '확인 안 됨');
const date = value => String(value || '').replace(/^(\d{4})(\d{2})(\d{2})$/, '$1-$2-$3');
const taxName = value => TAXES.find(([v]) => v === value)?.[1] || '세금';
const options = (rows, selected) => rows.map(([v, label]) => `<option value="${esc(v)}" ${v === selected ? 'selected' : ''}>${esc(label)}</option>`).join('');
const panel = () => '<div id="job-panel" class="job-panel"></div>';
const ready = row => row?.readiness === 'ready';
// The shell offers a new login beside the heading while logged in and asks for the login in its
// notice when logged out; with no connection yet, the screen itself offers the first login.
const start = (title, description) => heading(title, description);
const loginFirst = text => `<div class="empty-state">${text}<div class="section-actions">${button('지로 로그인', 'data-action="giro-login"', 'primary')}</div></div>`;
const close = (kind = 'primary') => `<div class="dialog-actions">${button('닫기', 'data-ui="close"', kind)}</div>`;

/* The jobs of one name for this login, newest first. The server filters before it limits, so a
   result is found however many other jobs came after it. */
async function listing(name, row, limit = 1) {
  const rows = (await api.get('/jobs?' + new URLSearchParams({name, login_id: row.id, limit: String(limit)}))).jobs;
  return rows.filter(j => j.name === name && j.login_id === row.id);
}
/* `tax` narrows by the stored input, so it reads the recent bill queries instead of only the newest. */
async function latest(name, row, tax = null) {
  const item = (await listing(name, row, tax ? 50 : 1)).find(j => !tax || j.input?.tax_type === tax);
  return item ? api.get('/jobs/' + encodeURIComponent(item.id)) : null;
}

function notices(job) {
  if (!job) return '';
  let result = job.local?.stopped ? note(esc(ui.message(job.local.stopped))) : '';
  const validationIssue = ['recipient_public_lookup_failed', 'recipient_validation_failed',
    'recipient_validation_incomplete'].find(code => job.local?.processing_issues?.includes(code));
  if (validationIssue) result += note(esc(ui.message(validationIssue)));
  if (job.result?.no_bills_reported) return result + note('기관에서 “고지내용 없음”으로 응답했어요. 납부할 고지가 없다는 안내이며, 정상 목록 조회(0건)와는 다른 응답이에요.');
  if (job.local?.next_action === 'identity_registration_required') result += note('지로에 본인정보 등록이 필요해요. 모바일지로 앱에서 등록 상태를 확인하세요.');
  if (job.local?.next_action === 'integrated_busy_day') result += note('납부집중일에는 통합조회가 제한돼요. 개별 항목을 선택해 조회하세요.');
  if (job.local?.next_action === 'direct_input_payment_required') result += note('이 지로번호는 조회납부를 지원하지 않아요. 고지서 내용을 직접 입력하는 납부는 현재 지원하지 않아요.');
  if (job.result?.complete === false) result += note('조회가 완료되지 않았어요. 수신한 항목만 표시해요.');
  if (job.outcome === 'rejected') result += note(`기관에서 요청을 처리하지 않았어요. 응답 코드: ${esc(job.service_verdict?.response_code || '확인 안 됨')}`);
  return result;
}

export async function giroLogin(ctx, row = null) {
  row ||= connection();
  const inputs = await askSecrets('모바일지로 로그인', [PIN], 'CLI에서 등록한 지로 기기로 로그인해요. 모바일지로 앱이나 CLI에서 사용한 로그인 간편비밀번호를 입력하세요.');
  if (!inputs) return;
  if (!row) {
    row = await api.post('/logins', {institution: 'giro', method: 'pin', name: '모바일지로'});
    await refreshModel();
  }
  await ctx.run('giro.login', {login_id: row.id}, {secrets: inputs, panel: 'job-panel', onDone: async job => {
    await refreshModel();
    if (job.outcome === 'success' && job.result?.session_id) {
      ui.toast('지로에 로그인했어요.');
      await render();
    } else ui.showDialog('지로 로그인 결과', jobState(job) + notices(job) +
      (!job.result?.session_id && job.outcome === 'success' ? note('기관 로그인은 성공했지만 세션 보관을 완료하지 못했어요.') : '') + close());
  }});
}

function billsResult(job, live) {
  if (!job) return `<div class="empty-state">${live ? '요금 종류를 고르고 고지 조회를 누르세요.' : '아직 조회한 고지가 없어요.'}</div>`;
  const rows = job.result?.bills;
  const region = job.result?.query_region;
  const where = region ? note(`조회 지역: ${esc([region.province, region.district].filter(Boolean).join(' '))}`) : '';
  // Nothing billed: the institution says so in place of a list, so no list count is shown for it.
  if (job.result?.no_bills_reported) return jobState(job) + where + '<div class="empty-state">납부할 고지가 없어요.</div><div class="list-footer">기관이 목록 대신 “고지내용 없음”으로 응답했어요.</div>';
  const before = jobState(job) + notices(job) + where;
  if (!Array.isArray(rows)) return before + note('고지 목록을 확인하지 못했어요.');
  const shown = rows.filter(Boolean);
  if (!shown.length) return before + note(job.result.complete ? '조회된 고지가 없어요.' : '표시할 고지 항목을 받지 못했어요.');
  return before + `<div class="table-wrap"><table class="table data"><thead><tr><th>세목</th><th>청구기관</th><th class="num">납부금액</th><th>납부기한</th><th>전자납부번호</th><th></th></tr></thead><tbody>${shown.map(r => `<tr><td data-label="세목">${esc(r.tax_name || taxName(r.tax_type))}</td><td data-label="청구기관">${esc(r.issuer || '확인 안 됨')}</td><td class="num" data-label="납부금액">${esc(money(r.amount_raw?.replaceAll(',', '') ?? r.amount))}</td><td data-label="납부기한">${esc(r.due_date || r.due_date_raw || '확인 안 됨')}</td><td data-label="전자납부번호">${esc(r.electronic_number)}</td><td>${live ? button('상세', `data-action="giro-bill-detail" data-job="${esc(job.id)}" data-ref="${esc(r.ref)}"`) : ''}${live && PAYABLE.includes(r.tax_type || job.input?.tax_type) ? button('납부하기', `data-action="giro-payment-options" data-job="${esc(job.id)}" data-ref="${esc(r.ref)}"`) : ''}</td></tr>`).join('')}</tbody></table></div><div class="list-footer">표시 ${shown.length}건 · ${job.result.complete ? '마지막 페이지까지 확인' : '조회 범위 미완료'} · ${live ? '상세에서 고지 내용을 확인하세요. 국세·지방세·관세는 계좌 납부도 지원해요.' : '로그인하면 고지 상세를 조회할 수 있어요.'}</div>`;
}

function summaryResult(job) {
  if (!job) return '';
  const rows = job.result?.categories;
  return jobState(job) + notices(job) + (Array.isArray(rows) ? `<div class="settings-body">${rows.map(r =>
    `<div class="setting-row"><span>${esc(r.label)}<span class="meta">${esc(r.summary?.count == null ? '건수 미확인' : r.summary.count + '건')} · ${esc(money(r.summary?.amount))} · 항목 응답 ${esc(r.summary?.respCode ?? '미확인')}</span></span>${button('항목 선택', `data-action="giro-select-tax" data-tax="${esc(r.tax_type)}"`)}</div>`).join('')}</div>` : note('통합조회 결과를 확인하지 못했어요.'));
}

async function billsView(ctx) {
  const row = connection(), tax = state.params.tax_type || 'national';
  const job = row ? await latest(NUMBER_INPUTS[tax] ? 'giro.bills.search' : 'giro.bills.list', row, tax) : null;
  const summary = row ? await latest('giro.bills.summary', row) : null;
  const inputs = (NUMBER_INPUTS[tax] || []).map(([name, label]) => `<div class="field"><label for="giro-query-${name}">${esc(label)}</label><input id="giro-query-${name}" name="${name}" required maxlength="100" autocomplete="off"></div>`).join('');
  return start('고지·납부', '세금·공과금 고지를 조회해요. 국세·지방세·관세는 등록계좌 납부를 지원해요.') +
    `<section class="panel"><div class="panel-heading"><h2>본인 공과금 통합조회</h2>${ready(row) ? button('통합조회', 'data-action="giro-summary-query"', 'primary') : ''}</div>${summaryResult(summary)}</section>` +
    `<section class="panel"><form class="filter-bar" data-submit="giro-query"><div class="field"><label for="giro-tax">요금 종류</label><select id="giro-tax" name="tax_type" data-change="giro-tax-change">${options(TAXES, tax)}</select></div>${inputs}${ready(row) ? '<button class="button primary" type="submit">고지 조회</button>' : ''}</form>${panel()}<div id="giro-results">${row ? billsResult(job, ready(row)) : loginFirst('지로에 로그인하면 고지를 조회하고 납부할 수 있어요.')}</div>${note('인지대·송달료와 조회납부 미지원 일반지로는 고지서 내용을 직접 입력하는 납부 항목으로, 자동 고지 조회 대상이 아니에요.')}</section>`;
}

function preview(value = {}) {
  return ui.fieldsList({'세금 종류': taxName(value.tax_type), '세목': value.tax_name, '청구기관': value.issuer,
    '납부금액': money(value.amount), '전자납부번호': value.bill_number_masked,
    '출금 계좌': [value.account_alias, value.bank_name, value.account_masked].filter(Boolean).join(' · ')});
}

async function paymentDialog(ctx, job) {
  if (job.status !== 'awaiting_input') {
    const title = job.result?.payment_attempted ? job.outcome === 'success' ? '납부가 완료됐어요' : job.outcome === 'rejected' ? '기관에서 납부를 거절했어요' : '납부 결과를 확인하지 못했어요' : '납부 준비 결과';
    ui.showDialog(title, jobState(job) + notices(job) + preview(job.result?.preview || job.result) +
      (job.result?.payment_attempted ? note(job.outcome === 'success' ? '기관의 납부 성공 응답을 확인했어요. 고지나 납부내역을 다시 조회해 확인할 수 있어요.' : '같은 고지를 자동으로 다시 납부하지 않아요. 납부내역에서 결과를 확인하세요.') : '') +
      `<div class="dialog-actions">${button('고지 조회', 'data-action="giro-bills-open"')}${button('납부내역', 'data-action="giro-receipts-open"')}${button('닫기', 'data-ui="close"', 'primary')}</div>`);
    return;
  }
  const awaiting = job.awaiting, fields = [ACCOUNT, ...(awaiting.requires.includes('pin') ? [PIN] : [])];
  // The same warnings as a bank transfer: it cannot be taken back, and the preparation lapses.
  const expires = awaiting.expires_at ? `<p class="dialog-note">확인 기한: <span class="countdown" data-deadline="${esc(awaiting.expires_at)}"></span> 남음. 기한이 지나면 고지를 다시 조회해 납부 내용을 확인해요.</p>` : '';
  ui.showDialog('납부 내용 확인', `<p class="pill-row">${ui.verification(job.verification)}${ui.tag('되돌릴 수 없음', 'danger')}</p>` + preview(awaiting.preview) + expires + `<form data-submit="giro-payment-confirm" data-job="${esc(job.id)}" data-digest="${esc(awaiting.digest)}" autocomplete="off">${fields.map(([name, label, pattern]) => `<div class="field"><label for="giro-${name}">${esc(label)}</label><input id="giro-${name}" name="${name}" type="password" required inputmode="numeric" pattern="${pattern}" autocomplete="off"></div>`).join('')}${awaiting.requires.includes('pin') ? note('추가 인증에는 로그인할 때 사용한 지로 간편비밀번호 6자리를 입력해요.') : ''}<p class="dialog-note">확인한 세금 1건을 위 계좌에서 즉시 납부해요.</p><div class="dialog-actions">${button('나중에', 'data-ui="close"')}${button('납부 준비 취소', `data-action="giro-payment-cancel" data-job="${esc(job.id)}"`)}<button class="button primary" type="submit">확인하고 납부</button></div></form>`);
  // Time left to confirm; the clock stops with the dialog.
  const tick = () => {
    const clock = document.querySelector('#detail-dialog .countdown');
    if (!clock) return clearInterval(timer);
    const left = Math.max(0, Math.round(Number(clock.dataset.deadline) - Date.now() / 1000));
    clock.textContent = `${Math.floor(left / 60)}분 ${String(left % 60).padStart(2, '0')}초`;
    if (!left) clearInterval(timer);
  };
  const timer = setInterval(tick, 500);
  tick();
}

/* Payments prepared on the web: continue one that waits for confirmation, or reopen a result. */
function paymentJobs(jobs) {
  if (!jobs.length) return '';
  return `<section class="panel"><div class="panel-heading"><div><h2>웹에서 진행한 납부</h2><p class="meta">확인을 기다리는 납부를 이어가거나 결과를 다시 볼 수 있어요.</p></div></div><div class="settings-body">${jobs.map(j => `<div class="setting-row"><span>${ui.time(j.created_at)} ${ui.statusTags(j)}</span>${button(j.status === 'awaiting_input' ? '내용 확인·납부' : '결과 보기', `data-action="giro-payment-open" data-job="${esc(j.id)}"`)}</div>`).join('')}</div></section>`;
}

async function accountsView() {
  const row = connection(), job = row ? await latest('giro.accounts.list', row) : null;
  const rows = job?.result?.accounts;
  return start('등록계좌', '모바일지로에 등록된 납부 계좌와 별칭이에요.') +
    `<section class="panel"><div class="panel-heading"><h2>등록된 계좌</h2>${ready(row) ? button('계좌 조회', 'data-action="giro-accounts-query"', 'primary', 'refresh') : ''}</div>${panel()}<div id="giro-results">${!row ? loginFirst('지로에 로그인하면 등록계좌를 조회할 수 있어요.') : (job ? jobState(job) + notices(job) : '') + (Array.isArray(rows) ? ui.rowsTable(rows.filter(Boolean).map(r => ({별칭: r.name, 은행: r.bank_name, 계좌번호: r.account_masked, 상태: r.account_status})), {group: 'giro-accounts', keys: ['별칭', '은행', '계좌번호', '상태']}) : '<div class="empty-state">아직 확인한 계좌 목록이 없어요. 납부할 때는 해당 고지에서 쓸 수 있는 계좌를 따로 조회해요.</div>')}</div></section>`;
}

async function receiptsView() {
  const row = connection();
  const [job, payments] = row ? await Promise.all([latest('giro.receipts.list', row), listing('giro.payment.prepare', row, 20)]) : [null, []];
  const input = job?.input || {};
  const receipts = job?.result?.receipts;
  // The shown page keeps its own period, so paging never mixes it with an edited form.
  const page = Number(input.page) || 1, total = Number(job?.result?.page_navi?.totalPage) || null;
  const turn = (label, to) => button(label, `data-action="giro-receipts-page" data-page="${to}" data-start="${esc(input.start_date)}" data-end="${esc(input.end_date)}"`);
  const pager = Array.isArray(receipts) ? `<div class="section-actions">${page > 1 ? turn('이전 페이지', page - 1) : ''}${(total ? page < total : receipts.length > 0) ? turn('다음 페이지', page + 1) : ''}<span class="muted-block">${page}${total ? ' / ' + total : ''}쪽</span></div>` : '';
  const list = Array.isArray(receipts) ? `<div class="settings-body">${receipts.filter(Boolean).map(r => `<div class="setting-row"><span><strong>${esc(r.issuer || '납부내역')}</strong><span class="meta">${esc([date(r.paid_date), r.payment_type].filter(Boolean).join(' · '))}</span></span><strong class="row-amount">${esc(money(r.amount_raw?.replaceAll(',', '')))}</strong>${button('상세', `data-action="giro-receipt-detail" data-job="${esc(job.id)}" data-ref="${esc(r.ref)}"`)}</div>`).join('') || '<p class="field-help">이 페이지에 납부내역이 없어요.</p>'}</div>${pager}`
    : job ? `<div class="empty-state">${job.outcome === 'success' && page === 1 ? '기관 응답에 납부내역 목록이 없어요. 조회 기간을 확인해 주세요.' : '납부내역 목록을 확인하지 못했어요.'}</div>` : `<div class="empty-state">${ready(row) ? '기간을 정해 납부내역을 조회하세요.' : '아직 조회한 납부내역이 없어요.'}</div>`;
  return start('납부내역', '기간별 납부내역과 상세 내용을 조회해요.') +
    `<section class="panel"><form class="filter-bar" data-submit="giro-receipts-query">${[['start_date', '시작일', ui.kstDate(30)], ['end_date', '종료일', ui.kstDate()]].map(([name, label, fallback]) => `<div class="field"><label for="giro-${name}">${label}</label><input id="giro-${name}" name="${name}" type="date" required value="${esc(input[name] || fallback)}"></div>`).join('')}${ui.periodPresets([['1개월', 30], ['3개월', 90], ['6개월', 180]])}<input type="hidden" name="page" value="1">${ready(row) ? '<button type="submit" class="button primary">조회</button>' : ''}</form>${panel()}<div id="giro-results">${!row ? loginFirst('지로에 로그인하면 납부내역을 조회할 수 있어요.') : (job ? jobState(job) + notices(job) : '') + list}</div></section>` +
    paymentJobs(payments);
}

// 'giro-pay' used to be its own menu; payments in progress now sit under the receipts screen.
export const giroViews = {'giro-live': billsView, 'giro-pay': receiptsView, 'giro-accounts': accountsView, 'giro-receipts': receiptsView};
export const giroActions = {
  'giro-login': (ctx, element) => giroLogin(ctx, login(element.dataset.login)),
  'giro-bills-open': () => { ui.closeDialog(); changeView('giro-live'); },
  'giro-receipts-open': () => { ui.closeDialog(); changeView('giro-receipts'); },
  'giro-tax-change': async (ctx, element) => { state.params.tax_type = element.value; await render(); },
  'giro-select-tax': async (ctx, element) => { state.params.tax_type = element.dataset.tax; await render(); },
  'giro-summary-query': async ctx => {
    const row = connection(); if (!row) return giroLogin(ctx);
    await ctx.run('giro.bills.summary', {login_id: row.id}, {panel: 'job-panel', onDone: async () => { await refreshModel(); await render(); }});
  },
  'giro-bill-detail': async (ctx, element) => {
    const parent = await api.get('/jobs/' + encodeURIComponent(element.dataset.job));
    await ctx.run('giro.bills.detail', {login_id: parent.login_id, parent_job_id: parent.id, input: {ref: element.dataset.ref}},
      {panel: 'job-panel', onDone: job => ui.showDialog('고지 상세', jobState(job) + notices(job) +
        (job.result?.bill ? ui.fieldsList({'요금 종류': taxName(job.result.bill.tax_type), '세목': job.result.bill.tax_name,
          '청구기관': job.result.bill.issuer, '납부금액': money(job.result.bill.amount_raw),
          '납부기한': job.result.bill.due_date || job.result.bill.due_date_raw || '상세 응답에 없음',
          '전자납부번호': job.result.bill.electronic_number}) : note('상세 내용을 확인하지 못했어요.')) + close())});
  },
  'giro-query': async (ctx, form) => {
    const row = connection(); if (!row) return giroLogin(ctx);
    const data = Object.fromEntries(new FormData(form)), tax = data.tax_type;
    state.params.tax_type = tax;
    const numbers = Object.fromEntries((NUMBER_INPUTS[tax] || []).map(([name]) => [name, data[name]]));
    form.querySelectorAll('input').forEach(input => { input.value = ''; });
    await ctx.run(NUMBER_INPUTS[tax] ? 'giro.bills.search' : 'giro.bills.list', {login_id: row.id, input: {tax_type: tax}},
      {panel: 'job-panel', ...(NUMBER_INPUTS[tax] ? {secrets: {query_numbers: JSON.stringify(numbers)}} : {}),
        onDone: async () => { await refreshModel(); await render(); }});
  },
  'giro-payment-options': async (ctx, element) => {
    const parent = await api.get('/jobs/' + encodeURIComponent(element.dataset.job));
    await ctx.run('giro.payment.options', {login_id: parent.login_id, parent_job_id: parent.id, input: {ref: element.dataset.ref}}, {panel: 'job-panel', onDone: job => {
      const rows = job.result?.accounts?.filter(r => r.availability === 'available') || [];
      ui.showDialog('출금 계좌 선택', jobState(job) + notices(job) + ui.fieldsList({'세목': job.result?.bill?.tax_name || taxName(job.result?.bill?.tax_type), '납부금액': money(job.result?.amount), '납부기한': job.result?.bill?.due_date}) +
        (rows.length ? `<form data-submit="giro-payment-prepare" data-job="${esc(job.id)}"><div class="field"><label for="giro-account">등록된 납부계좌</label><select id="giro-account" name="account_index">${options(rows.map(r => [String(r.index), [r.account_alias, r.bank_name, r.account_masked].filter(Boolean).join(' · ')]))}</select></div>${job.result.amount_editable ? `<div class="field"><label for="giro-amount">납부금액 (원)</label><input id="giro-amount" name="amount" inputmode="numeric" pattern="[0-9]+" value="${esc(job.result.amount?.replaceAll(',', ''))}" required></div>` : ''}<div class="dialog-actions">${button('취소', 'data-ui="close"')}<button class="button primary" type="submit">납부 내용 확인</button></div></form>` : note('현재 납부에 사용할 수 있는 등록계좌를 확인하지 못했어요.') + close()));
    }});
  },
  'giro-payment-prepare': async (ctx, form) => {
    const data = Object.fromEntries(new FormData(form)), parent = await api.get('/jobs/' + encodeURIComponent(form.dataset.job));
    ui.closeDialog();
    await ctx.run('giro.payment.prepare', {login_id: parent.login_id, parent_job_id: parent.id,
      input: {account_index: Number(data.account_index), ...(data.amount ? {amount: data.amount} : {})}}, {panel: 'job-panel', onDone: job => paymentDialog(ctx, job)});
  },
  'giro-payment-open': async (ctx, element) => paymentDialog(ctx, await api.get('/jobs/' + encodeURIComponent(element.dataset.job))),
  'giro-payment-confirm': async (ctx, form) => {
    const inputs = Object.fromEntries(new FormData(form));
    form.querySelectorAll('input').forEach(input => { input.value = ''; });
    const jobId = form.dataset.job, digest = form.dataset.digest;
    ui.closeDialog();
    try {
      const job = await api.post('/jobs/' + encodeURIComponent(jobId) + '/confirm', {confirmation: digest, secrets: inputs}, {label: '지로 단건 계좌 납부'});
      for (const key of Object.keys(inputs)) delete inputs[key];
      await ctx.track(job, {panel: 'job-panel', hold: true, onDone: value => paymentDialog(ctx, value)});
    } catch (error) { ui.fail(ui.message(error.code)); }
    finally { for (const key of Object.keys(inputs)) delete inputs[key]; }
  },
  'giro-payment-cancel': async (ctx, element) => { await api.post('/jobs/' + encodeURIComponent(element.dataset.job) + '/cancel'); ui.closeDialog(); await render(); },
  'giro-accounts-query': async ctx => { const row = connection(); if (row) await ctx.run('giro.accounts.list', {login_id: row.id}, {panel: 'job-panel', onDone: async () => { await refreshModel(); await render(); }}); },
  'giro-receipts-query': async (ctx, form) => {
    const row = connection(); if (!row) return giroLogin(ctx);
    const data = Object.fromEntries(new FormData(form));
    await ctx.run('giro.receipts.list', {login_id: row.id, input: {...data, page: Number(data.page)}}, {panel: 'job-panel', onDone: async () => { await refreshModel(); await render(); }});
  },
  'giro-receipts-page': async (ctx, element) => {
    const row = connection(); if (!row) return giroLogin(ctx);
    const {start, end, page} = element.dataset;
    await ctx.run('giro.receipts.list', {login_id: row.id, input: {start_date: start, end_date: end, page: Number(page)}}, {panel: 'job-panel', onDone: async () => { await refreshModel(); await render(); }});
  },
  'giro-receipt-detail': async (ctx, element) => {
    const parent = await api.get('/jobs/' + encodeURIComponent(element.dataset.job));
    await ctx.run('giro.receipts.detail', {login_id: parent.login_id, parent_job_id: parent.id, input: {ref: element.dataset.ref}}, {panel: 'job-panel', onDone: job => ui.showDialog('납부내역 상세', jobState(job) + notices(job) +
      (Array.isArray(job.result?.items) ? job.result.items.filter(Boolean).map(r => ui.fieldsList({[r.name || '항목']: r.value})).join('') : note('상세 내용을 확인하지 못했어요.')) + close())});
  },
};
