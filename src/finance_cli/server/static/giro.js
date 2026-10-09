/* Giro uses the registered CLI device and asks for a PIN only at login/payment. */
import {api} from './api.js';
import * as ui from './ui.js';
import {state, login, askSecrets, refreshModel, render, changeView, jobState} from './app.js';

const {esc, button, heading, note} = ui;
const TAXES = [['national', '국세'], ['local', '지방세'], ['customs', '관세']];
const PIN = ['pin', '지로 로그인 간편비밀번호 6자리', '[0-9]{6}'];
const ACCOUNT = ['account_password', '출금 계좌 비밀번호 4자리', '[0-9]{4}'];
const connection = () => state.logins.find(r => r.institution === 'giro' && !r.disabled);
const money = value => /^\d+$/.test(String(value ?? '')) ? BigInt(value).toLocaleString('ko-KR') + '원' : String(value ?? '확인 안 됨');
const taxName = value => TAXES.find(([v]) => v === value)?.[1] || '세금';
const options = (rows, selected) => rows.map(([v, label]) => `<option value="${esc(v)}" ${v === selected ? 'selected' : ''}>${esc(label)}</option>`).join('');
const panel = () => '<div id="job-panel" class="job-panel"></div>';
const ready = row => row?.readiness === 'ready';
// Logged in: re-login is a quiet option. Logged out: the shell's notice under the heading asks for the
// login; with no connection yet, the screen itself offers the first login.
const start = (title, description) => heading(title, description,
  ready(connection()) ? button('다시 로그인', `data-action="giro-login" data-login="${esc(connection().id)}"`) : '');
const loginFirst = text => `<div class="empty-state">${text}<div class="section-actions">${button('지로 로그인', 'data-action="giro-login"', 'primary')}</div></div>`;
const close = (kind = 'primary') => `<div class="dialog-actions">${button('닫기', 'data-ui="close"', kind)}</div>`;

async function listing() { return (await api.get('/jobs?area=giro&limit=200&hide=session_extend')).jobs; }
async function latest(name, row, rows, tax = null) {
  const item = rows.find(j => j.name === name && j.login_id === row?.id && (!tax || j.input?.tax_type === tax));
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
  if (!job) return `<div class="empty-state">${live ? '세금 종류를 고르고 고지 조회를 누르세요.' : '아직 조회한 고지가 없어요.'}</div>`;
  const rows = job.result?.bills;
  const region = job.result?.query_region;
  const where = region ? note(`조회 지역: ${esc([region.province, region.district].filter(Boolean).join(' '))}`) : '';
  // Nothing billed: the institution says so in place of a list, so no list count is shown for it.
  if (job.result?.no_bills_reported) return jobState(job) + where + '<div class="empty-state">납부할 고지가 없어요.</div><div class="list-footer">기관이 목록 대신 “고지내용 없음”으로 응답했어요.</div>';
  const before = jobState(job) + notices(job) + where;
  if (!Array.isArray(rows)) return before + note('고지 목록을 확인하지 못했어요.');
  const shown = rows.filter(Boolean);
  if (!shown.length) return before + note(job.result.complete ? '조회된 고지가 없어요.' : '표시할 고지 항목을 받지 못했어요.');
  return before + `<div class="table-wrap"><table class="table data"><thead><tr><th>세목</th><th>청구기관</th><th class="num">납부금액</th><th>납부기한</th><th>전자납부번호</th><th></th></tr></thead><tbody>${shown.map(r => `<tr><td data-label="세목">${esc(r.tax_name || taxName(r.tax_type))}</td><td data-label="청구기관">${esc(r.issuer || '확인 안 됨')}</td><td class="num" data-label="납부금액">${esc(money(r.amount_raw?.replaceAll(',', '') ?? r.amount))}</td><td data-label="납부기한">${esc(r.due_date || r.due_date_raw || '확인 안 됨')}</td><td data-label="전자납부번호">${esc(r.electronic_number)}</td><td>${button('납부하기', `data-action="giro-payment-options" data-job="${esc(job.id)}" data-ref="${esc(r.ref)}"`)}</td></tr>`).join('')}</tbody></table></div><div class="list-footer">표시 ${shown.length}건 · ${job.result.complete ? '마지막 페이지까지 확인' : '조회 범위 미완료'} · 납부하기를 누르면 출금 계좌를 고르고 내용을 확인한 뒤 납부해요.</div>`;
}

async function billsView(ctx) {
  const row = connection(), tax = state.params.tax_type || 'national';
  const job = row ? await latest('giro.bills.list', row, await listing(), tax) : null;
  return start('고지·납부', '고지 금액과 납부기한을 확인하고 등록된 계좌로 납부해요.') +
    `<section class="panel"><form class="filter-bar" data-submit="giro-query"><div class="field"><label for="giro-tax">세금 종류</label><select id="giro-tax" name="tax_type">${options(TAXES, tax)}</select></div>${ready(row) ? '<button class="button primary" type="submit">고지 조회</button>' : ''}</form>${panel()}<div id="giro-results">${row ? billsResult(job, ready(row)) : loginFirst('지로에 로그인하면 고지를 조회하고 납부할 수 있어요.')}</div></section>`;
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
  ui.showDialog('납부 내용 확인', preview(awaiting.preview) + `<form data-submit="giro-payment-confirm" data-job="${esc(job.id)}" data-digest="${esc(awaiting.digest)}" autocomplete="off">${fields.map(([name, label, pattern]) => `<div class="field"><label for="giro-${name}">${esc(label)}</label><input id="giro-${name}" name="${name}" type="password" required inputmode="numeric" pattern="${pattern}" autocomplete="off"></div>`).join('')}${awaiting.requires.includes('pin') ? note('추가 인증에는 로그인할 때 사용한 지로 간편비밀번호 6자리를 입력해요.') : ''}<p class="dialog-note">확인한 세금 1건을 위 계좌에서 즉시 납부해요.</p><div class="dialog-actions">${button('나중에', 'data-ui="close"')}${button('납부 준비 취소', `data-action="giro-payment-cancel" data-job="${esc(job.id)}"`)}<button class="button primary" type="submit">확인하고 납부</button></div></form>`);
}

/* Payments prepared on the web: continue one that waits for confirmation, or reopen a result. */
function paymentJobs(rows, row) {
  const jobs = rows.filter(j => j.name === 'giro.payment.prepare' && j.login_id === row.id);
  if (!jobs.length) return '';
  return `<section class="panel"><div class="panel-heading"><div><h2>웹에서 진행한 납부</h2><p class="meta">확인을 기다리는 납부를 이어가거나 결과를 다시 볼 수 있어요.</p></div></div><div class="settings-body">${jobs.map(j => `<div class="setting-row"><span>${ui.time(j.created_at)} ${ui.statusTags(j)}</span>${button(j.status === 'awaiting_input' ? '내용 확인·납부' : '결과 보기', `data-action="giro-payment-open" data-job="${esc(j.id)}"`)}</div>`).join('')}</div></section>`;
}

async function accountsView() {
  const row = connection(), job = row ? await latest('giro.accounts.list', row, await listing()) : null;
  const rows = job?.result?.accounts;
  return start('등록계좌', '모바일지로에 등록된 납부 계좌와 별칭이에요.') +
    `<section class="panel"><div class="panel-heading"><h2>등록된 계좌</h2>${ready(row) ? button('계좌 조회', 'data-action="giro-accounts-query"', 'primary', 'refresh') : ''}</div>${panel()}<div id="giro-results">${!row ? loginFirst('지로에 로그인하면 등록계좌를 조회할 수 있어요.') : (job ? jobState(job) + notices(job) : '') + (Array.isArray(rows) ? ui.rowsTable(rows.filter(Boolean).map(r => ({별칭: r.name, 은행: r.bank_name, 계좌번호: r.account_masked, 상태: r.account_status})), {group: 'giro-accounts', keys: ['별칭', '은행', '계좌번호', '상태']}) : '<div class="empty-state">아직 확인한 계좌 목록이 없어요. 납부할 때는 해당 고지에서 쓸 수 있는 계좌를 따로 조회해요.</div>')}</div></section>`;
}

async function receiptsView() {
  const row = connection(), jobs = row ? await listing() : [];
  const job = row ? await latest('giro.receipts.list', row, jobs) : null;
  const input = job?.input || {};
  const receipts = job?.result?.receipts;
  // The shown page keeps its own period, so paging never mixes it with an edited form.
  const page = Number(input.page) || 1, total = Number(job?.result?.page_navi?.totalPage) || null;
  const turn = (label, to) => button(label, `data-action="giro-receipts-page" data-page="${to}" data-start="${esc(input.start_date)}" data-end="${esc(input.end_date)}"`);
  const pager = Array.isArray(receipts) ? `<div class="section-actions">${page > 1 ? turn('이전 페이지', page - 1) : ''}${(total ? page < total : receipts.length > 0) ? turn('다음 페이지', page + 1) : ''}<span class="muted-block">${page}${total ? ' / ' + total : ''}쪽</span></div>` : '';
  const list = Array.isArray(receipts) ? `<div class="settings-body">${receipts.filter(Boolean).map(r => `<div class="setting-row"><span><strong>${esc(r.issuer || '납부내역')}</strong><span class="meta">${esc(r.paid_date)} · ${esc(money(r.amount_raw?.replaceAll(',', '')))} · ${esc(r.payment_type || '')}</span></span>${button('상세', `data-action="giro-receipt-detail" data-job="${esc(job.id)}" data-ref="${esc(r.ref)}"`)}</div>`).join('') || '<p class="field-help">이 페이지에 납부내역이 없어요.</p>'}</div>${pager}`
    : job ? '' : `<div class="empty-state">${ready(row) ? '기간을 정해 납부내역을 조회하세요.' : '아직 조회한 납부내역이 없어요.'}</div>`;
  return start('납부내역', '기간별 납부내역과 상세 내용을 조회해요.') +
    `<section class="panel"><form class="filter-bar" data-submit="giro-receipts-query">${[['start_date', '시작일', ui.kstDate(30)], ['end_date', '종료일', ui.kstDate()]].map(([name, label, fallback]) => `<div class="field"><label for="giro-${name}">${label}</label><input id="giro-${name}" name="${name}" type="date" required value="${esc(input[name] || fallback)}"></div>`).join('')}${ui.periodPresets([['1개월', 30], ['3개월', 90], ['6개월', 180]])}<input type="hidden" name="page" value="1">${ready(row) ? '<button type="submit" class="button primary">조회</button>' : ''}</form>${panel()}<div id="giro-results">${!row ? loginFirst('지로에 로그인하면 납부내역을 조회할 수 있어요.') : (job ? jobState(job) + notices(job) : '') + list}</div></section>` +
    (row ? paymentJobs(jobs, row) : '');
}

// 'giro-pay' used to be its own menu; payments in progress now sit under the receipts screen.
export const giroViews = {'giro-live': billsView, 'giro-pay': receiptsView, 'giro-accounts': accountsView, 'giro-receipts': receiptsView};
export const giroActions = {
  'giro-login': (ctx, element) => giroLogin(ctx, login(element.dataset.login)),
  'giro-bills-open': () => { ui.closeDialog(); changeView('giro-live'); },
  'giro-receipts-open': () => { ui.closeDialog(); changeView('giro-receipts'); },
  'giro-query': async (ctx, form) => {
    const row = connection(); if (!row) return giroLogin(ctx);
    const tax = new FormData(form).get('tax_type');
    state.params.tax_type = tax;
    await ctx.run('giro.bills.list', {login_id: row.id, input: {tax_type: tax}}, {panel: 'job-panel', onDone: async () => { await refreshModel(); await render(); }});
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
      const job = await api.post('/jobs/' + encodeURIComponent(jobId) + '/confirm', {confirmation: digest, secrets: inputs});
      for (const key of Object.keys(inputs)) delete inputs[key];
      await ctx.track(job, {panel: 'job-panel', onDone: value => paymentDialog(ctx, value)});
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
