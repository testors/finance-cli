/* Corporate banking uses shared credentials, with separate logins and accounts. */
import {api} from './api.js';
import * as ui from './ui.js';
import {state, login, target, profile, scopeLogins, scopeTargets, refreshModel, render, changeView, jobState,
  secretFields, rememberField, applyRemember, onesignStore, SECRET_LABELS} from './app.js';

const {esc, button, heading, note, tag} = ui;
// Format decimal strings without passing financial amounts through Number.
function amount(value) {
  const match = /^(-?)(\d+)(?:\.(\d+))?$/.exec(String(value ?? ''));
  if (!match) return value ?? '—';
  const fraction = (match[3] || '').replace(/0+$/, '');
  return match[1] + BigInt(match[2]).toLocaleString('ko-KR') + (fraction ? '.' + fraction : '');
}
const money = value => esc(amount(value));
const date = value => String(value || '').replace(/^(\d{4})(\d{2})(\d{2})$/, '$1-$2-$3');
const time = value => String(value || '').replace(/^(\d{2})(\d{2})(\d{2})$/, '$1:$2:$3');
const PREFIX = 'hana.corporate.';
const METHODS = [['id_password', 'ID / 비밀번호'], ['joint_certificate', '공동인증서'], ['onesign', '하나인증서 (개인사업자)']];
const CATEGORIES = [['withdrawal', '출금계좌'], ['all', '전체 분류'], ['deposits', '예·적금'], ['fund', '펀드'], ['loans', '대출'], ['foreign', '외화'], ['payroll', '급여'], ['favorites', '즐겨찾기']];
const STATUS = {prepared: '준비 완료', submitted: '이체 요청 접수', completed: '이체 완료', approval_requested: '결재 요청',
  delayed: '지연이체', partial: '일부 성공', rejected: '은행 거절', unconfirmed: '결과 미확인', preparation_cancelled: '준비 취소'};
const options = (rows, selected) => rows.map(([v, label]) => `<option value="${esc(v)}" ${v === selected ? 'selected' : ''}>${esc(label)}</option>`).join('');
const field = (name, label, attrs = '') => `<div class="field"><label for="corp-${name}">${esc(label)}</label><input id="corp-${name}" name="${name}" ${attrs}></div>`;
const select = (name, label, rows, selected = '', attrs = '') => `<div class="field field-inline"><label for="corp-${name}">${esc(label)}</label><select id="corp-${name}" name="${name}" ${attrs}>${options(rows, selected)}</select></div>`;
const accounts = () => scopeTargets(['account']).filter(t => login(t.login_id)?.institution === 'hana_corporate');
const accountOptions = rows => rows.map(t => [t.id, `${t.display_name} · ${t.identity?.account_number} (${login(t.login_id)?.display_name})`]);
const cacheKey = (name, id) => 'corporate:' + name + ':' + id;
const panel = () => '<div id="job-panel" class="job-panel"></div>';
const close = (kind = 'primary') => `<div class="dialog-actions">${button('닫기', 'data-ui="close"', kind)}</div>`;
const AMOUNTS = ['금액', '입금액', '출금액', '잔액'];

function notices(job) {
  const messages = [];
  if (job?.local?.stopped) messages.push(ui.message(job.local.stopped));
  const guidance = job?.result?.follow_up?.customer_guidance;
  if (guidance === 'visit_branch_notice') messages.push('고객확인 안내: 영업점 방문이 필요해요. 로그인은 완료됐어요.');
  if (guidance === 'customer_verification_choice_required') messages.push('은행의 고객확인 절차를 확인하세요.');
  if (guidance === 'certificate_login_required') messages.push('은행에서 인증서 로그인을 요구해요.');
  if (job?.result?.complete === false) messages.push('조회가 끝나지 않았어요. 지금까지 받은 결과를 표시해요.');
  return messages.map(v => note(esc(v))).join('');
}

async function latest(name, id, listing) {
  const cached = state.cache.get(cacheKey(name, id));
  if (cached) return cached;
  const row = listing.jobs.find(j => j.name === PREFIX + name && (j.login_id === id || j.target_id === id));
  if (!row) return null;
  const job = await api.get('/jobs/' + encodeURIComponent(row.id));
  state.cache.set(cacheKey(name, id), job);
  return job;
}

export async function corporateLogin(ctx, row = null, method = 'id_password', selected = null) {
  method = row?.method || method;
  const credentials = (await api.get('/credentials')).credentials;
  state.credentials = credentials;
  const settings = method === 'id_password' ? await api.get('/corporate/options') : null;
  const kind = method === 'onesign' ? 'onesign' : 'joint';
  const available = credentials.filter(c => c.type === kind);
  selected = available.some(c => c.ref === selected) ? selected : available[0]?.ref;
  const store = row ? onesignStore(row) : method === 'onesign' ? selected : null;
  const required = method === 'id_password' ? [SECRET_LABELS.login_password] : method === 'onesign'
    ? [SECRET_LABELS.vault_passphrase, SECRET_LABELS.pin] : [SECRET_LABELS.certificate_password];
  const fields = secretFields(required, store);
  const selection = row ? `<p>${esc(row.display_name)} · ${esc(ui.METHOD[method])}</p>`
    : `<div class="field"><label for="corp-method">로그인 방법</label><select id="corp-method" name="method" data-change="corporate-login-method">${options(METHODS, method)}</select></div>`;
  const credential = row ? '' : method === 'id_password'
    ? field('credential', '기업 인터넷뱅킹 ID', 'required minlength="4" maxlength="20" pattern="[A-Za-z0-9]{4,20}" autocapitalize="characters" spellcheck="false"')
    : `<div class="field"><label for="corp-credential">${method === 'onesign' ? '보관한 하나인증서' : '보관한 공동인증서'}</label><select id="corp-credential" name="credential" required ${method === 'onesign' ? 'data-change="corporate-login-credential"' : ''}>${options(available.map(c => [c.ref, c.ref]), selected)}</select>${available.length ? '<p class="field-help">공통 보관함의 인증서를 그대로 사용해요.</p>' : note('보관한 인증서가 없어요. 연결·인증서에서 가져올 수 있어요.')}</div>`;
  const settingChoice = settings && !settings.selected && settings.settings.length > 1
    ? select('settings', '키패드 설정', settings.settings.map(s => [s, s])) : '';
  const unavailable = method === 'id_password' ? !settings.settings.length : !row && !available.length;
  ui.showDialog('하나기업뱅킹 로그인', `<form data-submit="corporate-login" data-login="${esc(row?.id || '')}" data-method="${method}" autocomplete="off">${selection}${credential}${settingChoice}${fields.map(([name, label, pattern]) => field(name, label, `type="password" required ${pattern ? `pattern="${pattern}" inputmode="numeric"` : ''}`)).join('')}${rememberField(fields, store)}${unavailable && method === 'id_password' ? note('서버에 하나은행 키패드 설정을 먼저 설치해야 해요. 이미 설치한 개인뱅킹 설정도 공유해요.') : ''}<p class="dialog-note">${method === 'id_password' ? '기업 ID와 비밀번호로 로그인해요. 인증서 등록은 필요 없어요.' : method === 'onesign' ? '기업 ID에 연결된 기존 하나인증서를 사용해요.' : '기존 공동인증서로 기업뱅킹에 로그인해요.'} 로그인 후 계좌를 조회해 바로 연결해요.</p><p class="form-error" role="alert"></p><div class="dialog-actions">${button('취소', 'data-ui="close"')}<button class="button primary" type="submit" ${unavailable ? 'disabled' : ''}>로그인하고 계좌 보기</button></div></form>`);
}

async function queryAccounts(ctx, row, category = 'withdrawal') {
  return ctx.run(PREFIX + 'accounts', {login_id: row.id, input: {category}}, {panel: 'job-panel',
    key: cacheKey('accounts', row.id), onDone: async () => { await refreshModel(); await render(); }});
}

async function accountsView(ctx) {
  const logins = scopeLogins('hana_corporate');
  const intro = heading('기업 계좌', '계좌를 누르면 거래내역으로 이동해요.',
    logins.length ? button('다른 ID·인증서로 로그인', 'data-action="corporate-login-add"') : '');
  if (!logins.length) return intro + `<section class="panel"><div class="empty-state">${profile() ? '이 프로필에 기업 계좌가 없어요. 전체에서 로그인하고 조회한 계좌를 선택하세요.' : 'ID/PW 또는 보관한 인증서로 바로 로그인하세요.'}<div class="section-actions">${button('기업뱅킹 로그인', 'data-action="corporate-login-add"', 'primary')}</div></div></section>`;
  const listing = await api.get('/jobs?limit=200&area=corporate');
  const panels = await Promise.all(logins.map(async row => {
    const job = await latest('accounts', row.id, listing);
    const allowed = new Set(accounts().map(t => t.id));
    const mapping = job?.result?.candidate_targets || {};
    const rows = (job?.result?.accounts || []).filter(a => !profile() || allowed.has(mapping[a.ref]));
    const live = row.readiness === 'ready';
    // A linked account opens its transaction history; the row itself is the control.
    const line = a => {
      const id = mapping[a.ref];
      return `<tr ${id ? `data-row="account" data-action="corporate-account-history" data-target="${esc(id)}" tabindex="0" title="거래내역 보기"` : ''}><td data-label="계좌">${esc(a.label)}</td><td data-label="번호">${esc(a.account_number)}</td><td data-label="통화">${esc(a.currency)}</td><td class="num" data-label="잔액">${money(a.balance)}</td><td class="row-go">${id ? ui.icon('arrow') : ''}</td></tr>`;
    };
    return `<section class="panel"><div class="panel-heading"><div><h2>${esc(row.display_name)}</h2><p class="meta">${esc(ui.METHOD[row.method])} · ${job?.observed_at ? ui.time(job.observed_at) + ' 조회' : '미조회'}</p></div>${tag(live ? '로그인됨' : '로그인 필요', live ? '' : 'warning')}</div><form class="filter-bar" data-submit="corporate-accounts" data-login="${esc(row.id)}">${select('category', '계좌 분류', CATEGORIES, job?.input?.category)}${live ? '<button class="button primary" type="submit">계좌 조회</button>' : ''}${button(live ? '다시 로그인' : '로그인', `data-action="corporate-relogin" data-login="${esc(row.id)}"`, live ? 'secondary' : 'primary')}</form>${job ? notices(job) : ''}${rows.length ? `<div class="table-wrap"><table class="table data"><thead><tr><th>계좌</th><th>번호</th><th>통화</th><th class="num">잔액</th><th></th></tr></thead><tbody>${rows.map(line).join('')}</tbody></table></div>` : `<div class="empty-state">${job?.result?.complete ? '조회한 분류에 계좌가 없어요.' : '아직 확인한 계좌가 없어요.'}</div>`}</section>`;
  }));
  return intro + panel() + `<div class="stack">${panels.join('')}</div>`;
}

function historyRows(job) {
  const raw = job.result?.transactions || [];
  const rows = raw.map(row => {
    const r = {...row, ...row.display};
    return {일자: date(r.TRSC_DT), 시각: time(r.TRSC_TM || r.TRSC_PROC_TM), 구분: r.LN_DPS_TRSC_KIND_NM || r.TRSC_KIND_CD_NM || ({'1': '입금', '2': '출금'}[r.BAL_FLCT_DV_CD]),
      내용: r.RMRK || r.NW_SUMM_PSBK_RMRK, 금액: amount(r.TRSC_AMT), 입금액: amount(r.RCV_AMT_CTT), 출금액: amount(r.PAYM_AMT_CTT),
      잔액: amount(r.TRSC_AF_BAL ?? r.TRSC_AF_BAL_CTT), 통화: r.CUR_CD || job.result?.currency, 메모: r.MEMO_CTT};
  });
  state.rows['corporate-history'] = {rows: raw, job};
  const amountKeys = raw.some(r => r.RCV_AMT_CTT !== undefined || r.PAYM_AMT_CTT !== undefined)
    ? ['금액', '입금액', '출금액'] : ['금액'];
  return notices(job) + (Array.isArray(job.result?.transactions) ? (!rows.length && !job.result?.complete ? note('확인한 거래내역이 아직 없어요. 조회가 완료된 것은 아니에요.') : ui.rowsTable(rows, {group: 'corporate-history', limit: rows.length,
    keys: ['일자', '시각', '구분', '내용', ...amountKeys, '잔액', '통화', '메모'], num: AMOUNTS})) : note('거래내역을 확인하지 못했어요.')) +
    `<div class="list-footer">${rows.length}건 · ${job.result?.complete ? '조회 완료' : '조회 범위 미완료'}</div>`;
}

async function historyView() {
  const rows = accounts();
  if (!rows.length) return heading('기업 거래내역', '계좌별 거래내역을 조회해요.') + `<section class="panel"><div class="empty-state">기업 계좌를 먼저 조회하면 여기서 거래내역을 볼 수 있어요.<div class="section-actions">${button('기업 계좌', 'data-view="corporate-accounts"', 'primary')}</div></div></section>`;
  const chosen = rows.find(r => r.id === state.params.target) || rows[0];
  const job = await latest('history', chosen.id, await api.get('/jobs?limit=200&area=corporate'));
  const previous = job?.input || {};
  return heading('기업 거래내역', '기간을 비우면 최근 7일을 조회해요. 다음 페이지도 자동으로 이어서 조회해요.') +
    `<section class="panel"><form class="filter-bar corporate-history-filter" data-submit="corporate-history">${select('target_id', '계좌', accountOptions(rows), chosen.id, 'data-change="corporate-history-target"')}${field('start', '시작일', `type="date" value="${esc(previous.start || '')}"`)}${field('end', '종료일', `type="date" value="${esc(previous.end || '')}"`)}${ui.periodPresets([['1주', 6], ['1개월', 30], ['3개월', 90]])}${select('direction', '구분', [['', '전체'], ['1', '입금'], ['2', '출금']], previous.direction)}${select('order', '정렬', [['latest', '최신순'], ['oldest', '과거순']], previous.order)}<button class="button primary" type="submit">조회</button><details class="advanced-block"><summary>검색·외화·대출 옵션</summary>${select('search_type', '원화 검색', [['', '선택 안 함'], ['04', '적요'], ['03', '금액'], ['05', '받는 분'], ['02', '메모']])}${field('search', '검색어', 'maxlength="100"')}${field('currency', '외화 통화 (예: USD, ALL)', 'maxlength="3" pattern="[A-Za-z]{3}"')}${field('sequence', '대출 실행번호 (필요할 때만)', 'inputmode="numeric" pattern="[0-9]+"')}<p class="field-help">대출은 입출금 구분 없이 조회해요.</p></details></form>${panel()}<div id="corporate-results">${job ? jobState(job) + historyRows(job) : '<div class="empty-state">계좌와 기간을 선택해 조회하세요.</div>'}</div></section>`;
}

function preview(value = {}) {
  const rows = value.items || [];
  return `<div class="summary-lines">${ui.fieldsList({'출금 계좌': value.acctNo, '출금 계좌명': value.acctNm,
    '이체 금액': amount(value.totlTrnsAmt), '수수료': amount(value.comm), '지연이체': value.dlayTrnsYn === 'Y' ? '예' : '아니요'})}</div>` + rows.map(r => ui.fieldsList({'받는 분': r.RMTE_NM, '은행': r.RCV_BNK_NM || r.RCV_BNK_CD,
      '받는 계좌': r.RCV_ACCT_NO, '금액': amount(r.TRNS_AMT), '수수료': amount(r.COMM), '출금 통장 표시': r.WDRW_PSBK_MARK_CTT, '입금 통장 표시': r.RCV_PSBK_MARK_CTT, '메모': r.MEMO})).join('');
}

async function transferDialog(ctx, job) {
  if (job.status !== 'awaiting_input') return resultDialog(job);
  const awaiting = job.awaiting, next = awaiting.next_step;
  const duplicate = (awaiting.preview?.items || []).some(r => r.DUP_YN === 'Y');
  if (awaiting.requires?.includes('signing_credential')) state.credentials = (await api.get('/credentials')).credentials;
  let input = '';
  for (const name of awaiting.requires || []) {
    if (name === 'signing_credential') input += select(name, '서명할 공동인증서', state.credentials.filter(c => c.type === 'joint').map(c => [c.ref, c.ref]));
    else { const [, label, pattern] = SECRET_LABELS[name]; input += field(name, label, `type="password" required ${pattern ? `pattern="${pattern}" inputmode="numeric"` : ''}`); }
  }
  if (next === 'ars') {
    const challenge = await api.get('/jobs/' + encodeURIComponent(job.id) + '/corporate-ars');
    input += `<div class="info-block">은행에서 걸려 온 전화에 인증번호 <strong>${esc(challenge.code)}</strong>를 입력한 뒤 아래 버튼을 누르세요.</div>`;
  }
  ui.showDialog(next === 'execute' ? '기업 이체 내용 확인' : '기업 이체 인증', `${preview(awaiting.preview)}${duplicate ? note('은행에서 중복 이체 가능성을 알렸어요.') : ''}<form data-submit="corporate-transfer-confirm" data-job="${esc(job.id)}" data-digest="${esc(awaiting.digest)}" autocomplete="off">${input}${duplicate && next === 'execute' ? '<label><input type="checkbox" required>중복 안내를 확인했으며 이체를 진행합니다.</label>' : ''}<p class="dialog-note">${next === 'execute' ? '확인하면 필요한 인증을 진행하고 이체를 한 번만 전송해요.' : '은행이 요구한 인증만 입력해요. 인증을 마치면 확인한 이체를 진행해요.'}</p><div class="dialog-actions">${button('나중에', 'data-ui="close"')}${button('준비 취소', `data-action="corporate-transfer-cancel" data-job="${esc(job.id)}"`)}<button class="button primary" type="submit">${next === 'ars' ? '전화 인증 완료 · 계속' : next === 'execute' ? '확인하고 이체' : '인증하고 계속'}</button></div></form>`);
}

function resultDialog(job) {
  const result = job.result || {};
  const parent = esc(job.parent_job_id || job.id);
  const tables = ['synchronous', 'asynchronous', 'records'].map(k => {
    if (!result[k]?.length) return '';
    const group = 'corporate-transfer-' + k;
    state.rows[group] = {rows: result[k], job};
    return ui.rowsTable(result[k].map(r => ({'받는 분': r.RMTE_NM, '받는 계좌': r.RCV_ACCT_NO,
      금액: amount(r.TRNS_AMT ?? r.TRSC_AMT), 상태: ({processing: '처리 중', delayed: '지연이체'}[r.processing_status]) || r.ERR_MSG,
      일자: date(r.TRSC_DT), 시각: time(r.TRSC_TM)})), {group, keys: ['받는 분', '받는 계좌', '금액', '상태', '일자', '시각']});
  }).join('');
  const sent = result.transfer_sent || job.name === PREFIX + 'transfer.result';
  const cancel = result.preparation_available && !sent && result.transfer_status !== 'preparation_cancelled' && job.status !== 'cancelled';
  ui.showDialog('기업 이체 결과', `${ui.statusTags(job)}<h3>${esc(STATUS[result.transfer_status] || '결과 미확인')}</h3>${notices(job)}${result.preview ? preview(result.preview) : ''}${tables}<div class="dialog-actions">${button('작업 상세', `data-action="job-detail" data-job="${esc(job.id)}"`)}${sent ? button('이체 결과 조회', `data-action="corporate-transfer-result" data-job="${parent}"`) : cancel ? button('준비 취소', `data-action="corporate-transfer-cancel" data-job="${parent}"`) : ''}${button('닫기', 'data-ui="close"', 'primary')}</div>`);
}

async function transferView() {
  const rows = accounts().filter(t => t.identity?.account_type === 'krw');
  const allowed = new Set(scopeLogins('hana_corporate').map(r => r.id));
  const listing = await api.get('/jobs?limit=200&area=corporate');
  const previous = listing.jobs.filter(j => j.name === PREFIX + 'transfer.prepare' && allowed.has(j.login_id));
  // Past and waiting transfers appear only once there are any.
  const recent = previous.length ? `<section class="panel"><div class="panel-heading"><h2>진행한 이체</h2></div><div class="settings-body">${previous.map(j => `<div class="setting-row"><span>${esc(j.fixed?.login?.display_name)} · ${ui.time(j.created_at)} ${ui.statusTags(j)}</span>${button(j.status === 'awaiting_input' ? '이어하기' : '결과 보기', `data-action="corporate-transfer-open" data-job="${esc(j.id)}"`)}</div>`).join('')}</div></section>` : '';
  const intro = heading('기업 이체', '일반 원화 이체의 수취인과 금액을 확인하고 진행해요.');
  if (!rows.length) return intro + `<section class="panel"><div class="empty-state">기업 계좌를 조회하면 출금 계좌를 선택할 수 있어요.<div class="section-actions">${button('기업 계좌', 'data-view="corporate-accounts"', 'primary')}</div></div></section>` + recent;
  return intro + `<form class="panel form-panel corporate-transfer-form" data-submit="corporate-transfer">${select('target_id', '출금 계좌', accountOptions(rows))}<div class="field-row">${select('bank', '받는 은행', ui.BANKS, '081')}${field('recipient', '받는 계좌', 'required inputmode="numeric" pattern="[0-9- ]+" maxlength="24"')}</div>${field('amount', '이체 금액 (원)', 'required inputmode="numeric" pattern="[0-9,]+"')}<details class="advanced-block"><summary>통장 표시·메모·지연이체</summary>${field('sender_text', '입금 통장 표시', 'maxlength="100"')}${field('recipient_text', '출금 통장 표시', 'maxlength="100"')}${field('memo', '메모', 'maxlength="100"')}${field('cms_code', 'CMS 코드', 'pattern="[A-Za-z0-9-]+" maxlength="100"')}<label><input name="delayed" type="checkbox">지연이체</label></details><div class="form-actions"><button class="button primary" type="submit">받는 분·금액 확인</button><p class="field-help">이 단계에서는 이체하지 않아요. 은행이 요구하는 인증은 내용 확인 후 입력해요.</p></div></form>${panel()}${recent}`;
}

export const corporateViews = {'corporate-accounts': accountsView, 'corporate-history': historyView, 'corporate-transfer': transferView};
export const corporateActions = {
  'corporate-login-add': ctx => corporateLogin(ctx),
  'corporate-login-method': (ctx, select) => corporateLogin(ctx, null, select.value),
  'corporate-login-credential': (ctx, select) => corporateLogin(ctx, null, 'onesign', select.value),
  'corporate-relogin': (ctx, el) => corporateLogin(ctx, login(el.dataset.login)),
  'corporate-login': async (ctx, form) => {
    const data = Object.fromEntries(new FormData(form)), method = form.dataset.method;
    let row = login(form.dataset.login);
    try {
      if (!row) {
        const credential = method === 'id_password' ? data.credential.toUpperCase() : data.credential;
        row = state.logins.find(r => r.institution === 'hana_corporate' && r.method === method && r.credential?.ref === credential && !r.disabled);
        if (!row) row = await api.post('/logins', {institution: 'hana_corporate', method, credential, name: '하나기업뱅킹 · ' + credential});
        if (!state.logins.some(r => r.id === row.id)) state.logins.push(row);
        form.dataset.login = row.id;
      }
      const supplied = Object.fromEntries(['login_password', 'certificate_password', 'vault_passphrase', 'pin', 'remember_vault'].filter(k => k in data).map(k => [k, data[k]]));
      const secrets = await applyRemember(supplied, onesignStore(row));
      form.reset(); ui.closeDialog();
      const job = await ctx.run(PREFIX + ({id_password: 'login-idpw', joint_certificate: 'login', onesign: 'login-onesign'}[method]),
        {login_id: row.id, input: data.settings ? {settings: data.settings} : {}}, {panel: 'job-panel', secrets});
      if (job) {
        await refreshModel();
        if (job.result?.session_id) { await queryAccounts(ctx, login(row.id)); changeView('corporate-accounts'); }
        else ui.showDialog('기업 로그인 결과', jobState(job) + notices(job) + close());
      }
      await render();
    } catch (error) { ui.fail(ui.message(error.code)); }
  },
  'corporate-accounts': (ctx, form) => queryAccounts(ctx, login(form.dataset.login), new FormData(form).get('category')),
  'corporate-accounts-query': (ctx, el) => queryAccounts(ctx, login(el.dataset.login)),
  'corporate-account-history': (ctx, el) => changeView('corporate-history', {target: el.dataset.target}),
  // Another account shows its own last result; nothing is requested from the bank.
  'corporate-history-target': (ctx, el) => changeView('corporate-history', {target: el.value}),
  'corporate-history': async (ctx, form) => {
    const data = Object.fromEntries(new FormData(form)), chosen = target(data.target_id); delete data.target_id;
    for (const k of Object.keys(data)) if (!data[k]) delete data[k];
    if (data.currency) data.currency = data.currency.toUpperCase();
    if (chosen.identity?.account_type === 'loan') delete data.direction;
    await ctx.run(PREFIX + 'history', {login_id: chosen.login_id, target_id: chosen.id, input: data}, {panel: 'job-panel',
      key: cacheKey('history', chosen.id), onDone: job => { state.params.target = chosen.id; document.getElementById('corporate-results').innerHTML = historyRows(job); }});
  },
  'corporate-transfer': async (ctx, form) => {
    const data = Object.fromEntries(new FormData(form)), chosen = target(data.target_id); delete data.target_id;
    data.delayed = data.delayed === 'on'; data.amount = data.amount.replaceAll(',', ''); data.recipient = data.recipient.replace(/[- ]/g, '');
    for (const k of ['sender_text', 'recipient_text']) if (!data[k]) delete data[k];
    await ctx.run(PREFIX + 'transfer.prepare', {login_id: chosen.login_id, target_id: chosen.id, input: data},
      {panel: 'job-panel', onDone: job => transferDialog(ctx, job)});
  },
  'corporate-transfer-confirm': async (ctx, form) => {
    const id = form.dataset.job;
    const secrets = Object.fromEntries(new FormData(form));
    form.reset();
    const job = await api.post('/jobs/' + encodeURIComponent(id) + '/confirm', {confirmation: form.dataset.digest, secrets});
    ui.closeDialog();
    const final = await ctx.track(job, {panel: 'job-panel'});
    if (final) await transferDialog(ctx, final);
  },
  'corporate-transfer-open': async (ctx, el) => transferDialog(ctx, await api.get('/jobs/' + encodeURIComponent(el.dataset.job))),
  'corporate-transfer-result': async (ctx, el) => {
    const parent = await api.get('/jobs/' + encodeURIComponent(el.dataset.job)); ui.closeDialog();
    await ctx.run(PREFIX + 'transfer.result', {login_id: parent.login_id, target_id: parent.target_id, parent_job_id: parent.id},
      {panel: 'job-panel', onDone: resultDialog});
  },
  'corporate-transfer-cancel': async (ctx, el) => {
    const parent = await api.get('/jobs/' + encodeURIComponent(el.dataset.job)); ui.closeDialog();
    await ctx.run(PREFIX + 'transfer.cancel', {login_id: parent.login_id, target_id: parent.target_id, parent_job_id: parent.id},
      {panel: 'job-panel', onDone: async job => { resultDialog(job); await render(); }});
  },
};
