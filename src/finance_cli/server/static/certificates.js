/* Certificate onboarding. Sensitive files and fields are passed once, never placed in jobs or browser storage. */
import {api, follow, idempotencyKey} from './api.js';
import * as ui from './ui.js';
import {applyRemember, refreshModel, rememberField, secretFields, state} from './app.js';

const {esc, button, note} = ui;
const REMOTE = new Set(['authenticate', 'request-sms', 'verify-sms', 'begin-id', 'identity', 'list-accounts', 'account', 'issue', 'complete']);
const SCREENS = ['휴대폰 인증', '신분증 확인', '계좌 확인', 'PIN 설정·발급'];
const GROUPS = {
  init: ['init', 'profile', 'authenticate', 'request-sms'], profile: ['profile', 'authenticate', 'request-sms'],
  authenticate: ['authenticate', 'request-sms'], 'request-sms': ['request-sms'], 'verify-sms': ['verify-sms'],
  consent: ['consent', 'begin-id', 'prepare-id', 'identity', 'list-accounts'], 'begin-id': ['begin-id', 'prepare-id', 'identity', 'list-accounts'],
  'prepare-id': ['prepare-id', 'identity', 'list-accounts'], identity: ['identity', 'list-accounts'], 'list-accounts': ['list-accounts'], account: ['account'],
  issue: ['issue', 'complete'], complete: ['complete'], inspect: ['inspect'],
};
const SCREEN = {init: 0, profile: 0, authenticate: 0, 'request-sms': 0, 'verify-sms': 0,
  consent: 1, 'begin-id': 1, 'prepare-id': 1, identity: 1, 'list-accounts': 2, account: 2, issue: 3, complete: 3};
const RUNNING = {init: '저장소를 준비하고 있어요.', profile: '휴대폰 정보를 저장하고 있어요.',
  authenticate: '휴대폰 인증을 준비하고 있어요.', 'request-sms': '인증문자를 요청하고 있어요.',
  'verify-sms': '인증번호를 확인하고 있어요.', consent: '약관 동의를 저장하고 있어요.',
  'begin-id': '신분증 확인을 준비하고 있어요.', 'prepare-id': '신분증 사진을 준비하고 있어요.',
  identity: '신분증을 확인하고 있어요.', 'list-accounts': '인증에 사용할 본인 계좌 목록을 불러오고 있어요.', account: '본인 계좌를 확인하고 있어요.',
  issue: '하나인증서를 발급하고 있어요.', complete: '가입을 마무리하고 있어요.', inspect: '발급 진행 상태를 확인하고 있어요.'};
const IDENTITY_INPUT_ERRORS = new Set(['invalid_identity_capture', 'identity_jpeg_required', 'identity_jpeg_invalid',
  'identity_image_required', 'identity_image_too_large', 'identity_image_dimensions_too_large',
  'identity_name_required', 'identity_date_format', 'identity_date_invalid', 'resident_number_format',
  'driver_number_format', 'identity_not_confirmed', 'identity_name_invalid', 'incorrect_passphrase_or_damaged_id_card',
  'id_card_not_found', 'passphrase_minimum_4_characters']);
const field = (name, label, attrs = '') => `<div class="field"><label for="cert-${name}">${label}</label><input id="cert-${name}" name="${name}" required ${attrs.includes('autocomplete=') ? '' : 'autocomplete="off"'} ${attrs}></div>`;
const password = () => field('vault_passphrase', '저장소 암호', 'type="password"');
function vaultFields(name = null) {
  const fields = secretFields([['vault_passphrase', '저장소 암호']], name);
  return fields.length ? password() + rememberField(fields, name || 'new')
    : '<p class="field-help">서버 메모리에 기억한 저장소 암호를 사용해요. 연결·인증서 화면의 잠그기로 암호를 지울 수 있어요.</p>';
}
const nameField = () => field('name', '보관할 이름', 'maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}" placeholder="예: personal"');
const controls = title => `<p class="form-error" id="certificate-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-ui="close">취소</button><button type="submit" class="button primary">${esc(title)}</button></div>`;
const terms = rows => `<ul>${rows.map(row => `<li>${esc(row.title)}${row.urls.map((url, i) => ` <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">약관 ${i + 1}</a>`).join('')}</li>`).join('')}</ul>`;
const agree = () => '<label class="check"><input type="checkbox" name="agree" required> 위 필수 약관을 읽고 동의합니다</label>';
// The reviewed support level of issuance, as the coverage screen shows it.
const issuanceLevel = () => ui.VERIFICATION[state.capabilities?.features?.find(f => f.id === 'hana-issuance')?.verification]?.[0] || '';

const IMAGE_LIMIT = 8 * 1024 * 1024;
const KIND_LABEL = {resident: '주민등록증', driver: '운전면허증'};
const identityFields = () => note('본인의 신분증 카드 영역 JPEG를 선택하세요(8 MiB 이하). 사진은 비율을 유지해 자동 축소하며 원본 파일은 바꾸지 않아요.')
  + '<div class="field"><label for="cert-id-kind">신분증 종류</label><select id="cert-id-kind" name="kind" data-change="certificate-id-kind"><option value="resident">주민등록증</option><option value="driver">운전면허증</option></select></div>'
  + field('image', '신분증 JPEG', 'type="file" accept="image/jpeg"') + '<div class="certificate-grid">'
  + field('id_name', '성명 (신분증에 적힌 본인 이름)', 'maxlength="60" placeholder="예: 홍길동"') + field('issueDate', '발급일 (YYYY.MM.DD)', 'pattern="[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}" maxlength="10"')
  + field('birthDate', '주민번호 앞 6자리', 'type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"')
  + field('resident', '주민번호 뒤 7자리', 'type="password" inputmode="numeric" pattern="[0-9]{7}" maxlength="7"') + '</div>'
  + '<div id="certificate-driver" hidden><div class="certificate-grid">' + ['regionCode', 'driver1', 'driver2', 'driver3'].map((key, i) => field(key, ['면허번호 지역 2자리', '면허번호 두 번째 구간 2자리', '면허번호 세 번째 구간 6자리', '면허번호 네 번째 구간 2자리'][i], `type="password" inputmode="numeric" pattern="[0-9]{${i === 2 ? 6 : 2}}" disabled`)).join('') + '</div></div>'
  + '<label class="check"><input type="checkbox" name="identity_confirmed" required> 본인의 마스킹하지 않은 신분증이며, 입력한 정보를 확인했습니다</label>';
// Saved cards come first; the direct form stays available for a card that is not saved.
const identityChoice = cards => `<div class="field"><label for="cert-id-source">신분증</label><select id="cert-id-source" name="id_source" data-change="certificate-id-source">${cards.map(c => `<option value="${esc(c.name)}">${esc(c.name)} · ${esc(KIND_LABEL[c.kind] || c.kind)} · 발급일 ${esc(c.issue_date)}</option>`).join('')}<option value="">직접 입력</option></select></div>`
  + `<div id="certificate-id-saved">${field('idcard_passphrase', '신분증 보관 암호', 'type="password"')}<label class="check"><input type="checkbox" name="saved_confirmed" required> 보관 후 재발급받지 않은 현재 유효한 본인 신분증입니다</label></div>`
  + `<div id="certificate-id-direct" hidden>${identityFields()}</div>`;

async function captureOf(data) {
  const kind = data.get('kind'), fields = {name: data.get('id_name'), issueDate: data.get('issueDate'), birthDate: data.get('birthDate'), resident: data.get('resident')};
  if (kind === 'driver') for (const key of ['regionCode', 'driver1', 'driver2', 'driver3']) fields[key] = data.get(key);
  const file = data.get('image');
  if (!(file instanceof File) || !file.size) throw new Error('identity_image_required');
  if (file.size > IMAGE_LIMIT) throw new Error('identity_image_too_large');
  return JSON.stringify({kind, fields, image: await file64(file, IMAGE_LIMIT), confirmation: data.get('identity_confirmed') ? '본인 신분증' : ''});
}

function toggle(block, on) {
  block.hidden = !on;
  block.querySelectorAll('input, select').forEach(input => { input.disabled = !on; });
}

async function file64(file, limit) {
  if (!(file instanceof File) || !file.size || file.size > limit) throw new Error('certificate_file_size_not_accepted');
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1]);
    reader.onerror = () => reject(new Error('invalid_certificate_file'));
    reader.readAsDataURL(file);
  });
}

function steps(stage) {
  const current = SCREEN[stage];
  return `<ol class="certificate-steps" aria-label="발급 단계">${SCREENS.map((title, i) => `<li ${i === current ? 'aria-current="step"' : ''} class="${i < current ? 'done' : ''}"><b>${i + 1}</b><span>${title}</span></li>`).join('')}</ol>`;
}

function identityDiagnostic(value) {
  if (!value) return '';
  const rows = (value.requests || []).map(row => {
    const label = row.stage === 'image' ? '신분증 사진 업로드' : '신분증 정보 확인';
    const rejected = row.service_status === 'rejected' || row.image_accepted === false
      || row.identity_response_code && row.identity_response_code !== '000';
    const status = rejected ? '은행 거절' : row.image_accepted === true ? '사진 접수 완료'
      : row.service_status === 'accepted' ? '요청 수락' : '결과 미확인';
    const codes = [...(row.error_codes || []), ...(row.identity_response_code ? [row.identity_response_code] : [])];
    return `<p>${label}: <strong>${status}</strong>${codes.length ? ` (${codes.map(esc).join(', ')})` : ''}${row.information_mismatch_reported ? ' · 은행 응답: 정보 불일치' : ''}</p>`;
  }).join('');
  const checks = value.input_checks || {};
  const guidance = checks.name_is_document_label ? '성명 칸에 신분증 종류가 입력되어 있어요. 신분증에 적힌 본인 이름을 입력해야 해요.'
    : checks.name_matches_phone === false ? '신분증에 입력한 성명이 휴대폰 본인확인에 사용한 이름과 달라요. 신분증에 적힌 본인 이름을 확인하세요.' : '';
  return `<div class="dialog-note">${rows}${guidance ? `<p role="alert">${guidance}</p>` : ''}<p>저장된 기록만 확인했어요. 은행에는 재전송하지 않았어요.</p></div>`;
}

function showStopped(name, job, {issued = false, error = '', mismatch = false} = {}) {
  const stopped = job?.local?.stopped;
  issued ||= job?.result?.certificate_issued === true;
  const correctable = job?.name === 'hana.onesign.issue.prepare-id' && job.outcome === 'not_started'
    && job.attempt && !job.attempt.sent && IDENTITY_INPUT_ERRORS.has(stopped);
  const text = issued ? '인증서 발급은 확인됐어요. 가입 완료 여부는 작업 기록에서 확인하세요.'
    : correctable ? '은행에 신분증을 보내기 전 입력 검사에서 중단됐어요. 사진이나 정보를 수정해 이어갈 수 있어요.'
    : mismatch ? '방금 단계는 완료됐지만 다음 진행 상태를 확인하지 못해 멈췄어요.'
    : '발급 진행을 멈췄어요. 작업 기록에서 마지막 처리 결과를 확인하세요. 자동 재전송하지 않아요.';
  const account = job?.result?.account_diagnostic;
  const accountNote = account?.selection_not_found ? note(`입력한 계좌번호가 은행의 발급용 본인계좌 목록 ${account.account_count}개와 일치하지 않아 중단됐어요.${account.password_verification_requested === false ? ' 계좌 비밀번호 검증 요청은 보내지 않았어요.' : ''} 새 발급에서는 은행이 제공한 목록에서 계좌를 선택하세요.`) : '';
  ui.showDialog('하나인증서 발급 상태', `${note(text)}${job?.name === 'hana.onesign.issue.inspect' ? '<p>저장된 발급 상태 확인 완료</p>' : job ? ui.statusTags(job) : ''}${identityDiagnostic(job?.result?.identity_diagnostic)}${accountNote}
    <p class="form-error" role="alert">${esc(ui.message(stopped || error))}</p>
    <div class="dialog-actions">${button('작업 기록', 'data-view="activity"')}${button(correctable ? '신분증 입력 수정' : '진행 상태 확인', `data-action="certificate-hana-inspect" data-name="${esc(name)}"`, 'primary')}</div>`);
}

async function showNext(name, job, warning = '') {
  if (job.result?.ready === true) {
    ui.showDialog('하나인증서 발급 완료', `${note('하나인증서 발급과 가입이 완료됐어요. 기관 연결을 추가하면 사용할 수 있어요.')}${ui.statusTags(job)}${button('기관 연결 추가', 'data-action="add-login-dialog"', 'primary')}`);
  } else if (job.result?.next_stage && GROUPS[job.result.next_stage]) {
    await stageDialog(name, job.result.next_stage, job.result, warning);
  } else showStopped(name, job);
}

async function start(form, name, input, secrets, onDone) {
  if (form.dataset.started) return;
  form.dataset.started = 'true';
  // One key per submitted form. A lost HTTP response never leads to an automatic re-send.
  const idempotency_key = idempotencyKey();
  try {
    const job = await api.post('/jobs', {name, input, secrets, idempotency_key});
    form.reset();
    ui.showDialog('인증서 작업 진행', `<p>${ui.working('서버에서 처리하고 있어요.')}</p><p class="field-help">창을 닫아도 작업은 계속되며 다시 전송하지 않아요.</p><div id="certificate-progress"></div>` + button('작업 기록', 'data-view="activity"'));
    const holder = document.querySelector('#certificate-progress');
    const final = await follow(job.id, value => { if (holder.isConnected) holder.innerHTML = ui.statusTags(value); });
    secrets = null;
    try { await refreshModel(); state.credentials = (await api.get('/credentials')).credentials; } catch {} // Preserve the completed result.
    if (holder.isConnected) await onDone(final);
  } catch (error) {
    // Even a transport error may follow an accepted job. Show history instead of offering a retry.
    form.reset();
    const target = document.querySelector('#certificate-error');
    if (target) target.textContent = ui.message(error.code || error.message) + ' 작업 기록을 확인하세요. 자동 재전송하지 않아요.';
    ui.toast('인증서 작업을 확인하세요. 작업 기록에서 진행 상태를 볼 수 있어요.');
  } finally { secrets = null; }
}

async function stageDialog(name, stage, progress = {}, warning = '') {
  const [options, vaults, saved] = await Promise.all([api.get('/certificates/options'), api.get('/vaults'), api.get('/id-cards')]);
  const cards = saved.id_cards;
  state.vaults = Object.fromEntries(vaults.vaults.map(v => [v.name, v.unlocked]));
  let fields = '', before = '', digest = progress.terms_digest || '';
  const phone = ['init', 'profile'].includes(stage);
  const capture = ['consent', 'begin-id', 'prepare-id'].includes(stage);
  if (stage === 'init') {
    state.credentials = (await api.get('/credentials')).credentials;
    const stores = state.credentials.filter(c => c.type === 'onesign');
    before = stores.length ? `<div class="certificate-resume"><strong>진행 중인 발급 이어하기</strong>${stores.map(c => button(c.ref, `data-action="certificate-hana-inspect" data-name="${esc(c.ref)}"`)).join('')}</div>` : '';
    fields += `<details class="certificate-settings"><summary>저장소 설정</summary>${nameField()}<div class="field"><label for="cert-settings">서비스 설정</label><select id="cert-settings" name="settings" required>${options.hana.settings.map(row => `<option value="${esc(row.name)}">${esc(row.name)}</option>`).join('')}</select></div></details>`;
    if (!options.hana.settings.length) fields += note('서버에 하나인증서 서비스 설정이 필요해요. 설정을 준비한 뒤 발급할 수 있어요.');
    before += cards.length ? `<p class="field-help">보관한 신분증 ${cards.length}개를 신분증 확인 단계에서 골라 쓸 수 있어요.</p>`
      : `<div class="certificate-resume"><span class="field-help">신분증을 먼저 보관해 두면 인증문자 확인 뒤 사진을 준비하느라 은행 세션이 기다리는 일이 없어요.</span>${button('신분증 먼저 보관', 'data-action="idcard-add"')}</div>`;
  }
  fields += vaultFields(stage === 'init' ? null : name);
  if (phone) {
    const carriers = options.hana.carriers;
    digest = carriers[0].terms_digest;
    fields += `<div class="certificate-grid">${field('customer_name', '이름', 'maxlength="60"')}${field('birth7', '생년월일 6자리 + 주민번호 뒤 첫 자리', 'type="password" inputmode="numeric" pattern="[0-9]{6}[1-4]" maxlength="7"')}${field('phone', '본인 휴대폰 번호', 'type="tel" pattern="0[0-9]{9,10}" maxlength="11"')}<div class="field"><label for="cert-carrier">통신사</label><select id="cert-carrier" name="carrier" data-change="certificate-carrier">${carriers.map(c => `<option value="${esc(c.code)}">${esc(c.name)}</option>`).join('')}</select></div></div><details><summary>휴대폰 인증 필수 약관</summary><div id="certificate-terms">${terms(carriers[0].terms)}</div></details>${agree()}`;
  }
  if (stage === 'verify-sms') fields += note('인증문자를 요청했어요. 문자가 도착하면 요청 후 180초 안에 인증번호를 입력하세요.') + field('sms', 'SMS 인증번호', 'type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"');
  if (stage === 'consent') fields += `<details><summary>하나인증서 가입 필수 약관</summary>${terms(progress.terms || [])}</details>${agree()}`;
  if (capture) fields += cards.length ? identityChoice(cards) : identityFields();
  if (stage === 'list-accounts') fields += note('은행에서 인증에 사용할 수 있는 본인 계좌 목록을 불러와요.');
  if (stage === 'account') fields += (progress.accounts?.length
    ? '<div class="field"><label for="cert-account-choice">인증할 본인 계좌</label><select id="cert-account-choice" name="account_choice" required><option value="">계좌를 선택하세요</option>'
      + progress.accounts.map(row => `<option value="${esc(row.choice)}">${esc(row.label)}</option>`).join('') + '</select></div>'
      + field('account_password', '계좌 비밀번호', 'type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4"')
    : note('은행 응답에서 선택할 수 있는 발급용 본인계좌를 확인하지 못했어요. 목록에 없는 계좌나 평생계좌번호를 직접 입력할 수는 없어요.'));
  if (stage === 'issue') fields += note('하나인증서에 사용할 PIN을 정하세요. 저장소 암호와 별개예요.')
    + field('new_pin', '새 PIN 6자리', 'type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"')
    + field('new_pin_confirmation', 'PIN 확인', 'type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"');
  const label = stage === 'inspect' ? '발급 이어하기' : stage === 'verify-sms' ? '인증번호 확인'
    : stage === 'complete' ? '가입 완료' : stage === 'list-accounts' ? '본인 계좌 불러오기' : SCREEN[stage] === 0 ? '인증문자 요청'
    : SCREEN[stage] === 1 ? '신분증 확인' : SCREEN[stage] === 2 ? '계좌 확인' : '하나인증서 발급';
  const approval = stage === 'inspect' ? '저장된 진행 상태를 확인하고 이어갈 화면을 열어요. 기관에는 접속하지 않아요.'
    : SCREEN[stage] === 0 ? (stage === 'verify-sms' ? '인증번호 확인을 누르면 기관에 인증번호를 보내 본인 여부를 확인해요.' : '인증문자 요청을 누르면 휴대폰 정보를 저장하고 앱 인증과 SMS 요청을 순서대로 진행해요.')
    : SCREEN[stage] === 1 ? '신분증 확인을 누르면 가입 동의와 사진 준비를 마친 뒤 은행에 신분증을 보내 확인하고, 인증할 본인 계좌 목록을 불러와요.'
    : stage === 'list-accounts' ? '본인 계좌 불러오기를 누르면 은행에 발급용 계좌 목록을 요청해요.'
    : SCREEN[stage] === 2 ? '은행에서 제공한 본인계좌를 선택하세요. 계좌 확인을 누르면 선택한 계좌의 비밀번호를 은행에 보내 확인해요.'
    : stage === 'complete' ? '가입 완료를 누르면 이미 발급한 인증서의 가입 절차를 마무리해요.' : '하나인증서 발급을 누르면 인증서를 새로 발급하고 가입 완료까지 진행해요.';
  ui.showDialog('하나인증서 발급', `${stage === 'inspect' ? '' : steps(stage)}${before}${warning ? note(esc(warning)) : ''}<form data-submit="certificate-hana-submit" data-name="${esc(name)}" data-stage="${esc(stage)}" data-digest="${esc(digest)}" autocomplete="off"><h3>${stage === 'inspect' ? '발급 이어하기' : SCREENS[SCREEN[stage]]}</h3>${issuanceLevel() ? `<p class="meta">지원 상태: ${esc(issuanceLevel())}</p>` : ''}${fields}<p class="field-help">${approval}</p>${controls(label)}</form>`, {wide: stage !== 'inspect'});
  const form = document.querySelector('[data-submit="certificate-hana-submit"]');
  if (stage === 'account' && !progress.accounts?.length) form.querySelector('button[type="submit"]').disabled = true;
  if (stage === 'init') {
    let candidate = 'hana', suffix = 2;
    while (state.credentials.some(c => c.ref === candidate)) candidate = 'hana-' + suffix++;
    form.elements.name.value = candidate;
    form.querySelector('button[type="submit"]').disabled = !options.hana.settings.length;
  }
  const source = form.querySelector('[name="id_source"]');
  if (source) certificateActions['certificate-id-source']({}, source);
  if (stage === 'inspect' && state.vaults[name]) await submitWizard(form);
}

async function submitWizard(form) {
  if (form.dataset.started || !form.reportValidity()) return;
  const stage = form.dataset.stage, chain = GROUPS[stage];
  if (!chain) return;
  form.dataset.started = 'true';
  let data = new FormData(form), name = stage === 'init' ? data.get('name') : form.dataset.name;
  let vault = data.has('vault_passphrase') ? {vault_passphrase: data.get('vault_passphrase')} : {};
  let privateInputs = {}, holder, last = null, issued = false, submitted = false, warning = '', idCard = '';
  const settings = stage === 'init' ? data.get('settings') : null;
  const remember = data.get('remember_vault') === 'on';
  try {
    if (chain.includes('profile')) privateInputs.profile = {
      phone_profile: JSON.stringify({name: data.get('customer_name'), birth7: data.get('birth7'), phone: data.get('phone'), carrier: data.get('carrier')}), agreement: data.get('agree') ? form.dataset.digest : ''};
    if (chain.includes('consent')) privateInputs.consent = {agreement: data.get('agree') ? form.dataset.digest : ''};
    if (chain.includes('prepare-id')) {
      idCard = data.get('id_source') || '';
      privateInputs['prepare-id'] = {identity_capture: idCard
        ? JSON.stringify({passphrase: data.get('idcard_passphrase'), confirmation: data.get('saved_confirmed') ? '본인 신분증' : ''})
        : await captureOf(data)};
    }
    if (stage === 'verify-sms') privateInputs[stage] = {sms: data.get('sms')};
    if (stage === 'account') privateInputs[stage] = {account_choice: data.get('account_choice'), account_password: data.get('account_password')};
    if (stage === 'issue') {
      if (data.get('new_pin') !== data.get('new_pin_confirmation')) throw new Error('new_pin_confirmation_mismatch');
      privateInputs.issue = {new_pin: data.get('new_pin'), new_pin_confirmation: data.get('new_pin_confirmation'), issue_confirmation: '발급'};
    }
    data = null;
    if (remember && stage !== 'init') await applyRemember(Object.assign(vault, {remember_vault: 'on'}), name);
    form.reset();
    ui.showDialog('하나인증서 발급', `${stage === 'inspect' ? '' : steps(stage)}<div id="certificate-progress" role="status" aria-live="polite"></div><p class="field-help">창을 닫으면 실행 중인 요청까지만 처리해요. 이후 절차는 발급 이어하기에서 계속할 수 있어요.</p>`);
    holder = document.querySelector('#certificate-progress');
    for (let i = 0; i < chain.length; i++) {
      if (!holder.isConnected) return;
      const current = chain[i];
      holder.innerHTML = ui.working(RUNNING[current]);
      submitted = true;
      // This dialog already holds the screen and says which step runs.
      const job = await api.post('/jobs', {name: 'hana.onesign.issue.' + current,
        input: {name, ...(current === 'init' ? {settings} : {}), ...(current === 'prepare-id' && idCard ? {id_card: idCard} : {}),
          ...(REMOTE.has(current) ? {send: true} : {})},
        secrets: {...vault, ...privateInputs[current]}, idempotency_key: idempotencyKey()}, {hold: false});
      delete privateInputs[current];
      last = await follow(job.id, () => {});
      issued ||= last.result?.certificate_issued === true;
      if (current === 'init' && remember && last.result?.created === true) {
        try { await applyRemember(Object.assign(vault, {remember_vault: 'on'}), name); }
        catch { delete vault.remember_vault; warning = '저장소는 만들었지만 암호를 기억하지 못했어요. 이 화면의 처리가 끝나면 암호를 다시 입력해야 해요.'; }
      }
      if (!holder.isConnected) return;
      if (last.outcome !== 'success' || last.local?.stopped) { showStopped(name, last, {issued}); return; }
      if (i + 1 < chain.length && last.result?.next_stage !== chain[i + 1]) {
        showStopped(name, last, {issued, mismatch: true}); return;
      }
    }
    vault = privateInputs = null;
    try { await refreshModel(); state.credentials = (await api.get('/credentials')).credentials; } catch {} // A list refresh cannot change the job outcome.
    if (holder.isConnected) {
      try { await showNext(name, last, warning); }
      catch { showStopped(name, last, {issued, mismatch: true}); }
    }
  } catch (error) {
    if (!submitted && form.isConnected) {
      delete form.dataset.started;
      form.querySelector('#certificate-error').textContent = ui.message(error.code || error.message);
    } else if (holder?.isConnected) showStopped(name, last, {issued, error: error.code || error.message});
  } finally { data = vault = privateInputs = null; }
}

export const certificateActions = {
  'certificate-add': async () => {
    ui.showDialog('인증서 발급·가져오기', `<div class="settings-body"><div class="setting-row"><span><strong>공동인증서</strong><span class="meta">신규 발급은 미지원이에요. 발급기관에서 받은 NPKI/PFX를 가져올 수 있어요.</span></span>${button('가져오기', 'data-action="certificate-joint"')}</div><div class="setting-row"><span><strong>금융인증서</strong><span class="meta">신규 발급·클라우드 연결은 아직 미지원이에요.</span></span>${ui.tag('미지원', 'neutral')}</div><div class="setting-row"><span><strong>하나인증서</strong><span class="meta">국내 성인 기존 하나은행 고객 · SMS·신분증·본인 계좌 확인${issuanceLevel() ? ' · ' + esc(issuanceLevel()) : ''}</span></span>${button('신규 발급·진행 확인', 'data-action="certificate-hana"', 'primary')}</div></div><p class="dialog-note">인증서 비밀과 파일은 브라우저 저장소·작업 기록에 남기지 않아요. 기관 로그인은 발급·가져오기 후 별도로 추가하세요.</p>`);
  },
  'certificate-joint': () => {
    ui.showDialog('공동인증서 가져오기', `<form data-submit="certificate-import" autocomplete="off">${nameField()}<div class="field"><label for="cert-format">파일 형식</label><select id="cert-format" name="format" data-change="certificate-format"><option value="pfx">PFX / P12</option><option value="npki">NPKI (signCert.der + signPri.key)</option></select></div>${field('certificate_file', 'PFX 또는 signCert.der 파일 (2 MiB 이하)', 'type="file" accept=".pfx,.p12,.der"')}<div id="certificate-npki" hidden>${field('private_key_file', 'signPri.key (2 MiB 이하)', 'type="file" accept=".key" disabled')}<div class="field"><label for="cert-compatibility">암호 호환 규칙</label><select id="cert-compatibility" name="compatibility"><option value="hana">하나은행 (기본)</option><option value="hometax">홈택스</option></select></div></div><div id="certificate-pfx-index">${field('pfx_index', 'PFX 인증서 순번 (여럿이면 지정, 0부터)', 'type="number" min="0"')}</div>${field('certificate_password', '인증서 비밀번호', 'type="password"')}<p class="dialog-note">새로 발급하지 않고 원본 파일을 암호화 보관해요. 기관에는 접속하지 않아요.</p>${controls('가져오기')}</form>`);
    document.querySelector('[name="pfx_index"]').required = false;
  },
  'certificate-format': (ctx, select) => {
    const npki = select.value === 'npki';
    document.querySelector('#certificate-npki').hidden = !npki;
    document.querySelector('[name="private_key_file"]').disabled = !npki;
    document.querySelector('#certificate-pfx-index').hidden = npki;
    document.querySelector('[name="pfx_index"]').disabled = npki;
  },
  'certificate-import': async (ctx, form) => {
    const data = new FormData(form), format = data.get('format');
    try {
      const input = {name: data.get('name'), format};
      if (format === 'npki') input.compatibility = data.get('compatibility');
      if (format === 'pfx' && data.get('pfx_index')) input.pfx_index = Number(data.get('pfx_index'));
      const secrets = {certificate_password: data.get('certificate_password'), certificate_file: await file64(data.get('certificate_file'), 2 * 1024 * 1024), private_key_file: format === 'npki' ? await file64(data.get('private_key_file'), 2 * 1024 * 1024) : 'unused'};
      await start(form, 'cert.joint.import', input, secrets, job => {
        ui.showDialog('공동인증서 가져오기 결과', `${ui.statusTags(job)}<p>${job.result?.imported ? '암호화 보관함에 가져왔어요. 기관 연결에서 이 인증서를 선택하세요.' : esc(ui.message(job.local?.stopped || 'certificate_import_failed'))}</p>` + button('연결·인증서', 'data-view="settings"', 'primary'));
      });
    } catch (error) { form.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; }); document.querySelector('#certificate-error').textContent = ui.message(error.code || error.message); }
  },
  'certificate-hana': () => stageDialog('', 'init'),
  'certificate-hana-inspect': (ctx, target) => stageDialog(target.dataset.name, 'inspect'),
  'certificate-carrier': async (ctx, select) => {
    const code = select.value;
    const carrier = (await api.get('/certificates/options')).hana.carriers.find(c => c.code === code);
    if (!select.isConnected || select.value !== code) return;
    select.form.dataset.digest = carrier.terms_digest;
    document.querySelector('#certificate-terms').innerHTML = terms(carrier.terms);
    select.form.querySelector('[name="agree"]').checked = false;
  },
  'certificate-id-kind': (ctx, select) => {
    const driver = document.querySelector('#certificate-driver');
    driver.hidden = select.value !== 'driver';
    driver.querySelectorAll('input').forEach(input => { input.disabled = driver.hidden; });
  },
  'certificate-id-source': (ctx, select) => {
    const saved = select.value !== '';
    toggle(document.querySelector('#certificate-id-saved'), saved);
    toggle(document.querySelector('#certificate-id-direct'), !saved);
    if (!saved) certificateActions['certificate-id-kind'](ctx, document.querySelector('[name="kind"]'));
  },
  'certificate-hana-submit': (ctx, form) => submitWizard(form),
  'idcard-add': () => {
    ui.showDialog('신분증 보관', `<form data-submit="idcard-save" autocomplete="off">${note('본인 신분증의 카드 영역 사진과 확인한 정보를 신분증 보관 암호로 암호화해 이 서버에 보관해요. 기관에는 접속하지 않아요. 보관한 신분증은 하나인증서 발급의 신분증 확인 단계에서 골라 써요.')}<div class="certificate-grid">${field('name', '보관할 이름', 'maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}" placeholder="예: resident-card"')}${field('idcard_passphrase', '신분증 보관 암호 (4자 이상)', 'type="password" minlength="4"')}${field('idcard_passphrase_confirmation', '보관 암호 확인', 'type="password" minlength="4"')}</div>${identityFields()}${controls('보관')}</form>`, {wide: true});
  },
  'idcard-save': async (ctx, form) => {
    if (form.dataset.started || !form.reportValidity()) return;
    const data = new FormData(form);
    try {
      if (data.get('idcard_passphrase') !== data.get('idcard_passphrase_confirmation')) throw new Error('passphrase_confirmation_mismatch');
      const secrets = {idcard_passphrase: data.get('idcard_passphrase'), identity_capture: await captureOf(data)};
      await start(form, 'idcard.add', {name: data.get('name')}, secrets, job => {
        ui.showDialog('신분증 보관 결과', `${ui.statusTags(job)}<p>${job.result?.saved ? '신분증을 암호화해 보관했어요. 하나인증서 발급의 신분증 확인 단계에서 골라 쓸 수 있어요.' : esc(ui.message(job.local?.stopped || 'id_card_not_saved'))}</p><div class="dialog-actions">${button('연결·인증서', 'data-view="settings"')}${button('하나인증서 발급', 'data-action="certificate-hana"', 'primary')}</div>`);
      });
    } catch (error) {
      form.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
      document.querySelector('#certificate-error').textContent = ui.message(error.code || error.message);
    }
  },
};
