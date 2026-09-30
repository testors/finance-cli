/* Certificate onboarding. Sensitive files and fields are passed once, never placed in jobs or browser storage. */
import {api, follow} from './api.js';
import * as ui from './ui.js';
import {applyRemember, refreshModel, rememberField, secretFields, state} from './app.js';

const {esc, button, note} = ui;
const REMOTE = new Set(['authenticate', 'request-sms', 'verify-sms', 'begin-id', 'identity', 'account', 'issue', 'complete']);
const STATES = {new: '시작 전', profiled: '휴대폰 정보 확인', authenticated: '앱 인증 완료', sms_sent: 'SMS 확인 대기', eligible: '본인 확인 완료', consented: '가입 약관 동의 완료', id_ready: '신분증 입력·확인 대기', identity_verified: '신분증 확인 완료', account_verified: '본인 계좌 확인 완료', issued: '발급 완료·가입 완료 대기', ready: '가입 완료', halted: '중단됨'};
const TITLES = {profile: '휴대폰 정보·약관', authenticate: '앱 인증', 'request-sms': 'SMS 요청',
  'verify-sms': 'SMS 확인', consent: '가입 약관', 'begin-id': '신분증 확인 시작', 'prepare-id': '신분증 입력',
  identity: '신분증 확인', account: '본인 계좌 확인', issue: '인증서 발급', complete: '가입 완료'};
const IDENTITY_INPUT_ERRORS = new Set(['invalid_identity_capture', 'identity_jpeg_required', 'identity_jpeg_invalid',
  'identity_image_required', 'identity_image_too_large', 'identity_image_dimensions_too_large',
  'identity_name_required', 'identity_date_format', 'identity_date_invalid', 'resident_number_format',
  'driver_number_format', 'identity_not_confirmed']);
const field = (name, label, attrs = '') => `<div class="field"><label for="cert-${name}">${label}</label><input id="cert-${name}" name="${name}" required autocomplete="off" ${attrs}></div>`;
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

async function file64(file, limit) {
  if (!(file instanceof File) || !file.size || file.size > limit) throw new Error('certificate_file_size_not_accepted');
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1]);
    reader.onerror = () => reject(new Error('invalid_certificate_file'));
    reader.readAsDataURL(file);
  });
}

function showProgress(name, job, {rememberFailed = false} = {}) {
  const result = job.result || {};
  const next = result.next_stage;
  const stopped = job.local?.stopped;
  const issued = result.certificate_issued === true;
  const ready = result.ready === true;
  const correctable = job.name === 'hana.onesign.issue.prepare-id' && job.outcome === 'not_started'
    && job.attempt && !job.attempt.sent && IDENTITY_INPUT_ERRORS.has(stopped);
  const text = ready ? '하나인증서 발급과 가입이 완료되었어요. 기관 연결을 추가한 뒤 별도로 로그인하세요.'
    : issued ? '인증서 발급이 확인되었어요. 등록·가입 완료 여부는 아래 상태를 함께 확인하세요.'
    : correctable ? '은행에 신분증을 보내기 전 입력 검사에서 중단됐어요. 아래 오류를 확인하고 신분증 입력 수정에서 사진과 정보를 다시 입력하세요.'
    : stopped || job.outcome === 'unknown' || !next && !ready ? '이 단계가 중단되었거나 결과를 확인하지 못했어요. 다시 전송하지 말고 작업 기록을 확인하세요.'
    : next === 'profile' ? '저장소를 만들었어요. 다음은 휴대폰 정보·약관 입력이에요. 아직 SMS를 요청하지 않았어요.'
    : next === 'authenticate' ? '휴대폰 정보와 약관 동의를 저장했어요. 아직 SMS를 요청하지 않았어요. 아래 앱 인증 계속을 누른 뒤, SMS 요청 단계까지 진행하세요.'
    : next === 'request-sms' ? '앱 인증을 완료했어요. 아직 SMS를 요청하지 않았어요. 아래 SMS 요청 계속을 눌러 실제 통신을 승인하고 SMS를 요청하세요.'
    : next === 'verify-sms' ? 'SMS 요청 절차가 완료되었어요. 휴대폰에 실제로 도착했는지는 확인되지 않았어요. 문자를 받으면 SMS 확인 계속을 눌러 요청 후 180초 안에 인증번호를 입력하세요.'
    : '이 단계의 처리를 완료했어요. 다음 단계는 아래 계속 버튼에서 진행하세요.';
  ui.showDialog('하나인증서 발급 진행', `${note(text)}${rememberFailed ? note('이 단계는 완료했지만 저장소 암호를 기억하지 못했어요. 다음 단계에서 다시 입력하세요.') : ''}${ui.statusTags(job)}${next && !ready ? '<p class="field-help">완료·성공 표시는 방금 실행한 한 단계의 결과예요. 인증서 발급 전체가 끝났다는 뜻은 아니에요.</p>' : ''}
    <p>저장소: <strong>${esc(name)}</strong></p><p class="meta">휴대폰 확인: ${esc(STATES[result.signup_state] || '미확인')} · 발급: ${esc(STATES[result.issuance_state] || '미확인')}</p>
    ${stopped ? `<p class="form-error">${esc(ui.message(stopped))}</p>` : ''}
    <div class="dialog-actions">${button('작업 기록', 'data-view="activity"')}${correctable ? button('신분증 입력 수정', `data-action="certificate-hana-next" data-name="${esc(name)}" data-stage="prepare-id" data-job="${esc(job.id)}"`, 'primary') : next && job.outcome === 'success' ? button(TITLES[next] + ' 계속', `data-action="certificate-hana-next" data-name="${esc(name)}" data-stage="${esc(next)}" data-job="${esc(job.id)}"`, 'primary') : ready ? button('기관 연결 추가', 'data-action="add-login-dialog"', 'primary') : button('닫기', 'data-ui="close"')}</div>`);
}

async function start(form, name, input, secrets, onDone, {rememberStore = null} = {}) {
  if (form.dataset.started) return;
  form.dataset.started = 'true';
  // One key per submitted form. A lost HTTP response never leads to an automatic re-send.
  const idempotency_key = 'web-' + crypto.randomUUID();
  try {
    const job = await api.post('/jobs', {name, input, secrets, idempotency_key});
    form.reset();
    ui.showDialog('인증서 작업 진행', '<p>서버에서 처리하고 있어요. 창을 닫아도 작업은 계속되며 다시 전송하지 않아요.</p><div id="certificate-progress"></div>' + button('작업 기록', 'data-view="activity"'));
    const holder = document.querySelector('#certificate-progress');
    const final = await follow(job.id, value => { if (holder.isConnected) holder.innerHTML = ui.statusTags(value); });
    let rememberFailed = false;
    if (rememberStore && final.result?.created === true) {
      try { await applyRemember({vault_passphrase: secrets.vault_passphrase, remember_vault: 'on'}, rememberStore); }
      catch (error) { rememberFailed = true; } // Keep the completed job's result visible.
    }
    secrets = null;
    await refreshModel();
    state.credentials = (await api.get('/credentials')).credentials;
    if (holder.isConnected) await onDone(final, {rememberFailed});
  } catch (error) {
    // Even a transport error may follow an accepted job. Show history instead of offering a retry.
    form.reset();
    const target = document.querySelector('#certificate-error');
    if (target) target.textContent = ui.message(error.code || error.message) + ' 작업 기록을 확인하세요. 자동 재전송하지 않아요.';
    ui.toast('인증서 작업을 확인하세요. 작업 기록에서 진행 상태를 볼 수 있어요.');
  } finally { secrets = null; }
}

async function stageDialog(name, stage, progress = {}) {
  const [options, vaults] = await Promise.all([api.get('/certificates/options'), api.get('/vaults')]);
  state.vaults = Object.fromEntries(vaults.vaults.map(v => [v.name, v.unlocked]));
  let fields = '';
  let digest = progress.terms_digest || '';
  if (stage === 'profile') {
    const carriers = options.hana.carriers;
    digest = carriers[0].terms_digest;
    fields = note('휴대폰 정보와 약관 동의를 저장하는 단계예요. 저장한 뒤 앱 인증 → SMS 요청을 진행해야 문자를 요청해요.') + field('customer_name', '이름', 'maxlength="60"') + field('birth7', '생년월일 6자리 + 주민번호 뒤 첫 자리', 'type="password" inputmode="numeric" pattern="[0-9]{6}[1-4]" maxlength="7"')
      + field('phone', '본인 휴대폰 번호', 'type="tel" pattern="0[0-9]{9,10}" maxlength="11"')
      + `<div class="field"><label for="cert-carrier">통신사</label><select id="cert-carrier" name="carrier" data-change="certificate-carrier">${carriers.map(c => `<option value="${esc(c.code)}">${esc(c.name)}</option>`).join('')}</select></div><div id="certificate-terms">${terms(carriers[0].terms)}</div>` + agree();
  } else if (stage === 'verify-sms') fields = note('SMS 요청 후 180초 안에 확인하세요. 시간 초과나 중단 후 자동 재요청하지 않아요.') + field('sms', 'SMS 인증번호', 'type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"');
  else if (stage === 'consent') fields = note('선택 상품은 신청하지 않아요. 마케팅 동의는 기존 동의를 유지하거나 미동의로 처리해요.') + terms(progress.terms || []) + agree();
  else if (stage === 'prepare-id') fields = note('본인의 마스킹하지 않은 신분증 카드 영역 JPEG를 선택하세요(8 MiB 이하). 사진의 회전 정보를 반영하고, 가로 1024픽셀을 넘으면 비율을 유지해 자동 축소해요. 원본 파일은 바꾸지 않으며, 입력과 처리한 사진은 암호화 저장소에만 보관해요.')
    + '<div class="field"><label for="cert-id-kind">신분증 종류</label><select id="cert-id-kind" name="kind" data-change="certificate-id-kind"><option value="resident">주민등록증</option><option value="driver">운전면허증</option></select></div>'
    + field('image', '신분증 JPEG', 'type="file" accept="image/jpeg"') + field('id_name', '신분증 이름', 'maxlength="60"')
    + field('issueDate', '발급일 (YYYY.MM.DD)', 'pattern="[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}" maxlength="10"')
    + field('birthDate', '주민번호 앞 6자리', 'type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"')
    + field('resident', '주민번호 뒤 7자리', 'type="password" inputmode="numeric" pattern="[0-9]{7}" maxlength="7"')
    + '<div id="certificate-driver" hidden>' + ['regionCode', 'driver1', 'driver2', 'driver3'].map((key, i) => field(key, ['면허번호 지역 2자리', '면허번호 두 번째 구간 2자리', '면허번호 세 번째 구간 6자리', '면허번호 네 번째 구간 2자리'][i], `type="password" inputmode="numeric" pattern="[0-9]{${i === 2 ? 6 : 2}}" disabled`)).join('') + '</div>'
    + field('identity_confirmation', '확인을 위해 “본인 신분증” 입력', 'pattern="본인 신분증"');
  else if (stage === 'account') fields = note('본인 하나은행 계좌번호를 입력하세요. 은행이 반환한 본인 계좌 목록에 포함된 경우에만 확인합니다.')
    + field('account_number', '본인 계좌번호', 'inputmode="numeric" pattern="[0-9]{8,20}" maxlength="20"')
    + field('account_password', '계좌 비밀번호', 'type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4"');
  else if (stage === 'issue') fields = note('아래 확인을 마치면 하나인증서를 실제로 새로 발급합니다. PIN은 저장소 암호와 별개예요. 이미 시도한 발급은 다시 보내지 않아요.')
    + field('new_pin', '새 하나인증서 PIN', 'type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"')
    + field('new_pin_confirmation', '새 PIN 확인', 'type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"')
    + field('issue_confirmation', '확인을 위해 “발급” 입력', 'pattern="발급"');
  else if (stage === 'inspect') fields = note('저장된 상태만 확인해요. 기관에는 접속하지 않아요. 중단된 단계를 재실행하지 않아요.');
  else if (stage === 'authenticate') fields = note('은행 앱 인증을 진행해요. 이 단계가 완료되면 SMS 요청을 별도로 진행해야 해요.');
  else if (stage === 'request-sms') fields = note('실제 기관 통신을 승인하고 SMS 요청을 누르면, 저장한 휴대폰 정보로 인증문자를 요청해요. 받은 인증번호는 다음 SMS 확인 단계에서 입력하세요.');
  else fields = note('이 단계의 요청만 한 번 전송해요. 다음 단계는 별도로 승인하며 로그인·이체는 실행하지 않아요.');
  ui.showDialog('하나인증서 · ' + (TITLES[stage] || '발급 상태 확인'), `<form data-submit="certificate-hana-submit" data-name="${esc(name)}" data-stage="${esc(stage)}" data-digest="${esc(digest)}" autocomplete="off"><p class="meta">${esc(name)} · 실서버 미검증</p>${vaultFields(name)}${fields}${REMOTE.has(stage) ? '<label class="check"><input type="checkbox" name="send" required> 이 단계의 실제 기관 통신을 승인합니다</label>' : '<p class="field-help">이 단계에서는 기관에 접속하지 않아요.</p>'}${controls(({profile: '휴대폰 정보·동의 저장', authenticate: '앱 인증 실행', 'request-sms': 'SMS 요청', 'verify-sms': 'SMS 확인', issue: '하나인증서 발급', inspect: '상태 확인'})[stage] || '이 단계 실행')}</form>`, {wide: stage === 'prepare-id' || stage === 'profile' || stage === 'consent'});
}

export const certificateActions = {
  'certificate-add': async () => {
    ui.showDialog('인증서 발급·가져오기', `<div class="settings-body"><div class="setting-row"><span><strong>공동인증서</strong><span class="meta">신규 발급은 미지원이에요. 발급기관에서 받은 NPKI/PFX를 가져올 수 있어요.</span></span>${button('가져오기', 'data-action="certificate-joint"')}</div><div class="setting-row"><span><strong>금융인증서</strong><span class="meta">신규 발급·클라우드 연결은 아직 미지원이에요.</span></span>${ui.tag('미지원', 'neutral')}</div><div class="setting-row"><span><strong>하나인증서</strong><span class="meta">국내 성인 기존 하나은행 고객 · SMS·신분증·본인 계좌 확인 · 실서버 미검증</span></span>${button('신규 발급·진행 확인', 'data-action="certificate-hana"', 'primary')}</div></div><p class="dialog-note">인증서 비밀과 파일은 브라우저 저장소·작업 기록에 남기지 않아요. 기관 로그인은 발급·가져오기 후 별도로 추가하세요.</p>`);
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
  'certificate-hana': async () => {
    const options = await api.get('/certificates/options');
    state.credentials = (await api.get('/credentials')).credentials;
    const stores = state.credentials.filter(c => c.type === 'onesign');
    ui.showDialog('하나인증서 신규 발급', `${note('지원 버전 1.0.27의 서비스 설정을 서버에서 먼저 추출·구성해야 해요. 설정 추출은 fin hana setup extract / configure를 사용하세요. 공동·금융인증서를 발급하는 기능과는 별개입니다.')}<form data-submit="certificate-hana-init" autocomplete="off">${nameField()}<div class="field"><label for="cert-settings">서버에 준비한 서비스 설정</label><select id="cert-settings" name="settings" required>${options.hana.settings.map(row => `<option value="${esc(row.name)}">${esc(row.name)} · ${esc(row.version)}</option>`).join('')}</select>${!options.hana.settings.length ? '<p class="field-help">준비된 설정이 없어요. 서버에서 설정을 먼저 구성하세요.</p>' : ''}</div>${vaultFields()}${controls('새 저장소 만들기')}</form>${stores.length ? '<hr><h3>기존 저장소의 발급 진행 확인</h3>' + stores.map(c => button(c.ref, `data-action="certificate-hana-inspect" data-name="${esc(c.ref)}"`)).join(' ') : ''}`);
    if (!options.hana.settings.length) document.querySelector('[data-submit="certificate-hana-init"] button[type="submit"]').disabled = true;
  },
  'certificate-hana-init': async (ctx, form) => {
    if (form.dataset.started) return;
    const data = new FormData(form), name = data.get('name');
    await start(form, 'hana.onesign.issue.init', {name, settings: data.get('settings')}, {vault_passphrase: data.get('vault_passphrase')}, (job, options) => showProgress(name, job, options), {rememberStore: data.get('remember_vault') === 'on' ? name : null});
  },
  'certificate-hana-inspect': (ctx, target) => stageDialog(target.dataset.name, 'inspect'),
  'certificate-hana-next': async (ctx, target) => {
    const job = await api.get('/jobs/' + encodeURIComponent(target.dataset.job));
    await stageDialog(target.dataset.name, target.dataset.stage, job.result || {});
  },
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
  'certificate-hana-submit': async (ctx, form) => {
    if (form.dataset.started) return;
    const data = new FormData(form), stage = form.dataset.stage, name = form.dataset.name;
    const secrets = data.has('vault_passphrase') ? {vault_passphrase: data.get('vault_passphrase')} : {};
    try {
      if (REMOTE.has(stage) && data.get('send') !== 'on') throw new Error('send_approval_required');
      if (stage === 'profile') {
        secrets.phone_profile = JSON.stringify({name: data.get('customer_name'), birth7: data.get('birth7'), phone: data.get('phone'), carrier: data.get('carrier')});
        secrets.agreement = data.get('agree') ? form.dataset.digest : '';
      } else if (stage === 'consent') secrets.agreement = data.get('agree') ? form.dataset.digest : '';
      else if (stage === 'prepare-id') {
        const kind = data.get('kind');
        const fields = {name: data.get('id_name'), issueDate: data.get('issueDate'), birthDate: data.get('birthDate'), resident: data.get('resident')};
        if (kind === 'driver') for (const key of ['regionCode', 'driver1', 'driver2', 'driver3']) fields[key] = data.get(key);
        secrets.identity_capture = JSON.stringify({kind, fields, image: await file64(data.get('image'), 8 * 1024 * 1024), confirmation: data.get('identity_confirmation')});
      } else for (const key of stage === 'verify-sms' ? ['sms'] : stage === 'account' ? ['account_number', 'account_password'] : stage === 'issue' ? ['new_pin', 'new_pin_confirmation', 'issue_confirmation'] : []) secrets[key] = data.get(key);
      secrets.remember_vault = data.get('remember_vault');
      await applyRemember(secrets, name);
      await start(form, 'hana.onesign.issue.' + stage, {name, ...(REMOTE.has(stage) ? {send: data.get('send') === 'on'} : {})}, secrets, job => showProgress(name, job));
    } catch (error) { form.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; }); document.querySelector('#certificate-error').textContent = ui.message(error.code || error.message); }
  },
};
