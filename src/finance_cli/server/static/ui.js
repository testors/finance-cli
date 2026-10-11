/* Shared rendering helpers. Every value from the API is escaped before use. */
const paths = {
  tax: '<path d="M4 7h16L12 2 4 7Zm2 3v8m6-8v8m6-8v8M3 21h18"/>',
  bill: '<path d="M6 3h12v18l-3-2-3 2-3-2-3 2V3Zm3 5h6m-6 4h6m-6 4h3"/>',
  invoice: '<path d="M5 3h10l4 4v14H5V3Zm10 0v5h4M8 12h8m-8 4h5"/>',
  report: '<path d="M5 3h14v18H5V3Zm4 4h6m-6 4h6m-6 4h6m-6 3h3"/>',
  business: '<path d="M4 21V3h12v18M8 7h4m-4 4h4m-4 4h4m4-7h4v13M2 21h20"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 3v4m10-4v4M3 10h18m-14 4h3m4 0h3"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v1"/>',
  chevrons: '<path d="m9 8 3-3 3 3m-6 8 3 3 3-3"/>',
  accounts: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M3 9h18m-5 5h2"/>',
  history: '<path d="M8 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-3M8 3v5h8V3H8Zm0 10h6m-6 4h9m1-9 3-3m-3 0h3v3"/>',
  transfer: '<path d="M4 7h15m-4-4 4 4-4 4M20 17H5m4-4-4 4 4 4"/>',
  activity: '<path d="M12 8v5l3 2M3 11a9 9 0 1 1 2 7M3 5v6h6"/>',
  arrow: '<path d="m9 5 7 7-7 7"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 2M18 18a8 8 0 0 1-13-2"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5M4 21h16"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  more: '<circle cx="5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="19" cy="12" r="1.6"/>',
};

export const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.accounts}</svg>`;
export const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
export const money = value => typeof value === 'number' && Number.isFinite(value) ? new Intl.NumberFormat('ko-KR').format(value) : esc(value ?? '—');

// Limit amounts are won, including numeric strings. Avoid rounding large strings
// through Number, and keep missing/malformed values distinct from a zero limit.
function limitAmount(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  if (typeof value !== 'string' || !/^(?:\d+|\d{1,3}(?:,\d{3})+)$/.test(value)) return null;
  return BigInt(value.replaceAll(',', ''));
}

function limitMoney(value) {
  const amount = limitAmount(value);
  if (amount === null) return '<strong>확인 안 됨</strong>';
  const exact = amount.toLocaleString('ko-KR') + '원';
  if (amount < 10000n || amount >= 100000000000000000000n) return `<strong>${exact}</strong>`;
  const parts = [];
  let rest = amount;
  for (const unit of ['', '만', '억', '조', '경']) {
    const part = rest % 10000n;
    if (part) parts.unshift(part.toLocaleString('ko-KR') + unit);
    rest /= 10000n;
  }
  return `<strong>${parts.join(' ')} 원</strong><small>${exact}</small>`;
}

export function transferLimits(observation) {
  const fields = observation.fields || {}, display = observation.display || {};
  // The protocol's fallback is OTP even when the medium is missing. Only label
  // a medium here when supported by the bank fields, not by that fallback.
  const medium = fields.scrtMdclDvCd === '1' ? 'card' : fields.mbphOtpYn === 'Y' ? 'mobile'
    : fields.scrtMdclDvCd === '2' && fields.mbphOtpYn === 'N' ? 'otp' : null;
  const mediumName = {card: '보안카드(자물쇠카드)', mobile: '모바일 OTP', otp: 'OTP'}[medium] || '확인 안 됨';
  const limits = [['1회 이체한도', fields.bot1TrnsLimAmt, display.once_ceiling_text],
    ['1일 이체한도', fields.dd1TrnsLimAmt, display.daily_ceiling_text]];
  const hasReference = medium && display.medium === medium;
  const exceedsReference = hasReference && limits.some(([, current, ceiling]) => {
    const amount = limitAmount(current), maximum = limitAmount(ceiling);
    return amount !== null && maximum !== null && amount > maximum;
  });
  const cards = index => `<dl class="limit-grid">${limits.map(row => `<div><dt>${row[0]}</dt><dd>${limitMoney(row[index])}</dd></div>`).join('')}</dl>`;
  return `<div class="limit-result">
    <div class="limit-heading"><h2>은행에서 조회한 이체한도</h2>${tag('보안매체 · ' + mediumName, medium ? '' : 'neutral')}</div>
    ${cards(1)}
    ${exceedsReference ? note('은행 조회값이 보안매체별 안내 한도보다 커요. 실제 이체 가능한 금액은 이 조회만으로 확정할 수 없어요.') : ''}
    ${fields.trnsLimRslt === 'true' ? note('이체한도 예외신청 안내가 있어요. 보안카드는 1회·1일 최대 1,000만 원이며, 예외신청을 하면 신청일에 한해 원래 지정한 한도로 이용할 수 있다는 은행 안내예요. 예외신청이 완료되었다는 뜻은 아니에요.') : ''}
    ${hasReference ? `<section class="limit-reference"><h3>보안매체별 안내 한도</h3><p>내 한도 조회값과 별도로 제공되는 ${esc(mediumName)}의 기본 안내예요.</p>${cards(2)}</section>` : ''}
  </div>`;
}

/* The local idle limit of a login's session in words; the server sends it per institution. */
export function idleLimit(row) {
  const seconds = row?.session?.idle_seconds || 600;
  return `${Math.floor(seconds / 60)}분${seconds % 60 ? ` ${seconds % 60}초` : ''}`;
}

export function time(value) {
  if (!value) return '—';
  const date = new Date(value * 1000);
  return date.toLocaleString('ko-KR', {month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false});
}

// Institution dates follow Korea time even before 09:00 KST or from an overseas browser.
export const kstDate = (daysAgo = 0) => new Date(Date.now() + 9 * 3600000 - daysAgo * 86400000).toISOString().slice(0, 10);

/* Quick period buttons for a form whose first two date inputs are its start and end. */
export function periodPresets(options) {
  return `<div class="period-presets" role="group" aria-label="기간 빠른 선택">${options.map(([text, days]) => `<button type="button" data-action="period" data-days="${days}">${esc(text)}</button>`).join('')}</div>`;
}

export function heading(title, sub, actions = '') {
  return `<div class="page-heading"><div><h1>${esc(title)}</h1><p>${sub}</p></div><div class="heading-actions">${actions}</div></div>`;
}

/* An on/off choice that takes effect at once. */
export function switchButton(label, on, attributes, hint = '') {
  return `<button type="button" class="switch ${on ? 'on' : ''}" role="switch" aria-checked="${on ? 'true' : 'false'}" ${hint ? `title="${esc(hint)}"` : ''} ${attributes}><span class="switch-track" aria-hidden="true"><i></i></span>${esc(label)}</button>`;
}

export function tag(text, tone = '') { return `<span class="status-pill ${tone}">${esc(text)}</span>`; }
export function note(text) { return `<div class="scope-note">${icon('info')}<p>${text}</p></div>`; }
/* Work in progress said inside a screen or dialog, with the same mark as the held screen. */
export function working(text) {
  return `<span class="working"><span class="spinner" aria-hidden="true"></span>${esc(text)}</span>`;
}

export function button(label, attributes, kind = 'secondary', iconName = '') {
  return `<button type="button" class="button ${kind}" ${attributes}>${iconName ? icon(iconName) : ''}${esc(label)}</button>`;
}

export const STATUS = {queued: ['대기 중', 'neutral'], running: ['실행 중', 'info'], awaiting_input: ['확인 대기', 'warning'],
  finished: ['완료', ''], cancelled: ['취소됨', 'neutral'], expired: ['만료됨', 'neutral']};
export const OUTCOME = {not_started: ['시작 안 함', 'neutral'], success: ['성공', ''], partial_success: ['부분 성공', 'warning'],
  rejected: ['기관 거절', 'danger'], unknown: ['결과 미확인', 'warning']};
export const VERIFICATION = {live_untested: ['실서버 미검증', 'untested'], live_verified: ['실사용 확인', ''],
  live_partial: ['일부 실사용 확인', 'warning'], offline: ['오프라인 처리', 'neutral']};
export const ORIGIN = {web: '웹', cli: 'CLI', agent: '에이전트'};

/* Giro answers a bill query that has nothing billed with “고지내용 없음” on its failure path. The
   summary says that instead of "기관 거절"; the recorded verdict and outcome stay as received. */
const noBills = job => ['giro.bills.list', 'giro.bills.search', 'giro.bills.detail'].includes(job.name)
  && Boolean(job.service_verdict?.no_bills_reported ?? job.result?.no_bills_reported);

export function outcomeLabel(job) {
  return noBills(job) ? ['고지 없음', 'neutral'] : OUTCOME[job.outcome] || [job.outcome, 'neutral'];
}

export function statusTags(job) {
  if (job.name?.startsWith('cli.')) {
    // Whether the run carried the transmission approval; older records do not say.
    const sent = job.local?.send_requested;
    const approval = sent === true ? tag('전송 승인(--send)', 'info') : sent === false ? tag('전송 승인 없음', 'neutral') : '';
    return `<span class="pill-row">${tag('CLI 실행 기록', 'neutral')}${approval}${tag('종료코드 ' + (job.local?.exit_code ?? '—'), 'neutral')}</span>`;
  }
  const [status, tone] = STATUS[job.status] || [job.status, 'neutral'];
  const [outcome, outcomeTone] = outcomeLabel(job);
  // The service verdict of a finished job says more than "완료"; a verdict seen while running keeps both.
  const html = job.status === 'finished' ? tag(outcome, outcomeTone)
    : tag(status, tone) + (job.status === 'running' && job.outcome !== 'not_started' ? tag(outcome, outcomeTone) : '');
  return `<span class="pill-row">${html}</span>`;
}

export function verification(level) {
  const [label, tone] = VERIFICATION[level] || [];
  return label ? tag(label, tone) : '';
}

const MESSAGES = {
  giro_device_registration_required: '서버에서 지로 기기를 먼저 등록해야 해요. fin giro auth register --send로 등록한 기기를 그대로 사용해요.',
  giro_invalid_login_pin: '지로 로그인 간편비밀번호 6자리를 입력하세요.',
  recipient_public_lookup_failed: '지로 서버 인증서·폐지목록을 조회하지 못해 PIN 인증 전에 중단했어요. 서버의 공개 인증서 조회 연결을 확인하세요.',
  recipient_validation_failed: '지로 서버 인증서·폐지목록 검증을 통과하지 못해 PIN 인증 전에 중단했어요. 공개 인증서 자료의 유효성을 확인하세요.',
  recipient_validation_incomplete: '지로 서버 인증서·폐지목록 검증을 완료하지 못해 PIN 인증 전에 중단했어요. 서버의 공개 인증서 자료와 조회 설정을 확인하세요.',
  giro_preparation_changed: '로그인 세션이나 확인 내역이 바뀌었어요. 납부를 전송하지 않았어요. 고지를 다시 조회하세요.',
  giro_preparation_expired: '납부 준비 시간이 지났어요. 고지를 다시 조회해 납부 내용을 확인하세요.',
  giro_payment_auth_unsupported: '이 고지는 인증서 또는 FIDO 추가 인증이 필요해요. 이 인증 방식은 아직 지원하지 않아요.',
  giro_preparation_stopped: '기관 응답으로 납부 준비를 중단했어요. 작업 상세에서 응답을 확인하세요.',
  giro_operation_stopped: '지로 작업을 계속할 수 없어요. 로그인 상태와 납부 기록을 확인하세요. 자동 재시도하지 않아요.',
  giro_parent_required: '지로 조회 결과에서 항목을 선택하세요.',
  giro_parent_not_successful: '확인된 조회 결과에서 항목을 선택하세요.',
  giro_item_not_found: '조회 결과에서 선택한 항목을 찾지 못했어요.',

  issuance_account_not_in_response: '입력한 계좌가 은행의 발급용 본인계좌 목록에 없어요. 새 발급에서는 목록에서 계좌를 선택하세요.',
  issuance_account_selection_invalid: '은행이 제공한 목록에서 인증할 본인 계좌를 선택하세요.',
  network_unreachable: '서버에 연결할 수 없어요. 네트워크와 서버 상태를 확인하세요.',
  access_required: '이 브라우저의 접속이 만료되었거나 철회되었어요. 다시 등록하세요.',
  csrf_token_invalid: '보안 확인이 만료되었어요. 화면을 새로 고치세요.',
  enrollment_code_invalid: '등록 코드가 맞지 않거나 만료되었어요.',
  enrollment_rate_limited: '등록 시도가 너무 많아요. 잠시 후 서버에서 새 코드를 만들어 입력하세요.',
  resource_busy: '같은 기관 자원을 쓰는 다른 작업이 실행 중이에요. 입력한 비밀번호는 전달하지 않았어요. 잠시 후 다시 시도하세요.',
  worker_not_started: '작업을 시작하지 못했어요. 입력한 비밀번호는 전달하지 않았어요.',
  login_required: '기관 로그인이 필요해요. 연결·인증서 화면에서 로그인하세요.',
  session_stale: '설정이 바뀌었거나 세션 저장을 확인하지 못했어요. 세션을 확인하거나 다시 로그인하세요.',
  session_expired: '기관 세션이 만료되었어요. 다시 로그인하세요.',
  session_idle_expired: '마지막 요청 후 유휴 제한(지로 4분 50초, 하나은행 9분 50초, 하나기업 10분, 홈택스 29분 50초)이 지나 로그아웃 처리됐어요. 요청을 보내지 않았어요. 다시 로그인한 뒤 필요한 작업을 직접 실행하세요.',
  session_consumed: '이 로그인 세션은 이미 사용했어요. 새로 로그인하세요.',
  target_required: '업무 대상을 선택하세요.',
  target_unverified: '기관 응답에서 선택한 대상을 확인하지 못해 업무를 실행하지 않았어요.',
  signing_not_configured: '이 업무에 쓸 서명 수단이 지정되지 않았어요.',
  capability_unavailable: '이 기능은 지금 사용할 수 없어요. 전체 기능·지원 상태를 확인하세요.',
  job_expired: '확인 기한이 지났어요. 새로 준비하세요.',
  login_revision_changed: '로그인 설정이 바뀌어 새로 준비해야 해요.',
  confirmation_mismatch: '확인한 내용과 준비된 내용이 달라요. 화면을 새로 고치세요.',
  step_secrets_required: '필요한 비밀번호 입력이 빠졌어요.',
  incorrect_password_or_damaged_credential: '인증서 비밀번호가 맞지 않아요. 기관에 요청하지 않았어요.',
  store_authentication_failed: '하나인증서 저장소 암호가 맞지 않아요. 은행에 요청하지 않았어요.',
  pin_six_digits_required: 'PIN 6자리를 입력하세요. 은행에 요청하지 않았어요.',
  new_pin_confirmation_mismatch: '새 PIN과 PIN 확인이 달라요. 같은 번호를 입력하세요.',
  account_password_four_digits_required: '계좌 비밀번호 4자리를 입력하세요.',
  invalid_identity_capture: '신분증 입력 구성을 확인하지 못했어요. 기존 저장소의 발급 상태를 확인한 뒤 신분증 입력을 다시 여세요.',
  identity_jpeg_required: '신분증 사진은 JPEG(.jpg·.jpeg) 파일이어야 해요. 확장자만 바꾸지 말고 JPEG로 저장해 선택하세요.',
  identity_jpeg_invalid: '신분증 JPEG 사진을 읽을 수 없어요. 손상되지 않은 JPEG 파일을 선택하세요.',
  identity_image_required: '신분증 사진 파일을 선택하세요.',
  identity_image_too_large: '신분증 사진 용량은 8 MiB 이하여야 해요.',
  identity_image_dimensions_too_large: '신분증 사진의 해상도가 너무 커서 읽을 수 없어요. 사진 크기를 줄여 선택하세요.',
  identity_name_required: '신분증에 적힌 이름을 입력하세요.',
  identity_date_format: '신분증 발급일을 YYYY.MM.DD 형식으로 입력하세요.',
  identity_date_invalid: '신분증 발급일이 실제 달력에 있는 날짜인지 확인하세요.',
  resident_number_format: '주민번호 앞 6자리와 뒤 7자리를 숫자로 입력하세요.',
  driver_number_format: '운전면허번호를 지역 2자리·다음 2자리·다음 6자리·마지막 2자리로 나누어 숫자만 입력하세요.',
  identity_not_confirmed: '본인 신분증임을 확인하려면 “본인 신분증”을 그대로 입력하세요.',
  identity_name_invalid: '신분증 이름은 100자 이하로, 줄바꿈 없이 입력하세요.',
  id_card_not_found: '보관함에 없는 신분증이에요. 화면을 새로 고치세요.',
  id_card_name_exists: '같은 이름으로 보관한 신분증이 이미 있어요.',
  id_card_name_unchanged: '지금과 같은 이름이에요.',
  incorrect_passphrase_or_damaged_id_card: '신분증 보관 암호가 맞지 않거나 보관 파일이 손상됐어요. 은행에 신분증을 보내지 않았어요.',
  id_card_not_saved: '신분증을 보관하지 못했어요. 입력을 확인하세요.',
  passphrase_minimum_4_characters: '암호는 4자 이상이어야 해요.',
  passphrase_confirmation_mismatch: '보관 암호와 확인 입력이 달라요.',
  fixed_session_not_usable: '작업을 접수한 뒤 세션이 바뀌어 실행하지 않았어요. 다시 조회하세요.',
  prepared_session_superseded: '초안 이후 다른 작업이 세션을 바꿨어요. 초안을 새로 만드세요.',
  hometax_runtime_not_installed: '홈택스 실행 환경이 설치되지 않았어요. 서버에서 fin runtime install hometax를 실행하세요.',
  node_not_found: '서버에 Node가 없어요.',
  jdk_17_or_later_required: '계산서 서명에 필요한 JDK 17 이상이 서버에 없어요.',
  registration_required: '기기·앱 등록 정보가 필요해요. 서버에서 fin server registration으로 연결하세요.',
  'registration_required:app_profile,login_input': '앱 프로필 파일과 로그인 입력 파일을 서버에서 fin server registration으로 연결하세요.',
  login_method_not_supported_by_job: '이 로그인 방식에서는 쓸 수 없는 업무예요.',
  accounts_query_required_in_session: '현재 로그인에서 조회한 계좌 정보를 읽을 수 없어요. 다시 로그인한 뒤 조회해 주세요.',
  accounts_query_incomplete: '계좌 확인을 완료하지 못해 내역 조회를 중단했어요. 계좌 확인 결과를 확인해 주세요.',
  account_not_in_session_accounts: '현재 로그인에서 확인된 계좌 목록에 선택한 계좌가 없어요. 로그인과 선택한 계좌를 확인해 주세요.',
  invalid_history_controls: '조회 기간이나 검색어를 확인해 주세요. 미래 날짜는 조회할 수 없으며, 거래 내역은 3년 미만, 이체 내역은 최근 2년 이내로 조회할 수 있어요.',
  continuation_cursor_requires_review: '은행 응답의 다음 페이지 정보를 확인할 수 없어 이어서 조회하지 않았어요. 받은 내역까지만 보여줘요.',
  history_processing_error: '거래 내역을 처리하다가 멈췄어요. 받은 내역까지만 보여주며 은행에 다시 요청하지 않았어요.',
  job_not_cancellable: '이미 시작한 작업은 취소할 수 없어요.',
  credential_in_use: '이 인증서를 쓰는 연결이 있어요. 먼저 그 연결의 인증서를 바꾸세요.',
  credential_not_found: '보관함에 없는 인증서예요. 화면을 새로 고치세요.',
  onesign_identity_not_found: '하나인증서 저장소를 찾지 못했어요. 화면을 새로 고치세요.',
  removal_confirmation_mismatch: '확인용으로 입력한 이름이 달라요.',
  credential_name_exists: '같은 이름의 인증서가 이미 있어요.',
  credential_name_unchanged: '지금과 같은 이름이에요.',
  invalid_name: '이름은 영문·숫자로 시작하고 영문·숫자·_ . -만 쓸 수 있어요(최대 64자).',
  login_has_active_jobs: '이 연결로 실행 중이거나 대기 중인 작업이 있어요. 끝난 뒤 다시 시도하세요.',
  revision_conflict: '다른 곳에서 설정이 바뀌었어요. 새로 불러온 뒤 다시 저장하세요.',
  idempotency_key_conflict: '같은 요청 키로 다른 내용이 접수되었어요.',
  candidate_not_found: '확인 작업 결과에 없는 대상이에요.',
  local_processing_error: '서버 처리 중 오류가 있었어요. 관측한 기관 판정은 보존했어요.',
  screen_processing_error: '화면에서 처리하지 못했어요. 이미 보낸 요청은 다시 보내지 않았어요. 전체 작업 기록에서 결과를 확인하세요.',
  session_not_saved: '세션 저장을 확인하지 못해 다음 단계를 진행하지 않았어요.',
  transfer_confirmation_required: '확인한 이체 내용과 달라 실행하지 않았어요.',
};

export function message(code) {
  if (!code) return '';
  return MESSAGES[code] || MESSAGES[String(code).split(':')[0]] || `처리하지 못했어요 (${esc(code)})`;
}

const dialog = () => document.querySelector('#detail-dialog');

export function showDialog(title, body, {wide = false} = {}) {
  const target = dialog();
  target.classList.toggle('wide', wide);
  document.querySelector('#dialog-content').innerHTML = `<div class="dialog-header"><h2 id="dialog-title">${esc(title)}</h2><button class="icon-button" data-ui="close" aria-label="닫기">${icon('close')}</button></div><div class="dialog-body">${body}</div>`;
  if (!target.open) target.showModal();
  target.querySelector('input,select,textarea,button:not([data-ui="close"])')?.focus();
}

export function closeDialog() {
  const target = dialog();
  target.querySelector('form')?.reset();
  if (target.open) target.close();
  document.querySelector('#dialog-content').innerHTML = '';
}

let toastTimer, toastGone;
export function toast(text) {
  const target = document.querySelector('#toast');
  clearTimeout(toastTimer);
  clearTimeout(toastGone);
  // A modal dialog is drawn above the page. Shown again as a popover, the toast joins that top
  // layer above whatever is open now; without popover support it stays on the page as before.
  const layered = target.popover === 'manual' && typeof target.showPopover === 'function';
  if (layered) {
    if (target.matches(':popover-open')) target.hidePopover();
    target.showPopover();
    void target.offsetWidth; // the fade starts from the hidden state
  }
  target.textContent = text;
  target.classList.add('show');
  toastTimer = setTimeout(() => {
    target.classList.remove('show');
    if (layered) toastGone = setTimeout(() => { if (target.matches(':popover-open')) target.hidePopover(); }, 250);
  }, Math.min(10000, 3500 + String(text).length * 70));
}

/* An error stays where the user is looking: in the open dialog, else at the top of the
   screen until it is drawn again. The toast still announces it. */
export function fail(text) {
  toast(text);
  const box = dialog();
  const node = document.createElement(box?.open ? 'p' : 'div');
  node.setAttribute('role', 'alert');
  if (box?.open) {
    const slot = box.querySelector('.form-error');
    if (slot) { slot.textContent = text; return; }
    node.className = 'form-error';
    node.textContent = text;
    const actions = box.querySelector('.dialog-actions');
    if (actions) actions.before(node); else box.querySelector('.dialog-body')?.append(node);
    return;
  }
  const main = document.querySelector('#main');
  if (!main) return;
  main.querySelector('.page-error')?.remove();
  node.className = 'scope-note page-error';
  node.innerHTML = icon('info') + '<p></p>';
  node.querySelector('p').textContent = text;
  const heading = main.querySelector('.page-heading');
  if (heading) heading.after(node); else main.prepend(node);
}

export function json(value) {
  return `<pre>${esc(JSON.stringify(value, null, 2))}</pre>`;
}

export function details(summary, value) {
  if (value === null || value === undefined || (typeof value === 'object' && !Object.keys(value).length)) return '';
  return `<details class="verdict"><summary>${esc(summary)}</summary>${json(value)}</details>`;
}

/* Korean names for institution fields, each one the name the institution's own screens give
   that field. A name that is not listed stays exactly as the institution sent it; nothing
   here guesses the meaning of an unknown field. */
export const FIELD_LABELS = {
  // Hometax dues and payments, and the parts of an electronic payment number.
  itrfNm: '세목', itrfCdNm: '세목', itrfCd: '세목 코드', itrfYm: '세목년월', pmtDdt: '납부기한', romAmt: '납부할 세액',
  romDt: '납부일자', romFnnOrgnNm: '수납점포', txhfOgzNm: '관서명', txhfOgzCd: '관서코드', txtnClNm: '과세구분', attrYr: '귀속연도',
  bankElctPmtPblNo: '전자납부번호', bankElctPmtNo: '전자납부번호', elctPmtNo: '전자납부번호', elctPmtPblNo: '전자납부발행번호',
  dcsClCd: '결정구분', impsTrgtTin: '부과대상 TIN', pmtDutyTin: '납부의무 TIN', txprFnm: '성명(상호)', txprClsfCd: '납세자분류코드',
  tmsnDtm: '전송일시', cardPmtCnclFeeCnfrYn: '카드납부취소수수료확인여부',
  // Hometax refunds.
  rfndDcsDfntDt: '환급일자', rfamtPymnAmt: '환급금액', bokTrtRsltCd: '지급구분', pymnDt: '지급일', bankNm: '은행',
  accnoEncCntn: '계좌번호', attrYm: '귀속년월', rmtnBrkdId: '송금내역ID', rmtnBrkdImpsTrgtTin: '송금내역의 부과대상TIN',
  icmAmsDt: '수입편입일자', rfamtPymnRqtClCd: '환급금지급요구구분코드', frsRfamtPymnRqtDt: '최초지급요구일자',
  actlBokTrtRsltCd: '한국은행처리결과코드', bokErrTypeCd: '한국은행오류유형코드', rfamtPymnCmplDt: '환급금지급완료일자',
  gdncFrwBrkdId: '안내발송내역ID',
  // Hometax electronic notices.
  pmtTxamt: '납부할 세액', dungPmtDdt: '독촉납부기한', txprDscmNoEncCntn: '사업자(주민)등록번호', dlvDt: '송달일',
  ntfTxamt: '고지세액', endtApplcYn: '전자고지 세액공제', rdcTxamt: '감액세액', pmtYn: '납부여부', elctNtfPrslDtm: '열람일시',
  chrgTxhfOgzNm: '관할관서', chrgMem: '담당자(연락처)',
  // Hometax returns and their forms.
  rtnCvaId: '신고 ID', txnrmYm: '과세연월', stmnKndNm: '신고서종류', stmnKndCd: '신고서종류코드', rtnClNm: '신고구분',
  rtnClDetailNm: '신고유형', rtnClDetailCd: '신고구분상세코드', txprNo: '사업자(주민)등록번호', rcatMthdCd: '접수방법',
  cvaAplnDtm: '접수일시', rcatNo: '접수번호', rcatDt: '접수일자', apndDcumRcpnScnt: '접수서류', stmnWrtMthdCd: '신고서작성방법코드',
  ogntxSbtrPmtTxamt: '본세차감납부세액', edctxSbtrPmtTxamt: '교육세차감납부세액', fnftxSbtrPmtTxamt: '농어촌특별세차감납부세액',
  ogntxWhlScpmTxamt: '본세총괄납부예정세액', edctxWhlScpmTxamt: '교육세총괄납부예정세액', fnftxWhlScpmTxamt: '농어촌특별세총괄납부예정세액',
  mdfAddVlpySchuTxamt: '수정추가자진납부세액', edctxAddVlpySchuTxamt: '교육세추가자진납부세액',
  fnftxAddVlpySchuTxamt: '농어촌특별세추가자진납부세액', aprpAfthPmtTxamt: '충당금이후금액', pmtCmpoTypeCd: '납부대사유형코드',
  cvaAgnRltCdNm: '제출자구분', rtnDt: '신고일자', lcltxResidEnc: '지방소득세', stmnSbmsScnt: '신고건수',
  tnmNm: '상호', txprNm: '상호(성명)', txprDscmNo: '사업자(주민)등록번호', userNm: '이름', frmlNm: '서식명', frmlCd: '서식 코드',
  // Hometax tax invoices: the list, one invoice, and its items.
  rprsFnm: '성명', sumSplCftStr: '공급가액', sumTxamtStr: '세액', isnDtm: '발급일자', tmsnDt: '전송일자', etxivSq1RmrkCntn: '비고',
  etan: '승인번호', etxivMdfRsnNm: '수정사유', sumSplCft: '공급가액', sumTxamt: '세액', totaAmt: '합계금액',
  splrTxprDscmNo: '공급자 사업자번호', splrMpbNo: '공급자 종사업장번호', splrTnmNm: '공급자 상호', splrRprsFnm: '공급자 대표자',
  splrPfbAdr: '공급자 주소', splrBcNm: '공급자 업태', splrItmNm: '공급자 종목', splrChrgEmlAdr: '공급자 이메일',
  splrMchrgEmlAdr: '공급자 이메일',
  dmnrTxprDscmNo: '공급받는 자 사업자번호', dmnrMpbNo: '공급받는 자 종사업장번호', dmnrTnmNm: '공급받는 자 상호',
  dmnrRprsFnm: '공급받는 자 대표자', dmnrPfbAdr: '공급받는 자 주소', dmnrBcNm: '공급받는 자 업태', dmnrItmNm: '공급받는 자 종목',
  dmnrMchrgEmlAdr: '공급받는 자 이메일', dmnrSchrgEmlAdr: '공급받는 자 이메일 2',
  cstnTxprDscmNo: '수탁자 사업자번호', cstnMpbNo: '수탁자 종사업장번호', cstnTnmNm: '수탁자 상호', cstnRprsFnm: '수탁자 대표자',
  cstnPfbAdr: '수탁자 주소', cstnBcNm: '수탁자 업태', cstnItmNm: '수탁자 종목', cstnMchrgEmlAdr: '수탁자 이메일',
  lsatSplDt: '공급일자', lsatSplMm: '월', lsatSplDd: '일', lsatNm: '품목', lsatRszeNm: '규격', lsatQty: '수량',
  lsatUtprc: '단가', lsatSplCft: '공급가액', lsatTxamt: '세액', lsatRmrkCntn: '품목 비고',
  wrtDt: '작성일', sumAmt: '합계', splCft: '공급가액', txamt: '세액', rmrkCntn: '비고',
  recApeClCd: '청구·영수 코드', etxivClsfCd: '계산서 분류 코드', etxivKndCd: '계산서 종류 코드',
  // Hana transfers and ledger rows.
  trscDt: '거래일자', trscTm: '거래시각', trscAmt: '거래금액', trscAfBal: '거래 후 잔액', curCd: '통화', trscStNm: '처리 상태',
  achvChnlNm: '거래구분', trnsDt: '처리일', trnsScheDt: '이체예정일자', trnsScheTm: '이체예정시각', rsvAcpnDt: '신청일자',
  rsvAcpnTm: '신청시각', canDt: '취소일자', canTm: '취소시각',
  wdrwAcctNo: '출금계좌번호', rcvBnkCd: '입금은행코드', rcvBnkNm: '입금은행', rcvAcctNo: '입금계좌번호', thrAcctNo: '상대 계좌번호',
  trnsAmt: '이체금액', rduAfComm: '수수료', commAmt: '수수료', rcvPsbkMarkCtt: '받는분에게표기', wdrwPsbkMarkCtt: '나에게표기',
  rcvAcctRmrkCtt: '받는분에게 표시', wdrwAcctRmrkCtt: '나에게 표시', rmteNm: '받는 분', rmtrNm: '보내는 분',
  memoCtt: '추가메모', rmrk: '적요',
  // Hana corporate ledger rows, which arrive in upper case.
  TRSC_DT: '거래일자', TRSC_TM: '거래시각', TRSC_AMT: '거래금액', TRSC_AF_BAL: '거래 후 잔액', TRSC_AF_BAL_CTT: '잔액',
  BAL_FLCT_DV_CD: '잔액변동구분', NW_SUMM_PSBK_RMRK: '구분', RMRK: '적요', MEMO_CTT: '추가메모', CUR_CD: '통화',
  TRSC_SPCL_MTTR: '거래특이사항', COMM_AMT: '중도상환수수료', ORGN_INT: '이자', RPAY_AMT: '실행/상환금액',
  TRSC_SEQ_NO: '거래일련번호', DTLS_SEQ_NO: '상세일련번호',
};

/* Names that hold on one screen only. Hometax uses one field for the amount still due and for
   the amount already paid, and the bank names a transfer's last date by the transfer's state,
   so that name is read from the row. Looked up before FIELD_LABELS. */
const SCREEN_LABELS = {
  payments: {romAmt: '납부세액', txhfOgzNm: '수납관서', elctPmtNo: '전자납부번호(세목년월+결정구분+세목코드+발행번호)'},
  refunds: {txhfOgzNm: '세무서명', itrfNm: '세목명'},
  notices: {itrfNm: '세목명'},
  returns: {userId: '제출자ID'},
  inquiry: row => {
    const last = entry({오류: '오류', 완료: row.achvChnlNm === '즉시이체' ? '이체' : '처리', 취소: row.canDt ? null : '취소'}, row.trscStNm);
    return {trscAmt: '이체금액', ...(last ? {lstTrscDt: last + '일자', lstTrscTm: last + '시각'} : {})};
  },
};
// Field names come from the institution, so a table is read by its own entries only.
const entry = (table, key) => Object.hasOwn(table, key) ? table[key] : undefined;
const screenLabels = (screen, row) => {
  const names = entry(SCREEN_LABELS, screen);
  return (typeof names === 'function' ? names(row || {}) : names) || {};
};
export const label = (key, screen = null, row = null) => entry(screenLabels(screen, row), key) || entry(FIELD_LABELS, key) || key;

// The fields each screen's table leads with, as the institution's own list does.
const SCREEN_COLUMNS = {
  payments: ['itrfCdNm', 'txhfOgzNm', 'romDt', 'romAmt'], refunds: ['itrfNm', 'rfndDcsDfntDt', 'rfamtPymnAmt', 'bokTrtRsltCd'],
  notices: ['itrfNm', 'pmtDdt', 'pmtTxamt', 'pmtYn'], returns: ['stmnKndNm', 'txnrmYm', 'rtnClNm', 'cvaAplnDtm'],
  forms: ['frmlNm', 'stmnKndNm', 'txnrmYm', 'stmnSbmsScnt'], invoices: ['tnmNm', 'wrtDt', 'sumSplCftStr', 'sumTxamtStr'],
};

/* Dates, times and amounts that arrive as bare digits, shown with separators. Display only: a
   value of any other shape is left exactly as received. */
const digits = (length, pattern, shape) => value => new RegExp(`^\\d{${length}}$`).test(String(value ?? '')) ? String(value).replace(pattern, shape) : value;
export const dateText = digits(8, /^(\d{4})(\d{2})(\d{2})$/, '$1-$2-$3');
export const timeText = digits(6, /^(\d{2})(\d{2})(\d{2})$/, '$1:$2:$3');
export const monthText = digits(6, /^(\d{4})(\d{2})$/, '$1-$2');
export const stampText = digits(14, /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/, '$1-$2-$3 $4:$5:$6');
// A whole or decimal amount sent as text, zero padding included, with the digits it carries and no more.
export const amountText = value => {
  const match = typeof value === 'string' ? /^(-?)(\d{1,30})(?:\.(\d{1,10}))?$/.exec(value) : null;
  if (!match) return value;
  const fraction = (match[3] || '').replace(/0+$/, '');
  return match[1] + new Intl.NumberFormat('ko-KR').format(BigInt(match[2])) + (fraction ? '.' + fraction : '');
};
// A code the institution's screen shows by name; a code it has no name for stays as received.
const codeName = names => value => entry(names, value) ?? value;
const each = (keys, format) => Object.fromEntries(keys.map(key => [key, format]));
// Institution fields this project reads as a date, a time of day, a month, an amount or a code.
const FIELD_FORMATS = {
  ...each(['pmtDdt', 'dungPmtDdt', 'romDt', 'rfndDcsDfntDt', 'pymnDt', 'dlvDt', 'rcatDt', 'rtnDt', 'wrtDt', 'tmsnDt', 'lsatSplDt',
    'trscDt', 'trnsDt', 'trnsScheDt', 'lstTrscDt', 'rsvAcpnDt', 'canDt', 'TRSC_DT'], dateText),
  ...each(['trscTm', 'trnsScheTm', 'lstTrscTm', 'rsvAcpnTm', 'canTm', 'TRSC_TM', 'TRSC_PROC_TM'], timeText),
  ...each(['attrYm', 'txnrmYm'], monthText),
  ...each(['cvaAplnDtm', 'elctNtfPrslDtm', 'isnDtm', 'tmsnDtm'], stampText),
  ...each(['romAmt', 'rfamtPymnAmt', 'pmtTxamt', 'ntfTxamt', 'rdcTxamt', 'sumSplCft', 'sumTxamt', 'totaAmt', 'ogntxSbtrPmtTxamt',
    'edctxSbtrPmtTxamt', 'fnftxSbtrPmtTxamt', 'trscAmt', 'trnsAmt', 'trscAfBal', 'rduAfComm', 'commAmt', 'TRSC_AMT', 'TRSC_AF_BAL',
    'COMM_AMT', 'ORGN_INT', 'RPAY_AMT'], amountText),
  bokTrtRsltCd: codeName({'00': '지급완료', '01': '미수령', '02': '1년경과 미수령', '03': '1년경과 미수령(지급요청)'}),
  BAL_FLCT_DV_CD: codeName({0: '잔액변동없음', 1: '입금', 2: '출금'}),
};
const AMOUNT_FIELDS = new Set(Object.keys(FIELD_FORMATS).filter(key => FIELD_FORMATS[key] === amountText));

function cell(key, value) {
  const format = entry(FIELD_FORMATS, key);
  const shown = format ? format(value) : value;
  return typeof shown === 'number' ? money(shown) : esc(shown ?? '');
}

/* Service rows arrive as the institution's own field names. Column choice is a
   display heuristic only; the detail view shows every allowlisted field. */
export function columns(rows, limit = 4, screen = null) {
  const keys = [];
  for (const row of rows || []) for (const key of Object.keys(row || {})) if (!keys.includes(key)) keys.push(key);
  const lead = (entry(SCREEN_COLUMNS, screen) || []).filter(key => keys.includes(key));
  if (lead.length >= 3) return lead.slice(0, limit);
  const pick = test => keys.filter(test);
  const chosen = [...pick(k => /Nm$|Name$|name$/.test(k)).slice(0, 2), ...pick(k => /Dt$|date$/i.test(k)).slice(0, 1),
    ...pick(k => /Amt$|amount|Bal$|balance/i.test(k)).slice(0, 1)];
  for (const key of keys) if (chosen.length < limit && !chosen.includes(key)) chosen.push(key);
  return chosen.slice(0, limit);
}

/* `mark(row, key, index)` may name a class for one cell, for example a deposit. */
export function rowsTable(rows, {group = 'rows', limit = 200, keys: fixed = null, num = [], mark = null} = {}) {
  if (!rows) return '';
  if (!rows.length) return '<div class="empty-state">조회 결과가 0건이에요.</div>';
  const keys = fixed || columns(rows, 4, group);
  const numeric = key => num.includes(key) || AMOUNT_FIELDS.has(key) || rows.every(r => r?.[key] === null || r?.[key] === undefined || typeof r[key] === 'number');
  // data-label lets a narrow screen show each cell as "label: value" without a header row.
  return `<div class="table-wrap"><table class="table data"><thead><tr>${keys.map(k => `<th scope="col" class="${numeric(k) ? 'num' : ''}">${esc(label(k, group))}</th>`).join('')}</tr></thead><tbody>${rows.slice(0, limit).map((row, index) => `<tr data-row="${group}:${index}" tabindex="0">${keys.map(k => `<td class="${[numeric(k) ? 'num' : '', mark?.(row, k, index)].filter(Boolean).join(' ')}" data-label="${esc(label(k, group))}">${cell(k, row?.[k])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>${rows.length > limit ? `<div class="list-footer">${rows.length}건 중 ${limit}건 표시</div>` : ''}`;
}

/* `screen` names the screen whose own field names apply; `source` is the whole row when
   `row` is only a part of it. */
export function fieldsList(row, screen = null, source = row) {
  return `<div class="summary-lines">${Object.entries(row || {}).map(([k, v]) => `<div class="summary-line"><span>${esc(label(k, screen, source))}</span><strong>${cell(k, v)}</strong></div>`).join('')}</div>`;
}

/* Row detail: fields with a known name first, the screen's own columns leading; names only
   the institution uses are folded. */
export function detailFields(row, screen = null) {
  const entries = Object.entries(row || {});
  const known = key => label(key, screen, row) !== key || /[^\x00-\x7F]/.test(key);
  const lead = entry(SCREEN_COLUMNS, screen) || [];
  const rank = key => lead.includes(key) ? lead.indexOf(key) : lead.length;
  const named = entries.filter(([k]) => known(k)).sort(([a], [b]) => rank(a) - rank(b));
  const raw = entries.filter(([k]) => !known(k));
  if (!named.length || !raw.length) return fieldsList(Object.fromEntries(named.length ? named : entries), screen, row);
  return fieldsList(Object.fromEntries(named), screen, row) +
    `<details class="verdict"><summary>그 밖의 항목 ${raw.length}개 (기관 필드명 그대로)</summary><div class="folded-fields">${fieldsList(Object.fromEntries(raw), screen, row)}</div></details>`;
}

export const KIND = {personal: '개인', sole_proprietor: '개인사업자', corporation: '법인', business: '사업장', account: '계좌'};
export const INSTITUTION = {hometax: '홈택스', hana: '하나개인뱅킹', hana_corporate: '하나기업뱅킹', giro: '모바일지로'};
export const METHOD = {pin: '지로 간편비밀번호', joint_certificate: '공동인증서', onesign: '하나인증서', id_password: '기업 ID/PW'};

export const BANKS = [['081', '하나은행'], ['004', 'KB국민은행'], ['088', '신한은행'], ['020', '우리은행'], ['011', 'NH농협은행'],
  ['003', 'IBK기업은행'], ['023', 'SC제일은행'], ['027', '한국씨티은행'], ['031', '대구은행'], ['032', '부산은행'],
  ['034', '광주은행'], ['035', '제주은행'], ['037', '전북은행'], ['039', '경남은행'], ['045', '새마을금고'], ['048', '신협'],
  ['071', '우체국'], ['089', '케이뱅크'], ['090', '카카오뱅크'], ['092', '토스뱅크']];
