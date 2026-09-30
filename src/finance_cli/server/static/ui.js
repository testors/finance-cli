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

export function time(value) {
  if (!value) return '—';
  const date = new Date(value * 1000);
  return date.toLocaleString('ko-KR', {month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false});
}

export function heading(title, sub, actions = '') {
  return `<div class="page-heading"><div><h1>${esc(title)}</h1><p>${sub}</p></div><div class="heading-actions">${actions}</div></div>`;
}

export function tag(text, tone = '') { return `<span class="status-pill ${tone}">${esc(text)}</span>`; }
export function note(text) { return `<div class="scope-note">${icon('info')}<p>${text}</p></div>`; }
export function button(label, attributes, kind = 'secondary', iconName = '') {
  return `<button type="button" class="button ${kind}" ${attributes}>${iconName ? icon(iconName) : ''}${esc(label)}</button>`;
}

export const STATUS = {queued: ['대기 중', 'neutral'], running: ['실행 중', 'info'], awaiting_input: ['확인 대기', 'warning'],
  finished: ['완료', ''], cancelled: ['취소됨', 'neutral'], expired: ['만료됨', 'neutral']};
export const OUTCOME = {not_started: ['시작 안 함', 'neutral'], success: ['성공', ''], partial_success: ['부분 성공', 'warning'],
  rejected: ['기관 거절', 'danger'], unknown: ['결과 미확인', 'warning']};
export const VERIFICATION = {live_untested: ['실서버 미검증', 'untested'], live_verified: ['실서버 검증', ''], offline: ['오프라인 처리', 'neutral']};
export const ORIGIN = {web: '웹', cli: 'CLI', agent: '에이전트'};

export function statusTags(job) {
  if (job.name?.startsWith('cli.')) return `<span class="pill-row">${tag('CLI 실행 기록', 'neutral')}${tag('종료코드 ' + (job.local?.exit_code ?? '—'), 'neutral')}</span>`;
  const [label, tone] = STATUS[job.status] || [job.status, 'neutral'];
  let html = tag(label, tone);
  if (job.status === 'finished' || job.status === 'running' && job.outcome !== 'not_started') {
    const [outcome, outcomeTone] = OUTCOME[job.outcome] || [job.outcome, 'neutral'];
    html += tag(outcome, outcomeTone);
  }
  return `<span class="pill-row">${html}</span>`;
}

export function verification(level) {
  const [label, tone] = VERIFICATION[level] || [];
  return label ? tag(label, tone) : '';
}

const MESSAGES = {
  issuance_account_not_in_response: '입력한 계좌가 은행의 발급용 본인계좌 목록에 없어요. 새 발급에서는 목록에서 계좌를 선택하세요.',
  issuance_account_selection_invalid: '은행이 제공한 목록에서 인증할 본인 계좌를 선택하세요.',
  network_unreachable: '서버에 연결할 수 없어요. 네트워크와 서버 상태를 확인하세요.',
  access_required: '이 브라우저의 접속이 만료되었거나 철회되었어요. 다시 등록하세요.',
  csrf_token_invalid: '보안 확인이 만료되었어요. 화면을 새로 고치세요.',
  origin_not_allowed: '허용되지 않은 주소에서 보낸 요청이에요.',
  enrollment_code_invalid: '등록 코드가 맞지 않거나 만료되었어요.',
  enrollment_rate_limited: '등록 시도가 너무 많아요. 잠시 후 서버에서 새 코드를 만들어 입력하세요.',
  resource_busy: '같은 기관 자원을 쓰는 다른 작업이 실행 중이에요. 입력한 비밀번호는 전달하지 않았어요. 잠시 후 다시 시도하세요.',
  worker_not_started: '작업을 시작하지 못했어요. 입력한 비밀번호는 전달하지 않았어요.',
  login_required: '기관 로그인이 필요해요. 연결·인증서 화면에서 로그인하세요.',
  session_stale: '설정이 바뀌었거나 세션 저장을 확인하지 못했어요. 세션을 확인하거나 다시 로그인하세요.',
  session_expired: '기관 세션이 만료되었어요. 다시 로그인하세요.',
  session_idle_expired: '마지막 은행 요청 후 10분이 지나 세션이 만료되었어요. 요청을 중단했어요. 다시 로그인한 뒤 필요한 작업을 직접 실행하세요.',
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
  registration_required: '기기·앱 등록 정보가 필요해요. 서버에서 fin server registration으로 연결하세요.',
  'registration_required:app_profile,login_input': '앱 프로필 파일과 로그인 입력 파일을 서버에서 fin server registration으로 연결하세요.',
  login_method_not_supported_by_job: '이 로그인 방식에서는 쓸 수 없는 업무예요.',
  accounts_query_required_in_session: '현재 로그인에서 조회한 계좌 정보를 읽을 수 없어요. 다시 로그인한 뒤 조회해 주세요.',
  accounts_query_incomplete: '계좌 확인을 완료하지 못해 내역 조회를 중단했어요. 계좌 확인 결과를 확인해 주세요.',
  account_not_in_session_accounts: '현재 로그인에서 확인된 계좌 목록에 선택한 계좌가 없어요. 로그인과 선택한 계좌를 확인해 주세요.',
  invalid_history_controls: '조회 기간이나 검색어를 확인해 주세요. 미래 날짜는 조회할 수 없으며, 거래 내역은 3년 미만, 이체 내역은 최근 2년 이내로 조회할 수 있어요.',
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

let toastTimer;
export function toast(text) {
  const target = document.querySelector('#toast');
  target.textContent = text;
  target.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => target.classList.remove('show'), 3500);
}

export function json(value) {
  return `<pre>${esc(JSON.stringify(value, null, 2))}</pre>`;
}

export function details(summary, value) {
  if (value === null || value === undefined || (typeof value === 'object' && !Object.keys(value).length)) return '';
  return `<details class="verdict"><summary>${esc(summary)}</summary>${json(value)}</details>`;
}

/* Service rows arrive as the institution's own field names. Column choice is a
   display heuristic only; the detail view shows every allowlisted field. */
export function columns(rows, limit = 4) {
  const keys = [];
  for (const row of rows || []) for (const key of Object.keys(row || {})) if (!keys.includes(key)) keys.push(key);
  const pick = test => keys.filter(test);
  const chosen = [...pick(k => /Nm$|Name$|name$/.test(k)).slice(0, 2), ...pick(k => /Dt$|date$/i.test(k)).slice(0, 1),
    ...pick(k => /Amt$|amount|Bal$|balance/i.test(k)).slice(0, 1)];
  for (const key of keys) if (chosen.length < limit && !chosen.includes(key)) chosen.push(key);
  return chosen.slice(0, limit);
}

export function rowsTable(rows, {group = 'rows', limit = 200, keys: fixed = null} = {}) {
  if (!rows) return '';
  if (!rows.length) return '<div class="empty-state">조회 결과가 0건이에요.</div>';
  const keys = fixed || columns(rows);
  const numeric = key => rows.every(r => r?.[key] === null || r?.[key] === undefined || typeof r[key] === 'number');
  return `<div class="table-wrap"><table class="table data"><thead><tr>${keys.map(k => `<th scope="col" class="${numeric(k) ? 'num' : ''}">${esc(k)}</th>`).join('')}</tr></thead><tbody>${rows.slice(0, limit).map((row, index) => `<tr data-row="${group}:${index}" tabindex="0">${keys.map(k => `<td class="${numeric(k) ? 'num' : ''}">${typeof row?.[k] === 'number' ? money(row[k]) : esc(row?.[k] ?? '')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>${rows.length > limit ? `<div class="list-footer">${rows.length}건 중 ${limit}건 표시</div>` : ''}`;
}

export function fieldsList(row) {
  return `<div class="summary-lines">${Object.entries(row || {}).map(([k, v]) => `<div class="summary-line"><span>${esc(k)}</span><strong>${typeof v === 'number' ? money(v) : esc(v)}</strong></div>`).join('')}</div>`;
}

export const KIND = {personal: '개인', sole_proprietor: '개인사업자', corporation: '법인', business: '사업장', account: '계좌'};
export const INSTITUTION = {hometax: '홈택스', hana: '하나은행', giro: '모바일지로'};
export const METHOD = {joint_certificate: '공동인증서', onesign: '하나인증서'};
