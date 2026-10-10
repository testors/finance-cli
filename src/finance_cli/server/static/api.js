/* Same-origin API client. Access tokens live in an HttpOnly cookie; the CSRF
   token is kept in memory only. Secrets are sent in one request body and never stored. */
import {during} from './busy.js';

let csrf = null;

export class ApiError extends Error {
  constructor(status, code, reasons = []) {
    super(code); this.status = status; this.code = code;
    this.reasons = Array.isArray(reasons) ? reasons.filter(r => typeof r === 'string') : [];
  }
}

async function request(method, path, body, headers = {}) {
  const options = {method, credentials: 'same-origin', headers: {...headers}};
  if (method !== 'GET') {
    options.headers['X-CSRF-Token'] = csrf || '';
    if (body !== undefined && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    } else if (body !== undefined) {
      options.body = body;
    }
  }
  let response;
  try {
    response = await fetch('/api/v1' + path, options);
  } catch (error) {
    throw new ApiError(0, 'network_unreachable');
  }
  let value = null;
  try { value = await response.json(); } catch (error) { value = null; }
  if (!response.ok) throw new ApiError(response.status, value && value.error || 'http_' + response.status, value?.reasons);
  return value;
}

/* A request that changes something holds the screen until it is answered. Reads never hold.
   Unnamed, it is expected to be over at once and shows nothing unless it takes longer; `label`
   names a request worth showing from the start. `hold: false` is for a caller that sends in the
   background or shows its own progress. */
function change(method, path, body, headers, {hold = true, label = ''} = {}) {
  const send = () => request(method, path, body, headers);
  return hold ? during(label, send, {quiet: !label}) : send();
}

export const api = {
  async state() {
    const value = await request('GET', '/auth/state');
    csrf = value.csrf_token || null;
    return value;
  },
  async enroll(code, deviceName) {
    const value = await change('POST', '/auth/enroll', {code, device_name: deviceName || null});
    csrf = value.csrf_token;
    return value;
  },
  get: path => request('GET', path),
  post: (path, body = {}, options) => change('POST', path, body, {}, options),
  patch: (path, body, options) => change('PATCH', path, body, {}, options),
  delete: (path, options) => change('DELETE', path, undefined, {}, options),
  upload: (kind, file) => change('POST', '/uploads?kind=' + encodeURIComponent(kind), file,
    {'Content-Type': file.type || 'application/json', 'X-File-Name': encodeURIComponent(file.name || '')}),
};

export const TERMINAL = new Set(['finished', 'cancelled', 'expired']);

/* Poll one job until it finishes or waits for the user. Disconnecting never cancels it. */
export async function follow(jobId, onUpdate, isCurrent = () => true) {
  let delay = 700;
  for (;;) {
    if (!isCurrent()) return null;
    const job = await api.get('/jobs/' + encodeURIComponent(jobId));
    if (!isCurrent()) return null;
    onUpdate?.(job);
    if (TERMINAL.has(job.status) || job.status === 'awaiting_input') return job;
    await new Promise(resolve => setTimeout(resolve, delay));
    delay = Math.min(delay * 1.4, job.name?.startsWith('hometax.tax.') ? 1000 : 3000);
  }
}

export function idempotencyKey() {
  if (typeof crypto.randomUUID === 'function') return 'web-' + crypto.randomUUID();
  // getRandomValues is available on HTTP origins as well as secure contexts.
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return 'web-' + [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
}

export function submit(name, fields = {}, options) {
  return api.post('/jobs', {name, idempotency_key: idempotencyKey(), ...fields}, options);
}
