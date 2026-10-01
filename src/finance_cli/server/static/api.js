/* Same-origin API client. Access tokens live in an HttpOnly cookie; the CSRF
   token is kept in memory only. Secrets are sent in one request body and never stored. */
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

export const api = {
  async state() {
    const value = await request('GET', '/auth/state');
    csrf = value.csrf_token || null;
    return value;
  },
  async enroll(code, deviceName) {
    const value = await request('POST', '/auth/enroll', {code, device_name: deviceName || null});
    csrf = value.csrf_token;
    return value;
  },
  get: path => request('GET', path),
  post: (path, body = {}) => request('POST', path, body),
  patch: (path, body) => request('PATCH', path, body),
  delete: path => request('DELETE', path),
  upload: (kind, file) => request('POST', '/uploads?kind=' + encodeURIComponent(kind), file,
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

export function submit(name, fields = {}) {
  return api.post('/jobs', {name, idempotency_key: 'web-' + crypto.randomUUID(), ...fields});
}
