// Restore the browserless session and run the original web session protocol.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {createPage, getPage, loadDOM} from './browserless.mjs';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
// MainActivity's normal entry for an existing session. The login screen is an
// authentication entry point and must not be used to restore a logged-in user.
export const SESSION_URL = 'https://mob.hometax.go.kr/jsonAction.do?actionId=UTBPPZAA01F001';

// Installed before jQuery's ready callback: startup contains a synchronous XHR.
// Observe original arguments/results without substituting server responses or
// changing callback order. Do not send raw tokens, response text or URLs to logs.
export function observeSession(window, report) {
  window.document.addEventListener('DOMContentLoaded', () => {
    const $ = window.$;
    if (!$?.ajax || !$.mobile?.loadPage) return;
    const ajax = $.ajax;
    $.ajax = function (url, options) {
      const settings = typeof url === 'object' ? url : {...options, url};
      const target = new URL(settings.url || window.location.href, window.location.href);
      if (target.pathname !== '/token.do') return ajax.apply(this, arguments);
      const params = new URLSearchParams(settings.data);
      const kind = params.get('idx') || target.searchParams.get('idx');
      const success = settings.success, error = settings.error;
      const observed = {...settings,
        success(data) {
          if (kind === 'verify') {
            const msg = data?.RESULT?.msg;
            const code = data?.RESULT?.errorCode;
            // Original switch(msg) is strict; errorCode checks are loose.
            const ended = msg === 'login' &&
              (code == '-9402' || code == '-9403' || code == '-9404' || code == '-9405');
            report({kind:'verify', result:['tokenOK','login','except','pubcPermission'].includes(msg)
              ? msg : 'unknown', ended});
          }
          try {return success?.apply(this, arguments);}
          catch (error) {report({kind:'callback-exception'}); throw error;}
        },
        error() {
          report({kind:'transport-error'});
          return error?.apply(this, arguments);
        },
      };
      report({kind:'token-request', operation:kind === 'verify' ? 'verify' : 'getToken'});
      return ajax.call(this, observed);
    };
    const portal = window.nts_reqPortalCallback;
    window.nts_reqPortalCallback = function (data) {
      // Use the original XML parser and exact token-empty comparison.
      try {
        const token = $($.parseXML(data)).find('ssoToken').text();
        report({kind:'portal-token', present:token != ''});
      } catch (_) {report({kind:'unreadable-token'});}
      return portal.apply(this, arguments);
    };
    const loadPage = $.mobile.loadPage;
    const wrapped = new WeakSet();
    $.mobile.loadPage = function (url) {
      const deferred = loadPage.apply(this, arguments);
      if (new URL(String(url), window.location.href).pathname === '/setSession.jsp') {
        report({kind:'binding-start'});
        deferred.done(() => {
          for (const [name, kind] of [['setSession','session-bound'],['delSession','session-cleared']]) {
            const original = window[name];
            if (typeof original !== 'function' || wrapped.has(original)) continue;
            const wrapper = function () {
              const result = original.apply(this, arguments);
              report({kind});
              return result;
            };
            wrapped.add(wrapper);
            window[name] = wrapper;
          }
        });
        deferred.fail(() => report({kind:'binding-error'}));
        deferred.always(() => report({kind:'binding-end'}));
      }
      return deferred;
    };
    Object.assign($.mobile.loadPage, loadPage);
  }, true);
}

export class SavedSession {
  constructor(jar, timeout, dependencies) {
    this.jar = jar;
    this.timeout = timeout;
    this.dependencies = dependencies;
    this.issues = new Set();
    this.warnings = [];
    this.refreshStarted = false;
    this.resetObservation();
  }

  resetObservation() {
    this.state = {branch:'no_action', reason:'unobserved', verify_observed:false,
      token_requested:false, session_binding_observed:false, session_cleared_observed:false};
    this.transportError = this.bindingError = false;
    this.bindingPending = 0;
    this.originalPresenceCallback = undefined;
    this.finalAt = undefined;
    this.boundAt = undefined;
  }

  report(event) {
    const state = this.state;
    if (event.kind === 'token-request') state.token_requested = true;
    if (event.kind === 'verify') {
      state.verify_observed = true;
      if (event.result === 'tokenOK') {
        state.branch = 'success'; state.reason = 'tokenOK'; this.finalAt = Date.now();
      } else if (event.ended) {
        state.branch = 'failure'; state.reason = 'sso_ended'; this.finalAt = Date.now();
      } else if (event.result === 'pubcPermission') {
        state.branch = 'no_action'; state.reason = 'permission'; this.finalAt = Date.now();
      }
    }
    if (event.kind === 'portal-token' && !event.present) {
      state.branch = 'failure'; state.reason = 'no_sso_token'; this.finalAt = Date.now();
    }
    if (event.kind === 'session-bound') {
      state.session_binding_observed = true;
      this.boundAt = Date.now();
    }
    if (event.kind === 'session-cleared') state.session_cleared_observed = true;
    if (event.kind === 'binding-start') this.bindingPending++;
    if (event.kind === 'binding-end') this.bindingPending--;
    if (event.kind === 'transport-error') this.transportError = true;
    if (event.kind === 'binding-error') this.bindingError = true;
    if (event.kind === 'callback-exception' || event.kind === 'unreadable-token')
      this.issues.add(event.kind);
    this.dependencies.onReport?.(event);
  }

  get pageReady() {
    const w = this.dom?.window;
    return Boolean(w?.__hometaxPageStarted && w.ntsframework?.session.get('sessionCheckResult') === 'success');
  }

  async wait(deadline, refreshing = false) {
    while (true) {
      // --timeout is per observation stage. Synchronous source scripts can
      // consume the initial resource deadline before tokenOK/setSession return.
      // An accepted session then gets its own bounded binding/startup window so
      // the original 500 ms timers can run. No response or success is invented.
      const stageDeadline = this.state.branch === 'success'
        ? Math.max(deadline,(this.boundAt ?? this.finalAt ?? 0) + this.timeout) : deadline;
      if (Date.now() >= stageDeadline) break;
      // Some original JSONP replies invoke the named portal callback but omit
      // jQuery's generated callback. Its parsererror can arrive after tokenOK;
      // still allow the accepted session's asynchronous binding to finish.
      if (this.bindingError || (this.transportError && this.state.branch !== 'success' && !this.bindingPending)) break;
      if (this.finalAt !== undefined) {
        if (this.state.branch !== 'success' && !this.bindingPending) break;
        if (this.state.session_binding_observed && this.pageReady &&
            (!refreshing || this.originalPresenceCallback !== undefined)) break;
        // A token response is not page initialization. Keep observing binding
        // and the original 500 ms startup timers until the requested deadline;
        // slow synchronous scripts must not impose a hidden 10-second cutoff.
      }
      await delay(50);
    }
  }

  async refresh() {
    if (this.state.branch !== 'success' || !this.pageReady) {
      this.warnings.push('현재 세션의 정상 초기화를 확인하지 못해 추가 토큰 갱신은 실행하지 않았습니다.');
      return;
    }
    this.initialValidation = {...this.state};
    this.resetObservation();
    this.refreshStarted = true;
    const w = this.dom.window;
    w.ntsframework.setSessionIfPresent(value => {this.originalPresenceCallback = value;});
    await this.wait(Date.now() + this.timeout, true);
  }

  record(operation) {
    const warnings = [...this.warnings];
    if (this.state.branch === 'success' && !this.state.session_binding_observed)
      warnings.push('서비스 tokenOK 판정은 성공입니다. 후속 세션 바인딩은 완료를 확인하지 못했습니다.');
    if (this.state.branch === 'success' && !this.pageReady)
      warnings.push('서비스 세션 판정은 성공입니다. 페이지 초기화 완료는 아직 확인하지 못했습니다.');
    if (this.state.branch === 'no_action')
      warnings.push('서비스의 최종 세션 판정을 확인하지 못했습니다. 저장된 과거 로그인 결과로 대체하지 않습니다.');
    if (this.transportError || this.bindingError)
      warnings.push('서비스 세션 통신 또는 바인딩에 오류가 있습니다. 이미 확인한 판정은 유지합니다.');
    if (this.issues.size) warnings.push('DOM 또는 콜백 처리에 경고가 있습니다. 세션 판정과 분리합니다.');
    const record = {scope:'browserless_saved_session', operation, ...this.state,
      refresh_started:this.refreshStarted, page_ready:this.pageReady,
      saved_at:new Date().toISOString(), runtime_issues:[...this.issues], warnings};
    if (this.initialValidation) record.initial_validation = this.initialValidation;
    if (this.originalPresenceCallback !== undefined)
      record.original_presence_callback = this.originalPresenceCallback;
    try {
      record.cookie_jar = this.jar.serializeSync();
      record.storage = {sessionStorage:Object.assign({}, this.dom.window.sessionStorage),
        localStorage:Object.assign({}, this.dom.window.localStorage)};
      record.session_origin = this.dom.window.location.origin;
      if (this.storageByOrigin) record.storage_by_origin = {
        ...this.storageByOrigin, [record.session_origin]:record.storage,
      };
    } catch (_) {warnings.push('세션 내보내기에 오류가 있습니다. 서비스 판정은 유지합니다.');}
    return record;
  }

  close() {
    this.detachLocalStorage?.();
    this.detachLocalStorage = undefined;
    this.dom?.window.close();
  }
}

// Reusable live runtime for subsequent, separately implemented business flows.
// Its window and cookie jar retain the server-verified session until close().
export async function openSavedSession(config, dependencies = {}) {
  const timeout = Math.ceil(config.timeout * 1000);
  if (!Number.isSafeInteger(timeout) || timeout <= 0) throw new Error('Invalid timeout');
  const saved = JSON.parse(await fs.readFile(config.session, 'utf8'));
  if (!saved.cookie_jar) throw new Error('Browserless cookie jar required');
  const {CookieJar} = loadDOM();
  const origin = new URL(SESSION_URL).origin;
  const storageByOrigin = {...saved.storage_by_origin};
  if (saved.storage) storageByOrigin[saved.session_origin || origin] = saved.storage;
  const runtime = await openSessionPage({url:SESSION_URL,
    jar:CookieJar.deserializeSync(saved.cookie_jar), timeout,
    storage:storageByOrigin[origin]}, dependencies);
  runtime.storageByOrigin = storageByOrigin;
  return runtime;
}

// Restore each document with its own origin's storage. Cross-domain SSO is then
// performed by that domain's original config.xml and session framework.
export async function openSessionPage({url, jar, storage, storageParent, timeout, referrer, request = {}}, dependencies = {}) {
  const runtime = new SavedSession(jar, timeout, dependencies);
  const deadline = Date.now() + timeout;
  const obtain = dependencies.getPage || getPage;
  try {
    const signal = AbortSignal.timeout(timeout);
    const page = await obtain(url, runtime.jar, {signal, referrer, ...request});
    const loaderPath = page.body.match(/<script\b[^>]*\bsrc=["']((?:\/)?js\/comm\/NtsCommonTb(?:_main)?\.js(?:\?[^"']*)?)["']/i)?.[1];
    if (!loaderPath) throw new Error('Common loader missing');
    const loader = await obtain(new URL(loaderPath, page.url).href,
      runtime.jar, {referrer:page.url, signal});
    runtime.dom = createPage({html:page.body, loader:loader.body, url:page.url, jar:runtime.jar,
      resources:dependencies.resources, onReport:() => {},
      onIssue:kind => runtime.issues.add(kind),
      beforeParse(window) {
        if (storageParent) runtime.detachLocalStorage = loadDOM().shareLocalStorage(window, storageParent);
        for (const name of ['sessionStorage','localStorage']) {
          for (const [key,value] of Object.entries(storage?.[name] || {}))
            window[name].setItem(key, value);
        }
        observeSession(window, event => runtime.report(event));
        dependencies.beforeParse?.(window);
      },
    });
    await runtime.wait(deadline);
  } catch (error) {
    dependencies.onError?.(error);
    runtime.warnings.push('HTTP 또는 서비스 세션 코드 실행을 완료하지 못했습니다. 이미 받은 판정은 유지합니다.');
  }
  return runtime;
}

export async function runSession(config, dependencies = {}) {
  // Reserve output before any server request. Never overwrite the input snapshot.
  const output = await fs.open(config.output, 'wx', 0o600);
  let runtime, record;
  try {
    runtime = await openSavedSession(config, dependencies);
    if (config.operation === 'refresh') {
      try {await runtime.refresh();}
      catch (error) {
        dependencies.onError?.(error);
        runtime.warnings.push('서비스 토큰 갱신 실행 중 오류가 있습니다. 이미 받은 판정은 유지합니다.');
      }
    }
    record = runtime.record(config.operation);
    try {runtime.close();}
    catch (_) {record.warnings.push('DOM 정리 중 오류가 있습니다. 서비스 판정은 유지합니다.');}
    record.session_file_saved = true;
    try {await output.writeFile(JSON.stringify(record, null, 2));}
    catch (_) {
      record.session_file_saved = false;
      record.warnings.push('세션 파일 저장에 실패했습니다. 서비스 판정은 유지합니다.');
    }
  } finally {
    try {await output.close();}
    catch (_) {
      if (record) {
        record.session_file_saved = false;
        record.warnings.push('세션 파일 닫기에 실패했습니다. 서비스 판정은 유지합니다.');
      }
    }
  }
  for (const warning of record.warnings) process.stderr.write('경고: ' + warning + '\n');
  return {scope:record.scope, operation:config.operation, branch:record.branch, reason:record.reason,
    session_binding_observed:record.session_binding_observed, refresh_started:record.refresh_started,
    session_file:config.output, session_file_saved:record.session_file_saved};
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  try {
    const result = await runSession(JSON.parse(input));
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exitCode = result.branch === 'success' ? 0 : result.branch === 'failure' ? 1 : 3;
  } catch (_) {
    process.stderr.write('오류: 저장 세션, 출력 경로 또는 Node 의존성을 확인하세요.\n');
    process.exitCode = 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
