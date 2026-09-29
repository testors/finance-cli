// Chromium CDP adapter. Invoked only by explicit `auth login-cert`.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';

export const LOGIN_URL = 'https://mob.hometax.go.kr/jsonAction.do?actionId=UTBMPBAA01F001';

export function nativeBridgeSource() {
  // Runs before jQuery's DOMContentLoaded listener. In the fetched sources all
  // initial native calls happen during document-ready, not during parsing.
  // The native side of this bridge is the CLI: never navigate to an app scheme.
  return `document.addEventListener('DOMContentLoaded', function () {
    if (!['https://mob.hometax.go.kr','https://mob.tbht.hometax.go.kr','https://mob.tbet.hometax.go.kr'].includes(location.origin)) return;
    window.nts_callNative = function (id, data) {
      if (id === 'MAIN') { goToMain(); return; }
      window.__hometaxReport(JSON.stringify({kind:'native-call', action:String(id)}));
    };
    window.__hometaxBridgeInstalled = true;
    const start = window.nts_start;
    if (typeof start === 'function') {
      window.nts_start = function () {
        const result = start.apply(this, arguments);
        window.__hometaxPageStarted = true;
        window.__hometaxReport(JSON.stringify({kind:'page-started'}));
        return result;
      };
      Object.assign(window.nts_start, start);
    }
  }, true);`;
}

export function observerSource() {
  return `(() => {
    if (location.origin !== 'https://mob.hometax.go.kr' ||
        new URL(location.href).searchParams.get('actionId') !== 'UTBMPBAA01F001')
      throw new Error('Unexpected page');
    if (!window.__hometaxBridgeInstalled) throw new Error('Native adapter unavailable');
    const emit = data => window.__hometaxReport(JSON.stringify(data));
    let pending;
    const complete = window.NetFunnel_Complete;
    window.NetFunnel_Complete = function (options, callback) {
      return complete.call(this, options, function () {
        if (pending !== undefined) {
          const response = pending; pending = undefined;
          let branch = 'no_action';
          try { branch = response.result.resultMsg.code != 'S' ? 'failure' : 'success'; }
          catch (_) {}
          emit({kind:'decision', branch, response});
        }
        try { if (typeof callback === 'function') return callback.apply(this, arguments); }
        catch (error) { emit({kind:'callback-exception'}); throw error; }
      });
    };
    const ajax = ntsframework.callAjax;
    ntsframework.callAjax = function (url, params, success, fail, options) {
      if (url === '/pubcMobLogin.do' && params && params.pkcLoginYn === 'Y') {
        emit({kind:'login-request'});
        const observed = function (data) {
          pending = data;
          return success.apply(this, arguments);
        };
        const failed = function () {
          emit({kind:'transport-error'});
          if (fail) return fail.apply(this, arguments);
        };
        return ajax.call(this, url, params, observed, failed, options);
      }
      return ajax.apply(this, arguments);
    };
    const loadPage = $.mobile.loadPage;
    $.mobile.loadPage = function (url) {
      const deferred = loadPage.apply(this, arguments);
      if (String(url).split('?')[0].endsWith('/setSession.jsp')) {
        deferred.done(function () {
          const originalSet = window.setSession;
          window.setSession = function () {
            const result = originalSet.apply(this, arguments);
            emit({kind:'session', sessionStorage:Object.assign({}, sessionStorage),
                  localStorage:Object.assign({}, localStorage)});
            return result;
          };
        });
      }
      return deferred;
    };
    Object.assign($.mobile.loadPage, loadPage);
    return true;
  })()`;
}

export class CDP {
  constructor(socket) {
    this.socket = socket; this.nextId = 1; this.pending = new Map(); this.listeners = [];
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id); clearTimeout(pending.timer);
        message.error ? pending.reject(new Error('CDP command failed')) : pending.resolve(message.result);
      } else {
        for (const listener of this.listeners) listener(message);
      }
    });
    socket.addEventListener('close', () => {
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer); pending.reject(new Error('CDP disconnected'));
      }
      this.pending.clear();
    });
  }
  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {socket.close(); reject(new Error('CDP timeout'));}, 15000);
      socket.addEventListener('open', () => {clearTimeout(timer); resolve();}, {once:true});
      socket.addEventListener('error', () => {clearTimeout(timer); reject(new Error('CDP unavailable'));}, {once:true});
    });
    return new CDP(socket);
  }
  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {this.pending.delete(id); reject(new Error('CDP timeout'));}, 15000);
      this.pending.set(id, {resolve, reject, timer});
      this.socket.send(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}));
    });
  }
  close() { this.socket.close(); }
}

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function login(config) {
  // Reserve a private artifact before making any connection or login attempt.
  const output = await fs.open(config.output, 'wx', 0o600);
  let client, browserContextId, targetId, sessionId, decision, session, loginSent = false;
  const warnings = [];
  const record = {scope:'browser_certificate_login', branch:'no_action'};
  let pageReady = false, transportError = false, callbackException = false, finalAt;
  try {
    let endpoint = config.cdp;
    if (/^https?:/.test(endpoint)) {
      const response = await fetch(new URL('/json/version', endpoint), {signal:AbortSignal.timeout(15000)});
      endpoint = (await response.json()).webSocketDebuggerUrl;
    }
    client = await CDP.connect(endpoint);
    ({browserContextId} = await client.send('Target.createBrowserContext', {disposeOnDetach:false}));
    ({targetId} = await client.send('Target.createTarget', {url:'about:blank', browserContextId}));
    ({sessionId} = await client.send('Target.attachToTarget', {targetId, flatten:true}));
    record.browser = {cdp:config.cdp, browserContextId, targetId};
    client.listeners.push(message => {
      if (message.sessionId !== sessionId || message.method !== 'Runtime.bindingCalled' ||
          message.params.name !== '__hometaxReport') return;
      let event;
      try { event = JSON.parse(message.params.payload); } catch (_) { return; }
      if (event.kind === 'decision') { decision = event; finalAt = Date.now(); }
      if (event.kind === 'session') session = event;
      if (event.kind === 'login-request') loginSent = true;
      if (event.kind === 'transport-error') transportError = true;
      if (event.kind === 'callback-exception') callbackException = true;
    });
    await client.send('Runtime.enable', {}, sessionId);
    await client.send('Page.enable', {}, sessionId);
    await client.send('Runtime.addBinding', {name:'__hometaxReport'}, sessionId);
    await client.send('Page.addScriptToEvaluateOnNewDocument', {source:nativeBridgeSource()}, sessionId);
    const {userAgent} = await client.send('Browser.getVersion');
    await client.send('Emulation.setUserAgentOverride', {userAgent:userAgent + ' Android511'}, sessionId);
    await client.send('Page.navigate', {url:LOGIN_URL}, sessionId);
    const deadline = Date.now() + config.timeout * 1000;
    const evaluate = async expression => {
      const result = await client.send('Runtime.evaluate', {expression, returnByValue:true}, sessionId);
      if (result.exceptionDetails) throw new Error('Page evaluation failed');
      return result.result.value;
    };
    while (Date.now() < deadline) {
      try {
        pageReady = await evaluate(`Boolean(window.__hometaxBridgeInstalled && window.__hometaxPageStarted &&
          window.ntsframework && window.nts_calledByNative && window.nts_getAppVersion &&
          window.NetFunnel_Action && window.NetFunnel_Complete && window.$ && $.mobile &&
          ntsframework.session.get('sessionCheckResult') === 'success')`);
      } catch (_) { /* Navigation may replace the execution context. */ }
      if (pageReady) break;
      await delay(250);
    }
    if (!pageReady) throw new Error('Login page initialization unavailable');
    await evaluate(observerSource());
    // The original MainActivity supplies this data after the login page loads.
    await evaluate(`nts_getAppVersion(${JSON.stringify({appVersion:config.appVersion, osNm:'Android'})})`);
    // WebView.loadUrl decodes javascript: URL escapes once before evaluation.
    // CDP evaluate needs that step explicitly; evaluating the encoded payload
    // directly would over-encode '+', '/' and '=' in the request.
    await evaluate(decodeURIComponent(config.callback.javascript.slice('javascript:'.length)));
    while (Date.now() < deadline) {
      if (transportError || (decision && decision.branch !== 'success')) break;
      if (decision && (session || Date.now() - finalAt > 10000)) break;
      await delay(200);
    }
    if (decision) {
      record.branch = decision.branch;
      record.response = decision.response;
      if (decision.branch === 'success' && !session)
        warnings.push('로그인은 성공했습니다. 후속 세션 바인딩은 아직 관찰하지 못했습니다.');
    } else {
      warnings.push(transportError ? '서비스 XHR 오류 경로입니다. 인증 성공·실패 판정은 없습니다.' :
                    '대기 시간 안에 서비스의 최종 판정이 관찰되지 않았습니다. 자동 재시도하지 않습니다.');
    }
    if (callbackException) warnings.push('서비스 후속 콜백에서 예외가 발생했습니다. 이미 받은 판정은 유지합니다.');
    if (session) record.storage = session;
    record.login_request_observed = loginSent;
    record.session_binding_observed = Boolean(session);
    try { record.cookies = (await client.send('Storage.getCookies', {browserContextId})).cookies; }
    catch (_) { warnings.push('쿠키 내보내기에 실패했습니다. 브라우저 컨텍스트는 유지합니다.'); }
  } catch (_) {
    // Authentication success must survive an unrelated CDP/storage failure.
    if (decision) {record.branch = decision.branch; record.response = decision.response;}
    warnings.push('브라우저 연결 또는 페이지 처리를 완료하지 못했습니다. 상세 비밀값은 로그에 출력하지 않습니다.');
  } finally {
    record.warnings = warnings;
    record.browser_context_retained = Boolean(browserContextId);
    record.session_file_saved = false;
    try {
      record.session_file_saved = true;
      await output.writeFile(JSON.stringify(record, null, 2));
      await output.close();
    } catch (_) {
      record.session_file_saved = false;
      warnings.push('세션 파일 저장을 완료하지 못했습니다. 이미 받은 로그인 판정은 유지합니다.');
      try {await output.close();} catch (_) {}
    } finally {client?.close();}
  }
  for (const warning of warnings) process.stderr.write('경고: ' + warning + '\n');
  // Do not emit response bodies, cookies, identifiers or tokens to agent logs.
  return {scope:record.scope, branch:record.branch, session_file:config.output,
          browser_context_retained:record.browser_context_retained,
          session_file_saved:record.session_file_saved,
          session_binding_observed:record.session_binding_observed || false};
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  try {
    const config = JSON.parse(input);
    const result = await login(config);
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exitCode = result.branch === 'success' ? 0 : result.branch === 'failure' ? 1 : 3;
  } catch (_) {
    process.stderr.write('오류: 브라우저 설정 또는 세션 출력 파일을 확인하세요.\n');
    process.exitCode = 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
