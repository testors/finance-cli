// Direct Node HTTP and site JavaScript with a DOM host.
import fs from 'node:fs/promises';
import vm from 'node:vm';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {LOGIN_URL, nativeBridgeSource, observerSource} from './browser.mjs';

export const USER_AGENT = 'Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Version/4.0 Mobile Safari/537.36 Android511';

export function loadDOM() {
  return createRequire(import.meta.url)('./jsdom_compat.cjs');
}

// jsdom does not parse split document.write() script tags in browser order.
// Evaluate the unmodified, write-only common loader separately and insert its
// combined output at the same position. Authentication/security scripts are not
// extracted, rewritten, skipped, or supplied with synthetic success results.
export function expandBootstrap(html, loader, url = LOGIN_URL) {
  let markup = '';
  const context = {window:{location:new URL(url)}, document:{write(...parts) {
    markup += parts.join('');
  }}};
  vm.runInNewContext(loader, context, {timeout:5000});
  const tag = /<script\b[^>]*\bsrc=["'](?:\/)?js\/comm\/NtsCommonTb(?:_main)?\.js(?:\?[^"']*)?["'][^>]*>\s*<\/script>/i;
  if (!tag.test(html) || !markup) throw new Error('Unsupported bootstrap');
  return html.replace(tag, () => markup);
}

// Initial HTML and its bootstrap must share cookies with the page runtime.
// Redirect responses can set cookies too; retain them before following Location.
export async function getPage(url, jar, {referrer, referrerPolicy = 'strict-origin-when-cross-origin',
                                       signal, method = 'GET', body, binary = false} = {}) {
  for (let redirects = 0; redirects <= 20; redirects++) {
    const headers = {'User-Agent':USER_AGENT};
    const cookies = await jar.getCookieString(url);
    if (cookies) headers.Cookie = cookies;
    if (method === 'POST') {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      headers.Origin = referrer ? new URL(referrer).origin : new URL(url).origin;
    }
    // Fetch applies URL stripping and the browser's referrer policy. Manually
    // setting Referer would incorrectly send the full path across origins.
    const response = await fetch(url, {method, body, headers, redirect:'manual', signal,
      referrer:referrer || '',referrerPolicy});
    for (const cookie of response.headers.getSetCookie()) {
      await jar.setCookie(cookie, url, {ignoreError:true});
    }
    if ([301,302,303,307,308].includes(response.status) && response.headers.has('location')) {
      await response.body?.cancel();
      // A redirect is still the same navigation, not a new referring document.
      const policies = (response.headers.get('referrer-policy') || '').split(',').map(value=>value.trim());
      const validPolicies = ['no-referrer','no-referrer-when-downgrade','same-origin','origin',
        'strict-origin','origin-when-cross-origin','strict-origin-when-cross-origin','unsafe-url'];
      referrerPolicy = policies.findLast(value=>validPolicies.includes(value)) || referrerPolicy;
      url = new URL(response.headers.get('location'), url).href;
      if (response.status === 303 || ([301,302].includes(response.status) && method === 'POST')) {
        method = 'GET'; body = undefined;
      }
      continue;
    }
    return {url, status:response.status, content_type:response.headers.get('content-type'),
      body:binary ? Buffer.from(await response.arrayBuffer()) : await response.text()};
  }
  throw new Error('Redirect limit');
}

export function createPage({html, loader, url = LOGIN_URL, jar, resources = {},
                            beforeParse, onReport, onIssue}) {
  const {JSDOM, VirtualConsole} = loadDOM();
  const virtualConsole = new VirtualConsole();
  // Never forward page console messages, exception text, request URLs or bodies:
  // any of those can contain credentials or session data.
  virtualConsole.on('jsdomError', error => onIssue?.(error.type || 'runtime'));
  return new JSDOM(expandBootstrap(html, loader, url), {
    url, cookieJar:jar, runScripts:'dangerously', virtualConsole,
    resources:{...resources, userAgent:USER_AGENT},
    beforeParse(window) {
      Object.defineProperty(window.navigator, 'platform', {value:'Linux aarch64'});
      window.__hometaxReport = text => onReport?.(JSON.parse(text));
      window.eval(nativeBridgeSource());
      window.document.addEventListener('DOMContentLoaded', () => {
        // jQuery Mobile's visual grade-A initialization requires CSS layout.
        // Its original loadPage()/AJAX/script evaluation works with a DOM host.
        // Supply that host without changing gradeA or security feature checks.
        if (window.$?.mobile && !window.$.mobile.pageContainer)
          window.$.mobile.pageContainer = window.$(window.document.body);
      }, true);
      beforeParse?.(window);
    },
  });
}

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function login(config, dependencies = {}) {
  const {CookieJar} = loadDOM();
  const timeoutMs = Math.ceil(config.timeout * 1000);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new Error('Invalid timeout');
  const jar = new CookieJar();
  const output = await fs.open(config.output, 'wx', 0o600);
  const record = {scope:'browserless_certificate_login', branch:'no_action',
    login_request_observed:false, session_binding_observed:false};
  let dom, decision, session, finalAt, transportError = false, callbackException = false;
  const warnings = [], issues = new Set();
  const timeout = AbortSignal.timeout(timeoutMs);
  const deadline = Date.now() + timeoutMs;
  const obtain = dependencies.getPage || getPage;
  try {
    const page = await obtain(LOGIN_URL, jar, {signal:timeout});
    const bootstrapURL = new URL('/js/comm/NtsCommonTb_main.js?version=1.4', page.url).href;
    const loader = await obtain(bootstrapURL, jar, {referrer:page.url, signal:timeout});
    dom = createPage({html:page.body, loader:loader.body, url:page.url, jar,
      resources:dependencies.resources, beforeParse:dependencies.beforeParse,
      onIssue:kind => issues.add(kind),
      onReport:event => {
        if (event.kind === 'decision') {decision = event; finalAt = Date.now();}
        if (event.kind === 'session') session = event;
        if (event.kind === 'login-request') record.login_request_observed = true;
        if (event.kind === 'transport-error') transportError = true;
        if (event.kind === 'callback-exception') callbackException = true;
      },
    });
    const w = dom.window;
    let ready = false;
    while (Date.now() < deadline) {
      ready = Boolean(w.__hometaxBridgeInstalled && w.__hometaxPageStarted && w.ntsframework && w.nts_calledByNative &&
        w.nts_getAppVersion && w.NetFunnel_Action && w.NetFunnel_Complete && w.$?.mobile &&
        w.ntsframework.session.get('sessionCheckResult') === 'success');
      if (ready) break;
      await delay(50);
    }
    if (!ready) throw new Error('Page initialization unavailable');
    w.eval(observerSource());
    w.nts_getAppVersion({appVersion:config.appVersion, osNm:'Android'});
    w.eval(decodeURIComponent(config.callback.javascript.slice('javascript:'.length)));
    while (Date.now() < deadline) {
      if (transportError || (decision && decision.branch !== 'success')) break;
      if (decision && (session || Date.now() - finalAt > 10000)) break;
      await delay(50);
    }
    if (!decision) warnings.push('서비스의 최종 인증 판정을 관찰하지 못했습니다. 자동 재시도하지 않습니다.');
  } catch (error) {
    dependencies.onError?.(error);
    warnings.push('HTTP 또는 서비스 JavaScript 처리를 완료하지 못했습니다. 이미 받은 판정은 유지합니다.');
  } finally {
    if (decision) {record.branch = decision.branch; record.response = decision.response;}
    record.session_binding_observed = Boolean(session);
    if (record.branch === 'success' && !session)
      warnings.push('로그인은 성공했습니다. 후속 세션 바인딩은 아직 관찰하지 못했습니다.');
    if (callbackException) warnings.push('서비스 후속 콜백에 예외가 있습니다. 로그인 판정은 유지합니다.');
    if (transportError) warnings.push('서비스 XHR 오류 경로가 관찰되었습니다. 별도의 인증 실패로 판정하지 않습니다.');
    if (issues.size) warnings.push('DOM 또는 화면 리소스 처리에 경고가 있습니다. 서비스 인증 판정과 분리합니다.');
    record.runtime_issues = [...issues];
    try {
      record.cookie_jar = jar.serializeSync();
      if (dom) record.storage = {sessionStorage:Object.assign({}, dom.window.sessionStorage),
        localStorage:Object.assign({}, dom.window.localStorage)};
    } catch (_) {warnings.push('세션 내보내기를 완료하지 못했습니다. 로그인 판정은 유지합니다.');}
    try {dom?.window.close();}
    catch (_) {warnings.push('DOM 정리 중 오류가 있습니다. 로그인 판정은 유지합니다.');}
    record.warnings = warnings;
    record.session_file_saved = true;
    try {await output.writeFile(JSON.stringify(record, null, 2));}
    catch (_) {
      record.session_file_saved = false;
      warnings.push('세션 파일 저장을 완료하지 못했습니다. 로그인 판정은 유지합니다.');
    }
    try {await output.close();}
    catch (_) {
      record.session_file_saved = false;
      warnings.push('세션 파일 닫기를 완료하지 못했습니다. 로그인 판정은 유지합니다.');
    }
  }
  for (const warning of warnings) process.stderr.write('경고: ' + warning + '\n');
  return {scope:record.scope, branch:record.branch, session_file:config.output,
    login_request_observed:record.login_request_observed,
    session_binding_observed:record.session_binding_observed,
    session_file_saved:record.session_file_saved};
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  try {
    const result = await login(JSON.parse(input));
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exitCode = result.branch === 'success' ? 0 : result.branch === 'failure' ? 1 : 3;
  } catch (_) {
    process.stderr.write('오류: Node 의존성(npm ci), 설정 또는 출력 파일을 확인하세요.\n');
    process.exitCode = 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
