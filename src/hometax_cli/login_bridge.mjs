// Page-side hooks that connect the service login page to the CLI.
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
