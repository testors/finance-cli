// Transport fixes for the pinned jsdom release. No site JavaScript is changed.
// Preloaded by sync-XHR workers as well as the parent DOM runtime.
const localRequire = require('./runtime_require.cjs');
const version = localRequire('jsdom/package.json').version;
if (version !== '30.1.1') throw new Error('Review transport compatibility for this jsdom version');
const dom = localRequire('jsdom');
const {implementation: XHR} = localRequire('jsdom/lib/jsdom/living/xhr/XMLHttpRequest-impl.js');
const {JSDOMDispatcher} = localRequire('jsdom/lib/jsdom/browser/resources/jsdom-dispatcher.js');
const decompress = localRequire('jsdom/lib/jsdom/browser/resources/decompress-interceptor.js');
const {getGlobalDispatcher} = localRequire('undici');

const adoptRequest = XHR.prototype._adoptSerializedRequest;
XHR.prototype._adoptSerializedRequest = function (config) {
  adoptRequest.call(this, config);
  // The stock worker restores _cookieJar but its dispatcher retains the empty
  // about:blank jar. Both outbound cookies and inbound Set-Cookie were lost.
  this._dispatcher = new JSDOMDispatcher({baseDispatcher:getGlobalDispatcher(),
    cookieJar:this._cookieJar, userAgent:this._userAgent,
    // Mirror lib/api.js: the dispatcher advertises gzip/deflate, so the sync
    // worker must retain the normal response decompression interceptor too.
    userInterceptors:[decompress()]});
};
const adoptResponse = XHR.prototype._adoptSerializedResponse;
XHR.prototype._adoptSerializedResponse = function (response) {
  // Main JS was blocked while the worker ran. Replace the snapshot, including
  // deletions, in the shared store; other page objects retain the same store.
  if (response.cookieJar) this._ownerDocument._cookieJar.removeAllCookiesSync();
  return adoptResponse.call(this, response);
};
const send = XHR.prototype.send;
XHR.prototype.send = function (body) {
  // Fetch's Origin algorithm includes same-origin non-GET/HEAD XHR. jsdom
  // currently adds this header only to cross-origin XHR (xhr-utils.js).
  if (this._url && this._method !== 'GET' && this._method !== 'HEAD' &&
      new URL(this._url).origin === this._origin && !this._requestHeaders.contains('origin'))
    this._requestHeaders.set('Origin', this._origin);
  return send.call(this, body);
};

// Python starts Node with --require pointing here; workers inherit that preload.
module.exports = dom;

// A DOM host has no document navigation implementation. Hand navigation to the
// CLI host while preserving the original location/form decision and parameters.
// This touches jsdom only; site scripts and Android code are not rewritten.
module.exports.captureNavigation = function (window, navigate) {
  const {implForWrapper} = localRequire('jsdom/lib/generated/idl/utils.js');
  const {serializeURL} = localRequire('whatwg-url');
  implForWrapper(window.location)._locationObjectNavigate = function (url) {
    navigate({url:serializeURL(url), method:'GET'});
  };
  window.HTMLFormElement.prototype.submit = function () {
    const params = new URLSearchParams();
    for (const [key,value] of new window.FormData(this)) params.append(key, String(value));
    const url = new URL(this.action || window.location.href, window.location.href);
    const method = this.method.toUpperCase();
    if (method === 'GET') url.search = params.toString();
    navigate({url:url.href, method, ...(method === 'POST' ? {body:params.toString()} : {})});
  };
};

// Android's separate report WebView shares origin-local storage and cookies,
// but has its own sessionStorage. Keep each window's native Storage wrapper and
// share only the backing localStorage map. Do not copy the parent's identity or
// page state into the report window. This adapter is for pinned jsdom 30.1.1.
const localStorageGroups = new WeakMap();
module.exports.shareLocalStorage = function (window, parent) {
  if (window.location.origin !== parent.location.origin)
    throw new Error('Local storage origin mismatch');
  const {implForWrapper} = localRequire('jsdom/lib/generated/idl/utils.js');
  const {fireAnEvent} = localRequire('jsdom/lib/jsdom/living/helpers/events.js');
  const StorageEvent = localRequire('jsdom/lib/generated/idl/StorageEvent.js');
  const source = implForWrapper(parent.localStorage), target = implForWrapper(window.localStorage);
  let group = localStorageGroups.get(source._items);
  if (!group) {
    group = new Map();
    localStorageGroups.set(source._items, group);
  }
  function join(storage) {
    if (group.has(storage)) return;
    group.set(storage, Object.getOwnPropertyDescriptor(storage, '_broadcast'));
    storage._broadcast = function (key, oldValue, newValue) {
      for (const recipient of group.keys()) {
        if (recipient === this) continue;
        const targetWindow = recipient._associatedWindow;
        targetWindow._document._queueATask(() => {
          if (group.has(recipient)) fireAnEvent('storage', targetWindow, StorageEvent, {
            key, oldValue, newValue, url:this._url, storageArea:targetWindow._localStorage,
          });
        });
      }
    };
  }
  join(source);
  target._items = source._items;
  target._associatedWindow._currentOriginData.localStorageArea = source._items;
  join(target);
  function leave(storage) {
    const descriptor = group.get(storage);
    if (descriptor) Object.defineProperty(storage, '_broadcast', descriptor);
    else delete storage._broadcast;
    group.delete(storage);
  }
  return () => {
    leave(target);
    if (group.size === 1) {
      leave(group.keys().next().value);
      localStorageGroups.delete(source._items);
    }
  };
};
