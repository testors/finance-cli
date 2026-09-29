// The original nts_addCmScreen declares asynchronously loaded common screens.
// Its page startup uses their functions, but its independent 500 ms timer can
// run first in the DOM host. Defer that original invocation until the declared
// loads settle. Do not retry startup, manufacture results, or wait on unrelated
// requests such as headers, footers, authentication, or business actions.
export function coordinateCommonScreenStartup(window) {
  const $ = window.$;
  if (!$.mobile?.loadPage || typeof window.nts_addCmScreen !== 'function' ||
      typeof window.nts_start !== 'function') return;
  const add = window.nts_addCmScreen, load = $.mobile.loadPage, start = window.nts_start;
  const state = window.__hometaxCommonStartup = {pending:0,deferred_calls:0};
  const queued = [];
  let declaring = 0;
  const flush = () => window.queueMicrotask(() => {
    // Original loadPage.done callbacks merge the mapper and run the common
    // screen's start function before this microtask. They may declare another
    // common screen, in which case its load must finish too.
    if (state.pending) return;
    while (queued.length && !state.pending) {
      const call = queued.shift();
      start.apply(call.receiver,call.args);
    }
  });
  window.nts_addCmScreen = function () {
    declaring++;
    try {return add.apply(this,arguments);}
    finally {declaring--;}
  };
  Object.assign(window.nts_addCmScreen,add);
  $.mobile.loadPage = function () {
    if (!declaring) return load.apply(this,arguments);
    state.pending++;
    try {
      const deferred = load.apply(this,arguments);
      deferred.always(() => {state.pending--;flush();});
      return deferred;
    } catch (error) {state.pending--;flush();throw error;}
  };
  Object.assign($.mobile.loadPage,load);
  window.nts_start = function () {
    if (!state.pending) return start.apply(this,arguments);
    state.deferred_calls++;
    queued.push({receiver:this,args:[...arguments]});
  };
  Object.assign(window.nts_start,start);
}
