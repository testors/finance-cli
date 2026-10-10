/* Work in progress, shown in one place and holding the whole screen while it runs.

   Whatever the person at the screen asked for takes a hold: the screen is closed to every other
   press from that moment and says what is running. It opens again when the last hold ends.
   A hold that lasts long can be sent to the background by hand: the work goes on as before, the
   screen is free again and a mark in the corner keeps saying what is still running.
   Nothing here sends, repeats or cancels a request. */
const LATER = 10000;   // ms before a held screen offers to continue in the background
const QUIET = 250;     // ms a short request holds the screen without showing anything
const WAITING = '요청을 처리하고 있어요';

const holds = [];
let box = null, corner = null, redraw = null, closing = null;

function build() {
  if (box?.isConnected) return;
  box = document.createElement('dialog');
  box.id = 'busy';
  box.setAttribute('aria-labelledby', 'busy-title');
  box.innerHTML = '<div class="busy-card" role="status" aria-live="polite"><span class="spinner" aria-hidden="true"></span>'
    + '<p id="busy-title"></p><p id="busy-status"></p></div>'
    + '<div id="busy-later" hidden><p>오래 걸리고 있어요. 작업은 서버에서 계속되며 다시 보내지 않아요.</p>'
    + '<button type="button" class="button secondary">백그라운드로 계속</button></div>';
  corner = document.createElement('div');
  corner.id = 'busy-corner';
  corner.setAttribute('role', 'status');
  corner.hidden = true;
  corner.innerHTML = '<span class="spinner" aria-hidden="true"></span><span></span>';
  document.body.append(box, corner);
  box.querySelector('button').addEventListener('click', background);
  // Escape does not open a held screen; only the end of the work or the button above does.
  box.addEventListener('cancel', event => event.preventDefault());
  box.addEventListener('close', () => { if (blocking()) open(); });
}

function open() {
  if (box.open) return;
  if (typeof box.showModal === 'function') box.showModal(); else box.setAttribute('open', '');
}

function shut() {
  if (!box?.open) return;
  if (typeof box.close === 'function') box.close(); else box.removeAttribute('open');
}

function draw() {
  build();
  clearTimeout(redraw);
  clearTimeout(closing);
  const now = Date.now();
  const front = holds.filter(h => h.blocking);
  if (front.length) {
    // The first hold names the work; a request made inside it does not rename it.
    const named = front.find(h => h.label) || front[0];
    const shown = front.some(h => !h.quiet) || now - front[0].since >= QUIET;
    const late = now - front[0].since >= LATER;
    box.classList.toggle('quiet', !shown);
    box.querySelector('#busy-title').textContent = named.label || WAITING;
    box.querySelector('#busy-status').textContent = named.status || '';
    box.querySelector('#busy-later').hidden = !late;
    open();
    if (!shown) redraw = setTimeout(draw, QUIET - (now - front[0].since));
    else if (!late) redraw = setTimeout(draw, LATER - (now - front[0].since));
  } else {
    // Two requests in a row keep one unbroken hold: the screen opens only once nothing follows.
    closing = setTimeout(() => { if (!blocking()) shut(); }, 0);
  }
  const behind = holds.filter(h => !h.blocking);
  corner.hidden = !behind.length;
  if (behind.length) {
    const first = behind.find(h => h.label) || behind[0];
    corner.lastChild.textContent = `백그라운드 작업${behind.length > 1 ? ` ${behind.length}건` : ''}: `
      + [first.label || WAITING, first.status].filter(Boolean).join(' · ');
  }
}

/* The screen is free again; whatever was holding it keeps running and stays in the corner. */
function background() {
  for (const item of holds) item.blocking = false;
  draw();
}

export function blocking() {
  return holds.some(h => h.blocking);
}

/* Hold the screen for one piece of work. `quiet` is for a request that is usually over at once:
   it blocks from the start but shows nothing unless it takes longer than a moment. */
export function hold(label = '', {quiet = false} = {}) {
  const item = {label, status: '', quiet, blocking: true, since: Date.now()};
  holds.push(item);
  draw();
  return {
    update(status, name) {
      if (!holds.includes(item)) return;
      item.status = status || '';
      if (name) item.label = name;
      draw();
    },
    release() {
      const index = holds.indexOf(item);
      if (index < 0) return;
      holds.splice(index, 1);
      draw();
    },
    /* True once the person sent this work to the background. */
    get background() { return !item.blocking; },
  };
}

export async function during(label, work, options) {
  const held = hold(label, options);
  try { return await (typeof work === 'function' ? work() : work); }
  finally { held.release(); }
}
