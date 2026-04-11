'use strict';
const socket = io();
socket.on('connect', () => console.log('[WS] connected'));

// Clock
function tick() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('en-GB', {hour12:false});
}
setInterval(tick, 1000); tick();

// Helpers
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function since(iso) {
  const d = (Date.now() - new Date(iso)) / 1000;
  if (d < 60)   return `${Math.floor(d)}s ago`;
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  return `${Math.floor(d/3600)}h ago`;
}

function appendLog(el, ts, level, msg) {
  const cls = {info:'li',success:'ls',warning:'lw',error:'le',banner:'lb',finding:'lf'}[level]||'li';
  const line = document.createElement('div');
  line.className = 'll';
  line.innerHTML = `<span class="lts">${esc(ts)}</span><span class="${cls}">[${level.toUpperCase()}]</span><span>${esc(msg)}</span>`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function badgeFor(sev) {
  const m = {critical:'bc',high:'bh',medium:'bm',low:'bl',info:'bi',pass:'bp'};
  const s = (sev||'info').toLowerCase();
  return `<span class="badge ${m[s]||'bi'}">${s.toUpperCase()}</span>`;
}

// Status pill global update
socket.on('scan_status', d => {
  const pill = document.getElementById('status-pill');
  const dot  = document.getElementById('pill-dot');
  const lbl  = document.getElementById('pill-lbl');
  if (!pill) return;
  const map = {
    running:  {bg:'rgba(0,212,255,0.08)', bc:'rgba(0,212,255,0.28)', cl:'var(--accent)', dc:'var(--accent)', txt: d.msg||'Scanning…'},
    complete: {bg:'rgba(0,255,157,0.07)', bc:'rgba(0,255,157,0.20)', cl:'var(--green)',  dc:'var(--green)',  txt:'Scan Complete'},
    error:    {bg:'rgba(255,62,108,0.07)',bc:'rgba(255,62,108,0.20)', cl:'var(--red)',    dc:'var(--red)',    txt:'Error'},
  };
  const c = map[d.status];
  if (!c) return;
  pill.style.cssText = `display:flex;align-items:center;gap:7px;background:${c.bg};border:1px solid ${c.bc};padding:4px 12px;border-radius:20px;font-size:11px;font-family:var(--mono);color:${c.cl};transition:all .3s`;
  if (dot) dot.style.background = c.dc;
  if (lbl) lbl.textContent = c.txt;
});
