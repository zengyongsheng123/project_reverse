// Blanket case-entry logging on top of the existing instrumented file.
// Injects __vlog(pc-1, N, "") into every case of every dispatch loop that lacks logging.
const fs = require('fs');
const src = fs.readFileSync('js/js_security_v3_0.1.4.instrumented.js', 'utf8');

const loopRe = /for\(;;\)\{switch\((\w+)\[(\w+)\+\+\]\)\{/g;
const loops = [];
let m;
while ((m = loopRe.exec(src)) !== null) {
  loops.push({ begin: m.index, codeVar: m[1], pcVar: m[2], switchOpen: m.index + m[0].lastIndexOf('{switch') + 6 });
}
console.log('loops:', loops.length);

function findClose(text, openPos) {
  let depth = 0, i = openPos, q = null;
  while (i < text.length) {
    const ch = text[i];
    if (q) { if (ch === '\\') { i += 2; continue; } if (ch === q) q = null; }
    else if (ch === '"' || ch === "'" || ch === '`') q = ch;
    else if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return i; }
    i++;
  }
  return -1;
}
for (const lp of loops) lp.end = findClose(src, lp.switchOpen);

// process from last to first
loops.sort((a, b) => b.begin - a.begin);
let result = src;
let injected = 0;
for (const lp of loops) {
  const seg = result.slice(lp.switchOpen + 1, lp.end);
  const pc = lp.pcVar;
  const newSeg = seg.replace(/case (\d+):/g, (whole, op) => {
    // check if already logged (next non-space chars are __vlog)
    return `case ${op}:if(!window.__quiet)__vlog(${pc}-1,${op},"");`;
  });
  const n = (newSeg.match(/__quiet/g) || []).length;
  injected += n;
  result = result.slice(0, lp.switchOpen + 1) + newSeg + result.slice(lp.end);
}
console.log('injected cases:', injected);
fs.writeFileSync('js/js_security_v3_0.1.4.instrumented.js', result);
console.log('written', result.length);
