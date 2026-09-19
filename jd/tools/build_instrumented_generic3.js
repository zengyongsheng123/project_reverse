// 通用 JSVMP 插桩器 v3：花括号配对定界 switch 范围，排除嵌套子循环区间
// 用法: node build_instrumented_generic3.js <in.js> <out.js>
const fs = require('fs');
const inFile = process.argv[2], outFile = process.argv[3];
const src = fs.readFileSync(inFile, 'utf8');

const loopRe = /var (\w+)=\[\];var (\w+)=\d+;[\s\S]{0,60}?for\(;;\)\{switch\((\w+)\[(\w+)\+\+\]\)\{/g;
const loops = [];
let m;
while ((m = loopRe.exec(src)) !== null) {
  loops.push({ begin: m.index, stackVar: m[1], codeVar: m[3], pcVar: m[4], switchOpen: m.index + m[0].lastIndexOf('{switch') + '{switch'.length - 1 });
}
console.log('found', loops.length, 'dispatch loops');
if (!loops.length) process.exit(1);

// 花括号配对（跳过字符串）
function findClose(text, openPos) {
  let depth = 0, i = openPos, q = null;
  while (i < text.length) {
    const ch = text[i];
    if (q) {
      if (ch === '\\') { i += 2; continue; }
      if (ch === q) q = null;
    } else if (ch === '"' || ch === "'" || ch === '`') q = ch;
    else if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return i; }
    i++;
  }
  return -1;
}

for (const lp of loops) {
  lp.end = findClose(src, lp.switchOpen);
  if (lp.end < 0) { console.error('no close for loop at', lp.begin); process.exit(1); }
}
// 父子关系
for (const lp of loops) {
  lp.children = loops.filter(c => c !== lp && c.begin > lp.begin && c.end < lp.end);
}

let totalInjected = 0;
function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function injectCases(seg, stackVar, pcVar) {
  let injected = 0;
  const SV = esc(stackVar), PC = esc(pcVar);
  const caseRe = /case (\d+):((?:(?!break;).)*?)break;/g;
  seg = seg.replace(caseRe, (whole, op, body) => {
    let r = body.match(new RegExp(`${SV}\\[${SV}\\.length-(\\d+)\\]=(\\w+)\\.call\\(`));
    if (r) {
      const depth = parseInt(r[1]);
      const fnSlot = `__s(${SV}[${SV}.length-${depth}])`;
      const thisSlot = `__s(${SV}[${SV}.length-${depth - 1}])`;
      const argSlots = [];
      for (let k = depth - 2; k >= 1; k--) argSlots.push(`__s(${SV}[${SV}.length-${k}])`);
      const pre = `__vlog(${pcVar}-1,${op},"call d${depth} fn="+${fnSlot}+" this="+${thisSlot}${argSlots.length ? '+" args="+' + argSlots.join('+","+') : ''});`;
      injected++; return `case ${op}:${pre}${body}break;`;
    }
    r = body.match(new RegExp(`return ${SV}\\.pop\\(\\)`));
    if (r) { injected++; return `case ${op}:__vlog(${pcVar}-1,${op},"ret "+__s(${SV}[${SV}.length-1]));${body}break;`; }
    r = body.match(new RegExp(`${SV}\\[${SV}\\.length-1\\]=${SV}\\[${SV}\\.length-1\\]\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[${PC}\\+\\+\\]\\]\\]`));
    if (r) { injected++; return `case ${op}:__vlog(${pcVar}-1,${op},"prop ."+${r[1]}[${r[2]}+${r[3]}[${pcVar}]]);${body}break;`; }
    r = body.match(new RegExp(`${SV}\\.push\\(${SV}\\[${SV}\\.length-1\\]\\);${SV}\\[${SV}\\.length-2\\]=${SV}\\[${SV}\\.length-2\\]\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[${PC}\\+\\+\\]\\]\\]`));
    if (r) { injected++; return `case ${op}:__vlog(${pcVar}-1,${op},"prop ."+${r[1]}[${r[2]}+${r[3]}[${pcVar}]]);${body}break;`; }
    r = body.match(new RegExp(`${SV}\\.push\\((_\\w+)\\[(\\d+)\\+(\\w+)\\[${PC}\\+\\+\\]\\]\\)`));
    if (r) { injected++; return `case ${op}:__vlog(${pcVar}-1,${op},"str "+${r[1]}[${r[2]}+${r[3]}[${pcVar}]]);${body}break;`; }
    r = body.match(new RegExp(`${SV}\\.push\\(this\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[${PC}\\+\\+\\]\\]\\]\\)`));
    if (r) { injected++; return `case ${op}:__vlog(${pcVar}-1,${op},"this."+${r[1]}[${r[2]}+${r[3]}[${pcVar}]]);${body}break;`; }
    r = body.match(new RegExp(`${SV}\\.push\\((\\w+)\\[${PC}\\+\\+\\]\\)`));
    if (r) { injected++; return `case ${op}:__vlog(${pcVar}-1,${op},"pushc "+${r[1]}[${pcVar}]);${body}break;`; }
    r = body.match(new RegExp(`if\\(${SV}\\.pop\\(\\)\\)\\+\\+${PC};else ${PC}\\+=(\\w+)\\[${PC}\\]`));
    if (r) { injected++; return `case ${op}:__vlog(${pcVar}-1,${op},"jif "+__s(${SV}[${SV}.length-1])+" off="+${r[1]}[${pcVar}]);${body}break;`; }
    return whole;
  });
  return { seg, injected };
}

// 从内层到外层处理（begin 降序），每段排除直接子循环区间
const sorted = [...loops].sort((a, b) => b.begin - a.begin);
let result = src;
for (const lp of sorted) {
  // 该循环 switch 区间 [switchOpen+1, end)，拆分为排除 children 的段
  const spans = [];
  let cur = lp.switchOpen + 1;
  const kids = [...lp.children].sort((a, b) => a.begin - b.begin);
  for (const c of kids) { spans.push([cur, c.begin]); cur = c.end + 1; }
  spans.push([cur, lp.end]);
  // 从后往前替换，保持偏移
  for (let i = spans.length - 1; i >= 0; i--) {
    const [a, b] = spans[i];
    if (b <= a) continue;
    const seg = result.slice(a, b);
    const { seg: newSeg, injected } = injectCases(seg, lp.stackVar, lp.pcVar);
    totalInjected += injected;
    result = result.slice(0, a) + newSeg + result.slice(b);
  }
}
console.log('total injected cases:', totalInjected);
fs.writeFileSync(outFile, result);
console.log('written', outFile, result.length, 'bytes');
