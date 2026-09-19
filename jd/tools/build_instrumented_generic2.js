// 通用 JSVMP 插桩器 v2：按循环提取栈变量，覆盖 call/ret/prop/str/int/jif
// 用法: node build_instrumented_generic2.js <in.js> <out.js>
const fs = require('fs');
const inFile = process.argv[2], outFile = process.argv[3];
let src = fs.readFileSync(inFile, 'utf8');

const loopRe = /var (\w+)=\[\];var (\w+)=\d+;[\s\S]{0,60}?for\(;;\)\{switch\((\w+)\[(\w+)\+\+\]\)\{/g;
const loops = [];
let m;
while ((m = loopRe.exec(src)) !== null) {
  loops.push({ begin: m.index, stackVar: m[1], tableVar: m[3], pcVar: m[4] });
}
console.log('found', loops.length, 'dispatch loops');
if (loops.length === 0) { process.exit(1); }

let totalInjected = 0;

function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function processLoop(seg, stackVar, pcVar) {
  let injected = 0;
  const caseRe = /case (\d+):((?:(?!break;).)*?)break;/g;
  seg = seg.replace(caseRe, (whole, op, body) => {
    const SV = esc(stackVar);
    const PC = esc(pcVar);
    // 1) call: SV[SV.length-D]=FN.call(  (FN 是任意标识符)
    let r = body.match(new RegExp(`${SV}\\[${SV}\\.length-(\\d+)\\]=(\\w+)\\.call\\(`));
    if (r) {
      const depth = parseInt(r[1]);
      const fnSlot = `__s(${SV}[${SV}.length-${depth}])`;
      const thisSlot = `__s(${SV}[${SV}.length-${depth - 1}])`;
      const argSlots = [];
      for (let k = depth - 2; k >= 1; k--) argSlots.push(`__s(${SV}[${SV}.length-${k}])`);
      const pre = `__vlog(${pcVar}-1,${op},"call d${depth} fn="+${fnSlot}+" this="+${thisSlot}${argSlots.length ? '+" args="+' + argSlots.join('+","+') : ''});`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 2) return SV.pop()
    r = body.match(new RegExp(`return ${SV}\\.pop\\(\\)`));
    if (r) {
      const pre = `__vlog(${pcVar}-1,${op},"ret "+__s(${SV}[${SV}.length-1]));`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 3) prop get into top: SV[SV.length-1]=SV[SV.length-1][TBL[OFF+IV[PV++]]]
    r = body.match(new RegExp(`${SV}\\[${SV}\\.length-1\\]=${SV}\\[${SV}\\.length-1\\]\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[${PC}\\+\\+\\]\\]\\]`));
    if (r) {
      const pre = `__vlog(${pcVar}-1,${op},"prop ."+${r[1]}[${r[2]}+${r[3]}[${pcVar}]]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 4) prop access dup: SV.push(SV[SV.length-1]);SV[SV.length-2]=SV[SV.length-2][TBL[..]]
    r = body.match(new RegExp(`${SV}\\.push\\(${SV}\\[${SV}\\.length-1\\]\\);${SV}\\[${SV}\\.length-2\\]=${SV}\\[${SV}\\.length-2\\]\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[${PC}\\+\\+\\]\\]\\]`));
    if (r) {
      const pre = `__vlog(${pcVar}-1,${op},"prop ."+${r[1]}[${r[2]}+${r[3]}[${pcVar}]]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 5) str push: SV.push(TBL[OFF+IV[PV++]])
    r = body.match(new RegExp(`${SV}\\.push\\((_\\w+)\\[(\\d+)\\+(\\w+)\\[${PC}\\+\\+\\]\\]\\)`));
    if (r) {
      const pre = `__vlog(${pcVar}-1,${op},"str "+${r[1]}[${r[2]}+${r[3]}[${pcVar}]]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 6) this prop: SV.push(this[TBL[OFF+IV[PV++]])
    r = body.match(new RegExp(`${SV}\\.push\\(this\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[${PC}\\+\\+\\]\\]\\]\\)`));
    if (r) {
      const pre = `__vlog(${pcVar}-1,${op},"this."+${r[1]}[${r[2]}+${r[3]}[${pcVar}]]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 7) int push: SV.push(CODE[PC++])
    r = body.match(new RegExp(`${SV}\\.push\\((\\w+)\\[${PC}\\+\\+\\]\\)`));
    if (r) {
      const pre = `__vlog(${pcVar}-1,${op},"pushc "+${r[1]}[${pcVar}]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 8) jif
    r = body.match(new RegExp(`if\\(${SV}\\.pop\\(\\)\\)\\+\\+${PC};else ${PC}\\+=(\\w+)\\[${PC}\\]`));
    if (r) {
      const pre = `__vlog(${pcVar}-1,${op},"jif "+__s(${SV}[${SV}.length-1])+" off="+${r[1]}[${pcVar}]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    return whole;
  });
  return { seg, injected };
}

let result = src;
for (let i = loops.length - 1; i >= 0; i--) {
  const lp = loops[i];
  const regionEnd = i + 1 < loops.length ? loops[i + 1].begin : result.length;
  let seg = result.slice(lp.begin, regionEnd);
  const { seg: newSeg, injected } = processLoop(seg, lp.stackVar, lp.pcVar);
  totalInjected += injected;
  result = result.slice(0, lp.begin) + newSeg + result.slice(regionEnd);
}
console.log('total injected cases:', totalInjected);
fs.writeFileSync(outFile, result);
console.log('written', outFile, result.length, 'bytes');
