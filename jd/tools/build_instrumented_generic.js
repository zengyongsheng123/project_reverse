// 通用 JSVMP 插桩器：自动识别所有 stack-machine dispatch 循环并注入日志
// 用法: node build_instrumented_generic.js <in.js> <out.js>
const fs = require('fs');
const inFile = process.argv[2], outFile = process.argv[3];
let src = fs.readFileSync(inFile, 'utf8');

// 找出所有 for(;;){switch(X[PC++]){ 循环
const loopRe = /for\(;;\)\{switch\((\w+)\[(\w+)\+\+\]\)\{/g;
const loops = [];
let m;
while ((m = loopRe.exec(src)) !== null) {
  loops.push({ begin: m.index, codeVar: m[1], pcVar: m[2] });
}
console.log('found', loops.length, 'dispatch loops');

// 对每个 loop，找其 switch 的结束位置（匹配的最后一个 '}}' 不好找；
// 用下一个 'for(;;){switch' 或文件尾界定区域，区域内做 case 替换）
let totalInjected = 0;

function processLoop(seg) {
  // seg = switch 内部文本（含 case ... break; ...）
  // 表名: _1jhe5 这种，偏移常量 343
  let injected = 0;
  // case 体: case N:BODYbreak;   （BODY 不含 break）
  const caseRe = /case (\d+):((?:(?!break;).)*?)break;/g;
  seg = seg.replace(caseRe, (whole, op, body) => {
    // 识别栈变量
    const pushM = body.match(/(\w+)\.push\(/);
    const stackVar = pushM ? pushM[1] : null;
    // 表引用: _1jhe5[343+l[t++]] → table=_1jhe5, off=343, idxVar=l, pcVar=t
    const tblM = body.match(/(_\w+)\[(\d+)\+(\w+)\[(\w+)\+\+\]\]/);
    const callM = body.match(/(\w+)\.call\(/);
    const logParts = [];

    // 1) 字符串常量 push: X.push(TBL[OFF+IV[PV++]])
    let r = body.match(new RegExp(`\\b${stackVar}\\.push\\((_\\w+)\\[(\\d+)\\+(\\w+)\\[(\\w+)\\+\\+\\]\\]\\)`));
    if (r) {
      const pre = `__vlog(${r[4]}-1,${op},"str "+${r[1]}[${r[2]}+${r[3]}[${r[4]}]]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 2) 属性访问 push 型: X.push(X[X.length-1]);X[X.length-2]=X[X.length-2][TBL[...]]
    r = body.match(new RegExp(`\\b${stackVar}\\.push\\(${stackVar}\\[${stackVar}\\.length-1\\]\\);${stackVar}\\[${stackVar}\\.length-2\\]=${stackVar}\\[${stackVar}\\.length-2\\]\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[(\\w+)\\+\\+\\]\\]\\]`));
    if (r) {
      const pre = `__vlog(${r[4]}-1,${op},"prop ."+${r[1]}[${r[2]}+${r[3]}[${r[4]}]]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 3) 属性赋值型: X[X.length-1]=X[X.length-1][TBL[...]]
    r = body.match(new RegExp(`\\b${stackVar}\\[${stackVar}\\.length-1\\]=${stackVar}\\[${stackVar}\\.length-1\\]\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[(\\w+)\\+\\+\\]\\]\\]`));
    if (r) {
      const pre = `__vlog(${r[4]}-1,${op},"prop ."+${r[1]}[${r[2]}+${r[3]}[${r[4]}]]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 4) this 属性: X.push(this[TBL[...]])
    r = body.match(new RegExp(`\\b${stackVar}\\.push\\(this\\[(_\\w+)\\[(\\d+)\\+(\\w+)\\[(\\w+)\\+\\+\\]\\]\\]\\)`));
    if (r) {
      const pre = `__vlog(${r[4]}-1,${op},"this."+${r[1]}[${r[2]}+${r[3]}[${r[4]}]]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 5) 通用 call: 找 N = call 的参数槽位深度
    const callFull = body.match(new RegExp(`${stackVar}\\[${stackVar}\\.length-(\\d+)\\]=(\\w+)\\.call\\(`));
    if (callFull) {
      const depth = parseInt(callFull[1]); // fn 所在槽: len-depth
      const pcV = loops_pcVar;
      const args = [];
      for (let k = depth - 1; k >= 1; k--) args.push(`__s(${stackVar}[${stackVar}.length-${k}])`);
      const pre = `__vlog(${pcV}-1,${op},"call${depth - 2} "+__s(${stackVar}[${stackVar}.length-${depth}])+" <= ${args.join('","') ? '' : ''}${args.join('","')}");`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 6) return: return X.pop() / return;
    r = body.match(new RegExp(`return ${stackVar}\\.pop\\(\\)`));
    if (r) {
      const pre = `__vlog(${loops_pcVar}-1,${op},"ret "+__s(${stackVar}[${stackVar}.length-1]));`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 7) int push: X.push(VAR[PC++])
    r = body.match(new RegExp(`\\b${stackVar}\\.push\\((\\w+)\\[(\\w+)\\+\\+\\]\\)`));
    if (r) {
      const pre = `__vlog(${r[2]}-1,${op},"int "+${r[1]}[${r[2]}]);`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    // 8) jif: if(X.pop())++PC;else PC+=VAR[PC]
    r = body.match(new RegExp(`if\\(${stackVar}\\.pop\\(\\)\\)\\+\\+(\\w+);else (\\w+)\\+=(\\w+)\\[(\\w+)\\]`));
    if (r) {
      const pre = `__vlog(${r[1]}-1,${op},"jif");`;
      injected++;
      return `case ${op}:${pre}${body}break;`;
    }
    return whole;
  });
  return { seg, injected };
}

// 从后往前处理，避免偏移失效
let result = src;
for (let i = loops.length - 1; i >= 0; i--) {
  const lp = loops[i];
  const regionEnd = i + 1 < loops.length ? loops[i + 1].begin : result.length;
  let seg = result.slice(lp.begin, regionEnd);
  global.loops_pcVar = lp.pcVar;
  const { seg: newSeg, injected } = processLoop(seg);
  totalInjected += injected;
  result = result.slice(0, lp.begin) + newSeg + result.slice(regionEnd);
}
console.log('total injected cases:', totalInjected);
fs.writeFileSync(outFile, result);
console.log('written', outFile, result.length, 'bytes');
