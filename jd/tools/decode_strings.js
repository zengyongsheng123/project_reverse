const fs = require('fs');
const file = process.argv[2];
const src = fs.readFileSync(file, 'utf8');

// 动态提取解码器函数体并求值
const m = src.match(/function _\w+\(s\)\{var o='';[\s\S]*?return o;\}/);
if (!m) { console.error('decoder not found'); process.exit(1); }
const decoderName = m[0].match(/function (_\w+)\(/)[1];
eval(m[0]);

// 用 Function 构造解码器，避免 eval 作用域问题
const decode = new Function(m[0] + '; return ' + decoderName + ';')();

const re = new RegExp(decoderName + '\\("((?:[^"\\\\]|\\\\.)*)"\\)', 'g');
const seen = new Set();
const out = [];
let mm;
while ((mm = re.exec(src)) !== null) {
  let raw;
  try { raw = JSON.parse('"' + mm[1] + '"'); } catch (e) { continue; }
  const d = decode(raw);
  if (!seen.has(d)) { seen.add(d); out.push(d); }
}
fs.writeFileSync(process.argv[3], out.join('\n'), 'utf8');
console.log('decoded', out.length, 'unique strings ->', process.argv[3]);
