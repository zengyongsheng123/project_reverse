// 对 security_v3_main.js 的 _sdnmd VM 分发循环做日志插桩
const fs = require('fs');
const src = fs.readFileSync(__dirname + '/../js/security_v3_main.js', 'utf8');

const start = src.indexOf('_$Gn.prototype._$sdnmd=function(');
const end = src.indexOf('_$Gn.prototype.sign=function(', start);
if (start < 0 || end < 0) { console.error('region not found'); process.exit(1); }
let seg = src.slice(start, end);

function rep(oldStr, newStr) {
  const n = seg.split(oldStr).length - 1;
  if (n !== 1) { console.error('replace count=' + n + ' for: ' + oldStr.slice(0, 60)); process.exit(1); }
  seg = seg.split(oldStr).join(newStr);
}

// 各 opcode 插桩：记录 pc、操作数摘要。原语义保持不变。
rep('case 2:x[x.length-4]=n.call(x[x.length-4],x[x.length-3],x[x.length-2],x[x.length-1]);x.length-=3;break;',
    'case 2:__vlog(q-1,2,"call3 "+__s(x[x.length-4])+" <= "+__s(x[x.length-3])+"|"+__s(x[x.length-2])+"|"+__s(x[x.length-1]));x[x.length-4]=n.call(x[x.length-4],x[x.length-3],x[x.length-2],x[x.length-1]);x.length-=3;break;');

rep('case 6:x.push(g[q++]);break;',
    'case 6:__vlog(q-1,6,"pushi "+g[q]);x.push(g[q++]);break;');

rep('case 38:j=x.pop();x[x.length-1]-=j;break;',
    'case 38:__vlog(q-1,38,"sub "+__s(x[x.length-2])+" - "+__s(x[x.length-1]));j=x.pop();x[x.length-1]-=j;break;');

rep('case 42:x.push(this[_1vh6r[359+g[q++]]]);break;',
    'case 42:__vlog(q-1,42,"this."+_1vh6r[359+g[q]]);x.push(this[_1vh6r[359+g[q++]]]);break;');

rep('case 43:j=x.pop();x[x.length-1]=x[x.length-1]==j;break;',
    'case 43:__vlog(q-1,43,"eq "+__s(x[x.length-2])+" == "+__s(x[x.length-1]));j=x.pop();x[x.length-1]=x[x.length-1]==j;break;');

rep('case 63:if(x[x.length-2]!=null){x[x.length-3]=n.call(x[x.length-3],x[x.length-2],x[x.length-1]);x.length-=2;}else{j=x[x.length-3];x[x.length-3]=j(x[x.length-1]);x.length-=2;}break;',
    'case 63:__vlog(q-1,63,"call1 "+__s(x[x.length-3])+" <= "+__s(x[x.length-2])+"|"+__s(x[x.length-1]));if(x[x.length-2]!=null){x[x.length-3]=n.call(x[x.length-3],x[x.length-2],x[x.length-1]);x.length-=2;}else{j=x[x.length-3];x[x.length-3]=j(x[x.length-1]);x.length-=2;}break;');

rep('case 65:if(x.pop())++q;else q+=g[q];break;',
    'case 65:__vlog(q-1,65,"jif "+__s(x[x.length-1])+" -> "+g[q]);if(x.pop())++q;else q+=g[q];break;');

rep('case 71:x[x.length-5]=n.call(x[x.length-5],x[x.length-4],x[x.length-3],x[x.length-2],x[x.length-1]);x.length-=4;break;',
    'case 71:__vlog(q-1,71,"call4 "+__s(x[x.length-5])+" <= "+__s(x[x.length-4])+"|"+__s(x[x.length-3])+"|"+__s(x[x.length-2])+"|"+__s(x[x.length-1]));x[x.length-5]=n.call(x[x.length-5],x[x.length-4],x[x.length-3],x[x.length-2],x[x.length-1]);x.length-=4;break;');

rep('case 78:x.push(x[x.length-1]);x[x.length-2]=x[x.length-2][_1vh6r[359+g[q++]]];break;',
    'case 78:__vlog(q-1,78,"prop ."+_1vh6r[359+g[q]]);x.push(x[x.length-1]);x[x.length-2]=x[x.length-2][_1vh6r[359+g[q++]]];break;');

rep('case 79:x.push(_1vh6r[359+g[q++]]);break;',
    'case 79:__vlog(q-1,79,"str "+_1vh6r[359+g[q]]);x.push(_1vh6r[359+g[q++]]);break;');

rep('case 82:return x.pop();break;',
    'case 82:__vlog(q-1,82,"ret "+__s(x[x.length-1]));return x.pop();break;');

rep('case 95:if(x[x.length-1]!=null){x[x.length-2]=n.call(x[x.length-2],x[x.length-1]);}else{j=x[x.length-2];x[x.length-2]=j();}x.length--;break;',
    'case 95:__vlog(q-1,95,"call0 "+__s(x[x.length-2])+" <= "+__s(x[x.length-1]));if(x[x.length-1]!=null){x[x.length-2]=n.call(x[x.length-2],x[x.length-1]);}else{j=x[x.length-2];x[x.length-2]=j();}x.length--;break;');

const out = src.slice(0, start) + seg + src.slice(end);
fs.writeFileSync(__dirname + '/../js/security_v3_main.instrumented.js', out);
console.log('instrumented written,', out.length, 'bytes');
