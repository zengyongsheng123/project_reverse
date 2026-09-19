// 对 js_security_v3_0.1.4.js 的 _sdnmd VM 分发循环做日志插桩（真正的签名 VM）
const fs = require('fs');
let src = fs.readFileSync(__dirname + '/../js/js_security_v3_0.1.4.js', 'utf8');

const start = src.indexOf('prototype._$sdnmd=function(');
const end = src.indexOf('_$mx.prototype.sign=function(', start);
if (start < 0 || end < 0) { console.error('region not found'); process.exit(1); }
let seg = src.slice(start, end);

function rep(oldStr, newStr) {
  const n = seg.split(oldStr).length - 1;
  if (n !== 1) { console.error('count=' + n + ' :: ' + oldStr.slice(0, 70)); process.exit(1); }
  seg = seg.split(oldStr).join(newStr);
}

rep('case 3:m.push(_$Pd);break;',
    'case 3:__vlog(t-1,3,"pushPd "+__s(_$Pd));m.push(_$Pd);break;');
rep('case 5:if(m.pop())++t;else t+=l[t];break;',
    'case 5:__vlog(t-1,5,"jif "+__s(m[m.length-1])+" -> "+l[t]);if(m.pop())++t;else t+=l[t];break;');
rep('case 6:if(m[m.length-2]!=null){m[m.length-3]=q.call(m[m.length-3],m[m.length-2],m[m.length-1]);m.length-=2;}else{e=m[m.length-3];m[m.length-3]=e(m[m.length-1]);m.length-=2;}break;',
    'case 6:__vlog(t-1,6,"call1 "+__s(m[m.length-3])+" <= "+__s(m[m.length-2])+"|"+__s(m[m.length-1]));if(m[m.length-2]!=null){m[m.length-3]=q.call(m[m.length-3],m[m.length-2],m[m.length-1]);m.length-=2;}else{e=m[m.length-3];m[m.length-3]=e(m[m.length-1]);m.length-=2;}break;');
rep('case 8:e=m.pop();m[m.length-1]-=e;break;',
    'case 8:__vlog(t-1,8,"sub "+__s(m[m.length-2])+"-"+__s(m[m.length-1]));e=m.pop();m[m.length-1]-=e;break;');
rep('case 15:m.push(_$Px);break;',
    'case 15:__vlog(t-1,15,"pushPx "+__s(_$Px));m.push(_$Px);break;');
rep('case 16:m.push(m[m.length-1]);m[m.length-2]=m[m.length-2][_1jhe5[343+l[t++]]];break;',
    'case 16:__vlog(t-1,16,"prop ."+_1jhe5[343+l[t]]);m.push(m[m.length-1]);m[m.length-2]=m[m.length-2][_1jhe5[343+l[t++]]];break;');
rep('case 36:m[m.length-5]=q.call(m[m.length-5],m[m.length-4],m[m.length-3],m[m.length-2],m[m.length-1]);m.length-=4;break;',
    'case 36:__vlog(t-1,36,"call4 "+__s(m[m.length-5])+" <= "+__s(m[m.length-4])+"|"+__s(m[m.length-3])+"|"+__s(m[m.length-2])+"|"+__s(m[m.length-1]));m[m.length-5]=q.call(m[m.length-5],m[m.length-4],m[m.length-3],m[m.length-2],m[m.length-1]);m.length-=4;break;');
rep('case 43:m.push(_1jhe5[343+l[t++]]);break;',
    'case 43:__vlog(t-1,43,"str "+_1jhe5[343+l[t]]);m.push(_1jhe5[343+l[t++]]);break;');
rep('case 44:if(m[m.length-1]!=null){m[m.length-2]=q.call(m[m.length-2],m[m.length-1]);}else{e=m[m.length-2];m[m.length-2]=e();}m.length--;break;',
    'case 44:__vlog(t-1,44,"callA "+__s(m[m.length-2])+" <= "+__s(m[m.length-1]));if(m[m.length-1]!=null){m[m.length-2]=q.call(m[m.length-2],m[m.length-1]);}else{e=m[m.length-2];m[m.length-2]=e();}m.length--;break;');
rep('case 55:m.push(this[_1jhe5[343+l[t++]]]);break;',
    'case 55:__vlog(t-1,55,"this."+_1jhe5[343+l[t]]+"="+__s(this[_1jhe5[343+l[t]]]));m.push(this[_1jhe5[343+l[t++]]]);break;');
rep('case 71:m[m.length-4]=q.call(m[m.length-4],m[m.length-3],m[m.length-2],m[m.length-1]);m.length-=3;break;',
    'case 71:__vlog(t-1,71,"call3 "+__s(m[m.length-4])+" <= "+__s(m[m.length-3])+"|"+__s(m[m.length-2])+"|"+__s(m[m.length-1]));m[m.length-4]=q.call(m[m.length-4],m[m.length-3],m[m.length-2],m[m.length-1]);m.length-=3;break;');
rep('case 84:m.push(l[t++]);break;',
    'case 84:__vlog(t-1,84,"int "+l[t]);m.push(l[t++]);break;');
rep('case 85:e=m.pop();m[m.length-1]=m[m.length-1]==e;break;',
    'case 85:__vlog(t-1,85,"eq "+__s(m[m.length-2])+"=="+__s(m[m.length-1]));e=m.pop();m[m.length-1]=m[m.length-1]==e;break;');
rep('case 87:return m.pop();break;',
    'case 87:__vlog(t-1,87,"ret "+__s(m[m.length-1]));return m.pop();break;');

const out = src.slice(0, start) + seg + src.slice(end);
fs.writeFileSync(__dirname + '//../js/js_security_v3_0.1.4.instrumented.js', out);
console.log('instrumented 0.1.4 written,', out.length, 'bytes');
