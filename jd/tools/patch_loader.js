// 给旧 loader 打日志补丁：观察 main 加载后 ParamsSignMain 绑定情况
const fs = require('fs');
let src = fs.readFileSync(__dirname + '/../js/js_security_v3_0.1.8.js', 'utf8');

function rep(oldStr, newStr) {
  const n = src.split(oldStr).length - 1;
  if (n !== 1) { console.error('count=' + n + ' :: ' + oldStr.slice(0, 60)); process.exit(1); }
  src = src.split(oldStr).join(newStr);
}

// main js 加载完成后打印绑定
rep('wm("https://storage.360buyimg.com/webcontainer/main/js_security_v3_main_0.1.8.js?v="+ib(Gy()-36e5*1.1,"yyyyMMdd"),1e3,2).then((function(t){console.log("load js success!")}))',
    'wm("https://storage.360buyimg.com/webcontainer/main/js_security_v3_main_0.1.8.js?v="+ib(Gy()-36e5*1.1,"yyyyMMdd"),1e3,2).then((function(t){console.log("load js success! typeof PSM=",typeof window.ParamsSignMain, "keys:", Object.keys(window).filter(function(k){return /param|sign|h5/i.test(k)}).join(","))}))');

// new window.ParamsSignMain 前打印
rep('c=new window.ParamsSignMain({appId:this.__appId',
    'console.log("BEFORE-NEW-PSM typeof=",typeof window.ParamsSignMain);c=new window.ParamsSignMain({appId:this.__appId');

fs.writeFileSync(__dirname + '/../js/js_security_v3_0.1.8.patched.js', src);
console.log('patched loader written');
