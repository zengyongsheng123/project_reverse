# -*- coding: utf-8 -*-
"""插桩采集 v2：追踪首个 pc_home_feed 签名的完整 VM 执行流"""
import json
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).parent
OUT = ROOT / "recon"
INST = (ROOT / "js" / "js_security_v3_0.1.4.instrumented.js").read_text(encoding="utf-8")

INIT_JS = r"""
window.__vmlog = [];
window.__h5log = [];
window.__vmtrace = false;
window.__traced = false;
window.__signIdx = 0;
window.__s = function(v){
  try{
    if(v===null) return 'null';
    if(v===undefined) return 'u';
    const t = typeof v;
    if(t==='number'||t==='boolean') return String(v);
    if(t==='string') return v.length>1200 ? v.slice(0,1200)+'~' : JSON.stringify(v);
    if(t==='function'){ const n=v.name||'anon'; return 'f<'+n+'>'; }
    if(Array.isArray(v)) return '['+v.slice(0,10).map(x=>{try{return window.__s(x)}catch(e){return '?'}}).join(',')+']';
    if(v instanceof Error) return 'Err:'+v.message;
    if(v && v.words && typeof v.sigBytes==='number') return 'WA('+(v.words||[]).join(',')+';'+v.sigBytes+')';
    if(v && v.constructor && v.constructor.name && ['Uint8Array','ArrayBuffer','DataView','Int8Array'].includes(v.constructor.name)) return v.constructor.name+'('+v.byteLength+'){'+Array.prototype.slice.call(new Uint8Array(v.buffer||v),0,16).join(',')+'}';
    try{ let j=JSON.stringify(v); if(j && j!=='{}') return j.length>300?j.slice(0,300)+'~':j; }catch(e){}
    return 'Obj<'+((v&&v.constructor&&v.constructor.name)||'?')+'>';
  }catch(e){ return '<?>_'+typeof v }
};
window.__vlog = function(pc,op,detail){
  if(!window.__vmtrace) return;
  window.__vmlog.push(pc+'|'+op+'|'+detail);
  if(window.__vmlog.length > 1500000) window.__vmtrace = false;
};
try{ Object.defineProperty(navigator, 'webdriver', {get: () => undefined}); }catch(e){}
(function(){
  const OF = Function;
  window.__funcs = [];
  const handler = { construct: function(t, args){
      const src = args[args.length-1];
      if(typeof src==='string' && src.length>100) window.__funcs.push(src);
      return new OF(...args);
    }, apply: function(t, th, args){
      const src = args[args.length-1];
      if(typeof src==='string' && src.length>100) window.__funcs.push(src);
      return OF.apply(th, args);
    }};
  try{ Function = new Proxy(OF, handler); }catch(e){}
})();
"""

PATCH_JS = r"""
(function(){
  function patchProto(P, tag){
    if(!P || !P.prototype) return 'no-proto';
    const proto = P.prototype;
    for(const m of ['signSync','sign']){
      const orig = proto[m];
      if(typeof orig !== 'function' || orig.__patched) continue;
      const wrapped = function(cfg){
        const idx = ++window.__signIdx;
        const wantTrace = !window.__traced && cfg && cfg.functionId === 'pc_home_feed';
        if(wantTrace){
          window.__vlog(-1,'CACHE','algos='+JSON.stringify(this._algos).slice(0,2000));
          window.__vmtrace = true; window.__vlog(-1,'SIGN','START '+idx);
        }
        window.__h5log.push({t:'in', idx:idx, tag:tag, m:m, cfg: JSON.parse(JSON.stringify(cfg||null))});
        const r = orig.call(this, cfg);
        Promise.resolve(r).then(rr=>{
          if(wantTrace){ window.__vlog(-1,'SIGN','END '+idx); window.__vmtrace = false; window.__traced = true; }
          window.__h5log.push({t:'out', idx:idx, tag:tag, m:m, result: (rr&&typeof rr==='object')? (rr.h5st||JSON.stringify(Object.keys(rr))) : String(rr)});
          return rr;
        });
        return r;
      };
      wrapped.__patched = true;
      proto[m] = wrapped;
    }
    try{
      const os = proto._$sdnmd;
      if(typeof os === 'function' && !os.__errpatched){
        const w2 = function(cfg){ try{ return os.call(this, cfg); }catch(e){ window.__h5log.push({t:'sdnmd-err', msg:String(e&&e.message||e), stack:String(e&&e.stack||'').slice(0,500)}); throw e; } };
        w2.__errpatched = true; w2.__patched = true;
        proto._$sdnmd = w2;
      }
    }catch(e){}
    return 'ok';
  }
  const a = patchProto(window.ParamsSignMain, 'Main');
  const b = patchProto(window.ParamsSign, 'Old');
  return 'patched Main='+a+' Old='+b;
})()
"""

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=False,
                                args=["--disable-blink-features=AutomationControlled"])
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, locale="zh-CN")
    ctx.add_init_script(INIT_JS)
    page = ctx.new_page()
    def serve_inst(route):
        route.fulfill(body=INST, content_type="application/javascript", status=200)

    page.route("**/js_security_v3_0.1.4.js*", serve_inst)
    reqs = []
    def on_req(r):
        try:
            pd = r.post_data or ""
        except Exception:
            pd = ""
        reqs.append((r.method, r.url, pd))
    page.on("request", on_req)
    page.goto("https://www.jd.com/", wait_until="domcontentloaded", timeout=60000)
    page.wait_for_timeout(6000)
    print("patch:", page.evaluate(PATCH_JS))

    for i in range(10):
        page.mouse.wheel(0, 1500)
        page.wait_for_timeout(1200)
    page.wait_for_timeout(5000)

    h5log = page.evaluate("window.__h5log")
    vmlog = page.evaluate("window.__vmlog")
    traced = page.evaluate("window.__traced")
    (OUT / "h5log2.json").write_text(json.dumps(h5log, ensure_ascii=False, indent=1), encoding="utf-8")
    (OUT / "vm_trace.txt").write_text("\n".join(vmlog), encoding="utf-8")
    funcs = page.evaluate("window.__funcs || []")
    (OUT / "gen_funcs.json").write_text(json.dumps(funcs, ensure_ascii=False, indent=1), encoding="utf-8")
    print("captured Function sources:", len(funcs))
    with open(OUT / "net_requests.txt", "w", encoding="utf-8") as fh:
        for m, u, pd in reqs:
            if "jd.com" in u:
                fh.write(f"{m} {u}\n{pd[:800]}\n---\n")
    print("h5log:", len(h5log), "vmlog lines:", len(vmlog), "traced:", traced)
    ins = [e for e in h5log if e.get("t") == "in"]
    outs = {e["idx"]: e for e in h5log if e.get("t") == "out"}
    for e in ins:
        o = outs.get(e["idx"])
        print(f"idx={e['idx']} {e['tag']}/{e['m']} fn={e['cfg'].get('functionId') if e.get('cfg') else '?'}")
        if o: print("   out:", str(o.get("result"))[:160])

    # probe _seData1 with chosen inputs
    has = page.evaluate("!!window.__hasher")
    print("hasher available:", has)
    if has:
        res = page.evaluate("""
(function(){
  var f = window.__hasher._seData1;
  var inputs = [];
  var base = 'A'.repeat(60);
  inputs.push(base);
  for(var p=0;p<60;p++){
    var s = base.split(''); s[p]='B'; inputs.push(s.join(''));
  }
  var res = [];
  for(var k=0;k<inputs.length;k++){
    try{ res.push(f.call(window.__hasher, inputs[k])); }
    catch(e){ res.push('ERR:'+e.message); }
  }
  return res;
})()""")
        (OUT / "sedata_sens.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        print("probes:", len(res))
    browser.close()
print("done")
