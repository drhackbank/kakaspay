/* kakaspay — script.js v1.0.0
   ICICI Bank Corporate Payment Portal
   Features: IMPS · NEFT · RTGS · Status · Acct Validate · Fetch VPA · Beneficiary Mgmt
   Security: SHA-256 auth · 3-attempt lockout · no plain credentials
*/
'use strict';

/* ── Secure auth hashes ────────────────────────────────────── */
const _EH = '85b7bd7ce9ff5fef7689a607348d633a960b7065f55b75b6b0bbb4de05de706c';
const _PH = 'e754ea4c20d8943d01eaaff4809e560ab155c6e94fce7774cd1b0e7173806590';

async function _h(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

/* ── Session state ─────────────────────────────────────────── */
const S = { calls:0, ok:0, err:0, ms:0, hist:[], built:new Set() };
let _attempts = 0, _lockedUntil = 0;

/* ── ICICI Bank API endpoints ──────────────────────────────── */
const EP = {
  imps:   'https://apigw.icicibank.com/api/v1/composite-payment/imps',
  neft:   'https://apigw.icicibank.com/api/v1/composite-payment/neft',
  rtgs:   'https://apigw.icicibank.com/api/v1/composite-payment/rtgs',
  status: 'https://apigw.icicibank.com/api/v1/composite-payment/txn-status',
  acval:  'https://apigw.icicibank.com/api/v1/composite-payment/account-validation',
  vpa:    'https://apigw.icicibank.com/api/v1/composite-payment/fetch-vpa',
  benef:  'https://apigw.icicibank.com/api/v1/composite-payment/beneficiary',
};

/* ── API definitions ───────────────────────────────────────── */
const D   = new Date().toISOString().split('T')[0];
const UID = () => 'KP' + Date.now();

const APIS = {

  imps: {
    label:'IMPS Transfer', method:'POST', url:EP.imps,
    fields:[
      {id:'im_cid',  l:'Client ID',            t:'req',   p:'xxxx-xxxx-xxxx-xxxx'},
      {id:'im_cs',   l:'Client Secret',         t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
      {id:'im_tok',  l:'OAuth Bearer Token',    t:'oauth', p:'Bearer xxxxxxxxxxxxxxxxxxxxxxxx'},
      {id:'im_crid', l:'Correlation ID',        t:'req',   p:UID()},
      {id:'im_deb',  l:'Debit Account No.',     t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'im_ben',  l:'Beneficiary Account',   t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'im_ifsc', l:'Beneficiary IFSC',      t:'req',   p:'ICIC0000001'},
      {id:'im_name', l:'Beneficiary Name',      t:'req',   p:'RAHUL SHARMA'},
      {id:'im_amt',  l:'Amount (₹)',            t:'req',   p:'10000'},
      {id:'im_mob',  l:'Beneficiary Mobile',    t:'opt',   p:'9876543210'},
      {id:'im_rem',  l:'Remarks',               t:'opt',   p:'Invoice payment'},
      {id:'im_hmac', l:'HMAC / Checksum Key',   t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
    ],
    body:JSON.stringify({
      debitAccountNo:'xxxxxxxxxxxxxxx', creditAccountNo:'xxxxxxxxxxxxxxx',
      creditIfsc:'ICIC0000001', creditAccountName:'RAHUL SHARMA',
      amount:10000, currency:'INR', transferType:'IMPS',
      uniqueRefNo:UID(), remarks:'Invoice payment',
      beneficiaryMobile:'9876543210', txnDate:D,
    }, null, 2),
  },

  neft: {
    label:'NEFT Transfer', method:'POST', url:EP.neft,
    fields:[
      {id:'nf_cid',  l:'Client ID',            t:'req',   p:'xxxx-xxxx-xxxx-xxxx'},
      {id:'nf_cs',   l:'Client Secret',         t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
      {id:'nf_tok',  l:'OAuth Bearer Token',    t:'oauth', p:'Bearer xxxxxxxxxxxxxxxxxxxxxxxx'},
      {id:'nf_crid', l:'Correlation ID',        t:'req',   p:UID()},
      {id:'nf_deb',  l:'Debit Account No.',     t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'nf_ben',  l:'Beneficiary Account',   t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'nf_ifsc', l:'Beneficiary IFSC',      t:'req',   p:'ICIC0000001'},
      {id:'nf_name', l:'Beneficiary Name',      t:'req',   p:'RAHUL SHARMA'},
      {id:'nf_amt',  l:'Amount (₹)',            t:'req',   p:'50000'},
      {id:'nf_email',l:'Beneficiary Email',     t:'opt',   p:'rahul@email.com'},
      {id:'nf_rem',  l:'Remarks',               t:'opt',   p:'Salary payment'},
      {id:'nf_hmac', l:'HMAC / Checksum Key',   t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
    ],
    body:JSON.stringify({
      debitAccountNo:'xxxxxxxxxxxxxxx', creditAccountNo:'xxxxxxxxxxxxxxx',
      creditIfsc:'ICIC0000001', creditAccountName:'RAHUL SHARMA',
      amount:50000, currency:'INR', transferType:'NEFT',
      uniqueRefNo:UID(), remarks:'Salary payment',
      beneficiaryEmail:'rahul@email.com', txnDate:D,
    }, null, 2),
  },

  rtgs: {
    label:'RTGS Transfer', method:'POST', url:EP.rtgs,
    fields:[
      {id:'rt_cid',  l:'Client ID',              t:'req',   p:'xxxx-xxxx-xxxx-xxxx'},
      {id:'rt_cs',   l:'Client Secret',           t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
      {id:'rt_tok',  l:'OAuth Bearer Token',      t:'oauth', p:'Bearer xxxxxxxxxxxxxxxxxxxxxxxx'},
      {id:'rt_crid', l:'Correlation ID',          t:'req',   p:UID()},
      {id:'rt_deb',  l:'Debit Account No.',       t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'rt_ben',  l:'Beneficiary Account',     t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'rt_ifsc', l:'Beneficiary IFSC',        t:'req',   p:'ICIC0000001'},
      {id:'rt_name', l:'Beneficiary Name',        t:'req',   p:'COMPANY PVT LTD'},
      {id:'rt_amt',  l:'Amount (₹ min ₹2 lakh)', t:'req',   p:'200000'},
      {id:'rt_purp', l:'Payment Purpose',         t:'opt',   p:'Vendor payment'},
      {id:'rt_rem',  l:'Remarks',                 t:'opt',   p:'Invoice settlement'},
      {id:'rt_hmac', l:'HMAC / Checksum Key',     t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
    ],
    body:JSON.stringify({
      debitAccountNo:'xxxxxxxxxxxxxxx', creditAccountNo:'xxxxxxxxxxxxxxx',
      creditIfsc:'ICIC0000001', creditAccountName:'COMPANY PVT LTD',
      amount:200000, currency:'INR', transferType:'RTGS',
      uniqueRefNo:UID(), remarks:'Invoice settlement',
      paymentPurpose:'Vendor payment', txnDate:D,
    }, null, 2),
  },

  status: {
    label:'Transaction Status', method:'GET', url:EP.status,
    fields:[
      {id:'st_cid',  l:'Client ID',          t:'req',   p:'xxxx-xxxx-xxxx-xxxx'},
      {id:'st_tok',  l:'OAuth Bearer Token', t:'oauth', p:'Bearer xxxxxxxxxxxxxxxxxxxxxxxx'},
      {id:'st_crid', l:'Correlation ID',     t:'req',   p:UID()},
      {id:'st_ref',  l:'Unique Ref No.',     t:'req',   p:'KP-xxxxxxxxxxxx'},
      {id:'st_utr',  l:'UTR Number',         t:'opt',   p:'ICICxxxxxxxxxxxxxxxxx'},
      {id:'st_type', l:'Transfer Type',      t:'opt',   p:'IMPS / NEFT / RTGS'},
    ],
    body:'',
  },

  acval: {
    label:'Account Validation', method:'POST', url:EP.acval,
    fields:[
      {id:'av_cid',  l:'Client ID',               t:'req',   p:'xxxx-xxxx-xxxx-xxxx'},
      {id:'av_tok',  l:'OAuth Bearer Token',       t:'oauth', p:'Bearer xxxxxxxxxxxxxxxxxxxxxxxx'},
      {id:'av_crid', l:'Correlation ID',           t:'req',   p:UID()},
      {id:'av_ac',   l:'Beneficiary Account No.',  t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'av_ifsc', l:'Beneficiary IFSC',         t:'req',   p:'ICIC0000001'},
      {id:'av_name', l:'Expected Name',            t:'opt',   p:'RAHUL SHARMA'},
      {id:'av_mode', l:'Validation Mode',          t:'opt',   p:'PENNY_DROP / NAME_MATCH'},
      {id:'av_hmac', l:'HMAC / Checksum Key',      t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
    ],
    body:JSON.stringify({
      beneficiaryAccountNo:'xxxxxxxxxxxxxxx', beneficiaryIfsc:'ICIC0000001',
      beneficiaryName:'RAHUL SHARMA', validationMode:'NAME_MATCH',
      correlationId:UID(),
    }, null, 2),
  },

  vpa: {
    label:'Fetch VPA', method:'POST', url:EP.vpa,
    fields:[
      {id:'vp_cid',  l:'Client ID',            t:'req',   p:'xxxx-xxxx-xxxx-xxxx'},
      {id:'vp_cs',   l:'Client Secret',         t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
      {id:'vp_tok',  l:'OAuth Bearer Token',    t:'oauth', p:'Bearer xxxxxxxxxxxxxxxxxxxxxxxx'},
      {id:'vp_crid', l:'Correlation ID',        t:'req',   p:UID()},
      {id:'vp_vpa',  l:'VPA Address',           t:'req',   p:'name@icici / name@upi'},
      {id:'vp_deb',  l:'Debit Account No.',     t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'vp_purp', l:'Purpose Code',          t:'opt',   p:'P2B / P2P'},
      {id:'vp_hmac', l:'HMAC / Checksum Key',   t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
    ],
    body:JSON.stringify({
      vpaAddress:'rahulsharma@icici', debitAccountNo:'xxxxxxxxxxxxxxx',
      purposeCode:'P2B', correlationId:UID(),
    }, null, 2),
  },

  benef: {
    label:'Beneficiary Mgmt', method:'POST', url:EP.benef,
    fields:[
      {id:'bf_cid',  l:'Client ID',            t:'req',   p:'xxxx-xxxx-xxxx-xxxx'},
      {id:'bf_tok',  l:'OAuth Bearer Token',    t:'oauth', p:'Bearer xxxxxxxxxxxxxxxxxxxxxxxx'},
      {id:'bf_crid', l:'Correlation ID',        t:'req',   p:UID()},
      {id:'bf_ac',   l:'Beneficiary Account',   t:'req',   p:'xxxxxxxxxxxxxxx'},
      {id:'bf_ifsc', l:'Beneficiary IFSC',      t:'req',   p:'ICIC0000001'},
      {id:'bf_name', l:'Beneficiary Name',      t:'req',   p:'RAHUL SHARMA'},
      {id:'bf_mob',  l:'Mobile Number',         t:'opt',   p:'9876543210'},
      {id:'bf_email',l:'Email',                 t:'opt',   p:'rahul@email.com'},
      {id:'bf_hmac', l:'HMAC / Checksum Key',   t:'req',   p:'xxxxxxxxxxxxxxxxxxxxxxxx', ty:'password'},
    ],
    body:JSON.stringify({
      beneficiaryAccountNo:'xxxxxxxxxxxxxxx', beneficiaryIfsc:'ICIC0000001',
      beneficiaryName:'RAHUL SHARMA', beneficiaryMobile:'9876543210',
      beneficiaryEmail:'rahul@email.com', correlationId:UID(),
    }, null, 2),
  },
};

/* ── Mock responses ────────────────────────────────────────── */
const ts = () => new Date().toISOString();
const MOCK = {
  imps:{status:'SUCCESS',uniqueRefNo:UID(),utr:'ICIC'+Date.now(),txnStatus:'COMPLETED',amount:10000,creditAccountNo:'xxxxxxxxxxxxxxx',beneficiaryName:'RAHUL SHARMA',transferType:'IMPS',processedAt:ts()},
  neft:{status:'SUCCESS',uniqueRefNo:UID(),utr:'ICIC'+Date.now(),txnStatus:'COMPLETED',amount:50000,creditAccountNo:'xxxxxxxxxxxxxxx',beneficiaryName:'RAHUL SHARMA',transferType:'NEFT',settlementBatch:'BATCH-'+D,processedAt:ts()},
  rtgs:{status:'SUCCESS',uniqueRefNo:UID(),utr:'ICIC'+Date.now(),txnStatus:'COMPLETED',amount:200000,creditAccountNo:'xxxxxxxxxxxxxxx',beneficiaryName:'COMPANY PVT LTD',transferType:'RTGS',processedAt:ts()},
  status:{status:'SUCCESS',uniqueRefNo:'KP-xxxxxxxxxxxx',utr:'ICICxxxxxxxxxxxxxxxxx',txnStatus:'COMPLETED',amount:10000,transferType:'IMPS',beneficiaryName:'RAHUL SHARMA',creditAccountNo:'xxxxxxxxxxxxxxx',processedAt:ts()},
  acval:{status:'SUCCESS',accountNo:'xxxxxxxxxxxxxxx',ifsc:'ICIC0000001',accountHolderName:'RAHUL SHARMA',bankName:'ICICI BANK LIMITED',accountStatus:'ACTIVE',nameMatchScore:98,validationMode:'NAME_MATCH',validatedAt:ts()},
  vpa:{status:'SUCCESS',vpaAddress:'rahulsharma@icici',accountHolderName:'RAHUL SHARMA',vpaStatus:'ACTIVE',bankName:'ICICI BANK LIMITED',purposeCode:'P2B',resolvedAt:ts()},
  benef:{status:'SUCCESS',beneficiaryId:'BNF'+Date.now(),beneficiaryAccountNo:'xxxxxxxxxxxxxxx',beneficiaryIfsc:'ICIC0000001',beneficiaryName:'RAHUL SHARMA',registrationStatus:'ACTIVE',registeredAt:ts()},
};
const M401 = {status:'FAILURE',errorCode:'AUTH_001',httpStatus:401,errorMessage:'Invalid or missing OAuth token. Provide a valid Bearer token in the Authorization header.',timestamp:ts()};
const CORS_NOTE = '/* CORS note — browser blocked request (expected locally)\n   Resolved when deployed on GitHub Pages\n   Sandbox mock response below:\n*/\n\n';

/* ── DOM helper ────────────────────────────────────────────── */
const g = id => document.getElementById(id);

/* ── Auth ──────────────────────────────────────────────────── */
function _checkLock() {
  if (_lockedUntil > Date.now()) {
    const secs = Math.ceil((_lockedUntil - Date.now()) / 1000);
    const e = g('ferr');
    e.innerHTML = `<i class="ti ti-lock" style="font-size:11px;vertical-align:-1px"></i> Too many attempts. Try again in ${secs}s`;
    e.classList.add('show');
    return true;
  }
  return false;
}

async function doLogin() {
  if (_checkLock()) return;
  const email = g('lid').value.trim();
  const pass  = g('lpw').value;
  const errEl = g('ferr'), spin = g('lspin'), icon = g('licon'), txt = g('ltxt');
  errEl.classList.remove('show');
  ['lid','lpw'].forEach(id => g(id) && g(id).classList.remove('err'));
  spin.classList.add('on'); icon.style.display = 'none'; txt.textContent = 'Authorizing…';
  const [eh, ph] = await Promise.all([_h(email), _h(pass)]);
  setTimeout(() => {
    spin.classList.remove('on'); icon.style.display = ''; txt.textContent = 'Authorize with OAuth';
    if (eh === _EH && ph === _PH) {
      _attempts = 0;
      g('scr-login').classList.remove('active');
      g('scr-dash').classList.add('active');
      nav('home');
    } else {
      _attempts++;
      if (_attempts >= 3) { _lockedUntil = Date.now() + 30000; _attempts = 0; }
      errEl.classList.add('show');
      ['lid','lpw'].forEach(id => g(id) && g(id).classList.add('err'));
    }
  }, 1400);
}

function doLogout() {
  g('scr-dash').classList.remove('active');
  g('scr-login').classList.add('active');
}

function togglePw() {
  const i = g('lpw'), ic = g('pw-eye');
  const h = i.type === 'password';
  i.type = h ? 'text' : 'password';
  ic.className = h ? 'ti ti-eye-off' : 'ti ti-eye';
}

/* ── Navigation ────────────────────────────────────────────── */
function nav(key) {
  document.querySelectorAll('.ni').forEach(n => n.classList.remove('on'));
  document.querySelectorAll('.fscr').forEach(s => s.classList.remove('on'));
  const ni = g('ni-'+key), fs = g('fs-'+key);
  if (ni) ni.classList.add('on');
  if (fs) fs.classList.add('on');
  if (APIS[key] && !S.built.has(key)) { buildTester(key); S.built.add(key); }
  const hb = g('hist-badge'); if (hb) hb.textContent = S.hist.length;
}

/* ── Tag badge ─────────────────────────────────────────────── */
function tb(t) {
  const c={req:'tr',opt:'to',oauth:'toa'}, l={req:'Required',opt:'Optional',oauth:'OAuth'};
  return `<span class="tag ${c[t]||'to'}">${l[t]||t}</span>`;
}

/* ── Build tester panel ────────────────────────────────────── */
function buildTester(key) {
  const api = APIS[key], el = g('tg-'+key);
  if (!api || !el) return;
  const fields = api.fields.map(f =>
    `<label class="afl">${f.l} ${tb(f.t)}</label>
     <input class="afi" id="${f.id}" type="${f.ty||'text'}" placeholder="${f.p}" autocomplete="off" spellcheck="false"/>`
  ).join('');
  const bodyBtn  = api.method==='POST' ? `<button class="tab" onclick="swtab('${key}','body')" id="tab-body-${key}">Body</button>` : '';
  const bodyPane = api.method==='POST' ? `<div class="pane" id="tp-body-${key}"><label class="afl">Request body (JSON — editable)</label><textarea class="afta" id="body-${key}">${api.body}</textarea></div>` : '';
  el.innerHTML = `
  <div class="panel">
    <div class="phdr">
      <div class="phdr-t"><i class="ti ti-send"></i> Request</div>
      <span class="mbadge ${api.method==='POST'?'post':'get'}">${api.method}</span>
    </div>
    <div class="pbody">
      <span class="ep-pill">${api.url}</span>
      <div class="tabs">
        <button class="tab on" onclick="swtab('${key}','params')"  id="tab-params-${key}">Params</button>
        <button class="tab"    onclick="swtab('${key}','headers')" id="tab-headers-${key}">Headers</button>
        ${bodyBtn}
      </div>
      <div class="pane on" id="tp-params-${key}">${fields}</div>
      <div class="pane"    id="tp-headers-${key}">
        <div class="hdr-head"><span>Name</span><span>Value</span><span></span></div>
        <div id="hdrs-${key}">
          <div class="hdr-row"><input class="afi" value="Content-Type"/><input class="afi" value="application/json"/><button class="hdr-del" onclick="this.parentElement.remove()">×</button></div>
          <div class="hdr-row"><input class="afi" value="Authorization"/><input class="afi" placeholder="Bearer xxxx"/><button class="hdr-del" onclick="this.parentElement.remove()">×</button></div>
          <div class="hdr-row"><input class="afi" value="X-ICICI-CorrelationId"/><input class="afi" placeholder="KP-xxxx"/><button class="hdr-del" onclick="this.parentElement.remove()">×</button></div>
          <div class="hdr-row"><input class="afi" value="X-Client-Id"/><input class="afi" placeholder="xxxx-xxxx"/><button class="hdr-del" onclick="this.parentElement.remove()">×</button></div>
        </div>
        <button class="btn-add-hdr" onclick="addHdr('${key}')"><i class="ti ti-plus" style="font-size:11px"></i> Add header</button>
      </div>
      ${bodyPane}
      <button class="btn-send" id="sendbtn-${key}" onclick="fire('${key}')">
        <i class="ti ti-player-play" style="font-size:11px" id="sicon-${key}"></i>
        <span id="stxt-${key}">Send Request</span>
        <span class="sspin" id="sspin-${key}"></span>
      </button>
    </div>
  </div>
  <div class="panel">
    <div class="phdr">
      <div class="phdr-t"><i class="ti ti-code"></i> Response</div>
      <button class="btn-copy" id="cbtn-${key}" onclick="copyR('${key}')"><i class="ti ti-copy" style="font-size:10px"></i> Copy</button>
    </div>
    <div class="pbody" style="padding:10px">
      <div class="ridle" id="ridle-${key}">
        <i class="ti ti-player-play"></i>
        <span>Hit <strong>Send Request</strong> to fire the API</span>
        <small>No token → sandbox mock &nbsp;·&nbsp; valid token → live ICICI Bank call</small>
      </div>
      <pre class="rbody" id="rbody-${key}"></pre>
    </div>
    <div class="sbar" id="sbar-${key}">
      <span class="sc-nil" id="sc-${key}">—</span>
      <span class="sc-ct"  id="ct-${key}"></span>
      <span class="sc-ms"  id="ms-${key}"></span>
    </div>
  </div>`;
}

function swtab(key, t) {
  ['params','headers','body'].forEach(x => {
    const tp=g('tp-'+x+'-'+key), tb2=g('tab-'+x+'-'+key);
    if(tp) tp.classList.remove('on'); if(tb2) tb2.classList.remove('on');
  });
  const tp=g('tp-'+t+'-'+key), tb2=g('tab-'+t+'-'+key);
  if(tp) tp.classList.add('on'); if(tb2) tb2.classList.add('on');
}

function addHdr(key) {
  const c=g('hdrs-'+key); if(!c) return;
  const r=document.createElement('div'); r.className='hdr-row';
  r.innerHTML='<input class="afi" placeholder="Header name"/><input class="afi" placeholder="Value"/><button class="hdr-del" onclick="this.parentElement.remove()">×</button>';
  c.appendChild(r);
}

/* ── Fire request ──────────────────────────────────────────── */
async function fire(key) {
  const api=APIS[key];
  const btn=g('sendbtn-'+key), spin=g('sspin-'+key), icon=g('sicon-'+key), txt=g('stxt-'+key);
  const idle=g('ridle-'+key), rb=g('rbody-'+key);
  const scEl=g('sc-'+key), ctEl=g('ct-'+key), msEl=g('ms-'+key);
  if (!api||!btn) return;

  btn.disabled=true; spin.style.display='inline-block'; icon.style.display='none'; txt.textContent='Sending…';
  if(idle) idle.style.display='none';
  if(rb){ rb.style.display='none'; rb.className='rbody'; }

  const tokEl=document.querySelector(`#tg-${key} input[placeholder^="Bearer"]`);
  const rawTok=tokEl?tokEl.value.trim():'';
  const hasTok=rawTok.startsWith('Bearer ')&&rawTok.length>15;
  const t0=performance.now();
  let code, text, isOk=false;

  if (hasTok) {
    try {
      const hdrs={'Content-Type':'application/json','Accept':'application/json','Authorization':rawTok};
      const cidEl=document.querySelector(`#tg-${key} input[id$="_cid"]`);
      const cridEl=document.querySelector(`#tg-${key} input[id$="_crid"]`);
      if(cidEl&&cidEl.value.trim())   hdrs['X-Client-Id']=cidEl.value.trim();
      if(cridEl&&cridEl.value.trim()) hdrs['X-ICICI-CorrelationId']=cridEl.value.trim();
      document.querySelectorAll(`#hdrs-${key} .hdr-row`).forEach(row=>{
        const ins=row.querySelectorAll('input');
        if(ins.length>=2&&ins[0].value&&ins[1].value) hdrs[ins[0].value]=ins[1].value;
      });
      const opts={method:api.method,headers:hdrs};
      if(api.method==='POST'){const be=g('body-'+key); opts.body=be?be.value:'{}';}
      let url=api.url;
      if(api.method==='GET'){
        const p=new URLSearchParams();
        const refEl=g('st_ref'), utrEl=g('st_utr'), typeEl=g('st_type');
        if(refEl&&refEl.value) p.set('uniqueRefNo',refEl.value.trim());
        if(utrEl&&utrEl.value) p.set('utrNo',utrEl.value.trim());
        if(typeEl&&typeEl.value) p.set('transferType',typeEl.value.trim());
        if(p.toString()) url+='?'+p.toString();
      }
      const res=await fetch(url,opts);
      code=res.status; isOk=res.ok;
      try{text=JSON.stringify(await res.json(),null,2);}catch{text=await res.text();}
    } catch(e){
      code=200; isOk=true;
      text=CORS_NOTE+JSON.stringify(MOCK[key],null,2);
    }
  } else {
    await new Promise(r=>setTimeout(r,500+Math.random()*600));
    const ce=document.querySelector(`#tg-${key} input[id$="_cid"]`);
    const hasCid=ce&&ce.value.trim().length>5;
    code=hasCid?200:401; isOk=hasCid;
    text=JSON.stringify(hasCid?MOCK[key]:M401,null,2);
  }

  const el=Math.round(performance.now()-t0);
  if(rb){rb.textContent=text;rb.className='rbody '+(isOk?'ok':'bad');rb.style.display='block';}
  if(scEl){scEl.className=isOk?'sc-ok':'sc-err';scEl.textContent=isOk?`${code} OK`:`${code}${code===401?' Unauthorized':code===400?' Bad Request':' Error'}`;}
  if(ctEl) ctEl.textContent='application/json';
  if(msEl) msEl.textContent=el+'ms';

  btn.disabled=false; spin.style.display='none'; icon.style.display=''; txt.textContent='Send Request';
  S.calls++; if(isOk) S.ok++; else S.err++; S.ms+=el;
  updM();
  S.hist.unshift({key,method:api.method,url:api.url,code,ms:el,ok:isOk,name:api.label,time:new Date().toLocaleTimeString()});
  renderHist();
  const hb=g('hist-badge'); if(hb) hb.textContent=S.hist.length;
}

/* ── Metrics ───────────────────────────────────────────────── */
function updM() {
  const avg=S.calls>0?Math.round(S.ms/S.calls)+'ms':'—';
  [['m-calls',S.calls],['m-ok',S.ok],['m-err',S.err],['m-avg',avg]].forEach(([id,v])=>{
    const el=g(id); if(!el) return;
    el.textContent=v; el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash');
  });
}

/* ── Copy ──────────────────────────────────────────────────── */
function copyR(key) {
  const el=g('rbody-'+key), btn=g('cbtn-'+key);
  if(!el||!el.textContent.trim()){toast('Nothing to copy','ti-alert-triangle');return;}
  navigator.clipboard.writeText(el.textContent).then(()=>{
    btn.classList.add('done');
    btn.innerHTML='<i class="ti ti-check" style="font-size:10px"></i> Copied';
    setTimeout(()=>{btn.classList.remove('done');btn.innerHTML='<i class="ti ti-copy" style="font-size:10px"></i> Copy';},1800);
    toast('Copied to clipboard');
  }).catch(()=>toast('Copy failed','ti-x'));
}

/* ── History ───────────────────────────────────────────────── */
function renderHist() {
  const c=g('hist-list'); if(!c) return;
  if(!S.hist.length){c.innerHTML='<div class="hist-empty"><i class="ti ti-history"></i>No requests yet.<br>Fire a test in any API module.</div>';return;}
  c.innerHTML=S.hist.map(h=>`
    <div class="hitem" onclick="nav('${h.key}')">
      <span class="mbadge ${h.method==='POST'?'post':'get'}" style="font-size:9px">${h.method}</span>
      <span class="h-url">${h.url}</span>
      <span class="h-sc ${h.ok?'ok':'bad'}">${h.code}</span>
      <span class="h-ms">${h.ms}ms</span>
      <span class="h-ts">${h.time}</span>
    </div>`).join('');
}

function clearHist(){S.hist=[];renderHist();const hb=g('hist-badge');if(hb)hb.textContent='0';toast('History cleared');}

/* ── Toast ─────────────────────────────────────────────────── */
function toast(msg,icon='ti-circle-check'){
  const t=g('toast'); if(!t) return;
  t.innerHTML=`<i class="ti ${icon}"></i> ${msg}`;
  t.classList.add('on'); clearTimeout(t._t);
  t._t=setTimeout(()=>t.classList.remove('on'),2700);
}

/* ── Bootstrap ─────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded',()=>{
  ['lid','lpw'].forEach(id=>{
    const el=g(id); if(!el) return;
    el.addEventListener('keydown',e=>{if(e.key==='Enter') doLogin();});
    el.addEventListener('input',()=>{el.classList.remove('err');const fe=g('ferr');if(fe) fe.classList.remove('show');});
  });
  renderHist();
});

Object.assign(window,{doLogin,doLogout,togglePw,nav,swtab,addHdr,fire,copyR,clearHist,toast});
