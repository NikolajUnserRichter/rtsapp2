/* GENERATED from the approved prototype by work/rts/mask-redesign/live/build_rtsapp2_masks.py – change the
   prototype or the build script, not this file. */
function startMask(LIVE){

/* ---------------- data: the F22 link (decoded in app.js) ----------------
   { fdpShort, kw, transports:[{orderId, werk, senke, dienstleister, cw, deliveredWagons, departureActualArrivalDate,
     destinationDepartureTime, departureDepartureTime, wagonProfileDelivery, wagonTypeDelivery, noShow, reasonTextConfirmed}] }
   The reason table comes from the Get-Reasons flow. The critical amount of the route is NOT in the link. */
const DP=LIVE.place;
const PROFILES=['G1','G2'], TYPES=['Offen','Geschlossen','Offen + Geschlossen'];
// RTS choice values used by the F22.R payload (same as the old mask: WAGON_PROFILE_OPTIONS / WAGON_TYPE_OPTIONS)
const PROFILE_VAL={G1:'914890000',G2:'914890001'}, TYPE_VAL={'Offen':'914890000','Geschlossen':'914890001','Offen + Geschlossen':'914890002'};
// Reason table (Get-Reasons flow): [kategorie, dropdown, code] – cascade Ursachencluster → Minderleistungskriterium
const REASONS=LIVE.reasons;
const CATS=[...new Set(REASONS.map(r=>r.kategorie))];
const normTime=RtsV2Boot.time;
const lbl=(map,v)=>Object.keys(map).find(k=>map[k]===String(v==null?'':v))||'';
let orders=LIVE.transports.map(t0=>{const t=Object.assign({},t0,{orderId:String(t0.orderId),departureActualArrivalDate:RtsV2Boot.iso(t0.departureActualArrivalDate),
    deliveredWagons:t0.deliveredWagons==null||t0.deliveredWagons===''?null:parseInt(t0.deliveredWagons,10),
    wagonProfileDelivery:lbl(PROFILE_VAL,t0.wagonProfileDelivery),wagonTypeDelivery:lbl(TYPE_VAL,t0.wagonTypeDelivery)});
  return {t,id:t.orderId,dest:t.senke||'',supp:t.dienstleister||'',date:t.departureActualArrivalDate,delivered:t.deliveredWagons,crit:null,profile:t.wagonProfileDelivery,type:t.wagonTypeDelivery,status:'open'};});
const DESTS={}; orders.forEach(o=>{DESTS[o.dest]=o.dest;});
const wkd=(iso,loc,n)=>{const d=new Date(iso+'T12:00:00'); return isNaN(d)?'':d.toLocaleDateString(loc,{weekday:'short'}).replace('.','').slice(0,n)};
const DAYS=[...new Set(orders.map(o=>o.date).filter(Boolean))].sort().map(d=>({d,de:wkd(d,'de-DE',2),en:wkd(d,'en-GB',3)}));
// prefills exactly like the old mask: loaded = deliveredWagons, date = departureActualArrivalDate,
// ramp time = destinationDepartureTime else departureDepartureTime, profile/type = delivery values, No Show = false,
// reason = code of reasonTextConfirmed (category derived), comment empty
orders.forEach(o=>{const t=o.t, code=String(t.reasonTextConfirmed||'').trim().split(' ')[0]||'', r=REASONS.find(x=>x.code===code);
  o.conf={wagons:t.deliveredWagons,date:t.departureActualArrivalDate,time:normTime(t.destinationDepartureTime)||normTime(t.departureDepartureTime),
    profile:t.wagonProfileDelivery||'',type:t.wagonTypeDelivery||'',noShow:t.noShow===true||t.noShow==='true',cat:r?r.kategorie:'',code:r?code:'',comment:''};
// PREFILL (user request 2026-11-17): the link carries no value for these dropdowns, so start with the FIRST option
    // (reason / cause lists stay empty on purpose)
  if(!o.conf.profile) o.conf.profile=PROFILES[0]; if(!o.conf.type) o.conf.type=TYPES[0];
  o.base=JSON.parse(JSON.stringify(o.conf));});
orders.sort((a,b)=>a.date.localeCompare(b.date)||a.dest.localeCompare(b.dest)||a.id.localeCompare(b.id));

/* ---------------- i18n ---------------- */
let lang='de';
const T={
 de:{title:'Beladung',brandsub:'Rail Transport System · BMW Group',dpEyebrow:'Übergabepunkt',dpCode:'Übergabepunkt-Code',
   lead:'Wiederbeladung am Übergabepunkt – bitte je Transport bestätigen, wie viele Wagen beladen wurden.',
   fWeek:'Kalenderwoche',fWeekV:'KW 46',fWeekR:'09.–15.11.2026',fNotified:'Benachrichtigung erhalten',fNotifiedV:'Mo 09.11.',fNotifiedT:'06:30 Uhr',fOpen:'Offen',
   openSub:(w)=>`${w} Wagen geliefert`,summary:'Übersicht',
   fDay:'Tag',fDest:'Senke',fSupp:'Dienstleister',reset:'Filter zurücksetzen',all:'Alle',search:'Suchen: Auftrag-ID, Senke, Dienstleister …',searchL:'Suchen',
   sOpen:'22 · Offen',sDraft:'Entwurf (nicht gesendet)',s31:'31 · Beladen',s32:'32 · Unter kritischer Menge',s92:'92 · Zug ausgefallen',
   draft:'Entwurf',draftTip:'RTS-Status 22 · noch nicht gesendet',
   cTransport:'Transport',cWagons:'Beladene Wagen',cDate:'Beladedatum',cRamp:'Abfahrt Rampe',cOpt:'optional',cNoShow:'No Show',cSend:'',
   no:'Nein',yes:'Ja',change:'ändern',profile:'Profil',type:'Wagonart',choose:'— bitte wählen —',
   delivered:'geliefert',critUnder:n=>`kritisch unter ${n}`,dateTxt:'Datum',
   transports:'Transporte',wagonsDel:'Wagen geliefert',open:'offen',allSent:'alle gesendet',confirmDay:'Tag bestätigen',
   send:'Senden',sentAt:'gesendet',willBe:'beim Senden →',
   devLoaded:(a,b)=>`${a} statt ${b} beladen`,devCrit:n=>`unter kritischer Menge (${n})`,devPT:(a,b)=>`${a} statt ${b}`,devPTset:a=>`${a} ergänzt`,
   devDate:(a,b)=>`beladen ${a} statt ${b}`,devNoShow:'No Show → Zug ausgefallen',devHint:'Ursache und Kommentar empfohlen',
   cat:'Ursachencluster',crit:'Minderleistungskriterium',comment:'Kommentar Lieferung',rec:'empfohlen',max:'max. 500 Zeichen',commentPh:'Kommentar zur Beladung …',
   addNote:'+ Ursache / Kommentar',hideNote:'Ursache / Kommentar ausblenden',noteHead:'Ursache / Kommentar (optional)',
   info:(o,d,s)=>`<b>${o}</b> offen · <b>${d}</b> Entwurf · <b>${s}</b> gesendet`,saved:t=>`Entwurf gespeichert · ${t}`,
   sendShown:n=>`Angezeigte bestätigen (${n})`,empty:'Keine Transporte für diese Filter.',
   confirmQ:(n,l)=>`${n} Transporte ${l} mit den angezeigten Werten bestätigen?`,lblShown:'(alle angezeigten)',lblOn:'am',
   toastSent:n=>`${n} Beladung${n>1?'en':''} gesendet`,badTime:'Uhrzeit bitte als hh:mm eingeben, z. B. 14:30',badNum:'Bitte eine ganze Zahl ≥ 0 eingeben',badDate:'Bitte ein gültiges Datum eingeben',
   cpApply:'Übernehmen',cpTip:'Für andere Transporte übernehmen',cpDay:'Alle offenen am ',cpRoute:'Alle offenen ',cpAll:'Alle angezeigten offenen',cpNone:'Keine weiteren offenen Transporte',
   cpRel:'Datum wird relativ zum jeweiligen Liefertag übernommen.',cpDone:n=>`Für ${n} Transport${n===1?'':'e'} übernommen`,dayRel:'Liefertag',less:'weniger',more:'mehr',
   light:'Hell',dark:'Dunkel',month:'Nov'},
 en:{title:'Loading',brandsub:'Rail Transport System · BMW Group',dpEyebrow:'Dispatch point',dpCode:'Dispatch point code',
   lead:'Reloading at the dispatch point – please confirm per transport how many wagons were loaded.',
   fWeek:'Calendar week',fWeekV:'CW 46',fWeekR:'09–15 Nov 2026',fNotified:'Notification received',fNotifiedV:'Mon 09.11.',fNotifiedT:'06:30',fOpen:'Open',
   openSub:(w)=>`${w} wagons delivered`,summary:'Overview',
   fDay:'Day',fDest:'Destination',fSupp:'Rail supplier',reset:'Reset filters',all:'All',search:'Search: order ID, destination, supplier …',searchL:'Search',
   sOpen:'22 · Open',sDraft:'Draft (not sent)',s31:'31 · Loaded',s32:'32 · Below critical amount',s92:'92 · Train cancelled',
   draft:'Draft',draftTip:'RTS status 22 · not sent yet',
   cTransport:'Transport',cWagons:'Loaded wagons',cDate:'Loading date',cRamp:'Ramp departure',cOpt:'optional',cNoShow:'No show',cSend:'',
   no:'No',yes:'Yes',change:'change',profile:'Profile',type:'Wagon type',choose:'— please choose —',
   delivered:'delivered',critUnder:n=>`critical below ${n}`,dateTxt:'Date',
   transports:'transports',wagonsDel:'wagons delivered',open:'open',allSent:'all sent',confirmDay:'Confirm day',
   send:'Send',sentAt:'sent',willBe:'on send →',
   devLoaded:(a,b)=>`${a} instead of ${b} loaded`,devCrit:n=>`below critical amount (${n})`,devPT:(a,b)=>`${a} instead of ${b}`,devPTset:a=>`${a} added`,
   devDate:(a,b)=>`loaded ${a} instead of ${b}`,devNoShow:'No show → train cancelled',devHint:'cause and comment recommended',
   cat:'Cause cluster',crit:'Shortfall criterion',comment:'Delivery comment',rec:'recommended',max:'max. 500 characters',commentPh:'Comment on the loading …',
   addNote:'+ Cause / comment',hideNote:'Hide cause / comment',noteHead:'Cause / comment (optional)',
   info:(o,d,s)=>`<b>${o}</b> open · <b>${d}</b> draft · <b>${s}</b> sent`,saved:t=>`Draft saved · ${t}`,
   sendShown:n=>`Confirm shown (${n})`,empty:'No transports for these filters.',
   confirmQ:(n,l)=>`Confirm ${n} transports ${l} with the values shown?`,lblShown:'(all shown)',lblOn:'on',
   toastSent:n=>`${n} loading${n>1?'s':''} sent`,badTime:'Please enter the time as hh:mm, e.g. 14:30',badNum:'Please enter a whole number ≥ 0',badDate:'Please enter a valid date',
   cpApply:'Apply',cpTip:'Apply to other transports',cpDay:'All open on ',cpRoute:'All open ',cpAll:'All open transports shown',cpNone:'No other open transports',
   cpRel:'Dates keep the same distance to each delivery day.',cpDone:n=>`Applied to ${n} transport${n===1?'':'s'}`,dayRel:'delivery day',less:'fewer',more:'more',
   light:'Light',dark:'Dark',month:'Nov'}
};
const t=k=>T[lang][k];
const TYPE_EN={'Offen':'Open','Geschlossen':'Closed','Offen + Geschlossen':'Open + closed'};
const typeTxt=v=>lang==='en'?(TYPE_EN[v]||v):v;
// RTS statuses this mask shows: 22 before sending; after F22.R the flow sets 31, 32 or 92
const RTS_ST={'22':{de:'Lieferung erfolgt',en:'Delivered',cls:'p-open'},'31':{de:'Beladung erfolgt',en:'Loading done',cls:'p-ok'},
  '32':{de:'Beladung erfolgt & kritische Menge unterschritten',en:'Loading done & below critical amount',cls:'p-dev'},'92':{de:'Zug ausgefallen',en:'Train cancelled',cls:'p-bad'}};

/* ---------------- helpers + state ---------------- */
let fDay='all', fDest='all', fSupp='all', fStatus='all', q='', lastSaved=null, focusCell=null;
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const fmt=iso=>{if(!iso)return'';const [,m,d]=iso.split('-');return `${d}.${m}.`};
const dayOf=iso=>DAYS.find(x=>x.d===iso)||{de:new Date(iso+'T12:00').toLocaleDateString('de-DE',{weekday:'short'}).slice(0,2),en:new Date(iso+'T12:00').toLocaleDateString('en-GB',{weekday:'short'})};
const dlabel=iso=>`${dayOf(iso)[lang]} ${fmt(iso)}`;
const addDays=(iso,k)=>{const x=new Date(iso+'T12:00:00Z');x.setUTCDate(x.getUTCDate()+k);return x.toISOString().slice(0,10)};
const dDiff=(a,b)=>Math.round((new Date(a+'T12:00:00Z')-new Date(b+'T12:00:00Z'))/864e5);
const byId=id=>orders.find(o=>o.id===id);
// result the F22.R flow will set (prototype mirrors its rule)
const outcome=o=>o.conf.noShow?'92':o.conf.wagons<o.crit?'32':'31';
const rtsCode=o=>o.status==='sent'?o.rts:'22';
const stateOf=o=>o.status==='sent'?(['31','32','92'].includes(o.rts)?o.rts:'31'):o.status;      // open | draft | 31 | 32 | 92
function devList(o){const c=o.conf, out=[];
  if(c.wagons!==o.delivered) out.push({x:t('devLoaded')(c.wagons,o.delivered)});
  if(c.wagons<o.crit) out.push({x:t('devCrit')(o.crit),bad:1});
  if(o.profile&&c.profile!==o.profile) out.push({x:t('devPT')(c.profile||'—',o.profile)});
  if(o.type&&c.type!==o.type) out.push({x:t('devPT')(typeTxt(c.type)||'—',typeTxt(o.type))});
  if(c.date&&c.date!==o.date) out.push({x:t('devDate')(dlabel(c.date),dlabel(o.date))});
  if(c.noShow) out.push({x:t('devNoShow'),bad:1});
  return out;}
const isDev=o=>devList(o).length>0;
// cause/comment line opens by itself only for fewer wagons than delivered or a No Show – not for profile/type/date changes
const isUnder=o=>o.conf.wagons<o.delivered||!!o.conf.noShow;

const LS='rtsMaskBel_v1';
/* Transports that are no longer in their open status are locked when the link is opened. The state comes from
   RTS (flow "Transportstatus lesen"). Nothing is remembered in the browser. */
let lockedOnOpen=0, lastSentAt='';
const fmtAt=v=>{const d=new Date(v); return v&&!isNaN(d)?d.toLocaleString('de-DE',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',',''):'';};
(LIVE.status||[]).forEach(s=>{const o=orders.find(x=>String(x.id)===String(s.orderId)); if(!o||s.open===true) return;
  o.status='sent'; o.lockedOnOpen=true; o.sentAt=''; lockedOnOpen++;
  o.rts=s.found===false?'':String(s.statusCode||''); o.rtsLabel=s.found===false?'nicht mehr in RTS':String(s.statusLabel||'').replace(/^[\d.]+\s*[-·]?\s*/,'');
  const v=s.values||{}, c=o.conf; c.time=''; c.comment=''; if(v.loadedWagons!=null) c.wagons=parseInt(v.loadedWagons,10)||0; if(RtsV2Boot.iso(v.loadedDate)) c.date=RtsV2Boot.iso(v.loadedDate); c.time=RtsV2Boot.time(v.departureTime); if(lbl(PROFILE_VAL,v.wagonProfile)) c.profile=lbl(PROFILE_VAL,v.wagonProfile); if(lbl(TYPE_VAL,v.wagonType)) c.type=lbl(TYPE_VAL,v.wagonType); c.noShow=v.noShow===true; if(v.comment) c.comment=String(v.comment);
});
function lockedPill(o){return `<span class="pill p-ok" title="RTS-Status ${o.rts}"><i></i>${[o.rts,o.rtsLabel].filter(Boolean).join(' · ')}</span>`;}
function saveSent(){}
function renderLock(){const el=document.getElementById('lockBar'); if(!el) return; const n=lockedOnOpen; el.hidden=!n; if(!n) return; const L=lang==='de';
  el.innerHTML=`<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></svg><span>${L?`<b>${n} ${n===1?'Transport':'Transporte'}</b> aus diesem Link ${n===1?'ist':'sind'} in RTS bereits bearbeitet und ${n===1?'ist':'sind'} gesperrt. Änderungen daran bitte an die BMW Logistik melden.`
    :`<b>${n} transport${n===1?'':'s'}</b> from this link ${n===1?'has':'have'} already been processed in RTS and ${n===1?'is':'are'} locked. Please report changes to BMW Logistics.`}</span>`;}
function persist(){
  lastSaved=null;
  saveSent();
}
function touch(o){ if(o.status==='open') o.status='draft'; persist(); }
function toast(msg,bad){const el=$('#toast');el.textContent=msg;el.style.background=bad?'var(--bad)':'';el.classList.add('show');clearTimeout(toast.t);toast.t=setTimeout(()=>el.classList.remove('show'),2600);}

/* ---------------- render ---------------- */
function filtered(){
  return orders.filter(o=>(fDay==='all'||o.conf.date===fDay)&&(fDest==='all'||o.dest===fDest)&&(fSupp==='all'||o.supp===fSupp)
    &&(fStatus==='all'||stateOf(o)===fStatus)
    &&(!q||(o.id+' '+DP.name+' '+o.dest+' '+DESTS[o.dest]+' '+o.supp).toLowerCase().includes(q.toLowerCase())))
    .sort((a,b)=>a.conf.date.localeCompare(b.conf.date)||a.dest.localeCompare(b.dest)||a.id.localeCompare(b.id));
}
function renderHead(){
  const op=orders.filter(o=>o.status!=='sent');
  $('#openCnt').textContent=op.length; $('#openSub').textContent=t('openSub')(op.reduce((a,o)=>a+o.delivered,0));
}
function renderSummary(){
  const c={open:0,draft:0,'31':0,'32':0,'92':0}; orders.forEach(o=>c[stateOf(o)]++);
  const tile=(k,lbl,col)=>`<button class="tile" data-st="${k}" aria-pressed="${fStatus===k}"><span class="k"><span class="sw" style="background:${col}"></span>${lbl}</span><span class="v num">${c[k]}</span></button>`;
  $('#summary').setAttribute('aria-label',t('summary'));
  $('#summary').innerHTML=tile('open',t('sOpen'),'var(--muted)')+tile('draft',t('sDraft'),'var(--draft)')+tile('31',t('s31'),'var(--ok)')+tile('32',t('s32'),'var(--warn)')+tile('92',t('s92'),'var(--bad)');
  document.querySelectorAll('#summary button.tile').forEach(b=>b.onclick=()=>{fStatus=fStatus===b.dataset.st?'all':b.dataset.st;render();});
}
function renderFilters(){
  const cnt=d=>orders.filter(o=>o.conf.date===d).length;
  $('#dayChips').innerHTML=`<button class="chip" data-d="all" aria-pressed="${fDay==='all'}">${t('all')}</button>`+DAYS.filter(d=>cnt(d.d)).map(d=>`<button class="chip" data-d="${d.d}" aria-pressed="${fDay===d.d}">${d[lang]} <span class="c">${cnt(d.d)}</span></button>`).join('');
  document.querySelectorAll('#dayChips .chip').forEach(b=>b.onclick=()=>{fDay=b.dataset.d;render();});
  $('#fDest').innerHTML=`<option value="all">${t('all')}</option>`+Object.keys(DESTS).filter(k=>orders.some(o=>o.dest===k)).map(k=>`<option value="${k}" ${fDest===k?'selected':''} title="${k}">${DESTS[k]}</option>`).join('');
  $('#fSupp').innerHTML=`<option value="all">${t('all')}</option>`+[...new Set(orders.map(o=>o.supp))].sort().map(s=>`<option value="${esc(s)}" ${fSupp===s?'selected':''}>${esc(s)}</option>`).join('');
}
function pill(o){
  if(o.lockedOnOpen) return lockedPill(o);
  if(o.status==='draft') return `<span class="pill p-draft" title="${t('draftTip')}"><i></i>${t('draft')}</span>`;
  const code=rtsCode(o), s=RTS_ST[code];
  return `<span class="pill ${s.cls}" title="RTS-Status ${code}"><i></i>${code} · ${s[lang]}</span>`;}

// editable cell controls (data-k = key in o.conf)
function ctl(o,k){
  const v=o.conf[k]??'', base=o.base[k]??'', sent=o.status==='sent', L=lang==='de';
  const delV={profile:o.profile,type:o.type}[k], devv=(!!delV&&v!==delV)||(k==='noShow'&&v===true), miss=(k==='profile'||k==='type')&&!v;
  const chg=!devv&&String(v)!==String(base);
  const tm=k==='time';
  const cls=`gi ${{date:'w-date',time:'w-time',noShow:'w-ns'}[k]||''} ${tm?'tm':''} ${chg?'chg':''} ${devv?'devv':''} ${miss?'miss':''}`, a=`class="${cls}" data-id="${o.id}" data-k="${k}"`;
  if(sent){const shown=k==='date'?(v?dlabel(v):'—'):k==='noShow'?(v?t('yes'):t('no')):(v||'—'); return `<span class="ro" title="${esc(shown)}">${esc(shown)}</span>`;}
  if(k==='profile') return `<select ${a} aria-label="Wagonprofil"><option value="" ${v?'':'selected'}>${t('profile')}</option>${PROFILES.map(x=>`<option ${x===v?'selected':''}>${x}</option>`).join('')}</select>`;
  if(k==='type') return `<select ${a} aria-label="Wagonart"><option value="" ${v?'':'selected'}>${t('type')}</option>${TYPES.map(x=>`<option value="${x}" ${x===v?'selected':''}>${typeTxt(x)}</option>`).join('')}</select>`;
  if(k==='noShow') return `<select ${a} aria-label="No Show"><option value="false" ${v?'':'selected'}>${t('no')}</option><option value="true" ${v?'selected':''}>${t('yes')}</option></select>`;
  if(k==='cat') return `<select ${a} aria-label="${t('cat')}"><option value="">${t('choose')}</option>${CATS.map(x=>`<option ${x===v?'selected':''}>${esc(x)}</option>`).join('')}</select>`;
  if(k==='code') return `<select ${a} aria-label="${t('crit')}" ${o.conf.cat?'':'disabled'}><option value="">${t('choose')}</option>${REASONS.filter(r=>r.kategorie===o.conf.cat).map(r=>`<option value="${esc(r.code)}" ${r.code===v?'selected':''} title="${esc(r.dropdown)}">${esc(r.dropdown)}</option>`).join('')}</select>`;
  if(k==='date') return v?`<input type="date" value="${v}" ${a} aria-label="${t('cDate')}">`:`<input type="text" data-ph="date" placeholder="${t('dateTxt')}" ${a} aria-label="${t('cDate')}">`;
  if(tm) return `<input type="text" inputmode="numeric" maxlength="5" autocomplete="off" list="qtimes" placeholder="hh:mm" value="${esc(v)}" ${a} aria-label="${t('cRamp')}">`;
  return `<input type="text" maxlength="500" value="${esc(v)}" placeholder="${t('commentPh')}" ${a} aria-label="${t('comment')}" title="${t('max')}">`;
}
const CG={date:['date'],time:['time'],wag:['wagons','cat','code','comment'],prof:['profile'],type:['type']};
const PARTS={wag:[
  {id:'n',k:['wagons'],show:o=>`<b class="num">${o.conf.wagons}</b> ${lang==='de'?'Wagen':'wagons'}`},
  {id:'rc',k:['cat','code','comment'],show:o=>(o.conf.cat||o.conf.code)?`<b>${lang==='de'?'Grund':'Reason'}</b>${o.conf.comment?(lang==='de'?' + Kommentar':' + comment'):''}`:''}]};
const hasV=v=>v!==''&&v!=null&&v!==false;
const _e=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
// ⇊ in the wagon cell: the menu lets the user tick which values to copy (amount, profile/type, reason)
function cpHead(o,g){const L=lang==='de', ps=(PARTS[g]||[]).map(p=>({id:p.id,h:p.show(o)})).filter(p=>p.h);
  if(ps.length<2) return `<div class="cph">${L?'Übernehmen':'Apply'}: ${ps.map(p=>p.h).join('')}</div>`;
  return `<div class="cph np">${L?'Übernehmen – was?':'Apply – what?'}</div><div class="cpparts">${ps.map(p=>`<label><input type="checkbox" value="${p.id}" checked>${p.h}</label>`).join('')}</div>`;}
function cpKeys(g,m){if(!PARTS[g]||!m.querySelector('.cpparts')) return CG[g]; return [...m.querySelectorAll('.cpparts input:checked')].flatMap(i=>PARTS[g].find(p=>p.id===i.value).k);}

const cpy=(o,g)=>o.status==='sent'||!CG[g].some(k=>hasV(o.conf[k]))?'':`<button class="cpy" data-cp="${g}" data-id="${o.id}" title="${t('cpTip')}" aria-label="${t('cpApply')}">⇊</button>`;
const cpyI=(o,g)=>cpy(o,g).replace('class="cpy"','class="cpy inl"');
function renderTable(){
  const list=filtered(), L=lang==='de';
  if(!list.length){$('#tableView').innerHTML=`<div class="empty">${t('empty')}<br><button class="link" id="emptyReset">${t('reset')}</button></div>`;$('#emptyReset').onclick=()=>$('#resetF').click();return;}
  const head=`<colgroup><col style="width:25%"><col style="width:25%"><col style="width:14%"><col style="width:12%"><col style="width:10%"><col style="width:14%"></colgroup>
   <thead><tr><th>${t('cTransport')}</th><th class="grp">${t('cWagons')}</th><th class="grp">${t('cDate')}</th><th>${t('cRamp')} <span class="opt">(${t('cOpt')})</span></th><th class="grp">${t('cNoShow')}</th><th></th></tr></thead>`;
  let lastDay='';
  const body=list.map(o=>{
    const sent=o.status==='sent', c=o.conf, dev=isDev(o);
    let grp=''; if(c.date!==lastDay){lastDay=c.date; const os=list.filter(x=>x.conf.date===c.date), op=os.filter(x=>x.status!=='sent').length, dd=dayOf(c.date);
      grp=`<tr class="dayrow"><td colspan="6"><span class="stub"><b class="num">${c.date.slice(8)}</b><span>${dd[lang]} · ${t('month')}</span></span><span class="meta"><b>${os.length}</b> ${t('transports')} · <b class="num">${os.reduce((a,x)=>a+x.delivered,0)}</b> ${t('wagonsDel')}${op?` · ${op} ${t('open')}`:` · ${t('allSent')} ✓`}</span>${op?`<button class="btn dayok" data-dayok="${c.date}">✓ ${t('confirmDay')} (${op})</button>`:''}</td></tr>`;}
    const ptSame=c.profile===o.profile&&c.type===o.type&&c.profile&&c.type;
    const wcls=c.wagons<o.crit?'crit':c.wagons!==o.delivered?'dev':'';
    const wag = sent
      ? `<span class="ordn ${c.wagons!==o.delivered?'w-dev':''}">${c.wagons}</span> <span class="pt">${esc(c.profile||'—')} · ${esc(typeTxt(c.type)||'—')}</span>`
      : `<div class="wg ${wcls}"><button data-ta="minus" data-id="${o.id}" aria-label="${t('less')}">−</button><input type="number" inputmode="numeric" min="0" max="99" value="${c.wagons}" data-id="${o.id}" data-k="wagons" aria-label="${t('cWagons')}"><button data-ta="plus" data-id="${o.id}" aria-label="${t('more')}">+</button></div>${cpyI(o,'wag')}
         <div class="mini mini2"><span class="mf">${ctl(o,'profile')}${cpyI(o,'prof')}</span><span class="mf grow">${ctl(o,'type')}${cpyI(o,'type')}</span></div>`;
    const hint=`<span class="ordhint">${t('delivered')} <b class="num">${o.delivered==null?'–':o.delivered}</b>${o.profile?' · '+o.profile:''}${o.type?' · '+esc(typeTxt(o.type)):''}${o.crit==null?'':` · <span class="${c.wagons<o.crit?'crit':''}">${t('critUnder')(o.crit)}</span>`}</span>`;
    const under=isUnder(o), showNote=!sent&&(under||o._note||c.cat||c.code||c.comment);
    const nx=outcome(o);
    const act=sent?`<div class="acts2"><span class="sentinfo">✓ ${t('sentAt')} ${o.sentAt}</span></div>`
      :`<div class="acts2"><button class="btn primary" data-ta="send" data-id="${o.id}">${t('send')}</button><span class="nextst" title="${o.crit==null&&nx==='31'?(lang==='de'?'32, wenn die kritische Menge der Strecke unterschritten ist':'32 if below the critical amount of the route'):'RTS-Status '+nx+' · '+RTS_ST[nx][lang]}">${t('willBe')} <b>${o.crit==null&&nx==='31'?'31 / 32':nx}</b></span>${(under||c.cat||c.code||c.comment)?'':`<button class="notelink" data-ta="note" data-id="${o.id}">${o._note?t('hideNote'):t('addNote')}</button>`}</div>`;
    const main=`<tr class="${sent?'sent':''}" data-row="${o.id}">
      <td><span class="rt" title="${DP.code} → ${o.dest}">${DP.name} → ${DESTS[o.dest]}</span>
          <span class="sub2"><span class="wpid">${o.id}</span><span class="supp">${esc(o.supp)}</span>${pill(o)}</span></td>
      <td class="grp"><div class="wcell">${wag}</div>${sent?'':hint}</td>
      <td class="grp cp">${ctl(o,'date')}${cpy(o,'date')}</td>
      <td class="cp">${ctl(o,'time')}${cpy(o,'time')}</td>
      <td class="grp">${ctl(o,'noShow')}</td>
      <td class="act">${act}</td></tr>`;
    const devRow=showNote?`<tr class="devrow ${under?'':'note'}"><td colspan="6"><div class="devline">
        <span class="devsum">${under?`⚠ ${devList(o).map(x=>`<span class="${x.bad?'bad':''}">${esc(x.x)}</span>`).join('')}<em>${t('devHint')}</em>`:`<em style="margin:0">${t('noteHead')}</em>`}</span>
        <div class="devf"><label>${t('cat')} <span class="rec">(${t('rec')})</span></label>${ctl(o,'cat')}</div>
        <div class="devf k2"><label>${t('crit')}</label>${ctl(o,'code')}</div>
        <div class="devf grow"><label>${t('comment')} <span class="rec">(${t('max')})</span></label>${ctl(o,'comment')}</div></div></td></tr>`:'';
    return grp+main+devRow;
  }).join('');
  $('#tableView').innerHTML=`<div class="grid" id="grid"><table>${head}<tbody>${body}</tbody></table></div>`;
}
const openShown=()=>filtered().filter(o=>o.status!=='sent');
function renderBars(){
  const c={open:0,draft:0,sent:0}; orders.forEach(o=>c[o.status]++);
  $('#bInfo').innerHTML=t('info')(c.open,c.draft,c.sent);
  $('#savedNote').textContent=lastSaved&&c.draft?`💾 ${t('saved')(lastSaved)}`:'';
  const sd=$('#sendShown'), no=openShown().length; sd.textContent=t('sendShown')(no); sd.disabled=!no;
}
function render(){
  document.querySelectorAll('[data-i]').forEach(el=>{const v=T[lang][el.dataset.i]; if(typeof v==='string') el.textContent=v;});
  $('#q').placeholder=t('search'); $('#q').setAttribute('aria-label',t('searchL')); $('.code').title=t('dpCode');
  $('#resetF').hidden=fDay==='all'&&fDest==='all'&&fSupp==='all'&&fStatus==='all'&&!q;
  renderHead(); renderLock(); renderSummary(); renderFilters(); renderTable(); renderBars(); restoreFocus(); themeUi();
}
function restoreFocus(){ if(!focusCell) return; const el=document.querySelector(`#tableView [data-id="${focusCell.id}"][data-k="${focusCell.k}"]`); if(el) el.focus({preventScroll:true}); }

/* ---------------- send (prototype: nothing leaves the browser) ----------------
   Real mask: POST to F22.R_Beladung bestätigen (ORDER_SUBMIT_URL, per environment) with exactly the
   body the old mask (rtsapp2/beladung/app.js → handleLoadSubmit) builds:
   {
     submissionTimestamp: new Date().toISOString(),
     sessionToken: <token from the auth flow>,
     loads: [{
       orderId,                     // Auftrag-ID (t.orderId)
       loadedWagons,                // number, or null when the field is empty
       loadedTransportDate,         // 'YYYY-MM-DD' (Beladedatum)
       destinationDepartureTime,    // 'HH:MM' or '' (Abfahrtszeit Rampe, optional)
       wagonProfileDelivery,        // '914890000' G1 | '914890001' G2 | ''
       wagonTypeDelivery,           // '914890000' Offen | '914890001' Geschlossen | '914890002' Offen + Geschlossen | ''
       noShow,                      // boolean
       reasonCode,                  // Minderleistungskriterium code, e.g. '06' ('-' = keine Unterlieferung, '' = none)
       loadedComment                // Kommentar Lieferung, max. 500 characters
     }]
   }
   The old mask sent all transports of the link in one call; this design sends one row, a day or all
   shown rows – the same body, with loads[] holding only the transports being confirmed.
   The flow then sets RTS status 31 (Beladung erfolgt), 32 (… & kritische Menge unterschritten, loaded
   below the route's critical amount) or 92 (Zug ausgefallen, noShow = true) – mirrored by outcome(). */
function buildPayload(list){
  return {submissionTimestamp:new Date().toISOString(),sessionToken:null,
    loads:list.map(o=>{const c=o.conf; return {orderId:o.t.orderId,loadedWagons:Number.isFinite(c.wagons)?c.wagons:null,loadedTransportDate:c.date||'',
      destinationDepartureTime:c.time||'',wagonProfileDelivery:PROFILE_VAL[c.profile]||'',wagonTypeDelivery:TYPE_VAL[c.type]||'',
      noShow:!!c.noShow,reasonCode:c.code||'',loadedComment:String(c.comment||'').substring(0,500)};})};
}
async function send(list){
  let bad=0; const good=[];
  list.forEach(o=>{ if(o.status==='sent'||o._sending) return; o._tried=true; if(!(Number.isInteger(o.conf.wagons)&&o.conf.wagons>=0)||!o.conf.date){bad++;return;} good.push(o); });
  const blocked=n=>lang==='de'?`${n} ${n===1?'Transport':'Transporte'} unvollständig – bitte prüfen`:`${n} transport${n===1?'':'s'} incomplete – please check`;
  if(!good.length){ render(); if(bad) toast(blocked(bad),true); return; }
  good.forEach(o=>o._sending=true);
  const res=await LIVE.submit(buildPayload(good));
  good.forEach(o=>o._sending=false);
  if(res.success){
    const at=new Date().toLocaleString('de-DE',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',','');
    good.forEach(o=>{o.rts=outcome(o); o._note=false; if(o.crit==null&&o.rts==='31'){o.lockedOnOpen=true; o.rts=''; o.rtsLabel=lang==='de'?'gesendet':'sent';} o.status='sent'; o.sentAt=at;});
    persist(); render(); toast(t('toastSent')(good.length));
    if(bad) setTimeout(()=>toast(blocked(bad),true),2700);
  } else { render(); toast(res.message,true); }
}
async function confirmMany(list,label){ if(!list.length) return;
  if(list.length>1&&!(await RtsV2Boot.ask(t('confirmQ')(list.length,label).replace(/\n/g,' '), lang==='de'?`${list.length} bestätigen`:`Confirm ${list.length}`, lang==='de'?'Abbrechen':'Cancel'))) return;
  send(list); }

/* ---------------- copy menu ⇊ ---------------- */
function copyTargets(src,scope){const open=orders.filter(o=>o.status!=='sent'&&o.id!==src.id);
  return scope==='all'?open.filter(o=>filtered().includes(o)):scope==='day'?open.filter(o=>o.conf.date===src.conf.date):scope==='route'?open.filter(o=>o.dest===src.dest):open;}
function applyCopy(src,g,scope,keys=CG[g]){const l=copyTargets(src,scope);
  l.forEach(o=>{keys.forEach(k=>{let v=src.conf[k]; if(!hasV(v)) return;
    if(k==='date') v=addDays(o.date,dDiff(v,src.date));   // same distance to each transport's own delivery day
    o.conf[k]=v;}); touch(o);});
  closeCp(); render(); toast(t('cpDone')(l.length));}
function closeCp(){const m=document.getElementById('cpMenu'); if(m) m.remove();}
function openCp(btn){closeCp(); const o=byId(btn.dataset.id), g=btn.dataset.cp, c=o.conf;
  const val=CG[g].map(k=>{const v=c[k]; if(!v) return ''; if(k==='type') return esc(typeTxt(v)); if(k!=='date') return esc(v); const d=dDiff(v,o.date); return dlabel(v)+(d?` <i>(${t('dayRel')} ${d>0?'+':''}${d})</i>`:'');}).filter(Boolean).join(' · ');
  const n=sc=>copyTargets(o,sc).length;
  const opts=[['day',t('cpDay')+dlabel(c.date)],['route',t('cpRoute')+DP.name+' → '+DESTS[o.dest]],['all',t('cpAll')]].filter(([k])=>n(k)>0);
  const m=document.createElement('div'); m.id='cpMenu'; m.className='cpmenu'; m.setAttribute('role','menu');
  m.innerHTML=(PARTS[g]?cpHead(o,g):`<div class="cph">${t('cpApply')}${g==='date'?' · '+t('cDate'):g==='time'?' · '+t('cRamp'):''}: <b>${val}</b></div>`)+(opts.length?opts.map(([k,l])=>`<button role="menuitem" data-sc="${k}">${esc(l)}<span>${n(k)}</span></button>`).join(''):`<div class="cpe">${t('cpNone')}</div>`)
    +(g==='date'?`<div class="cpf">${t('cpRel')}</div>`:'');
  document.body.appendChild(m); const r=btn.getBoundingClientRect(), w=m.offsetWidth;
  m.style.top=(r.bottom+window.scrollY+6)+'px'; m.style.left=Math.max(12,Math.min(r.right-w,window.innerWidth-w-12)+window.scrollX)+'px';
  m.onclick=e=>{const b=e.target.closest('[data-sc]'); if(!b) return; const ks=cpKeys(g,m); if(!ks.length){toast(lang==='de'?'Bitte mindestens einen Wert auswählen':'Choose at least one value',true);return;} applyCopy(o,g,b.dataset.sc,ks);}; m.querySelector('button')?.focus();}
document.addEventListener('click',e=>{if(!e.target.closest('#cpMenu,.cpy')) closeCp();});
document.addEventListener('keydown',e=>{if(e.key==='Escape') closeCp();});
window.addEventListener('scroll',closeCp,true);

/* ---------------- table interactions ---------------- */
// 24 h time: 1430 / 14:30 / 14.30 / 14 / 9 → HH:MM; > 23:59 rejected
function parseTime(raw){const d=String(raw||'').replace(/\s/g,''); if(!d) return ''; let h,mi,m;
  if((m=d.match(/^(\d{1,2})[:.,h](\d{1,2})$/))){h=+m[1];mi=+m[2];}
  else if((m=d.match(/^(\d{3,4})$/))){h=+m[1].slice(0,-2);mi=+m[1].slice(-2);}
  else if((m=d.match(/^(\d{1,2})$/))){h=+m[1];mi=0;}
  else return null;
  if(h>23||mi>59) return null; return `${String(h).padStart(2,'0')}:${String(mi).padStart(2,'0')}`;}
function setVal(o,k,raw){
  const c=o.conf, v=String(raw??'').trim();
  if(k==='wagons'){ if(!/^\d+$/.test(v)) {toast(t('badNum'),true);return false;} c.wagons=Math.min(99,parseInt(v,10)); return true;}
  if(k==='date'){ let x=v; const m=v.match(/^(\d{1,2})\.(\d{1,2})\.(\d{2,4})?$/); if(m){const y=m[3]?(m[3].length===2?'20'+m[3]:m[3]):'2026'; x=`${y}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;}
    if(!/^\d{4}-\d{2}-\d{2}$/.test(x)||isNaN(new Date(x+'T12:00:00Z'))){toast(t('badDate'),true);return false;} c.date=x; return true;}
  if(k==='time'){ const p=parseTime(v); if(p===null){toast(t('badTime'),true);return false;} c.time=p; return true;}
  if(k==='noShow'){ c.noShow=v==='true'; return true;}
  if(k==='cat'){ if(c.cat!==v){c.cat=v; c.code='';} return true;}
  if(k==='comment'){ c.comment=v.substring(0,500); return true;}
  c[k]=v; return true;
}
const tv=$('#tableView');
const later=()=>{clearTimeout(tv._r); tv._r=setTimeout(render,0);};
tv.addEventListener('focusin',e=>{const el=e.target.closest('[data-k]'); if(!el) return; focusCell={id:el.dataset.id,k:el.dataset.k};
  if(el.dataset.ph){ el.type=el.dataset.ph; delete el.dataset.ph; try{el.showPicker&&el.showPicker()}catch(_){}} });
tv.addEventListener('focusout',e=>{const el=e.target.closest('[data-k]'); if(el&&el.dataset.k==='date'&&!el.value&&el.type==='date') later();});
tv.addEventListener('input',e=>{const el=e.target; if(!el.classList||!el.classList.contains('tm')) return;
  const d=el.value.replace(/[^0-9]/g,''); if(/^\d{3,4}$/.test(d)&&!/[:.,]/.test(el.value)) el.value=d.slice(0,-2)+':'+d.slice(-2);});
tv.addEventListener('change',e=>{
  const el=e.target.closest('[data-k]'); if(!el) return; const o=byId(el.dataset.id); if(!o||o.status==='sent') return;
  if(el.dataset.k==='date'&&!el.value) { later(); return; }     // cleared date: keep the last valid one
  if(setVal(o,el.dataset.k,el.value)) touch(o);
  later();   // after focus has moved (Tab), so the new cell keeps focus
});
tv.addEventListener('keydown',e=>{
  const el=e.target.closest('[data-k]'); if(!el||e.key!=='Enter'||el.tagName==='SELECT') return; e.preventDefault();
  const ids=filtered().filter(o=>o.status!=='sent').map(o=>o.id), i=ids.indexOf(el.dataset.id), nxt=ids[i+(e.shiftKey?-1:1)];
  if(nxt) focusCell={id:nxt,k:el.dataset.k};
  el.dispatchEvent(new Event('change',{bubbles:true}));
});
tv.addEventListener('click',e=>{
  const cb=e.target.closest('.cpy'); if(cb){e.stopPropagation(); document.getElementById('cpMenu')?closeCp():openCp(cb); return;}
  const dk=e.target.closest('[data-dayok]'); if(dk){const d=dk.dataset.dayok; confirmMany(openShown().filter(o=>o.conf.date===d),`${t('lblOn')} ${dlabel(d)}`);return;}
  const ta=e.target.closest('[data-ta]'); if(!ta) return;
  const o=byId(ta.dataset.id), a=ta.dataset.ta;
  if(a==='minus'||a==='plus'){o.conf.wagons=Math.max(0,Math.min(99,o.conf.wagons+(a==='plus'?1:-1)));touch(o);focusCell=null;render();return;}
  if(a==='pt'){o._pt=true;focusCell={id:o.id,k:'profile'};render();return;}
  if(a==='note'){o._note=!o._note;focusCell=o._note?{id:o.id,k:'cat'}:null;render();return;}
  if(a==='send'){send([o]);return;}
});
$('#q').addEventListener('input',e=>{q=e.target.value;focusCell=null;render();$('#q').focus();});
$('#fDest').onchange=e=>{fDest=e.target.value;render();}; $('#fSupp').onchange=e=>{fSupp=e.target.value;render();};
$('#resetF').onclick=()=>{fDay='all';fDest='all';fSupp='all';fStatus='all';q='';$('#q').value='';render();};
$('#sendShown').onclick=()=>confirmMany(openShown(),t('lblShown'));

/* ---------------- language + theme ---------------- */
const setLang=l=>{lang=l;$('#lDE').setAttribute('aria-pressed',String(l==='de'));$('#lEN').setAttribute('aria-pressed',String(l==='en'));document.documentElement.lang=l;closeCp();render();};
$('#lDE').onclick=()=>setLang('de'); $('#lEN').onclick=()=>setLang('en');
const isDark=()=>{const r=document.documentElement;return r.dataset.theme?r.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;};
function themeUi(){const d=isDark(); $('#themeIco').innerHTML=d?'<svg width="15" height="15" viewBox="0 0 16 16" fill="currentColor"><path d="M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8M8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0m0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13m8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5M3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8m10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0m-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0m9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707M4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708"/></svg>':'<svg width="15" height="15" viewBox="0 0 16 16" fill="currentColor"><path d="M6 .278a.77.77 0 0 1 .08.858 7.2 7.2 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277q.792-.001 1.533-.16a.79.79 0 0 1 .81.316.73.73 0 0 1-.031.893A8.35 8.35 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.75.75 0 0 1 6 .278"/></svg>'; $('#themeTxt').textContent=d?t('light'):t('dark');}
$('#themeBtn').onclick=()=>{document.documentElement.dataset.theme=isDark()?'light':'dark'; try{localStorage.setItem('rtsMaskTheme',document.documentElement.dataset.theme)}catch(e){} themeUi();};
try{const th=localStorage.getItem('rtsMaskTheme'); if(th) document.documentElement.dataset.theme=th;}catch(e){}

$('#qtimes').innerHTML=Array.from({length:96},(_,i)=>`<option value="${String(Math.floor(i/4)).padStart(2,'0')}:${String(i%4*15).padStart(2,'0')}">`).join('');
window.addEventListener('beforeunload',e=>{if(orders.some(o=>o.status==='draft')){e.preventDefault();e.returnValue='';}});
/* header from the link */
(function(){const ds=orders.map(o=>o.date).filter(Boolean).sort(), f=d=>d.split('-').reverse().slice(0,2).join('.')+'.';
  const range=ds.length?(ds[0]===ds[ds.length-1]?f(ds[0]):f(ds[0])+' – '+f(ds[ds.length-1]))+ds[0].slice(0,4):'';
  ['de','en'].forEach(l=>{T[l].fWeekV=(l==='de'?'KW ':'CW ')+(LIVE.kw||'–'); T[l].fWeekR=range;});
  document.getElementById('heroName').textContent=LIVE.place.name||'–'; document.getElementById('heroCode').textContent=LIVE.place.code||''; document.getElementById('heroCode').hidden=!LIVE.place.code;
  document.getElementById('heroIni').textContent=(LIVE.place.code||LIVE.place.name||'?').slice(0,3).toUpperCase();
  document.title=document.title+(LIVE.place.name?' · '+LIVE.place.name:'');})();
render();

}
