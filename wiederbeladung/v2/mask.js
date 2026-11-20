/* GENERATED from the approved prototype by work/rts/mask-redesign/live/build_rtsapp2_masks.py – change the
   prototype or the build script, not this file. */
function startMask(LIVE){

/* ---------------- data: the F21 link (decoded in app.js) ----------------
   { fdpShort, kw, responsibles:[{id,name}], transports:[{orderId, werk, senke, dienstleister, cw, confirmedWagons,
     confirmedTransportDate, departureArrivalFrom, departureArrivalUntil, departureDepartureTime,
     wagonProfileConfirmed, wagonTypeConfirmed, reasonTextConfirmed}] } – the reason table comes from the Get-Reasons flow. */
const FDP=LIVE.place;
// Dataverse choice values, exactly as the first mask posts them
const PROFILES=[{v:'914890000',l:'G1'},{v:'914890001',l:'G2'}];
const TYPES=[{v:'914890000',de:'Offen',en:'Open'},{v:'914890001',de:'Geschlossen',en:'Closed'},{v:'914890002',de:'Offen + Geschlossen',en:'Open + closed'}];
const RESP=LIVE.responsibles;
const REASONS=LIVE.reasons;
const CATS=[...new Set(REASONS.map(r=>r.kategorie))];
const cv=v=>v==null?'':String(v);
let orders=LIVE.transports.map(t=>{const w=parseInt(t.confirmedWagons,10)||0, date=RtsV2Boot.iso(t.confirmedTransportDate), prof=PROFILES.some(p=>p.v===cv(t.wagonProfileConfirmed))?cv(t.wagonProfileConfirmed):'', typ=TYPES.some(p=>p.v===cv(t.wagonTypeConfirmed))?cv(t.wagonTypeConfirmed):'';
  const code=String(t.reasonTextConfirmed||'').trim().split(' ')[0]||'', r=REASONS.find(x=>x.code===code);
  return {id:String(t.orderId),dest:t.senke||'',supp:t.dienstleister||'',kw:t.cw||LIVE.kw||'',date,confWagons:w,confProfile:prof,confType:typ,
    conf:{wagons:w,defective:'',deliveryDate:date,arrFrom:RtsV2Boot.time(t.departureArrivalFrom),arrUntil:RtsV2Boot.time(t.departureArrivalUntil),depTime:RtsV2Boot.time(t.departureDepartureTime),profile:prof,type:typ,noShow:false,cat:r?r.kategorie:'',reason:r?code:'',costs:'',resp:'',comment:''},
    status:'open'};});
const DESTS={}; orders.forEach(o=>{DESTS[o.dest]=o.dest;});
const SUPPS=[...new Set(orders.map(o=>o.supp))].sort();
const wkd=(iso,loc,n)=>{const d=new Date(iso+'T12:00:00'); return isNaN(d)?'':d.toLocaleDateString(loc,{weekday:'short'}).replace('.','').slice(0,n)};
const DAYS=[...new Set(orders.map(o=>o.date).filter(Boolean))].sort().map(d=>({d,de:wkd(d,'de-DE',2),en:wkd(d,'en-GB',3)}));
orders.sort((a,b)=>a.date.localeCompare(b.date)||a.dest.localeCompare(b.dest)||a.id.localeCompare(b.id));
// the link carries no value for these dropdowns when RTS has none: start with the first option (agreed 17.11.2026)
orders.forEach(o=>{const c=o.conf; if(!c.profile) c.profile=PROFILES[0].v; if(!c.type) c.type=TYPES[0].v;});
// Verantwortlich: one shared login, so the mask preselects the person last chosen in this browser (per Übergabepunkt),
// or the only one in the list.
const RESP_KEY='rtsMaskWb_resp_'+FDP.code;
let lastResp=''; try{lastResp=localStorage.getItem(RESP_KEY)||'';}catch(e){}
if(!RESP.some(r=>r.id===lastResp)) lastResp='';
if(!lastResp&&RESP.length===1) lastResp=RESP[0].id;   // only one shareholder for this Werk (usual in PROD) → preselected
if(lastResp) orders.forEach(o=>{if(!o.conf.resp) o.conf.resp=lastResp;});
orders.forEach(o=>o.base=JSON.parse(JSON.stringify(o.conf)));

/* ---------------- i18n ---------------- */
let lang='de';
const T={
 de:{title:'Wiederbeladung',brandsub:'Rail Transport System · BMW Group',eyebrow:'Übergabepunkt',herosub:'Ankunft der leeren Wagen zur Wiederbeladung bestätigen',
   fWeek:'Kalenderwoche',fWeekV:'KW 46',fWeekR:'09.–15.11.2026',fNote:'Benachrichtigung erhalten',fNoteV:'Fr 06.11.',fNoteT:'14:00 Uhr',fOpen:'Offen',fOpenS:n=>`von ${n} Transporten`,codeTitle:'Kürzel Übergabepunkt',
   fDay:'Tag',fSupp:'Dienstleister',fDest:'Senke',reset:'Filter zurücksetzen',all:'Alle',qPh:'Suchen: Auftrag-ID, Senke, Dienstleister …',qLbl:'Suchen',summary:'Übersicht',
   sOpen:'21 · Offen',sDraft:'Entwurf (nicht gesendet)',sSent:'22 · Erfolgt',sDev:'Mit Abweichung',wagonsKpi:'Wagen geliefert',
   st21:'Lieferung erwartet',st22:'Lieferung erfolgt',draft:'Entwurf',notSent:'noch nicht gesendet',
   hTransport:'Transport',hWagons:'Wagen',hWagSub:'geliefert · Schad · Profil',hDate:'Lieferdatum',hArr:'Ankunft von – bis',hArrSub:'am Übergabepunkt',hDep:'Abfahrt',hResp:'Verantwortlich',hRespSub:'Lieferung',
   delivered:'Gelieferte Wagons',dmg:'Schad',dmgTitle:'Anzahl Schadwagons',noShow:'No Show',noShowT:'No Show (Ja/Nein)',change:'ändern',profPh:'Profil *',typePh:'Wagonart *',profL:'Wagonprofil',typeL:'Wagonart',
   datePh:'Datum',respPh:'– bitte wählen –',send:'Senden',dayOk:'Tag bestätigen',transports:'Transporte',open:'offen',allDone:'alle gesendet ✓',confirmedHint:'bestätigt',
   recommended:'empfohlen',cat:'Ursachencluster',crit:'Minderleistungskriterium',catPh:'– Cluster wählen –',critPh:'– Kriterium wählen –',critFirst:'– erst Cluster wählen –',
   costs:'Entstandene Kosten',comment:'Kommentar Lieferung',commentPh:'Freitext, max. 500 Zeichen',moreAdd:'+ Ursache, Kosten, Kommentar',moreHide:'− ausblenden',
   dWag:(a,b)=>`${a} statt ${b} Wagen`,dDmg:n=>`${n} Schadwagen`,dX:(a,b)=>`${a} statt ${b}`,dDate:(a,b)=>`Lieferung ${a} statt ${b}`,
   errResp:'Verantwortlichkeit Lieferung fehlt.',errPT:'Wagonprofil und Wagonart dürfen nicht leer sein.',errDef:'Schadwagen: ganze Zahl ≥ 0, höchstens so viele wie geliefert.',errCost:'Kosten: Betrag ≥ 0 (z. B. 250 oder 250,50).',
   errTime:'Uhrzeit bitte als hh:mm eingeben (00:00–23:59), z. B. 14:30',
   toastSent:n=>`${n} Meldung${n>1?'en':''} gesendet`,toastBlocked:n=>`${n} Transport${n>1?'e':''} unvollständig – bitte prüfen`,
   applied:n=>`Für ${n} Transport${n===1?'':'e'} übernommen`,copyH:'Übernehmen',copyTitle:'Für andere Transporte übernehmen',copyDay:d=>`Alle offenen am ${d}`,copyRoute:r=>`Alle offenen ${r}`,copyAll:'Alle angezeigten offenen Transporte',noOther:'Keine weiteren offenen Transporte',
   copyF:'Datum wird relativ zum jeweiligen Transporttag übernommen.',tday:'Transporttag',
   confirmQ:(n,l)=>`${n} Transporte ${l} mit den angezeigten Werten melden?`,confAll:'(alle angezeigten)',confOn:'am',
   info:(o,d,s)=>`<b>${o}</b> offen · <b>${d}</b> Entwurf · <b>${s}</b> gesendet`,saved:t=>`Entwurf gespeichert · ${t}`,sendShown:n=>`Angezeigte bestätigen (${n})`,
   empty:'Keine Transporte für diese Filter.',sentAt:'gesendet',pasted:n=>`${n} Werte aus Excel eingefügt`,light:'Hell',dark:'Dunkel',minus:'weniger',plus:'mehr'},
 en:{title:'Reloading',brandsub:'Rail Transport System · BMW Group',eyebrow:'Dispatch point',herosub:'Confirm the arrival of the empty wagons for re-loading',
   fWeek:'Calendar week',fWeekV:'CW 46',fWeekR:'09–15 Nov 2026',fNote:'Notification received',fNoteV:'Fri 06.11.',fNoteT:'14:00',fOpen:'Open',fOpenS:n=>`of ${n} transports`,codeTitle:'Dispatch point code',
   fDay:'Day',fSupp:'Service provider',fDest:'Destination',reset:'Reset filters',all:'All',qPh:'Search: order ID, destination, provider …',qLbl:'Search',summary:'Overview',
   sOpen:'21 · Open',sDraft:'Draft (not sent)',sSent:'22 · Delivered',sDev:'With deviation',wagonsKpi:'Wagons delivered',
   st21:'Delivery expected',st22:'Delivery made',draft:'Draft',notSent:'not sent yet',
   hTransport:'Transport',hWagons:'Wagons',hWagSub:'delivered · damaged · profile',hDate:'Delivery date',hArr:'Arrival from – to',hArrSub:'at dispatch point',hDep:'Departure',hResp:'Responsible',hRespSub:'delivery',
   delivered:'Wagons delivered',dmg:'Dmg.',dmgTitle:'Number of damaged wagons',noShow:'No show',noShowT:'No show (yes/no)',change:'change',profPh:'Profile *',typePh:'Wagon type *',profL:'Wagon profile',typeL:'Wagon type',
   datePh:'Date',respPh:'– please choose –',send:'Send',dayOk:'Confirm day',transports:'transports',open:'open',allDone:'all sent ✓',confirmedHint:'confirmed',
   recommended:'recommended',cat:'Cause cluster',crit:'Shortfall criterion',catPh:'– choose cluster –',critPh:'– choose criterion –',critFirst:'– choose a cluster first –',
   costs:'Costs incurred',comment:'Delivery comment',commentPh:'Free text, max. 500 characters',moreAdd:'+ Cause, costs, comment',moreHide:'− hide',
   dWag:(a,b)=>`${a} instead of ${b} wagons`,dDmg:n=>`${n} damaged wagon${n>1?'s':''}`,dX:(a,b)=>`${a} instead of ${b}`,dDate:(a,b)=>`delivery ${a} instead of ${b}`,
   errResp:'Responsible for delivery is missing.',errPT:'Wagon profile and wagon type must not be empty.',errDef:'Damaged wagons: whole number ≥ 0, at most the delivered count.',errCost:'Costs: amount ≥ 0 (e.g. 250 or 250.50).',
   errTime:'Please enter the time as hh:mm (00:00–23:59), e.g. 14:30',
   toastSent:n=>`${n} report${n>1?'s':''} sent`,toastBlocked:n=>`${n} transport${n>1?'s':''} incomplete – please check`,
   applied:n=>`Applied to ${n} transport${n===1?'':'s'}`,copyH:'Apply',copyTitle:'Apply to other transports',copyDay:d=>`All open on ${d}`,copyRoute:r=>`All open ${r}`,copyAll:'All open transports shown',noOther:'No other open transports',
   copyF:'Dates keep the same distance to each transport day.',tday:'transport day',
   confirmQ:(n,l)=>`Report ${n} transports ${l} with the values shown?`,confAll:'(all shown)',confOn:'on',
   info:(o,d,s)=>`<b>${o}</b> open · <b>${d}</b> draft · <b>${s}</b> sent`,saved:t=>`Draft saved · ${t}`,sendShown:n=>`Confirm shown (${n})`,
   empty:'No transports for these filters.',sentAt:'sent',pasted:n=>`${n} values pasted from Excel`,light:'Light',dark:'Dark',minus:'fewer',plus:'more'}
};
const t=k=>T[lang][k];

/* ---------------- helpers + state ---------------- */
let fDay='all', fSupp='all', fDest='all', fStatus='all', q='', lastSaved=null, focusCell=null;
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=iso=>{if(!iso)return'';const [y,m,d]=iso.split('-');return `${d}.${m}.`};
const dayOf=iso=>DAYS.find(x=>x.d===iso)||{de:new Date(iso+'T12:00').toLocaleDateString('de-DE',{weekday:'short'}).slice(0,2),en:new Date(iso+'T12:00').toLocaleDateString('en-GB',{weekday:'short'})};
const dLbl=iso=>`${dayOf(iso)[lang]} ${fmt(iso)}`;
const addDays=(iso,k)=>{const x=new Date(iso+'T12:00:00');x.setDate(x.getDate()+k);return x.toISOString().slice(0,10)};
const dDiff=(a,b)=>Math.round((new Date(a+'T12:00:00')-new Date(b+'T12:00:00'))/864e5);
const profL=v=>(PROFILES.find(p=>p.v===v)||{}).l||'';
const typeL=v=>(TYPES.find(p=>p.v===v)||{})[lang]||'';
const respL=id=>(RESP.find(r=>r.id===id)||{}).name||'';
const reasonL=c=>(REASONS.find(r=>r.code===c)||{}).dropdown||'';
const routeL=o=>`${FDP.name} → ${DESTS[o.dest]}`;
const intOk=v=>/^\d+$/.test(String(v).trim());
const costOk=v=>/^\d+([.,]\d{1,2})?$/.test(String(v).trim());
const toNum=v=>v===''||v==null?null:Number(String(v).replace(',','.'));

const devList=o=>{const c=o.conf, out=[];
  if(c.noShow) out.push(t('noShow'));
  if(c.wagons!==o.confWagons) out.push(t('dWag')(c.wagons,o.confWagons));
  if(intOk(c.defective)&&+c.defective>0) out.push(t('dDmg')(+c.defective));
  if(o.confProfile&&c.profile&&c.profile!==o.confProfile) out.push(t('dX')(profL(c.profile),profL(o.confProfile)));
  if(o.confType&&c.type&&c.type!==o.confType) out.push(t('dX')(typeL(c.type),typeL(o.confType)));
  if(c.deliveryDate&&c.deliveryDate!==o.date) out.push(t('dDate')(dLbl(c.deliveryDate),dLbl(o.date)));
  return out;};
const isDev=o=>devList(o).length>0;
// cause/costs/comment line opens by itself only for fewer wagons, damaged wagons or a No Show – not for profile/type/date changes
const isUnder=o=>{const c=o.conf; return c.wagons<o.confWagons||!!c.noShow||(intOk(c.defective)&&+c.defective>0);};
const stateOf=o=>o.status==='sent'?(isDev(o)?'dev':'ok'):o.status==='draft'?'draft':'open';

// drafts live only in this browser (new key: clean start, independent of the supplier mask)
const LS_KEY='rtsMaskWb_v1';
/* Transports that are no longer in their open status are locked when the link is opened. The state comes from
   RTS (flow "Transportstatus lesen"). Nothing is remembered in the browser. */
let lockedOnOpen=0, lastSentAt='';
const fmtAt=v=>{const d=new Date(v); return v&&!isNaN(d)?d.toLocaleString('de-DE',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',',''):'';};
(LIVE.status||[]).forEach(s=>{const o=orders.find(x=>String(x.id)===String(s.orderId)); if(!o||s.open===true) return;
  o.status='sent'; o.lockedOnOpen=true; o.sentAt=''; lockedOnOpen++;
  o.rts=s.found===false?'':String(s.statusCode||''); o.rtsLabel=s.found===false?'nicht mehr in RTS':String(s.statusLabel||'').replace(/^[\d.]+\s*[-·]?\s*/,'');
  const v=s.values||{}, c=o.conf; c.arrFrom=''; c.arrUntil=''; c.depTime=''; c.resp=''; c.comment=''; c.costs=''; c.defective=''; if(v.deliveredWagons!=null) c.wagons=parseInt(v.deliveredWagons,10)||0; if(v.defectiveWagons!=null) c.defective=String(v.defectiveWagons); if(v.wagonProfile!=null) c.profile=String(v.wagonProfile); if(v.wagonType!=null) c.type=String(v.wagonType); if(RtsV2Boot.iso(v.deliveryDate)) c.deliveryDate=RtsV2Boot.iso(v.deliveryDate); c.arrFrom=RtsV2Boot.time(v.arrivalFrom); c.arrUntil=RtsV2Boot.time(v.arrivalUntil); c.depTime=RtsV2Boot.time(v.departureTime); c.noShow=v.noShow===true; if(v.incurredCosts!=null) c.costs=String(v.incurredCosts); if(v.comment) c.comment=String(v.comment); if(v.responsibleId) c.resp=String(v.responsibleId);
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

// Required, like the old mask: Verantwortlichkeit Lieferung. Plus plausible numbers.
// Ursache / Kommentar are only recommended on a deviation (the old mask never required them).
function validate(o){
  const e={}, c=o.conf;
  if(!c.resp) e.resp=t('errResp');
  if(!c.profile||!c.type) e.pt=t('errPT');   // required (user 2026-11-17): prefilled, but may not be sent empty
  if(c.defective!==''&&(!intOk(c.defective)||+c.defective>c.wagons)) e.def=t('errDef');
  if(c.costs!==''&&!costOk(c.costs)) e.cost=t('errCost');
  return e;
}

/* ---------------- render ---------------- */
function filtered(){
  const qq=q.toLowerCase();
  return orders.filter(o=>(fDay==='all'||o.date===fDay)&&(fSupp==='all'||o.supp===fSupp)&&(fDest==='all'||o.dest===fDest)
    &&(fStatus==='all'||stateOf(o)===fStatus)
    &&(!qq||(o.id+' '+o.dest+' '+DESTS[o.dest]+' '+o.supp+' '+FDP.name).toLowerCase().includes(qq)));
}
function renderHead(){
  const total=orders.length, open=orders.filter(o=>o.status!=='sent').length;
  $('#openCnt').textContent=open; $('#openSub').textContent=t('fOpenS')(total);
}
function renderSummary(){
  const c={open:0,draft:0,ok:0,dev:0}; orders.forEach(o=>c[stateOf(o)]++);
  const sent=orders.filter(o=>o.status==='sent'), exp=orders.reduce((a,o)=>a+o.confWagons,0), del=sent.reduce((a,o)=>a+o.conf.wagons,0);
  const tile=(k,lbl,col,v)=>`<button class="tile" data-st="${k}" aria-pressed="${fStatus===k}"><span class="k"><span class="sw" style="background:${col}"></span>${lbl}</span><span class="v num">${v}</span></button>`;
  $('#summary').innerHTML=tile('open',t('sOpen'),'var(--muted)',c.open)+tile('draft',t('sDraft'),'var(--draft)',c.draft)+tile('ok',t('sSent'),'var(--ok)',c.ok)+tile('dev',t('sDev'),'var(--warn)',c.dev)
   +`<div class="tile"><span class="k">${t('wagonsKpi')}</span><span class="v num">${del} <span style="font-size:14px;color:var(--muted)">/ ${exp}</span></span><span class="bar"><i style="width:${exp?Math.min(100,Math.round(del/exp*100)):0}%"></i></span></div>`;
  $('#summary').setAttribute('aria-label',t('summary'));
  document.querySelectorAll('#summary button.tile').forEach(b=>b.onclick=()=>{fStatus=fStatus===b.dataset.st?'all':b.dataset.st;render();});
}
function renderFilters(){
  const cnt=d=>orders.filter(o=>o.date===d).length;
  $('#dayChips').innerHTML=`<button class="chip" data-d="all" aria-pressed="${fDay==='all'}">${t('all')}</button>`+DAYS.filter(d=>cnt(d.d)).map(d=>`<button class="chip" data-d="${d.d}" aria-pressed="${fDay===d.d}">${d[lang]} <span class="c">${cnt(d.d)}</span></button>`).join('');
  document.querySelectorAll('#dayChips .chip').forEach(b=>b.onclick=()=>{fDay=b.dataset.d;render();});
  $('#fSupp').innerHTML=`<option value="all">${t('all')}</option>`+SUPPS.filter(s=>orders.some(o=>o.supp===s)).map(s=>`<option value="${esc(s)}" ${fSupp===s?'selected':''}>${esc(s)}</option>`).join('');
  $('#fDest').innerHTML=`<option value="all">${t('all')}</option>`+Object.keys(DESTS).filter(k=>orders.some(o=>o.dest===k)).map(k=>`<option value="${k}" ${fDest===k?'selected':''}>${k} · ${DESTS[k]}</option>`).join('');
}
function pill(o){
  if(o.lockedOnOpen) return lockedPill(o);
  if(o.status==='draft') return `<span class="pill p-draft" title="RTS-Status 21 · ${t('notSent')}"><i></i>${t('draft')}</span>`;
  if(o.status==='sent') return `<span class="pill ${isDev(o)?'p-dev':'p-ok'}" title="RTS-Status 22"><i></i>22 · ${t('st22')}</span>`;
  return `<span class="pill p-open" title="RTS-Status 21"><i></i>21 · ${t('st21')}</span>`;
}
// editable controls (data-k = field key); TIMEK = 24h text fields
const TIMEK=['arrFrom','arrUntil','depTime'];
function ctl(o,k,extra=''){
  const c=o.conf, v=c[k]??'', e=o._tried?validate(o):{}, chg=String(v)!==String(o.base[k]??'');
  const base=`data-id="${o.id}" data-k="${k}" ${extra}`;
  if(k==='deliveryDate'){const dv=!!v&&v!==o.date, cls=`gi ${dv?'devv':chg?'chg':''}`;
    return v?`<input type="date" class="${cls}" value="${v}" ${base} aria-label="${t('hDate')}">`:`<input type="text" class="${cls}" data-ph="date" placeholder="${t('datePh')}" ${base} aria-label="${t('hDate')}">`;}
  if(TIMEK.includes(k)){const lbl={arrFrom:t('hArr')+' (1)',arrUntil:t('hArr')+' (2)',depTime:t('hDep')}[k];
    return `<input type="text" class="gi tm ${chg?'chg':''}" inputmode="numeric" maxlength="5" autocomplete="off" list="qtimes" placeholder="hh:mm" value="${esc(v)}" ${base} aria-label="${lbl}">`;}
  if(k==='profile'||k==='type'){const conf=k==='profile'?o.confProfile:o.confType, dv=!!conf&&!!v&&v!==conf, miss=!v;
    const opts=k==='profile'?PROFILES.map(p=>[p.v,p.l]):TYPES.map(p=>[p.v,p[lang]]);
    return `<select class="gi ${dv?'devv':''} ${miss?'miss':''} ${miss&&e.pt?'bad':''}" ${base} aria-required="true" title="${miss&&e.pt?esc(e.pt):''}" aria-label="${k==='profile'?t('profL'):t('typeL')}"><option value="" ${v?'':'selected'}>${k==='profile'?t('profPh'):t('typePh')}</option>${opts.map(([a,b])=>`<option value="${a}" ${a===v?'selected':''}>${b}</option>`).join('')}</select>`;}
  if(k==='resp') return `<select class="gi ${e.resp?'bad':''}" ${base} aria-required="true" aria-label="${t('hResp')}" title="${esc(e.resp||respL(v))}"><option value="">${t('respPh')}</option>${RESP.map(r=>`<option value="${r.id}" ${r.id===v?'selected':''}>${esc(r.name)}</option>`).join('')}</select>`;
  if(k==='cat') return `<select class="gi" ${base} aria-label="${t('cat')}"><option value="">${t('catPh')}</option>${CATS.map(x=>`<option value="${esc(x)}" ${x===v?'selected':''}>${esc(x)}</option>`).join('')}</select>`;
  if(k==='reason'){const list=REASONS.filter(r=>r.kategorie===c.cat);
    return `<select class="gi" ${base} ${c.cat?'':'disabled'} aria-label="${t('crit')}"><option value="">${c.cat?t('critPh'):t('critFirst')}</option>${list.map(r=>`<option value="${esc(r.code)}" ${r.code===v?'selected':''}>${esc(r.dropdown)}</option>`).join('')}</select>`;}
  if(k==='costs') return `<span class="eur"><input type="text" inputmode="decimal" class="gi ${e.cost?'bad':''}" value="${esc(v)}" placeholder="0" ${base} aria-label="${t('costs')}" title="${e.cost||''}"></span>`;
  if(k==='comment') return `<input type="text" class="gi" maxlength="500" value="${esc(v)}" placeholder="${t('commentPh')}" ${base} aria-label="${t('comment')}">`;
  return '';
}
// ⇊ copy groups for this mask
const CG={date:['deliveryDate'],arr:['arrFrom','arrUntil'],dep:['depTime'],resp:['resp'],wag:['wagons','defective','cat','reason','comment'],prof:['profile'],type:['type']};
const PARTS={wag:[
  {id:'n',k:['wagons'],show:o=>`<b class="num">${o.conf.wagons}</b> ${lang==='de'?'Wagen':'wagons'}`},
  {id:'d',k:['defective'],show:o=>+o.conf.defective>0?`${t('dmg')} <b class="num">${_e(o.conf.defective)}</b>`:''},
  {id:'rc',k:['cat','reason','comment'],show:o=>(o.conf.cat||o.conf.reason)?`<b>${lang==='de'?'Grund':'Reason'}</b>${o.conf.comment?(lang==='de'?' + Kommentar':' + comment'):''}`:''}]};
const hasV=v=>v!==''&&v!=null&&v!==false;
const _e=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
// ⇊ in the wagon cell: the menu lets the user tick which values to copy (amount, profile/type, reason)
function cpHead(o,g){const L=lang==='de', ps=(PARTS[g]||[]).map(p=>({id:p.id,h:p.show(o)})).filter(p=>p.h);
  if(ps.length<2) return `<div class="cph">${L?'Übernehmen':'Apply'}: ${ps.map(p=>p.h).join('')}</div>`;
  return `<div class="cph np">${L?'Übernehmen – was?':'Apply – what?'}</div><div class="cpparts">${ps.map(p=>`<label><input type="checkbox" value="${p.id}" checked>${p.h}</label>`).join('')}</div>`;}
function cpKeys(g,m){if(!PARTS[g]||!m.querySelector('.cpparts')) return CG[g]; return [...m.querySelectorAll('.cpparts input:checked')].flatMap(i=>PARTS[g].find(p=>p.id===i.value).k);}

const cpy=(o,g)=>o.status==='sent'||!CG[g].some(k=>hasV(o.conf[k]))?'':`<button class="cpy" data-cp="${g}" data-id="${o.id}" title="${t('copyTitle')}" aria-label="${t('copyH')}">⇊</button>`;
const cpyI=(o,g)=>cpy(o,g).replace('class="cpy"','class="cpy inl"');
function sentVal(o,k){const v=o.conf[k];
  if(k==='deliveryDate') return v?dLbl(v):'—';
  if(k==='resp') return v?esc(respL(v)):'—';
  return v||'—';}
function renderTable(){
  const list=filtered(), host=$('#tableView');
  if(!list.length){host.innerHTML=`<div class="empty">${t('empty')}<br><button class="link" id="emptyReset">${t('reset')}</button></div>`; $('#emptyReset').onclick=()=>$('#resetF').click(); return;}
  const head=`<colgroup><col style="width:17%"><col style="width:21%"><col style="width:12.5%"><col style="width:18%"><col style="width:9%"><col style="width:15.5%"><col style="width:7%"></colgroup>
   <thead><tr class="h"><th>${t('hTransport')}</th><th>${t('hWagons')}<small>${t('hWagSub')}</small></th>
   <th class="grp">${t('hDate')}</th><th class="grp">${t('hArr')}<small>${t('hArrSub')}</small></th><th>${t('hDep')}</th><th class="grp">${t('hResp')} <span class="req">*</span><small>${t('hRespSub')}</small></th><th></th></tr></thead>`;
  let lastDay='';
  const body=list.map(o=>{
    const e=o._tried?validate(o):{}, errs=Object.values(e), sent=o.status==='sent', dd=dayOf(o.date), dev=isDev(o), c=o.conf;
    let grp=''; if(o.date!==lastDay){lastDay=o.date; const os=list.filter(x=>x.date===o.date), op=os.filter(x=>x.status!=='sent').length;
      grp=`<tr class="dayrow"><td colspan="7"><span class="stub"><b class="num">${o.date.slice(8)}</b><span>${dd[lang]} · ${fmt(o.date)}</span></span><span class="meta">${os.length} ${t('transports')}${op?` · ${op} ${t('open')}`:` · ${t('allDone')}`}</span>${op?`<button class="btn dayok" data-dayok="${o.date}">✓ ${t('dayOk')} (${op})</button>`:''}</td></tr>`;}
    const ptDev=(o.confProfile&&c.profile!==o.confProfile)||(o.confType&&c.type!==o.confType);
    const ptShow=(o._pt||!c.profile||!c.type);
    const wag = sent
      ? `<span class="ordn ${c.wagons!==o.confWagons?'w-dev':''}">${c.wagons}</span> <span class="pt">${c.defective&&+c.defective>0?`· ${t('dmg')} ${c.defective} · `:''}${profL(c.profile)} · ${typeL(c.type)}${c.noShow?' · '+t('noShow'):''}</span>`
      : `<div class="wcell"><div class="wg ${c.wagons!==o.confWagons?'dev':''}"><button data-ta="minus" data-id="${o.id}" aria-label="${t('minus')}">−</button><input type="number" inputmode="numeric" min="0" max="60" value="${c.wagons}" data-id="${o.id}" data-k="wagons" aria-label="${t('delivered')}"><button data-ta="plus" data-id="${o.id}" aria-label="${t('plus')}">+</button></div>${cpyI(o,'wag')}
           <label class="dmg" title="${t('dmgTitle')}">${t('dmg')}<input type="number" inputmode="numeric" min="0" placeholder="0" value="${esc(c.defective)}" data-id="${o.id}" data-k="defective" class="${e.def?'bad':(intOk(c.defective)&&+c.defective>0?'devv':'')}" aria-label="${t('dmgTitle')}"></label></div>
         <div class="wcell2"><div class="mini mini2"><span class="mf">${ctl(o,'profile')}${cpyI(o,'prof')}</span><span class="mf grow">${ctl(o,'type')}${cpyI(o,'type')}</span></div>
           <button class="nsbtn" data-ta="noshow" data-id="${o.id}" aria-pressed="${!!c.noShow}" title="${t('noShowT')}">${t('noShow')}${c.noShow?' ✓':''}</button></div>`;
    const hint=dev&&!sent?`<span class="ordhint">${t('confirmedHint')} ${o.confWagons}${o.confProfile?' · '+profL(o.confProfile):''}${o.confType?' · '+typeL(o.confType):''}</span>`:'';
    const timeCell=(ks)=>sent?`<span class="ro num">${ks.map(k=>o.conf[k]||'—').join(' – ')}</span>`:'';
    const main=`<tr class="${sent?'sent':''}" data-row="${o.id}">
      <td><span class="rt" title="${esc(routeL(o))}">${FDP.code} <span class="arr">→</span> ${DESTS[o.dest]}</span>
          <span class="sub2"><span class="supp">${esc(o.supp)}</span><span class="wpid">${o.id} · KW ${o.kw}</span></span>
          <span class="sub2">${pill(o)}${errs.length?`<span class="errb" title="${esc(errs.join(' · '))}">!</span>`:''}</span>
          ${!sent&&!isUnder(o)?`<button class="morel" data-ta="more" data-id="${o.id}" aria-expanded="${!!o._more}">${o._more?t('moreHide'):t('moreAdd')}</button>`:''}</td>
      <td>${wag}${hint}</td>
      <td class="grp cp">${sent?`<span class="ro">${sentVal(o,'deliveryDate')}</span>`:ctl(o,'deliveryDate')+cpy(o,'date')}</td>
      <td class="grp cp">${sent?timeCell(['arrFrom','arrUntil']):`<div class="pair">${ctl(o,'arrFrom')}<span class="dash">–</span>${ctl(o,'arrUntil')}</div>${cpy(o,'arr')}`}</td>
      <td class="cp">${sent?timeCell(['depTime']):ctl(o,'depTime')+cpy(o,'dep')}</td>
      <td class="grp cp">${sent?`<span class="ro" title="${sentVal(o,'resp')}">${sentVal(o,'resp')}</span>`:ctl(o,'resp')+cpy(o,'resp')}</td>
      <td class="act">${sent?`<span class="sentinfo">✓ ${t('sentAt')}<br>${o.sentAt||''}</span>`:`<button class="btn primary" data-ta="send" data-id="${o.id}">${t('send')}</button>`}</td></tr>`;
    let devRow='';
    if(sent&&(dev||c.reason||c.costs||c.comment)){
      devRow=`<tr class="devrow sent"><td colspan="7"><div class="devline ro-dev">${dev?`<span class="devsum">⚠ ${devList(o).map(x=>`<span>${esc(x)}</span>`).join('')}</span>`:''}
        ${c.reason?`<span><b>${t('crit')}:</b>${esc(reasonL(c.reason))}</span>`:''}${c.costs?`<span><b>${t('costs')}:</b>${esc(c.costs)} €</span>`:''}${c.comment?`<span><b>${t('comment')}:</b>${esc(c.comment)}</span>`:''}</div></td></tr>`;
    } else if(!sent&&(isUnder(o)||o._more)){
      const under=isUnder(o), rec=under?` <em>· ${t('recommended')}</em>`:'';
      devRow=`<tr class="devrow ${under?'':'plain'}"><td colspan="7"><div class="devline">
        ${under?`<span class="devsum">⚠ ${devList(o).map(x=>`<span>${esc(x)}</span>`).join('')}</span>`:''}
        <div class="devf"><label>${t('cat')}${rec}</label>${ctl(o,'cat')}</div>
        <div class="devf"><label>${t('crit')}${rec}</label>${ctl(o,'reason')}</div>
        <div class="devf cost"><label>${t('costs')}</label>${ctl(o,'costs')}</div>
        <div class="devf grow"><label>${t('comment')}${rec}</label>${ctl(o,'comment')}</div></div></td></tr>`;
    }
    return grp+main+devRow;
  }).join('');
  host.innerHTML=`<div class="grid" id="grid"><table>${head}<tbody>${body}</tbody></table></div>`;
}
function renderBars(){
  const c={open:0,draft:0,sent:0}; orders.forEach(o=>c[o.status]++);
  $('#bInfo').innerHTML=t('info')(c.open,c.draft,c.sent);
  $('#savedNote').textContent=lastSaved&&c.draft?`💾 ${t('saved')(lastSaved)}`:'';
  const sd=$('#sendShown'), no=openShown().length; sd.textContent=t('sendShown')(no); sd.disabled=!no;
}
function render(){
  $('#resetF').hidden=fDay==='all'&&fSupp==='all'&&fDest==='all'&&fStatus==='all'&&!q;
  document.querySelectorAll('[data-i]').forEach(el=>{const v=T[lang][el.dataset.i]; if(typeof v==='string') el.textContent=v;});
  document.title=lang==='de'?'RTS Wiederbeladung':'RTS Reloading';
  $('#q').placeholder=t('qPh'); $('#q').setAttribute('aria-label',t('qLbl')); document.querySelector('.code').title=t('codeTitle');
  renderHead(); renderLock(); renderSummary(); renderFilters(); renderTable(); renderBars(); restoreFocus(); themeUi();
}

/* ---------------- interactions ---------------- */
const byId=id=>orders.find(o=>o.id===id);
function touch(o){ if(o.status==='open') o.status='draft'; persist(); }
function toast(msg,bad){const el=$('#toast');el.textContent=msg;el.style.background=bad?'var(--bad)':'';el.classList.add('show');clearTimeout(toast.t);toast.t=setTimeout(()=>el.classList.remove('show'),2600);}
const openShown=()=>filtered().filter(o=>o.status!=='sent');

/* Prototype only: NOTHING is sent. In the live mask send() would POST this payload to the
   F21.R_Lieferung (leer) bestätigen flow (CONFIG.ORDER_SUBMIT_URL), built exactly like the old mask
   (rtsapp2/wiederbeladung/app.js, handleReloadSubmit):
   {
     submissionTimestamp: new Date().toISOString(),
     sessionToken,                                   // from the shared RTS login flow
     reloads: [{
       orderId,                                      // Auftrag-ID (raw, unsanitised)
       deliveredWagons,                              // number | null   (Gelieferte Wagons)
       defectiveWagons,                              // number | null   (Anzahl Schadwagons)
       deliveryDate,                                 // 'YYYY-MM-DD' | ''
       destinationArrivalFrom,                       // 'HH:MM' | ''    (Ankunft von, am Übergabepunkt)
       destinationArrivalUntil,                      // 'HH:MM' | ''    (Ankunft bis)
       destinationDepartureTime,                     // 'HH:MM' | ''    (Abfahrtszeit)
       wagonProfileDelivery,                         // '914890000' G1 | '914890001' G2 | ''
       wagonTypeDelivery,                            // '914890000' Offen | '914890001' Geschlossen | '914890002' Offen + Geschlossen | ''
       noShow,                                       // boolean
       reasonCode,                                   // Minderleistungskriterium code, e.g. '06' | ''
       incurredCosts,                                // number | null   (Entstandene Kosten, €)
       responsibleId,                                // REQUIRED – id from payload.responsibles
       deliveredComment                              // string, max. 500
     }]
   }
   Difference to the old mask: one POST per send action, with only the transports being sent
   (row / day / all shown) instead of one form submit for all cards. buildPayload() below produces
   that object; it is kept in window.__rtsWbLastPayload for inspection only. */
function buildPayload(list){
  return {submissionTimestamp:new Date().toISOString(), sessionToken:null,
    reloads:list.map(o=>{const c=o.conf; return {
      orderId:o.id, deliveredWagons:c.wagons, defectiveWagons:toNum(c.defective), deliveryDate:c.deliveryDate||'',
      destinationArrivalFrom:c.arrFrom||'', destinationArrivalUntil:c.arrUntil||'', destinationDepartureTime:c.depTime||'',
      wagonProfileDelivery:c.profile||'', wagonTypeDelivery:c.type||'', noShow:!!c.noShow, reasonCode:c.reason||'',
      incurredCosts:toNum(c.costs), responsibleId:c.resp, deliveredComment:(c.comment||'').substring(0,500)};})};
}
async function send(list){
  let bad=0; const good=[];
  list.forEach(o=>{ if(o.status==='sent'||o._sending) return; o._tried=true; if(Object.keys(validate(o)).length){bad++;return;} good.push(o); });
  const blocked=n=>lang==='de'?`${n} ${n===1?'Transport':'Transporte'} unvollständig – bitte prüfen`:`${n} transport${n===1?'':'s'} incomplete – please check`;
  if(!good.length){ render(); if(bad) toast(blocked(bad),true); return; }
  good.forEach(o=>o._sending=true);
  const res=await LIVE.submit(buildPayload(good));
  good.forEach(o=>o._sending=false);
  if(res.success){
    const at=new Date().toLocaleString('de-DE',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',','');
    good.forEach(o=>{o._more=false; try{if(o.conf.resp) localStorage.setItem(RESP_KEY,o.conf.resp);}catch(e){} o.status='sent'; o.sentAt=at;});
    persist(); render(); toast(t('toastSent')(good.length));
    if(bad) setTimeout(()=>toast(blocked(bad),true),2700);
  } else { render(); toast(res.message,true); }
}
async function confirmMany(list,label){ if(!list.length) return;
  if(list.length>1&&!(await RtsV2Boot.ask(t('confirmQ')(list.length,label).replace(/\n/g,' '), lang==='de'?`${list.length} bestätigen`:`Confirm ${list.length}`, lang==='de'?'Abbrechen':'Cancel'))) return;
  send(list); }

/* copy menu */
function copyTargets(src,scope){const open=orders.filter(o=>o.status!=='sent'&&o.id!==src.id);
  return scope==='all'?open.filter(o=>filtered().includes(o)):scope==='day'?open.filter(o=>o.date===src.date):scope==='route'?open.filter(o=>o.dest===src.dest):open;}
function applyCopy(src,g,scope,keys=CG[g]){const l=copyTargets(src,scope);
  l.forEach(o=>{keys.forEach(k=>{let v=src.conf[k]; if(!hasV(v)) return;
    if(k==='deliveryDate') v=addDays(o.date,dDiff(v,src.date));   // same distance to each transport's own day
    o.conf[k]=v;}); touch(o);});
  closeCp(); render(); toast(t('applied')(l.length));}
function closeCp(){const m=document.getElementById('cpMenu'); if(m) m.remove();}
function openCp(btn){closeCp(); const o=byId(btn.dataset.id), g=btn.dataset.cp, c=o.conf;
  const val=CG[g].map(k=>{const v=c[k]; if(!v) return '';
    if(k==='resp') return esc(respL(v)); if(k==='profile') return esc(profL(v)); if(k==='type') return esc(typeL(v));
    if(k!=='deliveryDate') return v; const d=dDiff(v,o.date); return dLbl(v)+(d?` <i>(${t('tday')} ${d>0?'+':''}${d})</i>`:'');}).filter(Boolean).join(' – ');
  const nn=sc=>copyTargets(o,sc).length;
  const opts=[['day',t('copyDay')(dLbl(o.date))],['route',t('copyRoute')(routeL(o))],['all',t('copyAll')]].filter(([k])=>nn(k)>0);
  const m=document.createElement('div'); m.id='cpMenu'; m.className='cpmenu'; m.setAttribute('role','menu');
  m.innerHTML=(PARTS[g]?cpHead(o,g):`<div class="cph">${t('copyH')}: <b>${val}</b></div>`)+(opts.length?opts.map(([k,l])=>`<button role="menuitem" data-sc="${k}">${esc(l)}<span>${nn(k)}</span></button>`).join(''):`<div class="cpe">${t('noOther')}</div>`)
    +(g==='date'?`<div class="cpf">${t('copyF')}</div>`:'');
  document.body.appendChild(m); const r=btn.getBoundingClientRect(), w=m.offsetWidth;
  m.style.top=(r.bottom+window.scrollY+6)+'px'; m.style.left=Math.max(12,Math.min(r.right-w,window.innerWidth-w-12)+window.scrollX)+'px';
  m.onclick=e=>{const b=e.target.closest('[data-sc]'); if(!b) return; const ks=cpKeys(g,m); if(!ks.length){toast(lang==='de'?'Bitte mindestens einen Wert auswählen':'Choose at least one value',true);return;} applyCopy(o,g,b.dataset.sc,ks);}; m.querySelector('button')?.focus();}
document.addEventListener('click',e=>{if(!e.target.closest('#cpMenu,.cpy')) closeCp();});
document.addEventListener('keydown',e=>{if(e.key==='Escape') closeCp();});
window.addEventListener('scroll',closeCp,true);

function restoreFocus(){ if(!focusCell) return; const el=document.querySelector(`#tableView [data-id="${focusCell.id}"][data-k="${focusCell.k}"]`); if(el&&document.activeElement!==el) el.focus({preventScroll:true}); }
function parseTime(raw){const d=String(raw??'').replace(/\s/g,''); let h,mi,m; if(!d) return '';
  if((m=d.match(/^(\d{1,2})[:.,h](\d{1,2})$/))){h=+m[1];mi=+m[2];}
  else if((m=d.match(/^(\d{3,4})$/))){h=+m[1].slice(0,-2);mi=+m[1].slice(-2);}
  else if((m=d.match(/^(\d{1,2})$/))){h=+m[1];mi=0;}
  else return null;
  if(h>23||mi>59) return null; return `${String(h).padStart(2,'0')}:${String(mi).padStart(2,'0')}`;}
function setVal(o,k,raw){
  const c=o.conf; let v=String(raw??'').trim();
  if(k==='wagons'){const n=parseInt(v,10); if(isNaN(n)) return false; c.wagons=Math.max(0,Math.min(99,n)); return true;}
  if(k==='defective'||k==='costs'){c[k]=v; return true;}
  if(k==='deliveryDate'){ const m=v.match(/^(\d{1,2})\.(\d{1,2})\.(\d{2,4})?$/); if(m){const y=m[3]?(m[3].length===2?'20'+m[3]:m[3]):'2026'; v=`${y}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;} if(v&&!/^\d{4}-\d{2}-\d{2}$/.test(v)) return false; c[k]=v; return true;}
  if(TIMEK.includes(k)){const tt=parseTime(v); if(tt===null) return false; c[k]=tt; return true;}
  if(k==='resp'){ if(!v){c.resp='';return true;} const hit=RESP.find(r=>r.id===v)||RESP.find(r=>r.name.toLowerCase()===v.toLowerCase())||RESP.find(r=>r.name.toLowerCase().startsWith(v.toLowerCase())); if(!hit) return false; c.resp=hit.id; try{localStorage.setItem(RESP_KEY,hit.id);}catch(e){} return true;}
  if(k==='cat'){ c.cat=v; if(!REASONS.some(r=>r.kategorie===v&&r.code===c.reason)) c.reason=''; return true;}
  if(k==='comment'){ c.comment=v.substring(0,500); return true;}
  c[k]=v; return true;   // profile, type, reason (option values)
}
const tv=$('#tableView');
const later=()=>{clearTimeout(tv._r); tv._r=setTimeout(render,0);};
tv.addEventListener('focusin',e=>{const el=e.target.closest('[data-k]'); if(!el) return; focusCell={id:el.dataset.id,k:el.dataset.k};
  if(el.dataset.ph){ el.type=el.dataset.ph; try{el.showPicker&&el.showPicker()}catch(_){}} });
tv.addEventListener('focusout',e=>{const el=e.target.closest('[data-k]'); if(el&&focusCell&&focusCell.id===el.dataset.id&&focusCell.k===el.dataset.k) setTimeout(()=>{if(!tv.contains(document.activeElement)) focusCell=null;},0);});
// 24h text time: auto-colon while typing 1430 → 14:30
tv.addEventListener('input',e=>{const el=e.target; if(!el.classList||!el.classList.contains('tm')) return;
  const d=el.value.replace(/[^0-9]/g,''); if(/^\d{3,4}$/.test(d)&&!/[:.,h]/.test(el.value)) el.value=d.slice(0,-2)+':'+d.slice(-2);});
tv.addEventListener('change',e=>{
  const el=e.target.closest('[data-k]'); if(!el) return; const o=byId(el.dataset.id); if(!o||o.status==='sent') return;
  if(setVal(o,el.dataset.k,el.value)) touch(o);
  else if(TIMEK.includes(el.dataset.k)) toast(t('errTime'),true);
  later();   // after focus has moved (Tab), so the new cell keeps focus
});
tv.addEventListener('keydown',e=>{
  const el=e.target.closest('[data-k]'); if(!el||e.key!=='Enter'||el.tagName==='SELECT') return; e.preventDefault();
  const ids=filtered().filter(o=>o.status!=='sent').map(o=>o.id), i=ids.indexOf(el.dataset.id), nxt=ids[i+(e.shiftKey?-1:1)];
  if(nxt) focusCell={id:nxt,k:el.dataset.k};
  el.dispatchEvent(new Event('change',{bubbles:true})); later();
});
// paste a block from Excel: columns in visual order
const PASTE=['wagons','defective','deliveryDate','arrFrom','arrUntil','depTime','resp'];
tv.addEventListener('paste',e=>{
  const el=e.target.closest('[data-k]'); if(!el) return; const txt=(e.clipboardData||window.clipboardData).getData('text');
  if(!/[\t\n]/.test(txt.trim())||!PASTE.includes(el.dataset.k)) return;
  e.preventDefault();
  const rows=txt.replace(/\r/g,'').replace(/\n$/,'').split('\n').map(r=>r.split('\t'));
  const ids=filtered().filter(o=>o.status!=='sent').map(o=>o.id), r0=ids.indexOf(el.dataset.id), c0=PASTE.indexOf(el.dataset.k); let n=0;
  rows.forEach((cells,ri)=>{const o=byId(ids[r0+ri]); if(!o) return;
    cells.forEach((v,ci)=>{const k=PASTE[c0+ci]; if(k&&setVal(o,k,v)) n++;}); touch(o);});
  render(); toast(t('pasted')(n));
});
tv.addEventListener('click',e=>{
  const cb=e.target.closest('.cpy'); if(cb){e.stopPropagation(); document.getElementById('cpMenu')?closeCp():openCp(cb); return;}
  const dk=e.target.closest('[data-dayok]'); if(dk){const d=dk.dataset.dayok; confirmMany(openShown().filter(o=>o.date===d),`${t('confOn')} ${dLbl(d)}`);return;}
  const ta=e.target.closest('[data-ta]'); if(!ta) return; const o=byId(ta.dataset.id), a=ta.dataset.ta; if(!o) return;
  if(a==='minus'||a==='plus'){o.conf.wagons=Math.max(0,Math.min(99,o.conf.wagons+(a==='plus'?1:-1)));touch(o);render();return;}
  if(a==='pt'){o._pt=true;focusCell={id:o.id,k:'profile'};render();return;}
  if(a==='noshow'){o.conf.noShow=!o.conf.noShow;touch(o);render();return;}
  if(a==='more'){o._more=!o._more;if(o._more)focusCell={id:o.id,k:'cat'};render();return;}
  if(a==='send'){send([o]);return;}
});
$('#q').addEventListener('input',e=>{q=e.target.value;render();});
$('#fSupp').onchange=e=>{fSupp=e.target.value;render();}; $('#fDest').onchange=e=>{fDest=e.target.value;render();};
$('#resetF').onclick=()=>{fDay='all';fSupp='all';fDest='all';fStatus='all';q='';$('#q').value='';render();};
$('#sendShown').onclick=()=>confirmMany(openShown(),t('confAll'));
function setLang(l){lang=l;$('#lDE').setAttribute('aria-pressed',String(l==='de'));$('#lEN').setAttribute('aria-pressed',String(l==='en'));document.documentElement.lang=l;closeCp();render();}
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
