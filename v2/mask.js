/* GENERATED from the approved prototype by work/rts/mask-redesign/live/build_rtsapp2_masks.py – change the
   prototype or the build script, not this file. */
function startMask(LIVE){

/* ---------------- link data ----------------
   Shape = what F41 puts into ?data= (base64 JSON), field names as read by getOrdersFromUrl() in rtsapp2/app.js:
   OrderID, SupplierName, CW, Departure, Destination, DlTransportdate (DD.MM.YYYY), DeliveredWagons,
   'Reason Short Delivery Destination'. ExpectedWagons (loaded / ordered wagons) is NOT in today's F41 payload –
   the mask uses it only if present (deviation by count + prefill), otherwise the field starts empty. */
/* data: the transports of this link (decoded in app.js). Field names as F41 sends them. */
const RAW=LIVE.raw;
const DEST=LIVE.place;
const wkd=(iso,loc,n)=>{const d=new Date(iso+'T12:00:00'); return isNaN(d)?'':d.toLocaleDateString(loc,{weekday:'short'}).replace('.','').slice(0,n)};
const DAYS=[...new Set(RAW.map(r=>RtsV2Boot.iso(r.DlTransportdate||r.dlTransportdate)).filter(Boolean))].sort().map(d=>({d,de:wkd(d,'de-DE',2),en:wkd(d,'en-GB',3)}));

// same reason list + values as REASON_SHORT_DELIVERY in rtsapp2/app.js
const REASONS=[['None','— Keine Unterlieferung —'],['05','05 Falsche Waggongattung angeliefert'],['06','06 Fehlende Waggons - Schadwaggon'],['07','07 Ausrangierung Schadwaggons'],['08','08 fehlende Lokführerverfügbarkeit'],['09','09 zu wenige Waggons - falsche Planung Bahn-DL'],['10','10 zu spät angelieferte Waggons'],['11','11 Fehlende Lokführerverfügbarkeit'],['12','12 Zugverspätung - Arbeitszeit Ende'],['13','13 Zugverspätung - Sonstiges Bahn DL'],['14','14 Zugverspätung -   Sonstiges'],['15','15 Streik - Bahn Infrastruktur'],['25','25 technische Störungen Bahnhof bzw. Rangierer'],['26','26 technische Störungen auf der Strecke (z.B. Bahnübergang, Stellwerkstörung)'],['27','27 Rangierleistung nicht ausreichend - Rangierdienst unterbesetzt'],['28','28 Rangierleistung nicht ausreichend  - Rangierdienst in Pause'],['29','29 Rangierleistung nicht ausreichend - Lokschaden/ Lokstörung'],['30','30 Zeitplanung Rangierverkehr'],['31','31 Rangierleistung nicht ausreichend (z.B. bei zu viel Rangierung Schadwaggons/Züge gleichzeitig/Lokverfügbarkeit/Lokführer krank, Lokstörrung…)'],['32','32 Stellwerk nicht besetzt'],['33','33 Lokzuführung verspätet'],['34','34 Warten aus Lok - Störung auf der Strecke; Fahren auf Sicht'],['35','35 Warten auf Lok - Infrastruktur überlastet'],['36','36 Warten aus Lok - Sonstiges'],['37','37 Streckensperrung --> keine Umleitung möglich'],['38','38 Baustelle/ Infrastruktur'],['39','39 Blockierung Transportwege (Abgrenzung zur technischen Störrung, z.B. liegengebliebener Zug auf der Strecke)'],['40','40 Umleitung netzbedingt; Personen im Gleis'],['41','41 Infrastruktur (Baustellen, Oberleitungsstörung, Rückstau wg. Überfüllung der Umleitungen)'],['42','42 fehlende Trassenverfügbarkeit'],['43','43 Dispositive Zulaufsteuerung'],['53','53 Fehlende Waggons - falsche Planung Bahn-DL']];
// same values as generate2HourSlots() in rtsapp2/app.js: "00:00 - 02:00" … "22:00 - 00:00"
const SLOTS=Array.from({length:12},(_,i)=>{const a=String(i*2).padStart(2,'0'),b=String((i*2+2)%24).padStart(2,'0');return a+':00 - '+b+':00'});
const MAX_COMMENT=500;
const toISO=s=>{if(!s)return'';const p=String(s).split('.');return p.length===3?`${p[2]}-${p[1].padStart(2,'0')}-${p[0].padStart(2,'0')}`:s;};

// normalise like getOrdersFromUrl(); prefills like createDeliveryCard()
let orders=RAW.map(r=>{
  const exp=r.ExpectedWagons??r.expectedWagons, expected=exp===''||exp==null?null:parseInt(exp,10);
  const dw=r.DeliveredWagons||r.deliveredWagons||'', date=toISO(r.DlTransportdate||r.dlTransportdate||'');
  const rc=(r['Reason Short Delivery Destination']||r.reasonShortDeliveryDestination||'').split(' ')[0];
  return {id:r.OrderID||r.orderId, supplier:r.SupplierName||r.supplier, cw:r.CW||r.cw, plant:r.Departure||r.departure||r.Depature||'N/A',
    dest:r.Destination||r.destination||'N/A', soll:r.DlTransportdate||'', date, expected,
    conf:{wagons:dw!==''?parseInt(dw,10):(expected??''), date, slot:'', noShow:'No', reason:REASONS.some(x=>x[0]===rc)?rc:'None', comment:''},
    status:'open'};
});
// PREFILL (user request 2026-11-17): the link carries no value for these dropdowns, so start with the FIRST option
// (reason / cause lists stay empty on purpose)
orders.forEach(o=>{if(!o.conf.slot) o.conf.slot=SLOTS[0];});
orders.forEach(o=>o.base=JSON.parse(JSON.stringify(o.conf)));
orders.sort((a,b)=>a.date.localeCompare(b.date)||a.plant.localeCompare(b.plant));

/* ---------------- i18n ---------------- */
let lang='de';
const T={
 de:{title:'Transportbestätigung',brandsub:'Rail Transport System · BMW Group',destEyebrow:'Empfangsort',herosub:'Transportbestätigung durch Empfangsort',
   fWeek:'Kalenderwoche',fWeekV:'KW 46',fWeekR:'09.–15.11.2026',fNotif:'Benachrichtigung erhalten',fNotifV:'Fr 06.11.',fNotifT:'14:00 Uhr',fOpen:'Offen',fOpenS:n=>`von ${n} Transporten`,
   summary:'Übersicht',sOpen:'41 · Offen',sDraft:'Entwurf (nicht gesendet)',sSent:'42 · Erfolgt',sDev:'Mit Abweichung',
   qPh:'Suchen: Auftrag, Werk …',qAria:'Suchen: Auftrag-ID, Werk, Dienstleister',fDay:'Tag',fPlant:'Werk',fSupp:'Dienstleister',reset:'Filter zurücksetzen',all:'Alle',
   st41:'Lieferung (beladen) erwartet',st42:'Lieferung (beladen) erfolgt',draft:'Entwurf',draftTip:'RTS-Status 41 · noch nicht gesendet',rtsSt:'RTS-Status',devTag:'Abweichung',
   cTransport:'Transport',cWagons:'Gelieferte Wagen',cDate:'Ist-Transportdatum',cSlot:'Lieferzeit-Slot',cNoShow:'No Show',reqTip:'Pflichtfeld',
   expected:n=>`erwartet ${n}`,soll:'Soll',kw:'KW',datePh:'Datum',slotPh:'Slot wählen',no:'Nein',yes:'Ja',send:'Senden',minus:'weniger',plus:'mehr',wagAria:'Gelieferte Waggons',
   noShowAria:'No Show am Empfangsort',lblReason:'Grund Unterlieferung Empfangsort',lblComment:'Kommentar Empfangsort',recommended:'empfohlen',optional:'optional',
   commentPh:n=>`Freitext, max. ${n} Zeichen …`,addNote:'+ Kommentar',hideNote:'− Kommentar',noteSum:'Hinweis an Logistik',
   devWag:(a,b)=>`${a} statt ${b} Wagen`,devDate:(a,b)=>`Ankunft ${a} statt ${b}`,devNoShow:'No Show',
   nTransports:n=>`${n} Transport${n===1?'':'e'}`,nWag:n=>`${n} Wagen erwartet`,nOpen:n=>`${n} offen`,allDone:'alle bestätigt ✓',confirmDay:n=>`Tag bestätigen (${n})`,month:'Nov',
   info:(o,d,s)=>`<b>${o}</b> offen · <b>${d}</b> Entwurf · <b>${s}</b> erfolgt`,saved:t=>`Entwurf gespeichert · ${t}`,sendShown:n=>`Angezeigte bestätigen (${n})`,proto:'Prototyp · es wird nichts gesendet',
   confirmMsg:(n,l)=>`${n} Transporte ${l} mit den angezeigten Werten bestätigen?\nDie Lieferung wird an die Logistik gemeldet (Status 42).`,lblShown:'(alle angezeigten)',lblDay:d=>`am ${d}`,
   toastSent:n=>`${n} Lieferung${n>1?'en':''} bestätigt`,toastBlocked:n=>`${n} Transport${n>1?'e':''} unvollständig – bitte prüfen`,empty:'Keine Transporte für diese Filter.',
   errWag:'Gelieferte Waggons: bitte eine gültige Anzahl eingeben (Pflichtfeld).',
   cpTitle:'Für andere Transporte übernehmen',cpAria:'Übernehmen',cpHead:'Übernehmen',cpDay:d=>`Alle offenen am ${d}`,cpRoute:r=>`Alle offenen ${r}`,cpAll:'Alle angezeigten offenen Transporte',cpNone:'Keine weiteren offenen Transporte',cpRel:'Datum wird relativ zum jeweiligen Transporttag übernommen.',cpTday:'Transporttag',applied:n=>`Für ${n} Transport${n===1?'':'e'} übernommen`,
   dark:'Dunkel',light:'Hell'},
 en:{title:'Transport confirmation',brandsub:'Rail Transport System · BMW Group',destEyebrow:'Destination',herosub:'Transport confirmation by the destination',
   fWeek:'Calendar week',fWeekV:'CW 46',fWeekR:'09–15 Nov 2026',fNotif:'Notification received',fNotifV:'Fri 06.11.',fNotifT:'14:00',fOpen:'Open',fOpenS:n=>`of ${n} transports`,
   summary:'Overview',sOpen:'41 · Open',sDraft:'Draft (not sent)',sSent:'42 · Delivered',sDev:'With deviation',
   qPh:'Search: order, plant …',qAria:'Search: order ID, plant, service provider',fDay:'Day',fPlant:'Plant',fSupp:'Service provider',reset:'Reset filters',all:'All',
   st41:'Delivery (loaded) expected',st42:'Delivery (loaded) completed',draft:'Draft',draftTip:'RTS status 41 · not sent yet',rtsSt:'RTS status',devTag:'Deviation',
   cTransport:'Transport',cWagons:'Wagons delivered',cDate:'Actual transport date',cSlot:'Delivery time slot',cNoShow:'No show',reqTip:'Required',
   expected:n=>`expected ${n}`,soll:'Planned',kw:'CW',datePh:'Date',slotPh:'Choose slot',no:'No',yes:'Yes',send:'Send',minus:'fewer',plus:'more',wagAria:'Wagons delivered',
   noShowAria:'No show at destination',lblReason:'Reason short delivery destination',lblComment:'Comment destination',recommended:'recommended',optional:'optional',
   commentPh:n=>`Free text, max. ${n} characters …`,addNote:'+ Comment',hideNote:'− Comment',noteSum:'Note to logistics',
   devWag:(a,b)=>`${a} instead of ${b} wagons`,devDate:(a,b)=>`arrival ${a} instead of ${b}`,devNoShow:'No show',
   nTransports:n=>`${n} transport${n===1?'':'s'}`,nWag:n=>`${n} wagons expected`,nOpen:n=>`${n} open`,allDone:'all confirmed ✓',confirmDay:n=>`Confirm day (${n})`,month:'Nov',
   info:(o,d,s)=>`<b>${o}</b> open · <b>${d}</b> draft · <b>${s}</b> delivered`,saved:t=>`Draft saved · ${t}`,sendShown:n=>`Confirm shown (${n})`,proto:'Prototype · nothing is sent',
   confirmMsg:(n,l)=>`Confirm ${n} transports ${l} with the values shown?\nThe delivery is reported to logistics (status 42).`,lblShown:'(all shown)',lblDay:d=>`on ${d}`,
   toastSent:n=>`${n} deliver${n>1?'ies':'y'} confirmed`,toastBlocked:n=>`${n} transport${n>1?'s':''} incomplete – please check`,empty:'No transports for these filters.',
   errWag:'Wagons delivered: please enter a valid number (required).',
   cpTitle:'Apply to other transports',cpAria:'Apply',cpHead:'Apply',cpDay:d=>`All open on ${d}`,cpRoute:r=>`All open ${r}`,cpAll:'All open transports shown',cpNone:'No other open transports',cpRel:'Dates keep the same distance to each transport day.',cpTday:'transport day',applied:n=>`Applied to ${n} transport${n===1?'':'s'}`,
   dark:'Dark',light:'Light'}
};
const t=k=>T[lang][k];

/* ---------------- state ---------------- */
const LS_KEY='rtsMaskSenke_v1';
let fDay='all', fPlant='all', fSupp='all', fStatus='all', q='', lastSaved=null, focusCell=null;
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const fmt=iso=>{if(!iso)return'';const [y,m,d]=iso.split('-');return `${d}.${m}.`};
const dayOf=iso=>DAYS.find(x=>x.d===iso)||{de:new Date(iso+'T12:00').toLocaleDateString('de-DE',{weekday:'short'}).slice(0,2),en:new Date(iso+'T12:00').toLocaleDateString('en-GB',{weekday:'short'})};
const dLabel=iso=>`${dayOf(iso)[lang]} ${fmt(iso)}`;
const addDays=(iso,k)=>{const x=new Date(iso+'T12:00:00');x.setDate(x.getDate()+k);return `${x.getFullYear()}-${String(x.getMonth()+1).padStart(2,'0')}-${String(x.getDate()).padStart(2,'0')}`};
const dDiff=(a,b)=>Math.round((new Date(a+'T12:00:00')-new Date(b+'T12:00:00'))/864e5);
const route=o=>`${o.plant} → ${o.dest}`;

const devList=o=>{const c=o.conf, out=[];
  if(o.expected!=null&&c.wagons!==''&&c.wagons!==o.expected) out.push(t('devWag')(c.wagons,o.expected));
  if(c.date&&c.date!==o.date) out.push(t('devDate')(dLabel(c.date),dLabel(o.date)));
  if(c.noShow==='Yes') out.push(t('devNoShow'));
  return out;};
const isDev=o=>devList(o).length>0;
const stateOf=o=>o.status==='sent'?'ok':o.status==='draft'?'draft':'open';
// tiles: 41 Offen / Entwurf / 42 Erfolgt partition the transports; "Mit Abweichung" counts across them (draft or sent)
const matchStatus=o=>fStatus==='all'||(fStatus==='dev'?isDev(o):stateOf(o)===fStatus);
const validWag=v=>v!==''&&Number.isInteger(v)&&v>=0&&v<=9999;
function validate(o){const e={}; if(!validWag(o.conf.wagons)) e.wagons=t('errWag'); return e;}   // required: Gelieferte Waggons only (as in the old mask)

/* Transports that are no longer in their open status are locked when the link is opened. The state comes from
   RTS (flow "Transportstatus lesen"). Nothing is remembered in the browser. */
let lockedOnOpen=0, lastSentAt='';
const fmtAt=v=>{const d=new Date(v); return v&&!isNaN(d)?d.toLocaleString('de-DE',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',',''):'';};
(LIVE.status||[]).forEach(s=>{const o=orders.find(x=>String(x.id)===String(s.orderId)); if(!o||s.open===true) return;
  o.status='sent'; o.lockedOnOpen=true; o.sentAt=''; lockedOnOpen++;
  o.rts=s.found===false?'':String(s.statusCode||''); o.rtsLabel=s.found===false?'nicht mehr in RTS':String(s.statusLabel||'').replace(/^[\d.]+\s*[-·]?\s*/,'');
  const v=s.values||{}, c=o.conf; c.slot=''; c.comment=''; if(v.deliveredWagons!=null) c.wagons=parseInt(v.deliveredWagons,10)||0; if(RtsV2Boot.iso(v.deliveryDate)) c.date=RtsV2Boot.iso(v.deliveryDate); const sf=RtsV2Boot.time(v.slotFrom), su=RtsV2Boot.time(v.slotUntil); if(sf&&su) c.slot=sf+' - '+su; c.noShow=v.noShow===true?'Yes':'No'; if(v.comment) c.comment=String(v.comment);
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

/* ---------------- render ---------------- */
function filtered(){
  return orders.filter(o=>(fDay==='all'||o.date===fDay)&&(fPlant==='all'||o.plant===fPlant)&&(fSupp==='all'||o.supplier===fSupp)
    &&matchStatus(o)
    &&(!q||(o.id+' '+o.plant+' '+o.dest+' '+o.supplier).toLowerCase().includes(q.toLowerCase())));
}
function renderSummary(){
  const c={open:0,draft:0,ok:0,dev:0}; orders.forEach(o=>{c[stateOf(o)]++; if(isDev(o)) c.dev++;});
  const tile=(k,lbl,col,v)=>`<button class="tile" data-st="${k}" aria-pressed="${fStatus===k}"><span class="k"><span class="sw" style="background:${col}"></span>${lbl}</span><span class="v num">${v}</span></button>`;
  $('#summary').setAttribute('aria-label',t('summary'));
  $('#summary').innerHTML=tile('open',t('sOpen'),'var(--muted)',c.open)+tile('draft',t('sDraft'),'var(--draft)',c.draft)+tile('ok',t('sSent'),'var(--ok)',c.ok)+tile('dev',t('sDev'),'var(--warn)',c.dev);
  document.querySelectorAll('#summary button.tile').forEach(b=>b.onclick=()=>{fStatus=fStatus===b.dataset.st?'all':b.dataset.st;render();});
  const open=orders.filter(o=>o.status!=='sent').length; $('#openCnt').textContent=open; $('#openSub').textContent=t('fOpenS')(orders.length);
}
function renderFilters(){
  const cnt=d=>orders.filter(o=>o.date===d).length;
  $('#dayChips').innerHTML=`<button class="chip" data-d="all" aria-pressed="${fDay==='all'}">${t('all')}</button>`+DAYS.filter(d=>cnt(d.d)).map(d=>`<button class="chip" data-d="${d.d}" aria-pressed="${fDay===d.d}">${d[lang]} <span class="c">${cnt(d.d)}</span></button>`).join('');
  document.querySelectorAll('#dayChips .chip').forEach(b=>b.onclick=()=>{fDay=b.dataset.d;render();});
  const opt=(vals,cur)=>`<option value="all">${t('all')}</option>`+vals.map(v=>`<option value="${esc(v)}" ${cur===v?'selected':''}>${esc(v)}</option>`).join('');
  $('#fPlant').innerHTML=opt([...new Set(orders.map(o=>o.plant))].sort(),fPlant);
  $('#fSupp').innerHTML=opt([...new Set(orders.map(o=>o.supplier))].sort(),fSupp);
}
function pill(o){
  if(o.lockedOnOpen) return lockedPill(o);
  if(o.status==='draft') return `<span class="pill p-draft" title="${t('draftTip')}"><i></i>${t('draft')}</span>`;
  if(o.status==='sent') return `<span class="pill p-ok" title="${t('rtsSt')} 42"><i></i>42 · ${t('st42')}</span>${isDev(o)?`<span class="pill p-dev">⚠ ${t('devTag')}</span>`:''}`;
  return `<span class="pill p-open" title="${t('rtsSt')} 41"><i></i>41 · ${t('st41')}</span>`;
}
function ctl(o,k){
  const v=o.conf[k]??'', e=o._tried?validate(o):{}, chg=String(v)!==String(o.base[k]??'');
  const a=(cls,extra='')=>`class="gi ${cls} ${chg?'chg':''}" data-id="${esc(o.id)}" data-k="${k}" ${extra}`;
  if(k==='date') return v?`<input type="date" value="${v}" ${a(v!==o.date?'devv':'','aria-label="'+t('cDate')+'"')}>`:`<input type="text" data-ph="date" placeholder="${t('datePh')}" ${a('','aria-label="'+t('cDate')+'"')}>`;
  if(k==='slot') return `<select ${a('','aria-label="'+t('cSlot')+'"')}><option value="">${t('slotPh')}</option>${SLOTS.map(x=>`<option ${x===v?'selected':''}>${x}</option>`).join('')}</select>`;
  if(k==='noShow') return `<select ${a(v==='Yes'?'devv':'','aria-label="'+t('noShowAria')+'"')}><option value="No" ${v==='No'?'selected':''}>${t('no')}</option><option value="Yes" ${v==='Yes'?'selected':''}>${t('yes')}</option></select>`;
  if(k==='reason') return `<select ${a(isDev(o)&&v==='None'?'miss':'','aria-label="'+t('lblReason')+'"')}>${REASONS.map(([c,x])=>`<option value="${c}" ${c===v?'selected':''}>${esc(x)}</option>`).join('')}</select>`;
  if(k==='comment') return `<input type="text" maxlength="${MAX_COMMENT}" value="${esc(v)}" placeholder="${t('commentPh')(MAX_COMMENT)}" ${a(isDev(o)&&!String(v).trim()?'miss':'','aria-label="'+t('lblComment')+'"')}>`;
  return '';
}
// ⇊ groups: Ist-Transportdatum + Slot (in the date cell), Slot alone (in the slot cell)
const CG={ds:['date','slot'],slot:['slot'],wag:['wagons','reason','comment']};
const PARTS={wag:[
  {id:'n',k:['wagons'],show:o=>hasV(o.conf.wagons)?`<b class="num">${o.conf.wagons}</b> ${lang==='de'?'Wagen':'wagons'}`:''},
  {id:'rc',k:['reason','comment'],show:o=>(o.conf.reason&&o.conf.reason!=='None')?`<b>${lang==='de'?'Grund':'Reason'}</b>${String(o.conf.comment||'').trim()?(lang==='de'?' + Kommentar':' + comment'):''}`:''}]};
const hasV=v=>v!==''&&v!=null&&v!==false;
const _e=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
// ⇊ in the wagon cell: the menu lets the user tick which values to copy (amount, profile/type, reason)
function cpHead(o,g){const L=lang==='de', ps=(PARTS[g]||[]).map(p=>({id:p.id,h:p.show(o)})).filter(p=>p.h);
  if(ps.length<2) return `<div class="cph">${L?'Übernehmen':'Apply'}: ${ps.map(p=>p.h).join('')}</div>`;
  return `<div class="cph np">${L?'Übernehmen – was?':'Apply – what?'}</div><div class="cpparts">${ps.map(p=>`<label><input type="checkbox" value="${p.id}" checked>${p.h}</label>`).join('')}</div>`;}
function cpKeys(g,m){if(!PARTS[g]||!m.querySelector('.cpparts')) return CG[g]; return [...m.querySelectorAll('.cpparts input:checked')].flatMap(i=>PARTS[g].find(p=>p.id===i.value).k);}

const cpy=(o,g)=>o.status==='sent'||!CG[g].some(k=>hasV(o.conf[k]))?'':`<button class="cpy" data-cp="${g}" data-id="${esc(o.id)}" title="${t('cpTitle')}" aria-label="${t('cpAria')}">⇊</button>`;
function roVal(o,k){const v=o.conf[k];
  if(k==='date') return v?dLabel(v):'—'; if(k==='noShow') return v==='Yes'?t('yes'):t('no'); return v||'—';}
function renderTable(){
  const list=filtered();
  if(!list.length){$('#tableView').innerHTML=`<div class="empty">${t('empty')}<br><button class="link" data-reset="1">${t('reset')}</button></div>`;return;}
  const head=`<colgroup><col style="width:27%"><col style="width:16%"><col style="width:17%"><col style="width:17%"><col style="width:10%"><col style="width:13%"></colgroup>
   <thead><tr class="h"><th>${t('cTransport')}</th><th class="grp">${t('cWagons')} <span class="req" title="${t('reqTip')}">*</span></th><th class="grp">${t('cDate')}</th><th>${t('cSlot')}</th><th class="grp">${t('cNoShow')}</th><th></th></tr></thead>`;
  let lastDay='';
  const body=list.map(o=>{
    const e=o._tried?validate(o):{}, errs=Object.values(e), sent=o.status==='sent', c=o.conf, dev=isDev(o), id=esc(o.id);
    let grp=''; if(o.date!==lastDay){lastDay=o.date; const os=list.filter(x=>x.date===o.date), op=os.filter(x=>x.status!=='sent').length, ew=os.reduce((s,x)=>s+(x.expected||0),0);
      grp=`<tr class="dayrow"><td colspan="6"><span class="stub"><b class="num">${o.date.slice(8)}</b><span>${dayOf(o.date)[lang]} · ${t('month')}</span></span><span class="meta">${t('nTransports')(os.length)}${ew?` · ${t('nWag')(`<span class="num">${ew}</span>`)}`:''}${op?` · ${t('nOpen')(op)}`:` · ${t('allDone')}`}</span>${op?`<button class="btn dayok" data-dayok="${o.date}">✓ ${t('confirmDay')(op)}</button>`:''}</td></tr>`;}
    const wDev=o.expected!=null&&c.wagons!==''&&c.wagons!==o.expected, d=wDev?c.wagons-o.expected:0;
    const wag=sent
      ? `<span class="ordn ${wDev?'w-dev':''}">${c.wagons}</span>`
      : `<div class="wg ${wDev?'dev':''} ${e.wagons?'bad':''}"><button data-ta="minus" data-id="${id}" aria-label="${t('minus')}">−</button><input type="number" inputmode="numeric" min="0" max="9999" value="${c.wagons}" data-id="${id}" data-k="wagons" aria-label="${t('wagAria')}" aria-required="true"><button data-ta="plus" data-id="${id}" aria-label="${t('plus')}">+</button></div>${wDev?`<span class="delta">${d>0?'+':'−'}${Math.abs(d)}</span>`:''}`;
    const expHint=o.expected!=null&&(wDev||sent||c.wagons==='')?`<span class="hint2 ${wDev?'w':''}">${t('expected')(o.expected)}</span>`:'';
    const sollHint=c.date&&c.date!==o.date?`<span class="hint2 w">${t('soll')} ${dLabel(o.date)}</span>`:'';
    const hasNote=!!(String(c.comment).trim()||c.reason!=='None'), noteOpen=!sent&&(dev||o._note||hasNote);
    const noteLink=sent||dev||hasNote?'':`<button class="notelink" data-ta="note" data-id="${id}">${o._note?t('hideNote'):t('addNote')}</button>`;
    const main=`<tr class="${sent?'sent':''} ${errs.length?'errr':''}" data-row="${id}">
      <td><span class="rt" title="${esc(route(o))}">${esc(route(o))}</span>
          <span class="sub2"><span class="wpid">${id}</span><span class="supp">${esc(o.supplier)} <span>· ${t('kw')} ${esc(o.cw)}</span></span></span>
          <span class="sub2">${pill(o)}${errs.length?`<span class="errb" title="${esc(errs.join(' · '))}">!</span>`:''}</span></td>
      <td class="grp cp"><div class="wcell">${wag}</div>${expHint}${cpy(o,'wag')}</td>
      <td class="grp ${sent?'':'cp'}">${sent?`<span class="ro">${roVal(o,'date')}</span>`:ctl(o,'date')}${sollHint}${cpy(o,'ds')}</td>
      <td class="${sent?'':'cp'}">${sent?`<span class="ro">${roVal(o,'slot')}</span>`:ctl(o,'slot')}${cpy(o,'slot')}</td>
      <td class="grp">${sent?`<span class="ro ${c.noShow==='Yes'?'w-dev':''}">${roVal(o,'noShow')}</span>`:ctl(o,'noShow')}</td>
      <td class="act">${sent?`<span class="sentinfo">✓ ${o.sentAt}</span>`:`<button class="btn primary" data-ta="send" data-id="${id}">${t('send')}</button>${noteLink}`}</td></tr>`;
    const lbl=(l)=>`<small>${l} · <em>${dev?t('recommended'):t('optional')}</em></small>`;
    const devRow=noteOpen?`<tr class="devrow ${dev?'':'note'}"><td colspan="6"><div class="devline">
        <span class="devsum ${dev?'':'note'}">${dev?'⚠ '+devList(o).map(x=>`<span>${esc(x)}</span>`).join(''):t('noteSum')}</span>
        <div class="devf">${lbl(t('lblReason'))}${ctl(o,'reason')}</div><div class="devf grow">${lbl(t('lblComment'))}${ctl(o,'comment')}</div></div></td></tr>`:'';
    return grp+main+devRow;
  }).join('');
  $('#tableView').innerHTML=`<div class="grid" id="grid"><table>${head}<tbody>${body}</tbody></table></div>`;
}
const openShown=()=>filtered().filter(o=>o.status!=='sent');
function renderBars(){
  const c={open:0,draft:0,sent:0}; orders.forEach(o=>c[o.status]++);
  $('#bInfo').innerHTML=t('info')(c.open,c.draft,c.sent);
  $('#savedNote').innerHTML=lastSaved&&c.draft?`💾 ${t('saved')(lastSaved)}`:'';
  const sd=$('#sendShown'), n=openShown().length; sd.textContent=t('sendShown')(n); sd.disabled=!n;
}
function restoreFocus(){ if(!focusCell) return; const el=document.querySelector(`#tableView [data-id="${focusCell.id}"][data-k="${focusCell.k}"]`); if(el) el.focus({preventScroll:true}); }
function render(){
  $('#resetF').hidden=fDay==='all'&&fPlant==='all'&&fSupp==='all'&&fStatus==='all'&&!q;
  document.querySelectorAll('[data-i]').forEach(el=>{const v=T[lang][el.dataset.i]; if(typeof v==='string') el.textContent=v;});
  $('#q').placeholder=t('qPh'); $('#q').setAttribute('aria-label',t('qAria'));
  renderLock(); renderSummary(); renderFilters(); renderTable(); renderBars(); restoreFocus(); themeUi();
}

/* ---------------- sending ---------------- */
const byId=id=>orders.find(o=>o.id===id);
function touch(o){ if(o.status==='open') o.status='draft'; persist(); }
function toast(msg,bad){const el=$('#toast');el.textContent=msg;el.style.background=bad?'var(--bad)':'';el.classList.add('show');clearTimeout(toast.t);toast.t=setTimeout(()=>el.classList.remove('show'),2600);}
/* PROTOTYPE ONLY – nothing is sent anywhere.
   The real mask POSTs to the flow "Aufträge bestätigen & an Logistik senden - Senke" (CONFIG.ORDER_SUBMIT_URL,
   Content-Type application/json), body exactly as handleDeliverySubmit() in rtsapp2/app.js builds it:
   {
     submissionTimestamp: new Date().toISOString(),              // e.g. "2026-11-16T09:12:44.120Z"
     sessionToken: sessionToken,                                 // token from the login flow (result.token) or null
     deliveries: [{
       orderId: "WP-2461",                                       // sanitizeId(OrderID)
       deliveredWagons: 20,                                      // integer >= 0 (required)
       deliveredTransportDate: "2026-11-09",                     // value of <input type=date>: YYYY-MM-DD, "" if empty
       deliveryTimeSlot: "06:00 - 08:00",                        // generate2HourSlots() value "HH:00 - HH:00"
       deliveredDestinationNoShow: false,                        // boolean: select "Yes" -> true, "No" -> false
       reasonShortDeliveryDestination: "None",                   // REASON_SHORT_DELIVERY value: "None" | "05" | "06" | …
       destinationComment: ""                                    // string, cut to MAX_COMMENT_LENGTH (500)
     }]
   }
   Differences to the old mask: the old one always sends all cards in one POST; here per row / per day / all shown.
   The old slot select has no empty option (sends "00:00 - 02:00" when untouched); this one sends "" until a slot is chosen. */
function buildPayload(list){
  return {submissionTimestamp:new Date().toISOString(), sessionToken:null,
    deliveries:list.map(o=>({orderId:String(o.id).replace(/[^a-zA-Z0-9\-_äöüÄÖÜß]/g,''), deliveredWagons:o.conf.wagons, deliveredTransportDate:o.conf.date||'',
      deliveryTimeSlot:o.conf.slot||'', deliveredDestinationNoShow:o.conf.noShow==='Yes', reasonShortDeliveryDestination:o.conf.reason||'None',
      destinationComment:String(o.conf.comment||'').substring(0,MAX_COMMENT)}))};
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
    good.forEach(o=>{o._note=false; o.status='sent'; o.sentAt=at;});
    persist(); render(); toast(t('toastSent')(good.length));
    if(bad) setTimeout(()=>toast(blocked(bad),true),2700);
  } else { render(); toast(res.message,true); }
}
async function confirmMany(list,label){ if(!list.length) return;
  if(list.length>1&&!(await RtsV2Boot.ask(t('confirmMsg')(list.length,label).replace(/\n/g,' '), lang==='de'?`${list.length} bestätigen`:`Confirm ${list.length}`, lang==='de'?'Abbrechen':'Cancel'))) return;
  send(list); }

/* ---------------- copy menu (⇊) ---------------- */
function copyTargets(src,scope){const open=orders.filter(o=>o.status!=='sent'&&o.id!==src.id);
  return scope==='all'?open.filter(o=>filtered().includes(o)):scope==='day'?open.filter(o=>o.date===src.date):open.filter(o=>o.plant===src.plant&&o.dest===src.dest);}
function applyCopy(src,g,scope,keys=CG[g]){const l=copyTargets(src,scope);
  l.forEach(o=>{keys.forEach(k=>{let v=src.conf[k]; if(!hasV(v)) return;
    if(k==='date') v=addDays(o.date,dDiff(v,src.date));   // same distance to each transport's own day
    o.conf[k]=v;}); touch(o);});
  closeCp(); render(); toast(t('applied')(l.length));}
function closeCp(){const m=document.getElementById('cpMenu'); if(m) m.remove();}
function openCp(btn){closeCp(); const o=byId(btn.dataset.id), g=btn.dataset.cp, c=o.conf;
  const val=CG[g].map(k=>{const v=c[k]; if(!v) return ''; if(k!=='date') return esc(v); const d=dDiff(v,o.date); return dLabel(v)+(d?` <i>(${t('cpTday')} ${d>0?'+':''}${d})</i>`:'');}).filter(Boolean).join(' · ');
  const n=sc=>copyTargets(o,sc).length;
  const opts=[['day',t('cpDay')(dLabel(o.date))],['route',t('cpRoute')(esc(route(o)))],['all',t('cpAll')]].filter(([k])=>n(k)>0);
  const m=document.createElement('div'); m.id='cpMenu'; m.className='cpmenu'; m.setAttribute('role','menu');
  m.innerHTML=(PARTS[g]?cpHead(o,g):`<div class="cph">${t('cpHead')}: <b>${val}</b></div>`)+(opts.length?opts.map(([k,l])=>`<button role="menuitem" data-sc="${k}">${l}<span>${n(k)}</span></button>`).join(''):`<div class="cpe">${t('cpNone')}</div>`)
    +(CG[g].includes('date')?`<div class="cpf">${t('cpRel')}</div>`:'');
  document.body.appendChild(m); const r=btn.getBoundingClientRect(), w=m.offsetWidth;
  m.style.top=(r.bottom+window.scrollY+6)+'px'; m.style.left=Math.max(12,Math.min(r.right-w,window.innerWidth-w-12)+window.scrollX)+'px';
  m.onclick=e=>{const b=e.target.closest('[data-sc]'); if(!b) return; const ks=cpKeys(g,m); if(!ks.length){toast(lang==='de'?'Bitte mindestens einen Wert auswählen':'Choose at least one value',true);return;} applyCopy(o,g,b.dataset.sc,ks);}; m.querySelector('button')?.focus();}
document.addEventListener('click',e=>{if(!e.target.closest('#cpMenu,.cpy')) closeCp();});
document.addEventListener('keydown',e=>{if(e.key==='Escape') closeCp();});
window.addEventListener('scroll',closeCp,true);

/* ---------------- table interactions ---------------- */
function setVal(o,k,raw){
  const c=o.conf, v=String(raw??'');
  if(k==='wagons'){const s=v.trim(); if(s===''){c.wagons='';return true;} const n=parseInt(s,10); if(isNaN(n)) return false; c.wagons=Math.max(0,Math.min(9999,n)); return true;}
  if(k==='date'){const s=v.trim(); if(s&&!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false; c.date=s; return true;}
  if(k==='comment'){c.comment=v.substring(0,MAX_COMMENT); return true;}
  c[k]=v; return true;
}
const tv=$('#tableView');
const later=()=>{clearTimeout(tv._r); tv._r=setTimeout(render,0);};
tv.addEventListener('focusin',e=>{const el=e.target.closest('[data-k]'); if(!el) return; focusCell={id:el.dataset.id,k:el.dataset.k};
  if(el.dataset.ph){ el.type=el.dataset.ph; delete el.dataset.ph; try{el.showPicker&&el.showPicker()}catch(_){}} });
tv.addEventListener('change',e=>{
  const el=e.target.closest('[data-k]'); if(!el) return; const o=byId(el.dataset.id); if(!o) return;
  if(setVal(o,el.dataset.k,el.value)) touch(o);
  later();   // after focus has moved (Tab), so the new cell keeps focus
});
tv.addEventListener('keydown',e=>{
  const el=e.target.closest('[data-k]'); if(!el||e.key!=='Enter') return; e.preventDefault();
  const ids=filtered().filter(o=>o.status!=='sent').map(o=>o.id), i=ids.indexOf(el.dataset.id), nxt=ids[i+(e.shiftKey?-1:1)];
  if(nxt) focusCell={id:nxt,k:el.dataset.k};
  el.dispatchEvent(new Event('change',{bubbles:true})); later();
});
tv.addEventListener('click',e=>{
  if(e.target.closest('[data-reset]')){$('#resetF').click();return;}
  const cb=e.target.closest('.cpy'); if(cb){e.stopPropagation(); document.getElementById('cpMenu')?closeCp():openCp(cb); return;}
  const dk=e.target.closest('[data-dayok]'); if(dk){const d=dk.dataset.dayok; confirmMany(openShown().filter(o=>o.date===d),t('lblDay')(dLabel(d)));return;}
  const ta=e.target.closest('[data-ta]'); if(!ta) return; const o=byId(ta.dataset.id), a=ta.dataset.ta; if(!o) return;
  if(a==='minus'||a==='plus'){const cur=o.conf.wagons===''?(o.expected??0):o.conf.wagons; o.conf.wagons=Math.max(0,Math.min(9999,cur+(a==='plus'?1:-1))); touch(o); focusCell=null; render(); return;}
  if(a==='note'){ o._note=!o._note; focusCell=o._note?{id:o.id,k:'comment'}:null; render(); return;}
  if(a==='send'){send([o]); return;}
});

/* ---------------- filters, language, theme ---------------- */
$('#q').addEventListener('input',e=>{q=e.target.value;focusCell=null;render();$('#q').focus();});
$('#fPlant').onchange=e=>{fPlant=e.target.value;render();}; $('#fSupp').onchange=e=>{fSupp=e.target.value;render();};
$('#resetF').onclick=()=>{fDay='all';fPlant='all';fSupp='all';fStatus='all';q='';$('#q').value='';render();};
$('#sendShown').onclick=()=>confirmMany(openShown(),t('lblShown'));
const setLang=l=>{lang=l;$('#lDE').setAttribute('aria-pressed',String(l==='de'));$('#lEN').setAttribute('aria-pressed',String(l==='en'));document.documentElement.lang=l;render();};
$('#lDE').onclick=()=>setLang('de'); $('#lEN').onclick=()=>setLang('en');
const isDark=()=>{const r=document.documentElement;return r.dataset.theme?r.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;};
function themeUi(){const d=isDark(); $('#themeIco').innerHTML=d?'<svg width="15" height="15" viewBox="0 0 16 16" fill="currentColor"><path d="M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8M8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0m0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13m8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5M3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8m10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0m-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0m9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707M4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708"/></svg>':'<svg width="15" height="15" viewBox="0 0 16 16" fill="currentColor"><path d="M6 .278a.77.77 0 0 1 .08.858 7.2 7.2 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277q.792-.001 1.533-.16a.79.79 0 0 1 .81.316.73.73 0 0 1-.031.893A8.35 8.35 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.75.75 0 0 1 6 .278"/></svg>'; $('#themeTxt').textContent=d?t('light'):t('dark');}
$('#themeBtn').onclick=()=>{document.documentElement.dataset.theme=isDark()?'light':'dark'; try{localStorage.setItem('rtsMaskTheme',document.documentElement.dataset.theme)}catch(e){} themeUi();};
try{const th=localStorage.getItem('rtsMaskTheme'); if(th) document.documentElement.dataset.theme=th;}catch(e){}

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
