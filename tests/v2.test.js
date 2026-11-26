/**
 * Masks v2 – tests of the shared start code.  Run:  node tests/v2.test.js
 * Covers: link decoding (base64 with '+', URL-encoded once and twice, URL-safe base64, umlauts, array and
 * object payloads, rubbish), date / time helpers, and that every v2 mask uses exactly the endpoints of its first mask.
 */
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
global.atob = s => { if (/[^A-Za-z0-9+/=]/.test(s)) throw new Error('InvalidCharacterError'); return Buffer.from(s, 'base64').toString('latin1'); };
const B = require('../shared/v2boot.js');
console.error = () => {};   // the 'rubbish' case logs its decode error on purpose

let failed = 0;
const eq = (name, got, want) => {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `\n      got  ${JSON.stringify(got)}\n      want ${JSON.stringify(want)}`}`);
};

// a payload whose base64 contains '+', '/' and padding
function payload() {
    for (let i = 0; i < 5000; i++) {
        const o = { fdpShort: 'VZG', kw: 47, transports: [{ orderId: 'WP-' + (2000 + i), werk: 'MÜNCHEN', senke: 'Bremerhaven Süd – Überseehafen ' + '?>'.repeat(i % 4) }] };
        const b64 = Buffer.from(JSON.stringify(o), 'utf8').toString('base64');
        if (b64.includes('+') && b64.includes('/') && b64.endsWith('=')) return { o, b64 };
    }
    throw new Error('no suitable payload');
}
const { o, b64 } = payload();
const variants = {
    'raw link, + arrives as a space': '?data=' + b64,
    'URL-encoded once (F10 / F41)': '?data=' + encodeURIComponent(b64),
    'URL-encoded twice (F21 / F22)': '?data=' + encodeURIComponent(encodeURIComponent(b64)),
    'URL-safe base64 without padding': '?data=' + b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    'plain JSON, URL-encoded': '?data=' + encodeURIComponent(JSON.stringify(o)),
};
for (const [name, search] of Object.entries(variants)) eq('link: ' + name, B.decodeLink(search + '&env=c06da98d'), o);
const arr = [{ orderId: 'WP-1', Destination: 'Zeebrügge' }];
eq('link: array payload (F41)', B.decodeLink('?data=' + encodeURIComponent(Buffer.from(JSON.stringify(arr), 'utf8').toString('base64'))), arr);
eq('link: no data', B.decodeLink('?env=c06da98d'), null);
// data after '#' (new links: ?env=…#data=…) – never sent to the server, so long links do not hit the 400 size limit
for (const [name, search] of Object.entries(variants)) eq('link after #: ' + name, B.decodeLink('?env=c06da98d', '#' + search.slice(1)), o);
eq('link: ?data= wins over #data=', B.decodeLink('?data=' + encodeURIComponent(b64), '#data=xxx'), o);
const big = Array.from({ length: 40 }, (_, i) => ({ orderId: 'WP-' + (3000 + i), Departure: 'WERK DINGOLFING PLATTLING', Destination: 'ZEEBRUGGE TERMINAL', wagons: 24, confirmedTransportDate: '30.11.2026', wagonProfile: 'G1', wagonType: 'Offen' }));
const bigHash = '#data=' + encodeURIComponent(encodeURIComponent(Buffer.from(JSON.stringify(big), 'utf8').toString('base64')));
eq('link: 40 transports after #, encoded twice (> 8 KB) are all read', [bigHash.length > 8192, (B.decodeLink('?env=28ade5d3', bigHash) || []).length], [true, 40]);
eq('link: rubbish', B.decodeLink('?data=%%%not-base64%%%'), null);

eq('dates', [B.iso('2026-11-16T00:00:00Z'), B.iso('16.11.2026'), B.iso('7.1.2027'), B.iso(''), B.iso(null), B.iso('x')], ['2026-11-16', '2026-11-16', '2027-01-07', '', '', '']);
eq('times', [B.time('6:05'), B.time('14:30:00'), B.time(''), B.time(null), B.time('abc')], ['06:05', '14:30', '', '', '']);

// endpoints: each v2 mask must carry the block of its first mask unchanged (rebuild after changing the first mask)
const block = f => { const s = fs.readFileSync(path.join(root, f), 'utf8'); const a = s.indexOf('const RTS_ENV = '); return s.slice(a, s.indexOf('}[RTS_ENV];', a) + 11); };
for (const [first, v2] of [['app.js', 'v2/config.js'], ['wiederbeladung/app.js', 'wiederbeladung/v2/config.js'], ['beladung/app.js', 'beladung/v2/config.js']]) {
    eq(`endpoints: ${v2} = ${first}`, block(v2) === block(first) && block(first).length > 500, true);
}

console.log(failed ? `\n${failed} test(s) FAILED` : '\nall tests passed');
process.exit(failed ? 1 : 0);
