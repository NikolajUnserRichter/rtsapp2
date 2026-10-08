/**
 * Decoding test for the three rtsapp2 masks (Empfangsort, Wiederbeladung, Beladung).
 * The flows put base64 JSON into ?data=. Run before every push:  node tests/decode.test.js
 * Covers: '+' that arrives as a space, URL-encoded value, URL-safe base64 without padding,
 * umlauts (UTF-8) and a long payload.
 */
const fs = require('fs'), path = require('path'), vm = require('vm');

// atob as browsers implement it (WHATWG forgiving-base64): whitespace is dropped,
// only A-Z a-z 0-9 + / are allowed, '=' padding optional, length % 4 === 1 is an error.
function browserAtob(input) {
    let s = String(input).replace(/[\t\n\f\r ]/g, '');
    if (s.length % 4 === 0) s = s.replace(/={1,2}$/, '');
    if (s.length % 4 === 1 || /[^A-Za-z0-9+/]/.test(s)) {
        const err = new Error('InvalidCharacterError'); err.name = 'InvalidCharacterError'; throw err;
    }
    return Buffer.from(s, 'base64').toString('latin1');
}

function sandbox(search) {
    const el = new Proxy(function () {}, { get: (t, k) => (k === Symbol.toPrimitive ? () => '' : el), apply: () => el });
    const ctx = {
        console: { log() {}, warn() {}, error() {} },
        window: { location: { search }, addEventListener() {} },
        document: { addEventListener() {}, getElementById: () => null, querySelector: () => null,
                    querySelectorAll: () => [], createElement: () => el, body: el },
        URLSearchParams, atob: browserAtob,
        TextDecoder, Uint8Array, setTimeout() {}, fetch: async () => ({ ok: false, json: async () => [] }),
        bootstrap: { Modal: function () { return { show() {}, hide() {} }; } }
    };
    ctx.window.document = ctx.document;
    vm.createContext(ctx);
    return ctx;
}

function load(file, search, fnName) {
    const ctx = sandbox(search);
    vm.runInContext(fs.readFileSync(file, 'utf8') + `\n;this.__fn = ${fnName};`, ctx);
    return ctx.__fn();
}

// payload with umlauts; vary it until its base64 contains '+' (the case that broke links)
function payloadWithPlus(make) {
    for (let i = 0; i < 5000; i++) {
        const json = JSON.stringify(make(i));
        const b64 = Buffer.from(json, 'utf8').toString('base64');
        if (b64.includes('+')) return { b64, expect: JSON.parse(json) };
    }
    throw new Error('no payload with + found');
}

function variants(b64) {
    return {
        'raw link, + arrives as space': '?data=' + b64,
        'URL-encoded link': '?data=' + encodeURIComponent(b64),
        'URL-safe, no padding': '?data=' + b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    };
}

const transport = i => ({ OrderID: 'WP-' + (1400 + i) + '?>'.repeat(i % 3), SupplierName: 'ARS Altmann', CW: 42,
    Transportdatum: '16.10.2026', Departure: 'LEIPZIG WERK 5.0', Destination: 'Bremerhaven Süd – Überseehafen', WagonType: 'Offen' });
const many = n => Array.from({ length: n }, (_, k) => transport(k));

const pages = [
    { name: 'Empfangsort', file: 'app.js', fn: 'getOrdersFromUrl',
      make: i => [transport(i)], check: (r, e) => r.length === e.length && JSON.stringify(r).includes('Süd – Überseehafen') },
    { name: 'Empfangsort (40 transports)', file: 'app.js', fn: 'getOrdersFromUrl',
      make: i => many(40 + (i % 5)), check: (r, e) => r.length === e.length },
    { name: 'Wiederbeladung', file: 'wiederbeladung/app.js', fn: 'getPayloadFromUrl',
      make: i => ({ fdpShort: 'GRZPL', kw: 42, reasons: [], responsibles: [], transports: [transport(i)] }),
      check: (r, e) => r.transports.length === 1 && JSON.stringify(r).includes('Überseehafen') },
    { name: 'Beladung', file: 'beladung/app.js', fn: 'getPayloadFromUrl',
      make: i => ({ fdpShort: 'GRZPL', kw: 42, reasons: [], transports: [transport(i)] }),
      check: (r, e) => r.transports.length === 1 && JSON.stringify(r).includes('Überseehafen') }
];

let failed = 0;
for (const p of pages) {
    const { b64, expect } = payloadWithPlus(p.make);
    for (const [label, search] of Object.entries(variants(b64))) {
        let ok = false, info = '';
        try { ok = p.check(load(path.join(__dirname, '..', p.file), search, p.fn), expect); }
        catch (e) { info = ' (' + e.message + ')'; }
        console.log(`${ok ? 'PASS' : 'FAIL'}  ${p.name.padEnd(28)} ${label}${info}`);
        if (!ok) failed++;
    }
}
console.log(failed ? `\n${failed} test(s) failed` : '\nall decoding tests passed');
process.exit(failed ? 1 : 0);
