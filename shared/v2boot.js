/**
 * RTS masks v2 – shared start code for the three masks of this repo (destination, Wiederbeladung, Beladung).
 * Link decoding, login, status lock and sending. Each mask adds its own config.js (endpoints per environment,
 * generated from the first mask) and mask.js (generated from the approved prototype).
 */
const RtsV2Boot = (function () {
    'use strict';
    const $ = s => document.querySelector(s);
    const TIMEOUT = 30000;

    /** ?data= or #data= -> parsed JSON (object or array) or null. New links put the data after '#'
     *  (…/v2/?env=…#data=…): that part is never sent to the server, so long links do not hit GitHub Pages'
     *  request size limit (400). Accepts base64 with '+' turned into spaces, URL-safe base64, missing padding,
     *  a value that is still URL-encoded (the F21/F22 flows encode twice) and plain JSON. */
    function decodeLink(search, hash) {
        if (hash === undefined) hash = typeof window !== 'undefined' && window.location ? window.location.hash : '';
        let v = new URLSearchParams(search).get('data') || new URLSearchParams(String(hash || '').replace(/^#/, '')).get('data');
        if (!v) return null;
        for (let i = 0; i < 3 && /%[0-9A-Fa-f]{2}/.test(v) && !/^\s*[{\[]/.test(v); i++) {
            try { v = decodeURIComponent(v); } catch (e) { break; }
        }
        try {
            if (!/^\s*[{\[]/.test(v)) {
                let b64 = v.trim().replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
                while (b64.length % 4 !== 0) b64 += '=';
                const bin = atob(b64);
                v = new TextDecoder('utf-8').decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
            }
            return JSON.parse(v);
        } catch (e) {
            console.error('Link data could not be read', e);
            return null;
        }
    }

    function post(url, body) {
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), TIMEOUT);
        return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                            body: JSON.stringify(body), signal: ctl.signal }).finally(() => clearTimeout(timer));
    }

    /** yyyy-MM-dd from an ISO date/time or dd.MM.yyyy ('' if not a date) */
    function iso(value) {
        const v = String(value == null ? '' : value).trim();
        let m = v.match(/^(\d{4})-(\d{2})-(\d{2})/);
        if (m) return `${m[1]}-${m[2]}-${m[3]}`;
        m = v.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})$/);
        return m ? `${m[3]}-${m[2].padStart(2, '0')}-${m[1].padStart(2, '0')}` : '';
    }
    /** 'H:MM', 'HH:MM:SS' -> 'HH:MM' ('' if not a time) */
    function time(value) {
        const m = String(value == null ? '' : value).trim().match(/^(\d{1,2}):(\d{2})/);
        return m ? `${m[1].padStart(2, '0')}:${m[2]}` : '';
    }

    /**
     * opts: endpoints {auth, submit, reasons?, statusRead?}, mask ('delivery' | 'reload' | 'load'),
     *       orderIds [..], hasData bool, loadReasons? async () => [...], run (LIVE) => void
     * LIVE passed to run(): { reasons, status: [...transports of the status flow], statusAvailable, submit(payload) }
     */
    function boot(opts) {
        let sessionToken = null;

        async function loadStatus() {
            const url = opts.endpoints.statusRead;
            if (!url || !opts.orderIds.length) return { available: false, transports: [] };
            try {
                const r = await post(url, { mask: opts.mask, orderIds: opts.orderIds.slice(0, 200), sessionToken: sessionToken || '' });
                if (!r.ok) return { available: false, transports: [] };
                const b = await r.json();
                return { available: true, transports: Array.isArray(b.transports) ? b.transports : [] };
            } catch (e) { console.warn('Status could not be read', e); return { available: false, transports: [] }; }
        }

        /** payload = the body the write-back flow expects (built by the mask); the session token is added here */
        async function submit(payload) {
            try {
                const r = await post(opts.endpoints.submit, Object.assign({}, payload, { sessionToken }));
                if (r.ok) return { success: true, message: '' };
                return { success: false, message: `Senden fehlgeschlagen (Status ${r.status}). Es wurde nichts gespeichert – bitte erneut versuchen.` };
            } catch (e) {
                console.error('Submit error', e);
                return { success: false, message: 'Senden fehlgeschlagen. Bitte die Verbindung prüfen und erneut versuchen.' };
            }
        }

        async function start() {
            $('#loginScreen').hidden = true; $('#loading').hidden = false;
            const [reasons, status] = await Promise.all([opts.loadReasons ? opts.loadReasons(post) : Promise.resolve([]), loadStatus()]);
            $('#loading').hidden = true;
            document.body.classList.remove('gate');
            if (!opts.hasData) { $('#noData').hidden = false; return; }
            opts.run({ reasons, status: status.transports, statusAvailable: status.available, submit });
        }

        $('#loginForm').addEventListener('submit', async ev => {
            ev.preventDefault();
            const btn = $('#loginBtn'), msg = $('#loginMsg');
            const username = $('#username').value.trim(), password = $('#password').value;
            if (!username || !password) { msg.textContent = 'Benutzername und Passwort sind erforderlich.'; return; }
            btn.disabled = true; btn.textContent = 'Überprüfung …'; msg.textContent = '';
            try {
                const r = await post(opts.endpoints.auth, { username, password, timestamp: new Date().toISOString() });
                const res = await r.json();
                if (r.ok && res.authenticated === true) { sessionToken = res.token || null; start(); return; }
                msg.textContent = 'Ungültiger Benutzername oder Passwort.';
            } catch (e) {
                console.error('Login error', e);
                msg.textContent = 'Verbindungsfehler. Bitte später erneut versuchen.';
            }
            btn.disabled = false; btn.textContent = 'Anmelden';
        });
    }

    /** Page dialog instead of the browser's confirm(). Resolves true / false. */
    function ask(text, okLabel, cancelLabel) {
        return new Promise(res => {
            const d = document.getElementById('askDlg');
            document.getElementById('askText').textContent = text;
            document.getElementById('askOk').textContent = okLabel;
            document.getElementById('askNo').textContent = cancelLabel;
            const done = v => { d.onclose = null; d.close(); res(v); };
            document.getElementById('askOk').onclick = () => done(true);
            document.getElementById('askNo').onclick = () => done(false);
            d.onclose = () => res(false);
            d.showModal();
        });
    }

    return { decodeLink, post, iso, time, boot, ask };
})();

if (typeof module !== 'undefined') module.exports = RtsV2Boot;
