'use strict';

// ============================================
// CONFIGURATION & CONSTANTS
// ============================================

const CONFIG = {
    AUTH_FLOW_URL: 'https://e157ee54d75be7b59e64b3c2c12166.51.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/3f3444f8c3514fe8873204c368389636/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SwlTj3if5ZKKomFHRBl7RZA-kmS3-X4oMm7NkNRVYFU',
    // F22.R_Beladung bestätigen — HTTP write-back (env c06da98d, CSP-allowed).
    ORDER_SUBMIT_URL: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/18/workflows/2da33f7d32354e209c8ca5da3f36ad9f/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=2GptK-F0ZjIp22kh2gaieNxkN6Zj-bFVccdxtwCOsnE',
    REQUEST_TIMEOUT: 30000,
    MAX_USERNAME_LENGTH: 100,
    MAX_PASSWORD_LENGTH: 100,
    MAX_COMMENT_LENGTH: 500,
    VALID_ALERT_TYPES: ['success', 'danger', 'warning', 'info']
};

// Wagon picklist option values — hardcoded like the other masks.
// TODO: fill from the Dataverse choice columns rts_wagonprofile* / rts_wagontype*.
// Each entry: { value: '<stored value>', text: '<label shown>' }.
const WAGON_PROFILE_OPTIONS = [
    { value: '914890000', text: 'G1' },
    { value: '914890001', text: 'G2' }
];
const WAGON_TYPE_OPTIONS = [
    { value: '914890000', text: 'Offen' },
    { value: '914890001', text: 'Geschlossen' },
    { value: '914890002', text: 'Offen + Geschlossen' }
];

let sessionToken = null;

/** Whole decoded payload: { fdpShort, kw, reasons[], transports[] } */
let PAYLOAD = { fdpShort: '', kw: '', reasons: [], transports: [] };

const DOM_CACHE = {
    loginScreen: null, mainApp: null, loginForm: null,
    reloadForm: null, ordersContainer: null, alertContainer: null, loginAlert: null
};

// ============================================
// UTILITIES
// ============================================

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function validateAlertType(type) {
    return CONFIG.VALID_ALERT_TYPES.includes(type) ? type : 'info';
}

function sanitizeId(id) {
    return String(id === null || id === undefined ? 'UNKNOWN' : id).replace(/[^a-zA-Z0-9_-]/g, '_');
}

function validateInputLength(input, maxLength) {
    return typeof input === 'string' && input.length <= maxLength;
}

function base64DecodeUnicode(str) {
    return decodeURIComponent(atob(str).split('').map(c =>
        `%${('00' + c.charCodeAt(0).toString(16)).slice(-2)}`
    ).join(''));
}

function convertDateToISO(dateStr) {
    if (!dateStr) return '';
    const s = String(dateStr).trim();
    if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
    const parts = s.split('.');
    if (parts.length === 3) {
        const [day, month, year] = parts;
        return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
    }
    return '';
}

function normalizeTime(t) {
    if (!t) return '';
    const m = String(t).trim().match(/^(\d{1,2}):(\d{2})/);
    return m ? `${m[1].padStart(2, '0')}:${m[2]}` : '';
}

/** Abfahrtszeit Rampe prefill: Destination Departure Time, else Departure Departure Time. */
function rampePrefill(t) {
    const dest = normalizeTime(t.destinationDepartureTime);
    return dest || normalizeTime(t.departureDepartureTime);
}

function fetchWithTimeout(url, options = {}, timeout = CONFIG.REQUEST_TIMEOUT) {
    return Promise.race([
        fetch(url, options),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Request timeout')), timeout))
    ]);
}

// ============================================
// PAYLOAD
// ============================================

function getPayloadFromUrl() {
    let encoded = new URLSearchParams(window.location.search).get('data');
    const empty = { fdpShort: '', kw: '', reasons: [], transports: [] };
    if (!encoded) return empty;
    // URLSearchParams turns base64 '+' into spaces — restore them before decoding.
    encoded = encoded.replace(/ /g, '+');
    try {
        let jsonString;
        try { jsonString = base64DecodeUnicode(encoded); }
        catch { try { jsonString = atob(encoded); } catch { jsonString = decodeURIComponent(encoded); } }
        const data = JSON.parse(jsonString);
        return {
            fdpShort: data.fdpShort || '',
            kw: data.kw || '',
            reasons: Array.isArray(data.reasons) ? data.reasons : [],
            transports: Array.isArray(data.transports) ? data.transports : []
        };
    } catch (e) {
        console.error('Error parsing payload:', e);
        return empty;
    }
}

// ============================================
// OPTION-LIST BUILDERS
// ============================================

function reasonCategories() {
    const seen = new Set(); const out = [];
    PAYLOAD.reasons.forEach(r => {
        const k = r.kategorie || '';
        if (k && !seen.has(k)) { seen.add(k); out.push(k); }
    });
    return out;
}

function criterionOptionsFor(kategorie, selectedId) {
    return PAYLOAD.reasons
        .filter(r => (r.kategorie || '') === kategorie)
        .map(r => {
            const sel = String(r.id) === String(selectedId) ? ' selected' : '';
            return `<option value="${escapeHtml(r.id)}"${sel}>${escapeHtml(r.dropdown)}</option>`;
        }).join('');
}

function wagonOptions(list, prefill) {
    const opts = []; let hasPrefill = false;
    list.forEach(o => {
        const sel = String(o.value) === String(prefill) ? ' selected' : '';
        if (sel) hasPrefill = true;
        opts.push(`<option value="${escapeHtml(o.value)}"${sel}>${escapeHtml(o.text)}</option>`);
    });
    if (prefill && !hasPrefill) opts.unshift(`<option value="${escapeHtml(prefill)}" selected>${escapeHtml(prefill)}</option>`);
    opts.unshift(`<option value="">— bitte wählen —</option>`);
    return opts.join('');
}

// ============================================
// CARD RENDERING
// ============================================

function createLoadCard(t) {
    const id = sanitizeId(t.orderId);
    const cats = reasonCategories();
    // prefill the reason cascade from the transport's current reason id (rts_reasonshortdelivery)
    const confirmedReason = PAYLOAD.reasons.find(r => String(r.id) === String(t.reasonIdConfirmed || ''));
    const prefillCat = confirmedReason ? (confirmedReason.kategorie || '') : '';
    const prefillReasonId = confirmedReason ? confirmedReason.id : '';
    const catOpts = `<option value="">— bitte wählen —</option>` + cats.map(c =>
        `<option value="${escapeHtml(c)}"${c === prefillCat ? ' selected' : ''}>${escapeHtml(c)}</option>`).join('');
    const noShowTrue = t.noShow === true || t.noShow === 'true';

    return `
    <article class="order-card" data-order-id="${id}" data-raw-order-id="${escapeHtml(t.orderId ?? '')}" role="region" aria-labelledby="order-title-${id}">
      <h3 id="order-title-${id}" class="order-card-title">
        <span>${escapeHtml(t.werk || '')} &rarr; ${escapeHtml(t.senke || '')}</span>
        <span class="order-id-badge">Auftrag-ID: ${escapeHtml(t.orderId || 'UNKNOWN')}</span>
      </h3>
      <div class="order-meta">
        <span><strong>Dienstleister:</strong> ${escapeHtml(t.dienstleister || 'N/A')}</span>
        <span><strong>KW:</strong> ${escapeHtml(t.cw || PAYLOAD.kw || '')}</span>
      </div>

      <fieldset class="border-0 p-0">
        <legend class="visually-hidden">Angaben für ${escapeHtml(t.orderId || 'UNKNOWN')}</legend>

        <!-- Beladestatus -->
        <h4 class="section-title">Beladestatus</h4>
        <div class="row g-3 mb-2">
          <div class="col-md-4">
            <label for="loaded-wagons-${id}" class="form-label">Beladene Wagons</label>
            <input type="number" min="0" class="form-control" id="loaded-wagons-${id}" value="${escapeHtml(t.deliveredWagons ?? '')}">
          </div>
          <div class="col-md-4">
            <label for="loaded-date-${id}" class="form-label">Beladedatum</label>
            <input type="date" class="form-control" id="loaded-date-${id}" value="${escapeHtml(convertDateToISO(t.departureActualArrivalDate))}">
          </div>
          <div class="col-md-4">
            <label for="rampe-time-${id}" class="form-label">Abfahrtszeit Rampe <span class="text-muted">(optional)</span></label>
            <input type="time" class="form-control" id="rampe-time-${id}" value="${escapeHtml(rampePrefill(t))}">
          </div>
        </div>

        <!-- Wagonkonfiguration -->
        <h4 class="section-title">Wagonkonfiguration</h4>
        <div class="row g-3 mb-2">
          <div class="col-md-6">
            <label for="wagon-profile-${id}" class="form-label">Wagonprofil</label>
            <select class="form-select" id="wagon-profile-${id}">${wagonOptions(WAGON_PROFILE_OPTIONS, t.wagonProfileDelivery)}</select>
          </div>
          <div class="col-md-6">
            <label for="wagon-type-${id}" class="form-label">Wagonart</label>
            <select class="form-select" id="wagon-type-${id}">${wagonOptions(WAGON_TYPE_OPTIONS, t.wagonTypeDelivery)}</select>
          </div>
        </div>

        <!-- Probleme & Kosten -->
        <h4 class="section-title">Probleme &amp; Kosten</h4>
        <div class="row g-3 mb-2">
          <div class="col-md-4">
            <label for="no-show-${id}" class="form-label">No Show</label>
            <select class="form-select" id="no-show-${id}">
              <option value="false"${noShowTrue ? '' : ' selected'}>Nein</option>
              <option value="true"${noShowTrue ? ' selected' : ''}>Ja</option>
            </select>
          </div>
          <div class="col-md-4">
            <label for="reason-kategorie-${id}" class="form-label">Ursachenkluster</label>
            <select class="form-select reason-kategorie" id="reason-kategorie-${id}" data-order-id="${id}">${catOpts}</select>
          </div>
          <div class="col-md-4">
            <label for="reason-criterion-${id}" class="form-label">Minderleistungskriterium</label>
            <select class="form-select" id="reason-criterion-${id}">${criterionOptionsFor(prefillCat, prefillReasonId)}</select>
          </div>
        </div>

        <!-- Kommentare -->
        <h4 class="section-title">Kommentare</h4>
        <div class="row g-3 mb-1">
          <div class="col-12">
            <label for="comment-${id}" class="form-label">Kommentar Lieferung</label>
            <textarea class="form-control" id="comment-${id}" rows="2" maxlength="${CONFIG.MAX_COMMENT_LENGTH}"></textarea>
            <small class="form-text">Maximal ${CONFIG.MAX_COMMENT_LENGTH} Zeichen</small>
          </div>
        </div>
      </fieldset>
    </article>`;
}

function onKategorieChange(event) {
    const sel = event.target;
    if (!sel.classList.contains('reason-kategorie')) return;
    const id = sel.getAttribute('data-order-id');
    const crit = document.getElementById(`reason-criterion-${id}`);
    if (crit) crit.innerHTML = criterionOptionsFor(sel.value, '');
}

// ============================================
// UI ALERTS
// ============================================

function showLoginAlert(message, type) {
    const el = DOM_CACHE.loginAlert;
    if (!el) return;
    el.innerHTML = `<div class="alert alert-${validateAlertType(type)}" role="alert">${escapeHtml(message)}</div>`;
}

function showAlert(message, type) {
    const el = DOM_CACHE.alertContainer;
    if (!el) return;
    el.innerHTML = `<div class="alert alert-${validateAlertType(type)}" role="alert">${escapeHtml(message)}</div>`;
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ============================================
// FORM LOAD
// ============================================

function loadForm() {
    PAYLOAD = getPayloadFromUrl();
    const container = DOM_CACHE.ordersContainer || document.getElementById('orders-container');
    if (!PAYLOAD.transports.length) {
        container.innerHTML = `
            <div class="alert alert-danger" role="alert">
                <strong>Fehler:</strong> Es wurden keine Transportdaten übergeben oder die Daten konnten nicht geladen werden.<br><br>
                Bitte wenden Sie sich an das Logistik-Team oder überprüfen Sie den Link.
            </div>`;
        const submitBtn = document.querySelector('#reload-form button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
        return;
    }
    const fragment = document.createDocumentFragment();
    const tmp = document.createElement('div');
    PAYLOAD.transports.forEach(t => {
        tmp.innerHTML = createLoadCard(t);
        while (tmp.firstChild) fragment.appendChild(tmp.firstChild);
    });
    container.innerHTML = '';
    container.appendChild(fragment);
    container.addEventListener('change', onKategorieChange);
}

// ============================================
// LOGIN
// ============================================

async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    if (!validateInputLength(username, CONFIG.MAX_USERNAME_LENGTH)) { showLoginAlert('Benutzername ist zu lang.', 'danger'); return; }
    if (!validateInputLength(password, CONFIG.MAX_PASSWORD_LENGTH)) { showLoginAlert('Passwort ist zu lang.', 'danger'); return; }
    const loginBtn = document.getElementById('login-btn');
    const loginBtnText = document.getElementById('login-btn-text');
    const loginSpinner = document.getElementById('login-spinner');
    loginBtn.disabled = true; loginBtn.classList.add('loading');
    loginBtnText.textContent = 'Überprüfung...'; loginSpinner.classList.remove('hidden');
    try {
        const response = await fetchWithTimeout(CONFIG.AUTH_FLOW_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ username, password, timestamp: new Date().toISOString() })
        });
        const result = await response.json();
        if (response.ok && result.authenticated === true) {
            sessionToken = result.token || null;
            DOM_CACHE.loginScreen.classList.add('hidden');
            DOM_CACHE.mainApp.classList.remove('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.focus();
            loadForm();
        } else {
            showLoginAlert('Ungültiger Benutzername oder Passwort. Bitte versuchen Sie es erneut.', 'danger');
        }
    } catch (error) {
        console.error('Login error:', error);
        showLoginAlert(error.message === 'Request timeout'
            ? 'Die Anfrage hat zu lange gedauert. Bitte versuchen Sie es erneut.'
            : 'Verbindungsfehler. Bitte versuchen Sie es später erneut.', 'danger');
    } finally {
        loginBtn.disabled = false; loginBtn.classList.remove('loading');
        loginBtnText.textContent = 'Anmelden'; loginSpinner.classList.add('hidden');
    }
}

// ============================================
// CONFIRM MODAL (CSP-safe, class-based)
// ============================================

function showConfirm(message, opts = {}) {
    const { title = 'Bestätigung', confirmText = 'Absenden', cancelText = 'Abbrechen' } = opts;
    return new Promise((resolve) => {
        const overlay = document.createElement('div'); overlay.className = 'rts-confirm-overlay';
        const card = document.createElement('div'); card.className = 'rts-confirm-card';
        card.setAttribute('role', 'dialog'); card.setAttribute('aria-modal', 'true');
        const header = document.createElement('div'); header.className = 'rts-confirm-header'; header.textContent = title;
        const body = document.createElement('div'); body.className = 'rts-confirm-body'; body.textContent = message;
        const footer = document.createElement('div'); footer.className = 'rts-confirm-footer';
        const cancelBtn = document.createElement('button'); cancelBtn.type = 'button';
        cancelBtn.className = 'rts-confirm-btn rts-confirm-btn-cancel'; cancelBtn.textContent = cancelText;
        const confirmBtn = document.createElement('button'); confirmBtn.type = 'button';
        confirmBtn.className = 'rts-confirm-btn rts-confirm-btn-confirm'; confirmBtn.textContent = confirmText;
        footer.append(cancelBtn, confirmBtn); card.append(header, body, footer);
        overlay.appendChild(card); document.body.appendChild(overlay);
        requestAnimationFrame(() => overlay.classList.add('is-visible'));
        const cleanup = (result) => {
            document.removeEventListener('keydown', onKey);
            overlay.classList.remove('is-visible');
            setTimeout(() => overlay.remove(), 300);
            resolve(result);
        };
        const onKey = (e) => { if (e.key === 'Escape') cleanup(false); else if (e.key === 'Enter') cleanup(true); };
        cancelBtn.addEventListener('click', () => cleanup(false));
        confirmBtn.addEventListener('click', () => cleanup(true));
        overlay.addEventListener('click', (e) => { if (e.target === overlay) cleanup(false); });
        document.addEventListener('keydown', onKey);
        confirmBtn.focus();
    });
}

// ============================================
// SUBMIT
// ============================================

async function handleLoadSubmit(event) {
    event.preventDefault();
    if (!(await showConfirm('Möchten Sie die Angaben zur Beladung wirklich absenden? Diese Aktion kann nicht rückgängig gemacht werden.'))) {
        return;
    }
    const loads = [];
    document.querySelectorAll('.order-card').forEach(card => {
        const id = card.getAttribute('data-order-id');
        const orderId = card.getAttribute('data-raw-order-id') || id;
        const num = (elId) => {
            const el = document.getElementById(elId);
            if (!el || el.value === '') return null;
            const n = Number(el.value);
            return Number.isNaN(n) ? null : n;
        };
        const val = (elId) => { const el = document.getElementById(elId); return el ? el.value : ''; };
        loads.push({
            orderId: orderId,
            loadedWagons: num(`loaded-wagons-${id}`),
            loadedTransportDate: val(`loaded-date-${id}`),
            destinationDepartureTime: val(`rampe-time-${id}`),
            wagonProfileDelivery: val(`wagon-profile-${id}`),
            wagonTypeDelivery: val(`wagon-type-${id}`),
            noShow: val(`no-show-${id}`) === 'true',
            reasonId: val(`reason-criterion-${id}`),
            loadedComment: (val(`comment-${id}`) || '').substring(0, CONFIG.MAX_COMMENT_LENGTH)
        });
    });

    const payload = {
        submissionTimestamp: new Date().toISOString(),
        sessionToken: sessionToken,
        loads: loads
    };

    const submitBtn = event.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true; submitBtn.classList.add('loading');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Wird übermittelt...'; submitBtn.setAttribute('aria-busy', 'true');
    try {
        const response = await fetchWithTimeout(CONFIG.ORDER_SUBMIT_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (response.ok) {
            showAlert('Erfolg! Ihre Angaben zur Beladung wurden übermittelt.', 'success');
            submitBtn.textContent = 'Erfolgreich gesendet ✓';
        } else {
            const errorText = await response.text().catch(() => 'Keine Details verfügbar');
            showAlert(`Übermittlung fehlgeschlagen. Server-Status: ${response.status}. ${errorText}`, 'danger');
            submitBtn.disabled = false; submitBtn.textContent = originalText;
        }
    } catch (error) {
        console.error('Submission error:', error);
        showAlert(error.message === 'Request timeout'
            ? 'Die Übermittlung hat zu lange gedauert. Bitte versuchen Sie es erneut.'
            : 'Ein Fehler ist aufgetreten. Bitte prüfen Sie Ihre Verbindung oder wenden Sie sich an den Support.', 'danger');
        submitBtn.disabled = false; submitBtn.textContent = originalText;
    } finally {
        submitBtn.classList.remove('loading'); submitBtn.setAttribute('aria-busy', 'false');
    }
}

// ============================================
// INIT
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    DOM_CACHE.loginScreen = document.getElementById('login-screen');
    DOM_CACHE.mainApp = document.getElementById('main-app');
    DOM_CACHE.loginForm = document.getElementById('login-form');
    DOM_CACHE.reloadForm = document.getElementById('reload-form');
    DOM_CACHE.ordersContainer = document.getElementById('orders-container');
    DOM_CACHE.alertContainer = document.getElementById('alert-container');
    DOM_CACHE.loginAlert = document.getElementById('login-alert');
    DOM_CACHE.loginForm.addEventListener('submit', handleLogin);
    DOM_CACHE.reloadForm.addEventListener('submit', handleLoadSubmit);
    console.log('RTS Beladung mask initialized');
});
