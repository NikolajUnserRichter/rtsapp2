'use strict';

// ============================================
// CONFIGURATION & CONSTANTS
// ============================================

const CONFIG = {
    // Shared RTS login flow (same as the other masks)
    AUTH_FLOW_URL: 'https://e157ee54d75be7b59e64b3c2c12166.51.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/3f3444f8c3514fe8873204c368389636/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SwlTj3if5ZKKomFHRBl7RZA-kmS3-X4oMm7NkNRVYFU',
    // F21.R_Lieferung (leer) bestätigen — HTTP write-back (env c06da98d, CSP-allowed).
    ORDER_SUBMIT_URL: 'https://c06da98d80beeed0b9dfc8dfbc6001.57.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/31/workflows/611c9b8e26eb4655b5d28a0614f261f4/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=muqlB7zKUV3Y8qvHh4FxqtTsIYDAIV__pjDT--cUaj8',
    REQUEST_TIMEOUT: 30000,
    MAX_USERNAME_LENGTH: 100,
    MAX_PASSWORD_LENGTH: 100,
    MAX_COMMENT_LENGTH: 500,
    VALID_ALERT_TYPES: ['success', 'danger', 'warning', 'info']
};

// Wagon picklist option values — hardcoded like the other masks.
// TODO: fill these from the Dataverse choice columns
// rts_wagonprofile* / rts_wagontype* (couldn't be read from the export/msapp).
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

/** Whole decoded payload: { fdpShort, kw, reasons[], responsibles[], transports[] } */
let PAYLOAD = { fdpShort: '', kw: '', reasons: [], responsibles: [], transports: [] };

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

/** UTF-8 aware base64 decode. */
function base64DecodeUnicode(str) {
    return decodeURIComponent(atob(str).split('').map(c =>
        `%${('00' + c.charCodeAt(0).toString(16)).slice(-2)}`
    ).join(''));
}

/** DD.MM.YYYY (or already ISO) -> YYYY-MM-DD for <input type="date">. */
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

/** HH:MM (or HH:MM:SS) -> HH:MM for <input type="time">. */
function normalizeTime(t) {
    if (!t) return '';
    const m = String(t).trim().match(/^(\d{1,2}):(\d{2})/);
    return m ? `${m[1].padStart(2, '0')}:${m[2]}` : '';
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

/**
 * Decodes ?data= (base64 JSON) into the payload object.
 * Accepts the new shape { fdpShort, kw, reasons, responsibles, transports }.
 * @returns {{fdpShort:string, kw:(string|number), reasons:Array, responsibles:Array, transports:Array}}
 */
function getPayloadFromUrl() {
    const encoded = new URLSearchParams(window.location.search).get('data');
    const empty = { fdpShort: '', kw: '', reasons: [], responsibles: [], transports: [] };
    if (!encoded) return empty;
    try {
        let jsonString;
        try { jsonString = base64DecodeUnicode(encoded); }
        catch { try { jsonString = atob(encoded); } catch { jsonString = decodeURIComponent(encoded); } }
        const data = JSON.parse(jsonString);
        return {
            fdpShort: data.fdpShort || '',
            kw: data.kw || '',
            reasons: Array.isArray(data.reasons) ? data.reasons : [],
            responsibles: Array.isArray(data.responsibles) ? data.responsibles : [],
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

/** Unique Kategorie values from the reason list. */
function reasonCategories() {
    const seen = new Set();
    const out = [];
    PAYLOAD.reasons.forEach(r => {
        const k = r.kategorie || '';
        if (k && !seen.has(k)) { seen.add(k); out.push(k); }
    });
    return out;
}

/** <option>s for a given Kategorie: value = reason id, text = dropdown (Minderleistungskriterium). */
function criterionOptionsFor(kategorie, selectedId) {
    return PAYLOAD.reasons
        .filter(r => (r.kategorie || '') === kategorie)
        .map(r => {
            const sel = String(r.id) === String(selectedId) ? ' selected' : '';
            return `<option value="${escapeHtml(r.id)}"${sel}>${escapeHtml(r.dropdown)}</option>`;
        }).join('');
}

/** Build a wagon dropdown; always includes the prefilled confirmed value even if the option list is empty. */
function wagonOptions(list, prefill) {
    const opts = [];
    let hasPrefill = false;
    list.forEach(o => {
        const sel = String(o.value) === String(prefill) ? ' selected' : '';
        if (sel) hasPrefill = true;
        opts.push(`<option value="${escapeHtml(o.value)}"${sel}>${escapeHtml(o.text)}</option>`);
    });
    if (prefill && !hasPrefill) {
        opts.unshift(`<option value="${escapeHtml(prefill)}" selected>${escapeHtml(prefill)}</option>`);
    }
    opts.unshift(`<option value="">— bitte wählen —</option>`);
    return opts.join('');
}

function responsibleOptions() {
    const opts = PAYLOAD.responsibles.map(p =>
        `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join('');
    return `<option value="">— bitte wählen —</option>` + opts;
}

// ============================================
// CARD RENDERING
// ============================================

function createReloadCard(t) {
    const id = sanitizeId(t.orderId);
    const fdp = escapeHtml(PAYLOAD.fdpShort || '');
    const cats = reasonCategories();
    const prefillCat = t.reasonKategorieConfirmed || '';
    // resolve the confirmed reason id from kategorie + dropdown, for prefill of the criterion select
    const confirmedReason = PAYLOAD.reasons.find(r =>
        (r.kategorie || '') === prefillCat && (r.dropdown || '') === (t.reasonDropdownConfirmed || ''));
    const prefillReasonId = confirmedReason ? confirmedReason.id : '';

    const catOpts = `<option value="">— bitte wählen —</option>` + cats.map(c =>
        `<option value="${escapeHtml(c)}"${c === prefillCat ? ' selected' : ''}>${escapeHtml(c)}</option>`).join('');

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

        <!-- Lieferstatus -->
        <h4 class="section-title">Lieferstatus</h4>
        <div class="row g-3 mb-2">
          <div class="col-md-4">
            <label for="delivered-wagons-${id}" class="form-label">Gelieferte Wagons</label>
            <input type="number" min="0" class="form-control" id="delivered-wagons-${id}" value="${escapeHtml(t.confirmedWagons ?? '')}">
          </div>
          <div class="col-md-4">
            <label for="defective-wagons-${id}" class="form-label">Anzahl Schadwagons</label>
            <input type="number" min="0" class="form-control" id="defective-wagons-${id}" value="">
          </div>
          <div class="col-md-4">
            <label for="delivery-date-${id}" class="form-label">Lieferdatum</label>
            <input type="date" class="form-control" id="delivery-date-${id}" value="${escapeHtml(convertDateToISO(t.confirmedTransportDate))}">
          </div>
        </div>

        <!-- Ist-Zeiten am Übergabepunkt -->
        <h4 class="section-title">Ist-Zeiten am &Uuml;bergabepunkt${fdp ? ` [${fdp}]` : ''}</h4>
        <div class="row g-3 mb-2">
          <div class="col-md-4">
            <label for="arrival-from-${id}" class="form-label">Ankunftszeit an &Uuml;bergabepunkt (von)</label>
            <input type="time" class="form-control" id="arrival-from-${id}" value="${escapeHtml(normalizeTime(t.departureArrivalFrom))}">
          </div>
          <div class="col-md-4">
            <label for="arrival-until-${id}" class="form-label">Ankunftszeit an &Uuml;bergabepunkt (bis)</label>
            <input type="time" class="form-control" id="arrival-until-${id}" value="${escapeHtml(normalizeTime(t.departureArrivalUntil))}">
          </div>
          <div class="col-md-4">
            <label for="departure-time-${id}" class="form-label">Abfahrtszeit</label>
            <input type="time" class="form-control" id="departure-time-${id}" value="${escapeHtml(normalizeTime(t.departureDepartureTime))}">
          </div>
        </div>

        <!-- Wagonkonfiguration -->
        <h4 class="section-title">Wagonkonfiguration</h4>
        <div class="row g-3 mb-2">
          <div class="col-md-6">
            <label for="wagon-profile-${id}" class="form-label">Wagonprofil</label>
            <select class="form-select" id="wagon-profile-${id}">${wagonOptions(WAGON_PROFILE_OPTIONS, t.wagonProfileConfirmed)}</select>
          </div>
          <div class="col-md-6">
            <label for="wagon-type-${id}" class="form-label">Wagonart</label>
            <select class="form-select" id="wagon-type-${id}">${wagonOptions(WAGON_TYPE_OPTIONS, t.wagonTypeConfirmed)}</select>
          </div>
        </div>

        <!-- Probleme & Kosten -->
        <h4 class="section-title">Probleme &amp; Kosten</h4>
        <div class="row g-3 mb-2">
          <div class="col-md-3">
            <label for="no-show-${id}" class="form-label">No Show</label>
            <select class="form-select" id="no-show-${id}">
              <option value="false" selected>Nein</option>
              <option value="true">Ja</option>
            </select>
          </div>
          <div class="col-md-3">
            <label for="reason-kategorie-${id}" class="form-label">Ursachenkluster</label>
            <select class="form-select reason-kategorie" id="reason-kategorie-${id}" data-order-id="${id}">${catOpts}</select>
          </div>
          <div class="col-md-3">
            <label for="reason-criterion-${id}" class="form-label">Minderleistungskriterium</label>
            <select class="form-select" id="reason-criterion-${id}">${criterionOptionsFor(prefillCat, prefillReasonId)}</select>
          </div>
          <div class="col-md-3">
            <label for="incurred-costs-${id}" class="form-label">Entstandene Kosten</label>
            <input type="number" min="0" step="0.01" class="form-control" id="incurred-costs-${id}" value="">
          </div>
        </div>

        <!-- Verantwortlichkeit -->
        <h4 class="section-title">Verantwortlichkeit</h4>
        <div class="row g-3 mb-2">
          <div class="col-md-6">
            <label for="responsible-${id}" class="form-label">Verantwortlichkeit Lieferung <span class="required-mark">*</span></label>
            <select class="form-select" id="responsible-${id}" required aria-required="true">${responsibleOptions()}</select>
            <div class="invalid-feedback">Bitte wählen Sie eine verantwortliche Person aus.</div>
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

/** Repopulate a card's criterion select when its Kategorie changes. */
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
        tmp.innerHTML = createReloadCard(t);
        while (tmp.firstChild) fragment.appendChild(tmp.firstChild);
    });
    container.innerHTML = '';
    container.appendChild(fragment);
    // cascade: repopulate criterion when kategorie changes (delegated)
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
        const overlay = document.createElement('div');
        overlay.className = 'rts-confirm-overlay';
        const card = document.createElement('div');
        card.className = 'rts-confirm-card';
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

async function handleReloadSubmit(event) {
    event.preventDefault();

    if (!(await showConfirm('Möchten Sie die Angaben zur Wiederbeladung wirklich absenden? Diese Aktion kann nicht rückgängig gemacht werden.'))) {
        return;
    }

    const reloads = [];
    let hasValidationError = false;

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

        // Mandatory: Responsible for Delivery
        const responsibleEl = document.getElementById(`responsible-${id}`);
        if (!responsibleEl.value) {
            responsibleEl.setCustomValidity('Bitte wählen Sie eine verantwortliche Person aus.');
            responsibleEl.reportValidity();
            hasValidationError = true;
            return;
        }
        responsibleEl.setCustomValidity('');

        reloads.push({
            orderId: orderId,
            deliveredWagons: num(`delivered-wagons-${id}`),
            defectiveWagons: num(`defective-wagons-${id}`),
            deliveryDate: val(`delivery-date-${id}`),
            destinationArrivalFrom: val(`arrival-from-${id}`),
            destinationArrivalUntil: val(`arrival-until-${id}`),
            destinationDepartureTime: val(`departure-time-${id}`),
            wagonProfileDelivery: val(`wagon-profile-${id}`),
            wagonTypeDelivery: val(`wagon-type-${id}`),
            noShow: val(`no-show-${id}`) === 'true',
            reasonId: val(`reason-criterion-${id}`),
            incurredCosts: num(`incurred-costs-${id}`),
            responsibleId: responsibleEl.value,
            deliveredComment: (val(`comment-${id}`) || '').substring(0, CONFIG.MAX_COMMENT_LENGTH)
        });
    });

    if (hasValidationError) return;

    const payload = {
        submissionTimestamp: new Date().toISOString(),
        sessionToken: sessionToken,
        reloads: reloads
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
            showAlert('Erfolg! Ihre Angaben zur Wiederbeladung wurden übermittelt.', 'success');
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
    DOM_CACHE.reloadForm.addEventListener('submit', handleReloadSubmit);
    console.log('RTS Wiederbeladung mask initialized');
});
