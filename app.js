'use strict'; // Enable strict mode for better error checking

// ============================================
// CONFIGURATION & CONSTANTS
// ============================================

/**
 * Application configuration constants
 * @constant {Object}
 */
const CONFIG = {
    AUTH_FLOW_URL: 'https://e157ee54d75be7b59e64b3c2c12166.51.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/3f3444f8c3514fe8873204c368389636/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SwlTj3if5ZKKomFHRBl7RZA-kmS3-X4oMm7NkNRVYFU',
    ORDER_SUBMIT_URL: 'https://e157ee54d75be7b59e64b3c2c12166.51.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/c3b6894a81804e10a1040bf9d114ae16/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=3k9xRRQyzvzaQPioR6-EuOVGvns-Ap0jE3CYRe4C8Ys',
    REQUEST_TIMEOUT: 30000, // 30 seconds
    MAX_USERNAME_LENGTH: 100,
    MAX_PASSWORD_LENGTH: 100,
    MAX_COMMENT_LENGTH: 500,
    VALID_ALERT_TYPES: ['success', 'danger', 'warning', 'info'],
    DEBOUNCE_DELAY: 300 // milliseconds for input debouncing
};

/**
 * Session token for authenticated requests
 * @type {string|null}
 */
let sessionToken = null;

/**
 * Cache for DOM elements to reduce lookups and improve performance
 * @constant {Object}
 */
const DOM_CACHE = {
    loginScreen: null,
    mainApp: null,
    loginForm: null,
    deliveryForm: null,
    ordersContainer: null,
    alertContainer: null,
    loginAlert: null
};

/**
 * Reason codes for short delivery destination
 * @constant {Array<{value: string, text: string}>}
 */
const REASON_SHORT_DELIVERY = [
    { value: 'None', text: '— Keine Unterlieferung —' },
    { value: '05', text: '05 Falsche Waggongattung angeliefert' },
    { value: '06', text: '06 Fehlende Waggons - Schadwaggon' },
    { value: '07', text: '07 Ausrangierung Schadwaggons' },
    { value: '08', text: '08 fehlende Lokführerverfügbarkeit' },
    { value: '09', text: '09 zu wenige Waggons - falsche Planung Bahn-DL' },
    { value: '10', text: '10 zu spät angelieferte Waggons' },
    { value: '11', text: '11 Fehlende Lokführerverfügbarkeit' },
    { value: '12', text: '12 Zugverspätung - Arbeitszeit Ende' },
    { value: '13', text: '13 Zugverspätung - Sonstiges Bahn DL' },
    { value: '14', text: '14 Zugverspätung -   Sonstiges' },
    { value: '15', text: '15 Streik - Bahn Infrastruktur' },
    { value: '25', text: '25 technische Störungen Bahnhof bzw. Rangierer' },
    { value: '26', text: '26 technische Störungen auf der Strecke (z.B. Bahnübergang, Stellwerkstörung)' },
    { value: '27', text: '27 Rangierleistung nicht ausreichend - Rangierdienst unterbesetzt' },
    { value: '28', text: '28 Rangierleistung nicht ausreichend  - Rangierdienst in Pause' },
    { value: '29', text: '29 Rangierleistung nicht ausreichend - Lokschaden/ Lokstörung' },
    { value: '30', text: '30 Zeitplanung Rangierverkehr' },
    { value: '31', text: '31 Rangierleistung nicht ausreichend (z.B. bei zu viel Rangierung Schadwaggons/Züge gleichzeitig/Lokverfügbarkeit/Lokführer krank, Lokstörrung…)' },
    { value: '32', text: '32 Stellwerk nicht besetzt' },
    { value: '33', text: '33 Lokzuführung verspätet' },
    { value: '34', text: '34 Warten aus Lok - Störung auf der Strecke; Fahren auf Sicht' },
    { value: '35', text: '35 Warten auf Lok - Infrastruktur überlastet' },
    { value: '36', text: '36 Warten aus Lok - Sonstiges' },
    { value: '37', text: '37 Streckensperrung --> keine Umleitung möglich' },
    { value: '38', text: '38 Baustelle/ Infrastruktur' },
    { value: '39', text: '39 Blockierung Transportwege (Abgrenzung zur technischen Störrung, z.B. liegengebliebener Zug auf der Strecke)' },
    { value: '40', text: '40 Umleitung netzbedingt; Personen im Gleis' },
    { value: '41', text: '41 Infrastruktur (Baustellen, Oberleitungsstörung, Rückstau wg. Überfüllung der Umleitungen)' },
    { value: '42', text: '42 fehlende Trassenverfügbarkeit' },
    { value: '43', text: '43 Dispositive Zulaufsteuerung' },
    { value: '53', text: '53 Fehlende Waggons - falsche Planung Bahn-DL' }
];

// ============================================
// SECURITY & VALIDATION UTILITIES
// ============================================

/**
 * Escapes HTML to prevent XSS attacks
 * Uses browser's built-in textContent for safe escaping
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML string
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Validates alert type to prevent CSS class injection
 * @param {string} type - Alert type to validate
 * @returns {string} Validated alert type (defaults to 'info' if invalid)
 */
function validateAlertType(type) {
    return CONFIG.VALID_ALERT_TYPES.includes(type) ? type : 'info';
}

/**
 * Sanitizes ID to ensure it only contains safe characters for HTML attributes
 * Allows alphanumeric characters, dash, underscore, and German umlauts
 * @param {string} id - ID to sanitize
 * @returns {string} Sanitized ID
 */
function sanitizeId(id) {
    // Remove any characters that are not alphanumeric, dash, underscore, or German umlauts
    // Specifically supports: a-z, A-Z, 0-9, -, _, ä, ö, ü, Ä, Ö, Ü, ß
    // Note: HTML5 supports non-ASCII characters in IDs
    return String(id).replace(/[^a-zA-Z0-9\-_äöüÄÖÜß]/g, '');
}

/**
 * Validates input length to prevent DoS attacks
 * @param {string} input - Input to validate
 * @param {number} maxLength - Maximum allowed length
 * @returns {boolean} Whether input is valid
 */
function validateInputLength(input, maxLength) {
    return input && input.length <= maxLength;
}

// ============================================
// PERFORMANCE UTILITIES
// ============================================

/**
 * Creates a debounced function that delays invoking func until after delay milliseconds
 * have elapsed since the last time the debounced function was invoked
 * @param {Function} func - Function to debounce
 * @param {number} delay - Delay in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, delay) {
    let timeoutId;
    return function debounced(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
}

/**
 * Creates a throttled function that only invokes func at most once per delay milliseconds
 * @param {Function} func - Function to throttle
 * @param {number} delay - Delay in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(func, delay) {
    let lastCall = 0;
    return function throttled(...args) {
        const now = Date.now();
        if (now - lastCall >= delay) {
            lastCall = now;
            return func.apply(this, args);
        }
    };
}

// ============================================
// DATA PROCESSING UTILITIES
// ============================================

/**
 * UTF-8 aware base64 decoding
 * Handles multi-byte Unicode characters properly
 * @param {string} str - Base64 encoded string
 * @returns {string} Decoded string
 */
function base64DecodeUnicode(str) {
    // Convert base64 to percent-encoding, then decode
    return decodeURIComponent(atob(str).split('').map(c => 
        `%${('00' + c.charCodeAt(0).toString(16)).slice(-2)}`
    ).join(''));
}

/**
 * Converts date from DD.MM.YYYY format to YYYY-MM-DD (ISO format)
 * @param {string} dateStr - Date string in DD.MM.YYYY format
 * @returns {string} Date in ISO format or original string if parsing fails
 */
function convertDateToISO(dateStr) {
    if (!dateStr) return '';
    const parts = dateStr.split('.');
    if (parts.length === 3) {
        const [day, month, year] = parts;
        return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
    }
    return dateStr;
}

/**
 * Generates 2-hour time slots as HTML options (00:00-02:00, ..., 22:00-00:00)
 * @returns {string} HTML options string for time slot selection
 */
function generate2HourSlots() {
    const slots = [];
    for (let h = 0; h < 24; h += 2) {
        const from = `${String(h).padStart(2, '0')}:00`;
        const toHour = (h + 2) % 24;
        const to = `${String(toHour).padStart(2, '0')}:00`;
        slots.push({
            value: `${from} - ${to}`,
            text: `${from} - ${to}`
        });
    }
    // Time slots are generated from controlled numeric values, no escaping needed
    return slots.map(slot => `<option value="${slot.value}">${slot.text}</option>`).join('');
}

// Pre-generate time slots for performance optimization
const twoHourSlotOptionsHtml = generate2HourSlots();

/**
 * Gets and normalizes order data from URL parameters
 * Handles backward compatibility with different field naming conventions
 * @returns {Array<Object>} Array of normalized order objects
 */
function getOrdersFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const encodedData = params.get('data');
    
    try {
        if (!encodedData) return [];
        
        let jsonString;
        try {
            // Try UTF-8 aware base64 decoding first
            jsonString = base64DecodeUnicode(encodedData);
        } catch { 
            try {
                // Fallback to regular base64
                jsonString = atob(encodedData);
            } catch {
                // Last resort: try URL decoding
                jsonString = decodeURIComponent(encodedData);
            }
        }
        
        const parsedData = JSON.parse(jsonString);
        const ordersArray = Array.isArray(parsedData) ? parsedData : [parsedData];
        
        return ordersArray.map(order => {
            // Note: Handle 'Depature' typo in source data for backward compatibility
            const departure = order.Departure || order.departure || order.Depature || 'N/A';
            const destination = order.Destination || order.destination || 'N/A';
            
            return {
                orderId: order.OrderID || order.orderId,
                supplier: order.SupplierName || order.supplier,
                cw: order.CW || order.cw,
                route: `${departure} nach ${destination}`,
                deliveryDate: (order.deliveryDate || order.DeliveryDate || '').trim(),
                departure: departure,
                deliveredWagons: order.DeliveredWagons || order.deliveredWagons || '',
                dlTransportdate: order.DlTransportdate || order.dlTransportdate || '',
                reasonShortDelivery: order['Reason Short Delivery Destination'] || order.reasonShortDeliveryDestination || '',
            };
        });
    } catch (e) {
        console.error('Error parsing order data:', e);
        return [];
    }
}

// ============================================
// UI UTILITIES
// ============================================

/**
 * Displays an alert message in the login screen
 * @param {string} message - Message to display
 * @param {string} type - Alert type (success, danger, warning, info)
 */
function showLoginAlert(message, type) {
    const alertContainer = DOM_CACHE.loginAlert || document.getElementById('login-alert');
    const validType = validateAlertType(type);
    const escapedMessage = escapeHtml(message);
    
    alertContainer.innerHTML = `
        <div class="alert alert-${validType} alert-dismissible fade show" role="alert">
            ${escapedMessage}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Schließen"></button>
        </div>`;
}

/**
 * Displays an alert message in the main application
 * @param {string} message - Message to display
 * @param {string} type - Alert type (success, danger, warning, info)
 */
function showAlert(message, type) {
    const alertContainer = DOM_CACHE.alertContainer || document.getElementById('alert-container');
    const validType = validateAlertType(type);
    const escapedMessage = escapeHtml(message);
    
    alertContainer.innerHTML = `
        <div class="alert alert-${validType} alert-dismissible fade show" role="alert" style="font-size: 1rem;">
            ${escapedMessage}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Schließen"></button>
        </div>`;
}

/**
 * Creates HTML for a single delivery card with all form fields
 * @param {Object} order - Order data object
 * @returns {string} HTML string for the order card
 */
function createDeliveryCard(order) {
    const id = sanitizeId(order.orderId || 'UNKNOWN');
    
    // Extract the code from the reason (e.g., "38 Baustelle/Infrastruktur" -> "38")
    const reasonCode = (order.reasonShortDelivery || '').split(' ')[0] || '';
    
    const reasonOpts = REASON_SHORT_DELIVERY.map(r => {
        const selected = r.value === reasonCode ? ' selected' : '';
        return `<option value="${escapeHtml(r.value)}"${selected}>${escapeHtml(r.text)}</option>`;
    }).join('');

    return `
        <article class="order-card" data-order-id="${id}" role="region" aria-labelledby="order-title-${id}">
            <h3 id="order-title-${id}" style="font-weight: 700; color: var(--color-primary); margin-bottom: var(--spacing-sm); border-bottom: 2px solid var(--color-gray-100); padding-bottom: var(--spacing-xs); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; font-size: 1.25rem;">
                <span>${escapeHtml(order.route || '')}</span>
                <span class="order-id-badge">Auftrag-ID: ${escapeHtml(order.orderId || 'UNKNOWN')}</span>
            </h3>
            
            <fieldset class="border-0 p-0">
                <legend class="visually-hidden">Auftragsdetails für ${escapeHtml(order.orderId || 'UNKNOWN')}</legend>
                
                <div class="row g-3 mb-3">
                    <!-- Read-only Information -->
                    <div class="col-md-4 mb-1">
                        <span class="readonly-label">Dienstleister</span>
                        <span class="readonly-data">${escapeHtml(order.supplier || 'N/A')}</span>
                    </div>
                    <div class="col-md-4 mb-1">
                        <span class="readonly-label">KW</span>
                        <span class="readonly-data">${escapeHtml(order.cw || 'N/A')}</span>
                    </div>
                    <div class="col-md-4 mb-1">
                        <span class="readonly-label">Soll-Transportdatum</span>
                        <span class="readonly-data">${escapeHtml(order.dlTransportdate || 'N/A')}</span>
                    </div>
                </div>
                
                <hr class="my-2">
                
                <!-- Editable Form Fields -->
                <div class="row g-3">
                    <!-- Delivery Details Group -->
                    <div class="col-md-4">
                        <label for="delivered-wagons-${id}" class="form-label">Gelieferte Waggons</label>
                        <input 
                            type="number" 
                            class="form-control" 
                            id="delivered-wagons-${id}" 
                            name="delivered-wagons-${id}" 
                            min="0" 
                            max="9999" 
                            value="${escapeHtml(String(order.deliveredWagons || ''))}" 
                            required 
                            aria-required="true"
                            aria-describedby="delivered-wagons-${id}-hint"
                            placeholder="Anzahl eingeben">
                        <small id="delivered-wagons-${id}-hint" class="form-text">Geben Sie die Anzahl der gelieferten Waggons ein</small>
                    </div>
                    <div class="col-md-4">
                        <label for="delivered-transport-date-${id}" class="form-label" data-bs-toggle="tooltip" data-bs-placement="top" title="Dieses Datum ggf. am Empfangsort eintragen">Ist-Transportdatum</label>
                        <input 
                            type="date" 
                            class="form-control" 
                            id="delivered-transport-date-${id}" 
                            name="delivered-transport-date-${id}" 
                            value="${escapeHtml(convertDateToISO(order.dlTransportdate || ''))}" 
                            aria-label="Ist-Transportdatum">
                    </div>
                    <div class="col-md-4">
                        <label for="delivery-time-slot-${id}" class="form-label">Lieferzeit-Slot (2h)</label>
                        <select 
                            class="form-select" 
                            id="delivery-time-slot-${id}" 
                            name="delivery-time-slot-${id}" 
                            aria-label="Lieferzeit-Slot wählen">
                            ${twoHourSlotOptionsHtml}
                        </select>
                    </div>
                    
                    <!-- No Show and Reason Group -->
                    <div class="col-md-6">
                        <label for="destination-no-show-${id}" class="form-label">No Show am Empfangsort</label>
                        <select 
                            class="form-select" 
                            id="destination-no-show-${id}" 
                            name="destination-no-show-${id}" 
                            required 
                            aria-required="true">
                            <option value="No">Nein</option>
                            <option value="Yes">Ja</option>
                        </select>
                    </div>
                    <div class="col-md-6">
                        <label for="reason-short-destination-${id}" class="form-label">Grund Unterlieferung Empfangsort</label>
                        <select 
                            class="form-select" 
                            id="reason-short-destination-${id}" 
                            name="reason-short-destination-${id}" 
                            aria-label="Grund Unterlieferung wählen">
                            ${reasonOpts}
                        </select>
                    </div>
                    
                    <!-- Comment Group -->
                    <div class="col-12">
                        <label for="destination-comment-${id}" class="form-label">Kommentar Empfangsort</label>
                        <textarea 
                            class="form-control" 
                            id="destination-comment-${id}" 
                            name="destination-comment-${id}" 
                            maxlength="${CONFIG.MAX_COMMENT_LENGTH}" 
                            rows="3" 
                            aria-label="Kommentar eingeben"
                            aria-describedby="destination-comment-${id}-hint"
                            placeholder="Optional: Zusätzliche Hinweise oder Bemerkungen"></textarea>
                        <small id="destination-comment-${id}-hint" class="form-text">Maximal ${CONFIG.MAX_COMMENT_LENGTH} Zeichen</small>
                    </div>
                </div>
            </fieldset>
        </article>
    `;
}

/**
 * Initializes Bootstrap tooltips for the current page
 * Disposes existing tooltips to prevent memory leaks
 */
function initializeTooltips() {
    const tooltipTriggerList = Array.from(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.forEach((tooltipTriggerEl) => {
        // Dispose existing tooltip if any to prevent memory leaks
        const existingTooltip = bootstrap.Tooltip.getInstance(tooltipTriggerEl);
        if (existingTooltip) {
            existingTooltip.dispose();
        }
        new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Loads and displays order forms from URL data
 * Uses document fragment for optimal DOM performance
 */
function loadForm() {
    const ordersData = getOrdersFromUrl();
    const container = DOM_CACHE.ordersContainer || document.getElementById('orders-container');
    
    if (ordersData.length === 0) {
        container.innerHTML = `
            <div class="alert alert-danger" role="alert">
                <strong>Fehler:</strong> Es wurden keine Bestelldaten übergeben oder die Daten konnten nicht geladen werden.<br><br>
                Bitte wenden Sie sich an das Logistik-Team oder überprüfen Sie den Link.
            </div>`;
        const submitBtn = document.querySelector('#delivery-form button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
        return;
    }
    
    // Use document fragment for better performance - single reflow instead of multiple
    const fragment = document.createDocumentFragment();
    const tempDiv = document.createElement('div');
    
    ordersData.forEach(order => {
        tempDiv.innerHTML = createDeliveryCard(order);
        while (tempDiv.firstChild) {
            fragment.appendChild(tempDiv.firstChild);
        }
    });
    
    container.innerHTML = '';
    container.appendChild(fragment);
    
    // Initialize Bootstrap tooltips
    initializeTooltips();
}

// ============================================
// API UTILITIES
// ============================================

/**
 * Makes a fetch request with timeout to prevent hanging requests
 * @param {string} url - URL to fetch
 * @param {Object} options - Fetch options
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<Response>} Fetch promise with timeout
 */
function fetchWithTimeout(url, options = {}, timeout = CONFIG.REQUEST_TIMEOUT) {
    return Promise.race([
        fetch(url, options),
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Request timeout')), timeout)
        )
    ]);
}

// ============================================
// EVENT HANDLERS
// ============================================

/**
 * Handles login form submission with validation and error handling
 * @param {Event} event - Submit event
 * @returns {Promise<void>}
 */
async function handleLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    // Validate input lengths to prevent DoS
    if (!validateInputLength(username, CONFIG.MAX_USERNAME_LENGTH)) {
        showLoginAlert('Benutzername ist zu lang.', 'danger');
        return;
    }
    if (!validateInputLength(password, CONFIG.MAX_PASSWORD_LENGTH)) {
        showLoginAlert('Passwort ist zu lang.', 'danger');
        return;
    }
    
    const loginBtn = document.getElementById('login-btn');
    const loginBtnText = document.getElementById('login-btn-text');
    const loginSpinner = document.getElementById('login-spinner');
    
    // Update UI to show loading state
    loginBtn.disabled = true;
    loginBtn.classList.add('loading');
    loginBtnText.textContent = 'Überprüfung...';
    loginSpinner.classList.remove('hidden');
    
    try {
        const response = await fetchWithTimeout(CONFIG.AUTH_FLOW_URL, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password,
                timestamp: new Date().toISOString()
            })
        });
        
        const result = await response.json();
        
        if (response.ok && result.authenticated === true) {
            sessionToken = result.token || null;
            DOM_CACHE.loginScreen.classList.add('hidden');
            DOM_CACHE.mainApp.classList.remove('hidden');
            
            // Set focus to main content for screen readers
            const mainContent = document.getElementById('main-content');
            if (mainContent) {
                mainContent.focus();
            }
            
            loadForm();
        } else {
            showLoginAlert('Ungültiger Benutzername oder Passwort. Bitte versuchen Sie es erneut.', 'danger');
        }
    } catch (error) {
        console.error('Login error:', error);
        const errorMessage = error.message === 'Request timeout' 
            ? 'Die Anfrage hat zu lange gedauert. Bitte versuchen Sie es erneut.' 
            : 'Verbindungsfehler. Bitte versuchen Sie es später erneut.';
        showLoginAlert(errorMessage, 'danger');
    } finally {
        // Reset button state
        loginBtn.disabled = false;
        loginBtn.classList.remove('loading');
        loginBtnText.textContent = 'Anmelden';
        loginSpinner.classList.add('hidden');
    }
}

/**
 * Handles delivery form submission with comprehensive validation
 * @param {Event} event - Submit event
 * @returns {Promise<void>}
 */
async function handleDeliverySubmit(event) {
    event.preventDefault();
    
    // Show confirmation dialog before submitting
    if (!confirm('Möchten Sie die Transportbestätigung wirklich absenden? Diese Aktion kann nicht rückgängig gemacht werden.')) {
        return;
    }
    
    const deliveryData = [];
    const cards = document.querySelectorAll('.order-card');
    let hasValidationError = false;
    
    // Collect and validate data from all order cards
    cards.forEach(card => {
        const id = card.getAttribute('data-order-id');
        const deliveredWagonsEl = document.getElementById(`delivered-wagons-${id}`);
        const deliveredWagons = parseInt(deliveredWagonsEl.value, 10);
        
        // Validate number input
        if (isNaN(deliveredWagons) || deliveredWagons < 0) {
            deliveredWagonsEl.setCustomValidity('Bitte geben Sie eine gültige Anzahl ein.');
            deliveredWagonsEl.reportValidity();
            hasValidationError = true;
            return;
        }
        
        // Clear any previous custom validity
        deliveredWagonsEl.setCustomValidity('');
        
        const commentEl = document.getElementById(`destination-comment-${id}`);
        const comment = commentEl.value.substring(0, CONFIG.MAX_COMMENT_LENGTH);
        
        deliveryData.push({
            orderId: id,
            deliveredWagons: deliveredWagons,
            deliveredTransportDate: document.getElementById(`delivered-transport-date-${id}`).value,
            deliveryTimeSlot: document.getElementById(`delivery-time-slot-${id}`).value,
            deliveredDestinationNoShow: document.getElementById(`destination-no-show-${id}`).value === "Yes",
            reasonShortDeliveryDestination: document.getElementById(`reason-short-destination-${id}`).value,
            destinationComment: comment,
        });
    });
    
    // Stop submission if validation failed
    if (hasValidationError) {
        return;
    }

    const payload = {
        submissionTimestamp: new Date().toISOString(),
        sessionToken: sessionToken,
        deliveries: deliveryData
    };

    const submitBtn = event.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.classList.add('loading');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Wird übermittelt...';
    submitBtn.setAttribute('aria-busy', 'true');

    try {
        const response = await fetchWithTimeout(CONFIG.ORDER_SUBMIT_URL, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        if (response.ok) {
            showAlert('Erfolg! Die Lieferungen wurden bestätigt und übermittelt.', 'success');
            // Keep button disabled after successful submission to prevent duplicate submissions
            submitBtn.textContent = 'Erfolgreich gesendet ✓';
        } else {
            const errorText = await response.text().catch(() => 'Keine Details verfügbar');
            showAlert(`Übermittlung fehlgeschlagen. Server-Status: ${response.status}. ${errorText}`, 'danger');
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    } catch (error) {
        console.error('Submission error:', error);
        const errorMessage = error.message === 'Request timeout'
            ? 'Die Übermittlung hat zu lange gedauert. Bitte überprüfen Sie Ihre Verbindung und versuchen Sie es erneut.'
            : 'Ein Fehler ist aufgetreten. Bitte prüfen Sie Ihre Verbindung oder wenden Sie sich an den Support.';
        showAlert(errorMessage, 'danger');
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    } finally {
        submitBtn.classList.remove('loading');
        submitBtn.setAttribute('aria-busy', 'false');
    }
}

// ============================================
// INITIALIZATION
// ============================================

/**
 * Initializes the application when DOM is ready
 * Sets up event listeners and caches DOM elements
 */
document.addEventListener('DOMContentLoaded', () => {
    // Cache DOM elements for better performance
    DOM_CACHE.loginScreen = document.getElementById('login-screen');
    DOM_CACHE.mainApp = document.getElementById('main-app');
    DOM_CACHE.loginForm = document.getElementById('login-form');
    DOM_CACHE.deliveryForm = document.getElementById('delivery-form');
    DOM_CACHE.ordersContainer = document.getElementById('orders-container');
    DOM_CACHE.alertContainer = document.getElementById('alert-container');
    DOM_CACHE.loginAlert = document.getElementById('login-alert');
    
    // Register event handlers
    DOM_CACHE.loginForm.addEventListener('submit', handleLogin);
    DOM_CACHE.deliveryForm.addEventListener('submit', handleDeliverySubmit);
    
    // Log application initialization for debugging
    console.log('BMW Transport Confirmation Application initialized');
});
