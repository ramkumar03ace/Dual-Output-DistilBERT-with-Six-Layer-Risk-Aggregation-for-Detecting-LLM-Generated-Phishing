/* ============================================
   Hybrid AI Defense — Gmail Content Script
   Extracts email body, subject & headers from Gmail DOM
   ============================================ */

(() => {
    'use strict';

    /**
     * Extract the currently open email body (text + HTML) from Gmail.
     * Gmail uses several selectors; we try them in priority order.
     */
    function extractEmailBody() {
        // Primary: Gmail's email body container
        const selectors = [
            'div.a3s.aiL',                    // Main email body (most common)
            'div.ii.gt div.a3s',              // Alternative wrapper
            'div[data-message-id] div.a3s',   // Newer Gmail
            'div.maincontent',                // Basic HTML Gmail
        ];

        for (const sel of selectors) {
            const elements = document.querySelectorAll(sel);
            if (elements.length > 0) {
                // Get the last (most recently opened) email body
                const el = elements[elements.length - 1];
                return { text: el.innerText.trim(), html: el.innerHTML };
            }
        }

        // Fallback: try to get any visible email text from the reading pane
        const readingPane = document.querySelector('div[role="listitem"] div.gs');
        if (readingPane) {
            return { text: readingPane.innerText.trim(), html: readingPane.innerHTML };
        }

        return null;
    }

    /**
     * Extract the email subject line from Gmail.
     */
    function extractSubject() {
        const selectors = [
            'h2.hP',                           // Standard subject heading
            'div.ha h2',                       // Alternative subject container
            'span[data-thread-perm-id]',       // Thread subject
            'input[name="subject"]',           // Compose mode
        ];

        for (const sel of selectors) {
            const el = document.querySelector(sel);
            if (el) {
                return (el.value || el.innerText || '').trim();
            }
        }

        return '';
    }

    /**
     * Helper to simulate a click on an element
     */
    function simulateClick(element) {
        if (!element) return;
        ['mousedown', 'mouseup', 'click'].forEach(eventType => {
            const event = new MouseEvent(eventType, {
                bubbles: true,
                cancelable: true,
                view: window
            });
            element.dispatchEvent(event);
        });
    }

    /**
     * Helper to delay execution
     */
    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

    /**
     * Extract sender metadata from Gmail's header section.
     * Looks for from, mailed-by, signed-by, security fields.
     */
    async function extractHeaders() {
        const headers = {
            from_name: null,
            from_email: null,
            mailed_by: null,
            signed_by: null,
            security: null,
        };

        try {
            // --- FROM: sender name and email ---
            // Gmail shows sender in a span with class 'gD' (name) and email attribute
            const senderEls = document.querySelectorAll('span.gD[email], span[email]');
            for (const el of senderEls) {
                const em = el.getAttribute('email');
                if (em && em.includes('@')) {
                    headers.from_name = (el.getAttribute('name') || el.innerText || '').trim();
                    headers.from_email = em.trim();
                    break;
                }
            }

            // --- CLICK 'SHOW DETAILS' IF NEEDED ---
            // Gmail puts mailed-by/signed-by inside a table/div that loads when you click "Show details"
            
            // Look for the arrow dropdown button
            const arrowBtns = document.querySelectorAll('[data-tooltip="Show details"], [aria-label="Show details"], img.ajz, div.ajy');
            for (const btn of arrowBtns) {
                if (btn && btn.offsetParent !== null) { // if visible
                    simulateClick(btn);
                    await delay(300); // Wait 300ms for DOM to hydrate
                    break;
                }
            }

            // --- EXTRACT MAILED-BY, SIGNED-BY, SECURITY ---
            // 1. Look for typical Gmail header tables (usually a <table> with class gK or similar)
            const allTds = document.querySelectorAll('td');
            allTds.forEach(td => {
                const text = (td.textContent || '').trim().toLowerCase();
                const nextTd = td.nextElementSibling;
                if (!nextTd) return;
                
                const valText = nextTd.textContent.trim();
                if (text.includes('mailed-by')) {
                    headers.mailed_by = valText;
                } else if (text.includes('signed-by')) {
                    headers.signed_by = valText;
                } else if (text.includes('security')) {
                    // Extract TLS part
                    const secMatch = valText.match(/^(.*?encryption.*?TLS.*?|.*?encryption.*?SSL.*?|^[^<]*)/i);
                    headers.security = secMatch ? secMatch[1].trim() : valText;
                }
            });

            // 2. Fallback: Parse visible text in the expanded header area
            if (!headers.mailed_by || !headers.signed_by) {
                const headerAreas = document.querySelectorAll('div.gE.iv.gt, div[data-message-id] table.gH, table');
                for (const area of headerAreas) {
                    const html = area.innerHTML;
                    
                    if (!headers.mailed_by) {
                        const mailedMatch = html.match(/>\s*mailed-by\s*[<:\s]+.*?>(.*?)<\//i) || area.innerText.match(/mailed-by:\s*([^\n]+)/i);
                        if (mailedMatch) headers.mailed_by = mailedMatch[1].trim();
                    }
                    if (!headers.signed_by) {
                        const signedMatch = html.match(/>\s*signed-by\s*[<:\s]+.*?>(.*?)<\//i) || area.innerText.match(/signed-by:\s*([^\n]+)/i);
                        if (signedMatch) headers.signed_by = signedMatch[1].trim();
                    }
                    if (!headers.security) {
                        const secMatch = html.match(/>\s*security\s*[<:\s]+.*?>(.*?)<\//i) || area.innerText.match(/security:\s*(.*?)(?:\n|$)/i);
                        if (secMatch) headers.security = secMatch[1].replace(/<[^>]*>?/gm, '').trim();
                    }
                }
            }

            // 3. Ultimate Fallback: Scrape all spans on the entire page
            if (!headers.mailed_by && !headers.signed_by) {
                const allSpans = document.querySelectorAll('span');
                for (let i = 0; i < allSpans.length; i++) {
                    const text = allSpans[i].textContent.trim().toLowerCase();
                    if ((text === 'mailed-by:' || text === 'mailed-by') && allSpans[i+1]) {
                        headers.mailed_by = allSpans[i+1].textContent.trim();
                    } else if ((text === 'signed-by:' || text === 'signed-by') && allSpans[i+1]) {
                        headers.signed_by = allSpans[i+1].textContent.trim();
                    } else if ((text === 'security:' || text === 'security') && allSpans[i+1]) {
                        headers.security = allSpans[i+1].textContent.trim();
                    }
                }
            }

        } catch (e) {
            console.warn('[Hybrid AI Defense] Header extraction error:', e);
        }

        return headers;
    }

    /**
     * Extract value after colon in text like "mailed-by: vit.ac.in"
     */
    function extractValueAfterColon(text) {
        const match = (text || '').match(/:\s*(.+)/);
        return match ? match[1].trim() : '';
    }

    // Listen for messages from the popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'extract_email') {
            (async () => {
                const result = extractEmailBody();
                const subject = extractSubject();
                const headers = await extractHeaders();

                if (result) {
                    sendResponse({
                        success: true,
                        subject: subject,
                        body: result.text,
                        body_html: result.html,
                        headers: headers,
                    });
                } else {
                    sendResponse({
                        success: false,
                        error: 'No email found. Please open an email in Gmail first.',
                    });
                }
            })();
            return true; // Indicate asynchronous response
        }
    });

    console.log('[Hybrid AI Defense] Content script loaded on Gmail.');
})();
