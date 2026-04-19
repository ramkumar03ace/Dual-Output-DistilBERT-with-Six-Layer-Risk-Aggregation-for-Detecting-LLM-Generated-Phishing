/* ============================================
   Hybrid AI Defense — Extension Popup Logic
   Connects to backend /deep-analyze endpoint
   ============================================ */

const API_BASE = 'http://localhost:8001/api/v1';

// ---------- DOM Refs ----------
const $ = (sel) => document.querySelector(sel);
const statusChip = $('#statusChip');
const extractBtn = $('#extractBtn');
const analyzeBtn = $('#analyzeBtn');
const emailInput = $('#emailInput');
const subjectInput = $('#subjectInput');
const rawHeadersInput = $('#rawHeadersInput');
const crawlToggle = $('#crawlToggle');
const screenshotToggle = $('#screenshotToggle');
const resultsSection = $('#resultsSection');
const verdictBanner = $('#verdictBanner');
const verdictText = $('#verdictText');
const layersBadges = $('#layersBadges');
const gaugeFill = $('#gaugeFill');
const gaugeScore = $('#gaugeScore');
const errorToast = $('#errorToast');
const riskFactorsCard = $('#riskFactorsCard');
const riskFactorsList = $('#riskFactorsList');

const layers = {
    text: { score: $('#textScore'), bar: $('#textBar'), flags: $('#textFlags') },
    sender: { score: $('#senderScore'), bar: $('#senderBar'), flags: $('#senderFlags'), card: $('#senderCard') },
    url: { score: $('#urlScore'), bar: $('#urlBar'), flags: $('#urlFlags') },
    crawl: { score: $('#crawlScore'), bar: $('#crawlBar'), flags: $('#crawlFlags') },
    visual: { score: $('#visualScore'), bar: $('#visualBar'), flags: $('#visualFlags') },
    links: { score: $('#linkScore'), bar: $('#linkBar'), flags: $('#linkFlags') },
};

// Sender panel refs
const senderInfoPanel = $('#senderInfoPanel');
const senderFrom = $('#senderFrom');
const senderMailedBy = $('#senderMailedBy');
const senderSignedBy = $('#senderSignedBy');
const senderSecurity = $('#senderSecurity');

// Store extracted headers for sending to API
let extractedHeaders = null;

// ---------- Health Check ----------
async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
        const data = await res.json();
        if (data.model_loaded) {
            statusChip.textContent = '● API Online';
            statusChip.className = 'status-chip online';
        } else {
            statusChip.textContent = '● API Degraded';
            statusChip.className = 'status-chip offline';
        }
    } catch {
        statusChip.textContent = '● API Offline';
        statusChip.className = 'status-chip offline';
    }
}

// ---------- Toast ----------
let toastTimer;
function showError(msg) {
    errorToast.textContent = msg;
    errorToast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => errorToast.classList.remove('visible'), 4000);
}

// ---------- Color Helpers ----------
function verdictClass(verdict) {
    if (verdict === 'PHISHING') return 'phishing';
    if (verdict === 'SUSPICIOUS') return 'suspicious';
    return 'safe';
}

function scoreColorClass(score) {
    if (score >= 0.65) return 'phishing';
    if (score >= 0.30) return 'suspicious';
    return 'safe';
}

function verdictHex(verdict) {
    if (verdict === 'PHISHING') return '#ff1744';
    if (verdict === 'SUSPICIOUS') return '#ffab00';
    return '#00e676';
}

// ---------- Gauge ----------
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 40;

function setGauge(score, verdict) {
    const offset = GAUGE_CIRCUMFERENCE * (1 - score);
    gaugeFill.style.strokeDashoffset = offset;
    gaugeFill.style.stroke = verdictHex(verdict);
    animateNumber(gaugeScore, score);
}

function animateNumber(el, target) {
    const duration = 800;
    const start = performance.now();
    function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        el.textContent = (target * ease * 100).toFixed(0) + '%';
        if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

// ---------- Layer Card Helpers ----------
function setLayerCard(layerRef, score, flagsArr) {
    const cls = scoreColorClass(score);
    layerRef.score.textContent = (score * 100).toFixed(0) + '%';
    layerRef.score.className = `layer-score score-${cls}`;
    layerRef.bar.className = `layer-bar__fill bar-${cls}`;
    requestAnimationFrame(() => {
        layerRef.bar.style.width = `${Math.max(score * 100, 2)}%`;
    });
    layerRef.flags.innerHTML = '';
    (flagsArr || []).forEach(f => {
        const li = document.createElement('li');
        li.textContent = f;
        layerRef.flags.appendChild(li);
    });
}

function resetLayerCard(layerRef) {
    layerRef.score.textContent = '—';
    layerRef.score.className = 'layer-score';
    layerRef.bar.style.width = '0';
    layerRef.bar.className = 'layer-bar__fill';
    layerRef.flags.innerHTML = '<li style="color:var(--text-muted);opacity:0.5;">No data</li>';
}

// ---------- Collapsible URLs Toggle ----------
function appendUrlsToggle(flagsEl, urlsList) {
    const toggle = document.createElement('li');
    toggle.className = 'urls-toggle';
    toggle.textContent = `▶ Show ${urlsList.length} URL(s)`;
    toggle.style.cssText = 'cursor:pointer;user-select:none;font-weight:600;color:var(--accent);opacity:0.8;list-style:none;';
    flagsEl.appendChild(toggle);

    const urlItems = [];
    urlsList.forEach(u => {
        const li = document.createElement('li');
        li.textContent = u;
        li.className = 'url-item';
        li.style.cssText = 'display:none;font-size:0.65rem;opacity:0.7;word-break:break-all;overflow-wrap:anywhere;';
        flagsEl.appendChild(li);
        urlItems.push(li);
    });

    let expanded = false;
    toggle.addEventListener('click', () => {
        expanded = !expanded;
        toggle.textContent = expanded ? `▼ Hide ${urlsList.length} URL(s)` : `▶ Show ${urlsList.length} URL(s)`;
        urlItems.forEach(li => li.style.display = expanded ? 'flex' : 'none');
    });
}

// ---------- Render Results ----------
function renderResults(data) {
    resultsSection.classList.add('visible');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Reset screenshot section
    const ssSection = document.getElementById('screenshotsSection');
    const ssGallery = document.getElementById('screenshotsGallery');
    ssSection.style.display = 'none';
    ssGallery.innerHTML = '';


    // Verdict banner
    const vc = verdictClass(data.overall_verdict);
    verdictBanner.className = `verdict-banner ${vc}`;
    verdictText.textContent = data.overall_verdict;

    // Gauge
    setGauge(data.overall_risk_score, data.overall_verdict);

    // Layer badges — use Map to avoid raw key fallthrough
    const layerNames = new Map([
        ['text_classification',     '🧠 Text'],
        ['sender_analysis',         '👤 Sender'],
        ['url_analysis',            '🔗 URL'],
        ['web_crawling',            '🕷️ Crawl'],
        ['visual_analysis',         '👁️ Visual'],
        ['link_checking',           '🔀 Links'],
        ['header_forensics',        '📋 Headers'],
        ['ai_authorship_detection', '🤖 AI Auth'],
        ['xai_explanation',         '🔍 XAI'],
    ]);
    layersBadges.innerHTML = (data.analysis_layers || [])
        .map(l => `<span>${layerNames.get(l) || l}</span>`)
        .join('');

    // Layer 1: Text
    const textConf = data.text_analysis.confidence;
    const textRisk = data.text_analysis.is_phishing ? textConf : (1 - textConf);
    const textFlags = [
        `Label: ${data.text_analysis.label}`,
        `Confidence: ${(textConf * 100).toFixed(1)}%`,
        `Risk: ${data.text_analysis.risk_level}`,
    ];
    setLayerCard(layers.text, textRisk, textFlags);

    // Sender Analysis
    if (data.sender_analysis) {
        layers.sender.card.style.display = 'block';
        const sa = data.sender_analysis;
        setLayerCard(layers.sender, sa.risk_score, sa.flags.length > 0 ? sa.flags : ['No sender issues detected']);
    } else {
        layers.sender.card.style.display = 'none';
    }

    // Layer 2: URL
    if (data.url_analysis && data.url_analysis.results.length > 0) {
        const urlFlags = [];
        urlFlags.push(`${data.url_analysis.total_urls} URL(s), ${data.url_analysis.suspicious_count} suspicious`);
        data.url_analysis.results.forEach(r => {
            if (r.flags && r.flags.length > 0) {
                r.flags.slice(0, 2).forEach(f => urlFlags.push(f));
            }
        });
        setLayerCard(layers.url, data.url_analysis.highest_risk, urlFlags);
        if (data.urls_list && data.urls_list.length > 0) {
            appendUrlsToggle(layers.url.flags, data.urls_list);
        }
    } else {
        if (data.urls_list && data.urls_list.length > 0) {
            const urlFlags = [`${data.urls_list.length} URL(s) found`];
            setLayerCard(layers.url, 0, urlFlags);
            appendUrlsToggle(layers.url.flags, data.urls_list);
        } else {
            resetLayerCard(layers.url);
        }
    }

    // Layer 3: Crawl
    if (data.crawl_results && data.crawl_results.length > 0) {
        const crawlFlags = [];
        let maxCrawlRisk = 0;
        data.crawl_results.forEach(c => {
            if (c.error) {
                crawlFlags.push(`❌ ${c.error}`);
            } else {
                crawlFlags.push(`${c.page_title || 'Untitled'}`);
                if (c.has_login_form) { crawlFlags.push('⚠️ Login form'); maxCrawlRisk = Math.max(maxCrawlRisk, 0.5); }
                if (c.has_password_field) { crawlFlags.push('⚠️ Password field'); maxCrawlRisk = Math.max(maxCrawlRisk, 0.6); }
                if (c.was_redirected) { crawlFlags.push(`↪ Redirected (${c.redirect_chain.length} hops)`); maxCrawlRisk = Math.max(maxCrawlRisk, 0.3); }
            }
        });
        setLayerCard(layers.crawl, maxCrawlRisk, crawlFlags);
    } else {
        resetLayerCard(layers.crawl);
    }

    // Layer 4: Visual
    if (data.visual_analysis && data.visual_analysis.length > 0) {
        const maxVisRisk = Math.max(...data.visual_analysis.map(v => v.risk_score));
        const visFlags = [];
        data.visual_analysis.forEach(v => {
            if (v.is_fake_login) visFlags.push(`🚨 Fake login — ${v.impersonated_brand || 'unknown'}`);
            (v.flags || []).slice(0, 2).forEach(f => visFlags.push(f));
        });
        if (visFlags.length === 0) visFlags.push('No visual threats');
        setLayerCard(layers.visual, maxVisRisk, visFlags);
    } else {
        resetLayerCard(layers.visual);
    }

    // Layer 5: Links
    if (data.link_analysis) {
        const la = data.link_analysis;
        const linkFlags = [];
        linkFlags.push(`${la.total_links} links, ${la.suspicious_links} suspicious`);
        (la.flags || []).slice(0, 3).forEach(f => linkFlags.push(f));
        setLayerCard(layers.links, la.risk_score, linkFlags);
    } else {
        resetLayerCard(layers.links);
    }

    // AI Authorship
    renderAIAuthorship(data.ai_authorship || null);

    // Header Forensics
    renderHeaders(data.header_analysis || null);

    // XAI summary
    renderXAISummary(data.xai_explanation || null);

    // Risk Factors
    if (data.risk_factors && data.risk_factors.length > 0) {
        riskFactorsCard.style.display = 'block';
        riskFactorsList.innerHTML = data.risk_factors
            .map(f => `<li><span class="rf-icon">🔴</span> ${escapeHtml(f)}</li>`)
            .join('');
    } else {
        riskFactorsCard.style.display = 'none';
    }

    // Screenshot Gallery (standalone section below cards)
    const ssResults = (data.crawl_results || []).filter(c => c.screenshot_url && !c.error);
    if (ssResults.length > 0) {
        ssResults.forEach(c => {
            const label = (c.page_title || (() => { try { return new URL(c.final_url || c.url).hostname; } catch { return c.url; } })() || c.url).substring(0, 28);
            const thumb = document.createElement('a');
            thumb.className = 'crawl-ss-thumb';
            thumb.href = c.screenshot_url;
            thumb.target = '_blank';
            thumb.rel = 'noopener';
            thumb.title = `Open screenshot: ${c.final_url || c.url}`;
            thumb.innerHTML = `
                <span class="crawl-ss-thumb-badge">🔍 View</span>
                <img src="${escapeHtml(c.screenshot_url)}" alt="Screenshot" loading="lazy">
                <div class="crawl-ss-thumb-label">${escapeHtml(label)}</div>`;
            ssGallery.appendChild(thumb);
        });
        ssSection.style.display = 'block';
    }
}

// ---------- AI Authorship Render ----------
function renderAIAuthorship(ai) {
    const card = document.getElementById('aiAuthorshipCard');
    if (!ai || !card) return;

    card.style.display = 'block';
    const score = ai.ai_authorship_score;
    const isAI = ai.is_ai_generated;

    const pill = document.getElementById('aiAuthPill');
    const scoreEl = document.getElementById('aiAuthScore');
    const signalsList = document.getElementById('aiAuthSignals');

    if (pill) {
        pill.textContent = isAI ? '🤖 AI-Generated' : '✍️ Human-Written';
        pill.className = 'ai-auth-pill ' + (isAI ? 'ai-auth-pill--ai' : 'ai-auth-pill--human');
    }
    if (scoreEl) {
        scoreEl.textContent = (score * 100).toFixed(0) + '%';
        scoreEl.style.color = isAI ? 'var(--phishing)' : 'var(--safe)';
    }

    // Signal bars
    const signals = [
        { id: 'sigB', label: 'Burstiness',  val: ai.burstiness_score  },
        { id: 'sigP', label: 'Perplexity',  val: ai.perplexity_proxy  },
        { id: 'sigV', label: 'Vocab',       val: ai.vocabulary_richness },
        { id: 'sigR', label: 'Repetition',  val: ai.repetition_score  },
        { id: 'sigF', label: 'Formality',   val: ai.formality_score   },
    ];
    if (signalsList) {
        signalsList.innerHTML = signals.map(s => {
            const pct = Math.round((s.val || 0) * 100);
            const color = pct >= 60 ? 'var(--phishing)' : pct >= 40 ? 'var(--suspicious)' : 'var(--safe)';
            return `<li class="ai-signal-row-ext">
                <span class="ai-sig-label">${s.label}</span>
                <div class="ai-sig-bar-wrap"><div class="ai-sig-bar" style="width:${pct}%;background:${color}"></div></div>
                <span class="ai-sig-val">${pct}%</span>
            </li>`;
        }).join('');
    }
}

// ---------- Header Forensics Render ----------
function renderHeaders(ha) {
    const card = document.getElementById('headerCard');
    if (!ha || !card) return;

    card.style.display = 'block';

    // Score bar
    const scoreEl = document.getElementById('headerScore');
    const barEl   = document.getElementById('headerBar');
    const flagsEl = document.getElementById('headerFlags');
    const badgesEl = document.getElementById('headerAuthBadges');

    if (scoreEl) {
        scoreEl.textContent = (ha.risk_score * 100).toFixed(0) + '%';
        const cls = ha.risk_score >= 0.65 ? 'phishing' : ha.risk_score >= 0.30 ? 'suspicious' : 'safe';
        scoreEl.className = `layer-score score-${cls}`;
    }
    if (barEl) {
        const cls = ha.risk_score >= 0.65 ? 'phishing' : ha.risk_score >= 0.30 ? 'suspicious' : 'safe';
        barEl.className = `layer-bar__fill bar-${cls}`;
        requestAnimationFrame(() => { barEl.style.width = Math.max(ha.risk_score * 100, 2) + '%'; });
    }

    // Auth badges
    if (badgesEl) {
        badgesEl.innerHTML = [
            { label: 'SPF',   val: ha.spf_result  },
            { label: 'DKIM',  val: ha.dkim_result },
            { label: 'DMARC', val: ha.dmarc_result },
        ].map(({ label, val }) => {
            const v = (val || 'none').toLowerCase();
            const cls = v === 'pass' ? 'hdr-badge--pass'
                      : v === 'fail' ? 'hdr-badge--fail'
                      : v === 'softfail' ? 'hdr-badge--softfail'
                      : 'hdr-badge--none';
            return `<span class="hdr-badge ${cls}">${label}: ${val || 'none'}</span>`;
        }).join('');
    }

    // Flags
    if (flagsEl) {
        flagsEl.innerHTML = '';
        const items = [];
        if (ha.display_name_spoof)   items.push(`🎭 Spoof: claims ${ha.spoofed_brand}`);
        if (ha.reply_to_mismatch)    items.push(`↪ Reply-To: ${ha.reply_to_domain}`);
        if (ha.return_path_mismatch) items.push(`↩ Return-Path: ${ha.return_path_domain}`);
        if (ha.date_anomaly)         items.push(`📅 Date anomaly`);
        if (ha.suspicious_mailer)    items.push(`⚙️ Suspicious mailer`);
        if (ha.received_hops > 7)    items.push(`🔁 ${ha.received_hops} Received hops`);
        if (ha.received_hops === 0)  items.push('⚠️ No Received headers');
        if (ha.from_domain)          items.push(`From: ${ha.from_domain}`);
        if (items.length === 0)      items.push('No header anomalies');
        items.forEach(f => {
            const li = document.createElement('li');
            li.textContent = f;
            flagsEl.appendChild(li);
        });
    }
}

// ---------- XAI Summary Render ----------
function renderXAISummary(xai) {
    const card = document.getElementById('xaiSummaryCard');
    if (!xai || !xai.available || !card) return;

    card.style.display = 'block';

    const summaryEl = document.getElementById('xaiSummaryText');
    const catsEl    = document.getElementById('xaiCatPills');
    const topEl     = document.getElementById('xaiTopTokens');

    if (summaryEl) summaryEl.textContent = xai.summary || '';

    if (catsEl) {
        const catLabels = {
            urgency:             '⏰ Urgency',
            credential_request:  '🔑 Credential',
            threat:              '🚨 Threat',
            reward:              '🎁 Reward',
            brand_impersonation: '🏷️ Brand Spoof',
            suspicious_url:      '🔗 Suspicious URL',
        };
        catsEl.innerHTML = (xai.risk_categories || [])
            .map(c => `<span class="xai-pill">${catLabels[c] || c}</span>`)
            .join('');
    }

    if (topEl && xai.top_tokens && xai.top_tokens.length > 0) {
        topEl.textContent = 'Top triggers: ' + xai.top_tokens.slice(0, 6).map(t => `"${t}"`).join(', ');
    }
}

// ---------- Escape HTML ----------
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ---------- Extract from Gmail ----------
async function extractFromGmail() {
    extractBtn.disabled = true;

    try {
        // Get the active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.url || !tab.url.includes('mail.google.com')) {
            extractBtn.classList.add('error');
            extractBtn.querySelector('.btn-icon').textContent = '❌';
            showError('Please open Gmail first!');
            setTimeout(() => {
                extractBtn.classList.remove('error');
                extractBtn.querySelector('.btn-icon').textContent = '📧';
            }, 2000);
            return;
        }

        // Inject content script if not already loaded
        try {
            await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                files: ['content.js'],
            });
        } catch {
            // Content script might already be injected
        }

        // Send message to content script
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'extract_email' });

        if (response && response.success) {
            // Set HTML directly in contenteditable div (preserves links)
            if (response.body_html) {
                emailInput.innerHTML = response.body_html;
            } else {
                emailInput.innerText = response.body;
            }
            if (response.subject) {
                subjectInput.value = response.subject;
            }

            // Display sender headers
            if (response.headers) {
                extractedHeaders = response.headers;
                senderInfoPanel.style.display = 'block';
                senderInfoPanel.open = false; // Collapse by default to save space
                senderFrom.textContent = response.headers.from_email
                    ? `${response.headers.from_name || ''} <${response.headers.from_email}>`.trim()
                    : '—';
                senderMailedBy.textContent = response.headers.mailed_by || '—';
                senderSignedBy.textContent = response.headers.signed_by || '—';
                senderSecurity.textContent = response.headers.security || '—';
            }

            extractBtn.classList.add('success');
            extractBtn.querySelector('.btn-icon').textContent = '✅';
            setTimeout(() => {
                extractBtn.classList.remove('success');
                extractBtn.querySelector('.btn-icon').textContent = '📧';
            }, 2000);
        } else {
            showError(response?.error || 'Could not extract email. Open an email first.');
            extractBtn.classList.add('error');
            extractBtn.querySelector('.btn-icon').textContent = '❌';
            setTimeout(() => {
                extractBtn.classList.remove('error');
                extractBtn.querySelector('.btn-icon').textContent = '📧';
            }, 2000);
        }
    } catch (err) {
        showError('Extraction failed. Make sure you have an email open in Gmail.');
        console.error('Extract error:', err);
    } finally {
        extractBtn.disabled = false;
    }
}

// ---------- Analyze ----------
async function analyze() {
    const text = emailInput.innerText.trim();
    if (!text) {
        showError('Please enter or extract an email to scan.');
        emailInput.focus();
        return;
    }

    // Get the raw HTML from the contenteditable div (preserves <a href> links)
    const emailHtml = emailInput.innerHTML || null;

    analyzeBtn.classList.add('loading');
    analyzeBtn.disabled = true;
    resultsSection.classList.remove('visible');

    try {
        const body = {
            text,
            email_html: emailHtml,
            subject: subjectInput.value.trim() || null,
            crawl_urls: crawlToggle.checked,
            take_screenshots: screenshotToggle.checked,
            sender_info: extractedHeaders || null,
            raw_headers: rawHeadersInput?.value?.trim() || null,
        };

        const res = await fetch(`${API_BASE}/deep-analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: res.statusText }));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        const data = await res.json();
        renderResults(data);

    } catch (err) {
        showError(`Analysis failed: ${err.message}`);
        console.error('Deep-analyze error:', err);
    } finally {
        analyzeBtn.classList.remove('loading');
        analyzeBtn.disabled = false;
    }
}

// ---------- Event Listeners ----------
extractBtn.addEventListener('click', extractFromGmail);
analyzeBtn.addEventListener('click', analyze);

// Screenshot toggle depends on crawl toggle
crawlToggle.addEventListener('change', () => {
    if (!crawlToggle.checked) {
        screenshotToggle.checked = false;
        screenshotToggle.disabled = true;
        screenshotToggle.parentElement.style.opacity = '0.4';
    } else {
        screenshotToggle.disabled = false;
        screenshotToggle.parentElement.style.opacity = '1';
    }
});

emailInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        analyze();
    }
});

// ---------- Init ----------
checkHealth();
