/* ============================================
   HYBRID AI DEFENSE — Frontend Logic
   ============================================ */

const API_BASE = 'http://localhost:8001/api/v1';

// ---------- DOM Refs ----------
const $ = (sel) => document.querySelector(sel);
const statusChip = $('#statusChip');
const analyzeBtn = $('#analyzeBtn');
const emailInput = $('#emailInput');
const subjectInput = $('#subjectInput');
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

// New feature refs
const progressStepper = $('#progressStepper');
const exportJsonBtn = $('#exportJsonBtn');
const historySection = $('#historySection');
const historyList = $('#historyList');
const clearHistoryBtn = $('#clearHistoryBtn');

// Store last analysis result for export
let lastAnalysisResult = null;

// Layer refs
const layers = {
    text: { score: $('#textScore'), bar: $('#textBar'), flags: $('#textFlags') },
    sender: { score: $('#senderScore'), bar: $('#senderBar'), flags: $('#senderFlags'), card: $('#layerSender') },
    url: { score: $('#urlScore'), bar: $('#urlBar'), flags: $('#urlFlags') },
    crawl: { score: $('#crawlScore'), bar: $('#crawlBar'), flags: $('#crawlFlags') },
    visual: { score: $('#visualScore'), bar: $('#visualBar'), flags: $('#visualFlags') },
    links: { score: $('#linkScore'), bar: $('#linkBar'), flags: $('#linkFlags') },
};

// AI authorship refs
const aiAuthorshipBanner = $('#aiAuthorshipBanner');
const aiIcon = $('#aiIcon');
const aiTitle = $('#aiTitle');
const aiSubtitle = $('#aiSubtitle');
const aiRingFill = $('#aiRingFill');
const aiScoreLabel = $('#aiScoreLabel');
const aiVerdictPill = $('#aiVerdictPill');
const aiSignalNotes = $('#aiSignalNotes');
const AI_RING_CIRCUMFERENCE = 2 * Math.PI * 24; // r=24

const aiSignalEls = {
    burstiness:  { bar: $('#sigBurstiness'),  val: $('#sigBurstinessVal')  },
    perplexity:  { bar: $('#sigPerplexity'),   val: $('#sigPerplexityVal')  },
    vocab:       { bar: $('#sigVocab'),        val: $('#sigVocabVal')       },
    repetition:  { bar: $('#sigRepetition'),   val: $('#sigRepetitionVal')  },
    formality:   { bar: $('#sigFormality'),    val: $('#sigFormalityVal')   },
};

// Sender input refs
const senderEmailInput = $('#senderEmail');
const senderNameInput = $('#senderName');
const mailedByInput = $('#mailedBy');
const signedByInput = $('#signedBy');
const securityInput = $('#securityInfo');

// ---------- Health Check ----------
async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        if (data.model_loaded) {
            statusChip.textContent = '● API Online — Model Loaded';
            statusChip.className = 'status-chip status-chip--online';
        } else {
            statusChip.textContent = '● API Degraded — Model Not Loaded';
            statusChip.className = 'status-chip status-chip--offline';
        }
    } catch {
        statusChip.textContent = '● API Offline';
        statusChip.className = 'status-chip status-chip--offline';
    }
}

// ---------- Toast ----------
let toastTimer;
function showError(msg) {
    errorToast.textContent = msg;
    errorToast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => errorToast.classList.remove('visible'), 5000);
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
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 40; // r=40

function setGauge(score, verdict) {
    const offset = GAUGE_CIRCUMFERENCE * (1 - score);
    gaugeFill.style.strokeDashoffset = offset;
    gaugeFill.style.stroke = verdictHex(verdict);
    // Animate score number
    animateNumber(gaugeScore, score);
}

function animateNumber(el, target) {
    const duration = 1000;
    const start = performance.now();
    const from = 0;
    function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        const val = from + (target - from) * ease;
        el.textContent = (val * 100).toFixed(0) + '%';
        if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

// ---------- Layer Card Helpers ----------
function setLayerCard(layerRef, score, flagsArr) {
    const cls = scoreColorClass(score);
    layerRef.score.textContent = (score * 100).toFixed(0) + '%';
    layerRef.score.className = `layer-card__score score-${cls}`;
    layerRef.bar.className = `layer-card__bar-fill bar-${cls}`;
    // Trigger animation after a frame
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
    layerRef.score.className = 'layer-card__score';
    layerRef.bar.style.width = '0';
    layerRef.bar.className = 'layer-card__bar-fill';
    layerRef.flags.innerHTML = '<li style="color:var(--text-muted);opacity:0.5;">No data</li>';
}

// ---------- Collapsible URLs Toggle ----------
function appendUrlsToggle(flagsEl, urlsList) {
    // Toggle button
    const toggle = document.createElement('li');
    toggle.className = 'urls-toggle';
    toggle.textContent = `▶ Show ${urlsList.length} URL(s)`;
    toggle.style.cssText = 'cursor:pointer;user-select:none;font-weight:600;color:var(--accent);opacity:0.8;list-style:none;';
    flagsEl.appendChild(toggle);

    // URL items (hidden by default)
    const urlItems = [];
    urlsList.forEach(u => {
        const li = document.createElement('li');
        li.textContent = u;
        li.className = 'url-item';
        li.style.cssText = 'display:none;font-size:0.78rem;opacity:0.7;word-break:break-all;overflow-wrap:anywhere;';
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
    // Show section
    resultsSection.classList.add('visible');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Reset screenshot section for fresh render
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

    // Layer badges
    const layerNames = {
        text_classification:    '🧠 Text',
        sender_analysis:        '👤 Sender',
        url_analysis:           '🔗 URL',
        web_crawling:           '🕷️ Crawl',
        visual_analysis:        '👁️ Visual',
        link_checking:          '🔀 Links',
        ai_authorship_detection:'🤖 AI Author',
    };
    layersBadges.innerHTML = (data.analysis_layers || [])
        .map(l => `<span>${layerNames[l] || l}</span>`)
        .join('');

    // --- Layer 1: Text ---
    const textConf = data.text_analysis.confidence;
    const textRisk = data.text_analysis.is_phishing ? textConf : (1 - textConf);
    const textFlags = [];
    textFlags.push(`Label: ${data.text_analysis.label}`);
    textFlags.push(`Confidence: ${(textConf * 100).toFixed(1)}%`);
    textFlags.push(`Risk Level: ${data.text_analysis.risk_level}`);
    setLayerCard(layers.text, textRisk, textFlags);

    // --- Sender Analysis ---
    if (data.sender_analysis) {
        layers.sender.card.style.display = 'block';
        const sa = data.sender_analysis;
        const senderFlags = sa.flags.length > 0 ? sa.flags : ['No sender issues detected'];
        setLayerCard(layers.sender, sa.risk_score, senderFlags);
    } else {
        layers.sender.card.style.display = 'none';
    }

    // --- Layer 2: URL ---
    if (data.url_analysis && data.url_analysis.results.length > 0) {
        const urlRisk = data.url_analysis.highest_risk;
        const urlFlags = [];
        urlFlags.push(`${data.url_analysis.total_urls} URL(s) found, ${data.url_analysis.suspicious_count} suspicious`);
        data.url_analysis.results.forEach(r => {
            if (r.flags && r.flags.length > 0) {
                r.flags.slice(0, 3).forEach(f => urlFlags.push(f));
            }
        });
        setLayerCard(layers.url, urlRisk, urlFlags);
        // Add collapsible URLs toggle
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

    // --- Layer 3: Crawl ---
    if (data.crawl_results && data.crawl_results.length > 0) {
        const crawlFlags = [];
        let maxCrawlRisk = 0;
        data.crawl_results.forEach(c => {
            if (c.error) {
                crawlFlags.push(`❌ ${c.url}: ${c.error}`);
            } else {
                crawlFlags.push(`${c.page_title || 'Untitled'} — ${c.final_url}`);
                if (c.has_login_form) { crawlFlags.push('⚠️ Login form detected'); maxCrawlRisk = Math.max(maxCrawlRisk, 0.5); }
                if (c.has_password_field) { crawlFlags.push('⚠️ Password field detected'); maxCrawlRisk = Math.max(maxCrawlRisk, 0.6); }
                if (c.was_redirected) { crawlFlags.push(`↪ Redirected (${c.redirect_chain.length} hops)`); maxCrawlRisk = Math.max(maxCrawlRisk, 0.3); }
            }
        });
        setLayerCard(layers.crawl, maxCrawlRisk, crawlFlags);
    } else {
        resetLayerCard(layers.crawl);
    }

    // --- Layer 4: Visual ---
    if (data.visual_analysis && data.visual_analysis.length > 0) {
        const maxVisRisk = Math.max(...data.visual_analysis.map(v => v.risk_score));
        const visFlags = [];
        data.visual_analysis.forEach(v => {
            if (v.is_fake_login) visFlags.push(`🚨 Fake login page — ${v.impersonated_brand || 'unknown brand'}`);
            (v.flags || []).slice(0, 3).forEach(f => visFlags.push(f));
        });
        if (visFlags.length === 0) visFlags.push('No visual threats detected');
        setLayerCard(layers.visual, maxVisRisk, visFlags);
    } else {
        resetLayerCard(layers.visual);
    }

    // --- Layer 5: Links ---
    if (data.link_analysis) {
        const la = data.link_analysis;
        const linkFlags = [];
        linkFlags.push(`${la.total_links} links found, ${la.checked_links} checked, ${la.suspicious_links} suspicious`);
        (la.flags || []).slice(0, 4).forEach(f => linkFlags.push(f));
        setLayerCard(layers.links, la.risk_score, linkFlags);
    } else {
        resetLayerCard(layers.links);
    }

    // --- AI Authorship ---
    renderAIAuthorship(data.ai_authorship || null);

    // --- Risk Factors ---
    if (data.risk_factors && data.risk_factors.length > 0) {
        riskFactorsCard.style.display = 'block';
        riskFactorsList.innerHTML = data.risk_factors
            .map(f => `<li><span class="rf-icon">🔴</span> ${escapeHtml(f)}</li>`)
            .join('');
    } else {
        riskFactorsCard.style.display = 'none';
    }

    // --- Screenshot Gallery (standalone section below cards) ---
    const screenshotResults = (data.crawl_results || []).filter(c => c.screenshot_url && !c.error);
    if (screenshotResults.length > 0) {
        screenshotResults.forEach(c => {
            const card = document.createElement('div');
            card.className = 'crawl-screenshot-card';
            const label = (c.page_title || (() => { try { return new URL(c.final_url || c.url).hostname; } catch { return c.url; } })() || c.url).substring(0, 40);
            card.innerHTML = `
                <span class="crawl-screenshot-hint">🔍 Preview</span>
                <img src="${escapeHtml(c.screenshot_url)}" alt="Screenshot of ${escapeHtml(label)}" loading="lazy">
                <div class="crawl-screenshot-label" title="${escapeHtml(c.final_url || c.url)}">${escapeHtml(label)}</div>`;
            card.addEventListener('click', () => openLightbox(c.screenshot_url, c.final_url || c.url));
            ssGallery.appendChild(card);
        });
        ssSection.style.display = 'block';
    }
}

// ---------- AI Authorship Rendering ----------
function renderAIAuthorship(ai) {
    if (!ai) {
        aiAuthorshipBanner.style.display = 'none';
        return;
    }

    aiAuthorshipBanner.style.display = 'block';

    const score = ai.ai_authorship_score;
    const isAI = ai.is_ai_generated;

    // Ring
    const offset = AI_RING_CIRCUMFERENCE * (1 - score);
    aiRingFill.style.strokeDashoffset = offset;
    aiRingFill.style.stroke = isAI ? '#ff1744' : '#00e676';

    // Animate score number
    animateNumber(aiScoreLabel, score);

    // Verdict pill
    if (isAI) {
        aiVerdictPill.textContent = '🤖 AI-Generated';
        aiVerdictPill.className = 'ai-verdict-pill ai-verdict-pill--ai';
        aiIcon.textContent = '🤖';
        aiTitle.textContent = 'AI-Generated Email Detected';
        aiSubtitle.textContent = `Authorship score ${(score * 100).toFixed(0)}% — statistical signals indicate LLM-generated text`;
        aiAuthorshipBanner.className = 'ai-authorship-banner card ai-banner--ai';
    } else {
        aiVerdictPill.textContent = '✍️ Human-Written';
        aiVerdictPill.className = 'ai-verdict-pill ai-verdict-pill--human';
        aiIcon.textContent = '✍️';
        aiTitle.textContent = 'Human-Written Email';
        aiSubtitle.textContent = `Authorship score ${(score * 100).toFixed(0)}% — writing patterns consistent with human authorship`;
        aiAuthorshipBanner.className = 'ai-authorship-banner card ai-banner--human';
    }

    // Signal bars
    function setSignalBar(key, value) {
        const el = aiSignalEls[key];
        if (!el) return;
        const pct = Math.round(value * 100);
        el.val.textContent = pct + '%';
        requestAnimationFrame(() => {
            el.bar.style.width = Math.max(pct, 2) + '%';
            el.bar.style.background = value >= 0.6
                ? 'var(--phishing)'
                : value >= 0.4
                    ? 'var(--suspicious)'
                    : 'var(--safe)';
        });
    }

    setSignalBar('burstiness', ai.burstiness_score);
    setSignalBar('perplexity',  ai.perplexity_proxy);
    setSignalBar('vocab',       ai.vocabulary_richness);
    setSignalBar('repetition',  ai.repetition_score);
    setSignalBar('formality',   ai.formality_score);

    // Signal notes
    aiSignalNotes.innerHTML = '';
    (ai.signals || []).forEach(s => {
        const li = document.createElement('li');
        li.textContent = s;
        aiSignalNotes.appendChild(li);
    });
}

// ---------- HTML Escape ----------
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ---------- Screenshot Lightbox ----------
let lightboxEl = null;

function getLightbox() {
    if (lightboxEl) return lightboxEl;
    lightboxEl = document.createElement('div');
    lightboxEl.className = 'screenshot-lightbox';
    lightboxEl.innerHTML = `
        <div class="lightbox-inner">
            <button class="lightbox-close" id="lightboxClose" title="Close">✕</button>
            <img id="lightboxImg" src="" alt="Crawl Screenshot">
            <div class="lightbox-caption" id="lightboxCaption"></div>
            <a class="lightbox-open-btn" id="lightboxOpenBtn" href="" target="_blank" rel="noopener">🔗 Open in new tab</a>
        </div>`;
    document.body.appendChild(lightboxEl);

    // Close on backdrop click
    lightboxEl.addEventListener('click', (e) => {
        if (e.target === lightboxEl) closeLightbox();
    });
    document.getElementById('lightboxClose').addEventListener('click', closeLightbox);
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeLightbox();
    });
    return lightboxEl;
}

function openLightbox(imgSrc, caption) {
    const lb = getLightbox();
    document.getElementById('lightboxImg').src = imgSrc;
    document.getElementById('lightboxCaption').textContent = caption || '';
    document.getElementById('lightboxOpenBtn').href = imgSrc;
    lb.classList.add('open');
    document.body.style.overflow = 'hidden';
}

function closeLightbox() {
    if (lightboxEl) lightboxEl.classList.remove('open');
    document.body.style.overflow = '';
}


// ---------- Progress Stepper ----------
const stepIds = ['step-text', 'step-url', 'step-crawl', 'step-visual', 'step-links', 'step-ai'];
let progressCancelled = false;

function resetProgress() {
    progressCancelled = false;
    stepIds.forEach(id => {
        const el = document.getElementById(id);
        el.className = 'progress-step waiting';
        el.querySelector('.progress-step__status').textContent = '';
    });
}

function setStepState(stepId, state, statusText) {
    const el = document.getElementById(stepId);
    el.className = `progress-step ${state}`;
    el.querySelector('.progress-step__status').textContent = statusText || '';
}

async function animateProgress(crawlEnabled, screenshotsEnabled) {
    resetProgress();
    progressStepper.classList.add('visible');

    // Step 1: Text
    setStepState('step-text', 'running', 'Analyzing…');
    await sleep(600);
    if (progressCancelled) return;
    setStepState('step-text', 'done', '✓ Done');

    // Step 2: URL
    setStepState('step-url', 'running', 'Checking…');
    await sleep(500);
    if (progressCancelled) return;
    setStepState('step-url', 'done', '✓ Done');

    // Step 3: Crawl
    if (crawlEnabled) {
        setStepState('step-crawl', 'running', 'Crawling…');
        await sleep(800);
        if (progressCancelled) return;
        setStepState('step-crawl', 'done', '✓ Done');
    } else {
        setStepState('step-crawl', 'skipped', 'Skipped');
    }

    // Step 4: Visual
    if (crawlEnabled && screenshotsEnabled) {
        setStepState('step-visual', 'running', 'Scanning…');
        await sleep(600);
        if (progressCancelled) return;
        setStepState('step-visual', 'done', '✓ Done');
    } else {
        setStepState('step-visual', 'skipped', 'Skipped');
    }

    // Step 5: Links
    setStepState('step-links', 'running', 'Following…');
    await sleep(500);
    if (progressCancelled) return;
    setStepState('step-links', 'done', '✓ Done');

    // Step 6: AI Authorship
    setStepState('step-ai', 'running', 'Detecting…');
}

function finalizeProgress(data) {
    // Cancel any in-flight animation so it stops overwriting
    progressCancelled = true;

    const layerMap = {
        text_classification:     'step-text',
        url_analysis:            'step-url',
        web_crawling:            'step-crawl',
        visual_analysis:         'step-visual',
        link_checking:           'step-links',
        ai_authorship_detection: 'step-ai',
    };
    stepIds.forEach(id => {
        const found = Object.entries(layerMap).find(([, v]) => v === id);
        if (found && data.analysis_layers.includes(found[0])) {
            setStepState(id, 'done', '✓ Done');
        } else {
            setStepState(id, 'skipped', 'Skipped');
        }
    });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---------- History ----------
const HISTORY_KEY = 'phishing_analysis_history';
const MAX_HISTORY = 10;

function loadHistory() {
    try {
        return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch { return []; }
}

function saveToHistory(inputText, subject, data) {
    const history = loadHistory();
    history.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        inputPreview: (subject ? subject + ' — ' : '') + inputText.substring(0, 120),
        verdict: data.overall_verdict,
        riskScore: data.overall_risk_score,
        layers: data.analysis_layers.length,
        // Store lightweight summary only — full result objects can be 50-200KB each
        // which would exceed the ~5MB localStorage limit with MAX_HISTORY=10
        summary: {
            overall_verdict: data.overall_verdict,
            overall_risk_score: data.overall_risk_score,
            risk_factors: (data.risk_factors || []).slice(0, 5),
            analysis_layers: data.analysis_layers,
            urls_found: data.urls_found,
            text_analysis: data.text_analysis,
        }
    });
    if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    renderHistory();
}

function renderHistory() {
    const history = loadHistory();
    if (history.length === 0) {
        historySection.style.display = 'none';
        return;
    }
    historySection.style.display = 'block';
    historyList.innerHTML = history.map(h => {
        const vc = verdictClass(h.verdict);
        const time = new Date(h.timestamp).toLocaleString();
        return `
            <div class="history-item" data-id="${h.id}">
                <span class="history-item__verdict ${vc}">${h.verdict}</span>
                <div class="history-item__info">
                    <div class="history-item__text">${escapeHtml(h.inputPreview)}</div>
                    <div class="history-item__meta">${time} · ${h.layers} layers</div>
                </div>
                <span class="history-item__score score-${vc}">${(h.riskScore * 100).toFixed(0)}%</span>
            </div>`;
    }).join('');

    // Click handler: re-render that result (summary view)
    historyList.querySelectorAll('.history-item').forEach(el => {
        el.addEventListener('click', () => {
            const id = parseInt(el.dataset.id);
            const entry = history.find(h => h.id === id);
            if (entry && entry.summary) {
                lastAnalysisResult = entry.summary;
                renderResults(entry.summary);
            }
        });
    });
}

function clearHistory() {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
}

// ---------- Export JSON ----------
function exportJson() {
    if (!lastAnalysisResult) return;
    const blob = new Blob([JSON.stringify(lastAnalysisResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing-analysis-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// ---------- Analyze ----------
async function analyze() {
    const text = emailInput.innerText.trim();
    if (!text) {
        showError('Please enter an email body to analyze.');
        emailInput.focus();
        return;
    }

    // Get the raw HTML from the contenteditable div (preserves <a href> links)
    const emailHtml = emailInput.innerHTML || null;

    // Set loading state
    analyzeBtn.classList.add('loading');
    analyzeBtn.disabled = true;
    resultsSection.classList.remove('visible');

    // Start progress animation
    const crawlOn = crawlToggle.checked;
    const ssOn = screenshotToggle.checked;
    animateProgress(crawlOn, ssOn);

    try {
        const body = {
            text,
            email_html: emailHtml,
            subject: subjectInput.value.trim() || null,
            crawl_urls: crawlOn,
            take_screenshots: ssOn,
        };

        // Build sender_info if any field is filled
        const se = senderEmailInput?.value?.trim();
        if (se) {
            body.sender_info = {
                from_email: se || null,
                from_name: senderNameInput?.value?.trim() || null,
                mailed_by: mailedByInput?.value?.trim() || null,
                signed_by: signedByInput?.value?.trim() || null,
                security: securityInput?.value?.trim() || null,
            };
        }

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
        lastAnalysisResult = data;
        finalizeProgress(data);
        renderResults(data);
        saveToHistory(text, subjectInput.value.trim(), data);

    } catch (err) {
        showError(`Analysis failed: ${err.message}`);
        console.error('Deep-analyze error:', err);
        progressStepper.classList.remove('visible');
    } finally {
        analyzeBtn.classList.remove('loading');
        analyzeBtn.disabled = false;
    }
}

// ---------- Event Listeners ----------
analyzeBtn.addEventListener('click', analyze);
exportJsonBtn.addEventListener('click', exportJson);
clearHistoryBtn.addEventListener('click', clearHistory);

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

// Ctrl+Enter to submit
emailInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        analyze();
    }
});

// ---------- Init ----------
checkHealth();
setInterval(checkHealth, 30000);
renderHistory();
