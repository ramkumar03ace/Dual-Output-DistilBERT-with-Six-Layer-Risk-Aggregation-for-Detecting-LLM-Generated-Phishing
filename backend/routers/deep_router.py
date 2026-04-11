"""
Deep analysis API router - combines all detection layers.

Pipeline:
1. ML text classification (DistilBERT)
2. URL static analysis (WHOIS, SSL, VirusTotal, patterns)
3. Web crawling (Playwright headless browser + screenshots)
4. Visual analysis (fake login page detection)
5. Recursive link checking (redirects, domain changes)
6. Email header forensics (SPF/DKIM/DMARC, Reply-To mismatch, Received chain)
7. AI authorship detection (perplexity, burstiness, vocabulary, repetition)
8. XAI explanation (token attribution, risk categories, explanation text)
"""

import asyncio
import logging
from pathlib import Path
from fastapi import APIRouter, HTTPException

from models.schemas import (
    DeepAnalysisRequest,
    DeepAnalysisResponse,
    EmailResponse,
    URLResult,
    URLAnalysisResponse,
    CrawlResultSchema,
    VisualAnalysisSchema,
    LinkCheckSchema,
    SenderAnalysisSchema,
    AIAuthorshipSchema,
    XAIExplanationSchema,
    TokenAttributionSchema,
    HeaderAnalysisSchema,
)
from analyzers.url_analyzer import url_analyzer
from analyzers.email_parser import EmailParser
from analyzers.web_crawler import web_crawler
from analyzers.visual_analyzer import visual_analyzer
from analyzers.link_checker import link_checker
from analyzers.sender_analyzer import sender_analyzer
from analyzers.header_analyzer import header_analyzer
from services.email_classifier import classifier
from services.ai_authorship import ai_authorship_detector
from services.xai_explainer import xai_explainer
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix=settings.API_V1_PREFIX, tags=["Deep Analysis"])


@router.post("/deep-analyze", response_model=DeepAnalysisResponse)
async def deep_analysis(request: DeepAnalysisRequest):
    """
    Perform deep multi-layer analysis of an email.
    
    Combines 5 detection layers:
    1. **Text Classification** — DistilBERT ML model
    2. **URL Analysis** — WHOIS, SSL, VirusTotal, patterns
    3. **Web Crawling** — Visit URLs in headless browser, capture screenshots
    4. **Visual Analysis** — Detect fake login pages, brand impersonation
    5. **Link Checking** — Follow redirects, detect suspicious chains
    """
    if not classifier.is_loaded():
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please try again later."
        )
    
    try:
        analysis_layers = []
        risk_factors = []
        
        # ==========================================
        # LAYER 1: Text Classification
        # ==========================================
        is_phishing, confidence, label, risk_level = classifier.predict(
            text=request.text,
            subject=request.subject
        )
        
        text_result = EmailResponse(
            is_phishing=is_phishing,
            confidence=round(confidence, 4),
            label=label,
            risk_level=risk_level
        )
        analysis_layers.append("text_classification")
        
        if is_phishing:
            risk_factors.append(f"Email text classified as phishing ({confidence:.1%} confidence)")
        
        # ==========================================
        # SENDER ANALYSIS (when metadata provided)
        # ==========================================
        sender_schema = None
        sender_risk = 0.0
        
        if request.sender_info:
            si = request.sender_info
            sender_result = sender_analyzer.analyze(
                from_name=si.from_name,
                from_email=si.from_email,
                mailed_by=si.mailed_by,
                signed_by=si.signed_by,
                security=si.security,
            )
            sender_schema = SenderAnalysisSchema(
                is_suspicious=sender_result.is_suspicious,
                risk_score=round(sender_result.risk_score, 4),
                flags=sender_result.flags,
            )
            sender_risk = sender_result.risk_score
            
            if sender_result.is_suspicious:
                risk_factors.extend(sender_result.flags[:3])
            
            analysis_layers.append("sender_analysis")
        
        # ==========================================
        # LAYER 2: URL Static Analysis
        # ==========================================
        parsed_email = EmailParser.parse(request.text, request.subject)
        urls = parsed_email.urls
        
        # Also extract URLs from raw HTML (captures href links on images, buttons, etc.)
        if request.email_html:
            html_urls = EmailParser.extract_urls(request.email_html)
            existing = set(urls)
            for u in html_urls:
                if u not in existing:
                    urls.append(u)
                    existing.add(u)
        
        url_response = None
        max_url_risk = 0.0
        
        if urls:
            url_results = url_analyzer.analyze_urls(urls)
            
            url_items = []
            suspicious_url_count = 0
            
            for r in url_results:
                url_items.append(URLResult(
                    url=r.url,
                    domain=r.domain,
                    is_suspicious=r.is_suspicious,
                    risk_score=round(r.risk_score, 4),
                    flags=r.flags,
                    domain_age_days=r.domain_age_days,
                    registrar=r.registrar,
                    ssl_valid=r.ssl_valid,
                    ssl_issuer=r.ssl_issuer,
                    vt_malicious=r.vt_malicious,
                ))
                
                if r.is_suspicious:
                    suspicious_url_count += 1
                    risk_factors.extend(r.flags[:2])
                
                max_url_risk = max(max_url_risk, r.risk_score)
            
            url_response = URLAnalysisResponse(
                results=url_items,
                total_urls=len(url_items),
                suspicious_count=suspicious_url_count,
                highest_risk=round(max_url_risk, 4)
            )
            analysis_layers.append("url_analysis")
        
        # ==========================================
        # LAYER 3: Web Crawling
        # ==========================================
        crawl_schemas = []
        visual_schemas = []
        max_visual_risk = 0.0
        
        # Crawl only runs when crawl toggle is enabled
        # (UI enforces: screenshots requires crawl to be on)
        should_crawl = urls and request.crawl_urls
        # Visual analysis only runs when screenshots are also enabled
        should_visual = request.take_screenshots
        
        if should_crawl:
            for url in urls[:5]:  # Limit to 5 URLs
                try:
                    crawl_result = await web_crawler.crawl_url(
                        url, 
                        take_screenshot=request.take_screenshots
                    )
                    
                    # Build screenshot URL if a screenshot was captured
                    screenshot_url = None
                    if crawl_result.screenshot_path:
                        fname = Path(crawl_result.screenshot_path).name
                        screenshot_url = f"http://localhost:8001/screenshots/{fname}"

                    crawl_schemas.append(CrawlResultSchema(
                        url=crawl_result.url,
                        final_url=crawl_result.final_url,
                        status_code=crawl_result.status_code,
                        page_title=crawl_result.page_title,
                        was_redirected=crawl_result.was_redirected,
                        redirect_chain=crawl_result.redirect_chain,
                        has_login_form=crawl_result.has_login_form,
                        has_password_field=crawl_result.has_password_field,
                        screenshot_path=crawl_result.screenshot_path,
                        screenshot_url=screenshot_url,
                        error=crawl_result.error,
                    ))
                    
                    # ==========================================
                    # LAYER 4: Visual Analysis (per crawled page)
                    # Only runs when screenshots are enabled
                    # ==========================================
                    if should_visual and not crawl_result.error:
                        visual_result = visual_analyzer.analyze(crawl_result)
                        
                        visual_schemas.append(VisualAnalysisSchema(
                            is_fake_login=visual_result.is_fake_login,
                            risk_score=round(visual_result.risk_score, 4),
                            impersonated_brand=visual_result.impersonated_brand,
                            flags=visual_result.flags,
                        ))
                        
                        max_visual_risk = max(max_visual_risk, visual_result.risk_score)
                        
                        if visual_result.is_fake_login:
                            brand = visual_result.impersonated_brand or "unknown"
                            risk_factors.append(f"Fake login page detected (impersonating {brand})")
                            risk_factors.extend(visual_result.flags[:2])
                    
                except Exception as e:
                    logger.error(f"Error in crawl/visual for {url}: {e}")
            
            if crawl_schemas:
                analysis_layers.append("web_crawling")
            if visual_schemas:
                analysis_layers.append("visual_analysis")
        
        # Compute crawl risk from crawl findings
        crawl_risk = 0.0
        if crawl_schemas:
            for cs in crawl_schemas:
                if cs.error:
                    continue
                if cs.has_password_field:
                    crawl_risk = max(crawl_risk, 0.7)
                    risk_factors.append("Password field detected on crawled page")
                elif cs.has_login_form:
                    crawl_risk = max(crawl_risk, 0.5)
                    risk_factors.append("Login form detected on crawled page")
                if cs.was_redirected:
                    crawl_risk = max(crawl_risk, 0.3)
        
        # ==========================================
        # AI AUTHORSHIP DETECTION (runs on all requests)
        # ==========================================
        ai_result = await asyncio.to_thread(
            ai_authorship_detector.analyze, request.text, request.subject
        )
        ai_schema = AIAuthorshipSchema(
            is_ai_generated=ai_result.is_ai_generated,
            ai_authorship_score=round(ai_result.ai_authorship_score, 4),
            signals=ai_result.signals,
            burstiness_score=ai_result.burstiness_score,
            perplexity_proxy=ai_result.perplexity_proxy,
            vocabulary_richness=ai_result.vocabulary_richness,
            repetition_score=ai_result.repetition_score,
            formality_score=ai_result.formality_score,
        )
        analysis_layers.append("ai_authorship_detection")

        if ai_result.is_ai_generated:
            risk_factors.append(
                f"Email text likely AI-generated (score: {ai_result.ai_authorship_score:.0%})"
            )

        # ==========================================
        # XAI: Explainable AI — token attribution + risk explanation
        # ==========================================
        xai_result = await asyncio.to_thread(
            xai_explainer.explain,
            request.text,
            request.subject,
            is_phishing,
            confidence,
            classifier,
        )
        xai_schema = XAIExplanationSchema(
            available=xai_result.available,
            tokens=[
                TokenAttributionSchema(
                    token=t.token,
                    score=t.score,
                    is_highlighted=t.is_highlighted,
                )
                for t in xai_result.tokens
            ],
            top_tokens=xai_result.top_tokens,
            risk_categories=xai_result.risk_categories,
            explanation=xai_result.explanation,
            summary=xai_result.summary,
            top_token_confidence_delta=xai_result.top_token_confidence_delta,
        )
        analysis_layers.append("xai_explanation")

        # ==========================================
        # LAYER 5: Link Checking
        # ==========================================
        link_schema = None
        link_risk = 0.0
        
        if urls:
            link_result = await asyncio.to_thread(link_checker.check_links, urls)
            
            link_schema = LinkCheckSchema(
                total_links=link_result.total_links,
                checked_links=link_result.checked_links,
                suspicious_links=link_result.suspicious_links,
                risk_score=round(link_result.risk_score, 4),
                flags=link_result.flags,
            )
            
            link_risk = link_result.risk_score
            
            if link_result.suspicious_links > 0:
                risk_factors.extend(link_result.flags[:3])
            
            analysis_layers.append("link_checking")

        # ==========================================
        # LAYER 6: Header Forensics
        # ==========================================
        header_schema = None
        header_risk = 0.0

        if request.raw_headers:
            header_result = await asyncio.to_thread(
                header_analyzer.analyze, request.raw_headers
            )
            header_schema = HeaderAnalysisSchema(
                spf_result=header_result.spf_result,
                dkim_result=header_result.dkim_result,
                dmarc_result=header_result.dmarc_result,
                reply_to_mismatch=header_result.reply_to_mismatch,
                from_domain=header_result.from_domain,
                reply_to_domain=header_result.reply_to_domain,
                return_path_domain=header_result.return_path_domain,
                return_path_mismatch=header_result.return_path_mismatch,
                received_hops=header_result.received_hops,
                display_name_spoof=header_result.display_name_spoof,
                spoofed_brand=header_result.spoofed_brand,
                suspicious_mailer=header_result.suspicious_mailer,
                mailer=header_result.mailer,
                date_anomaly=header_result.date_anomaly,
                date_days_diff=header_result.date_days_diff,
                is_suspicious=header_result.is_suspicious,
                risk_score=round(header_result.risk_score, 4),
                flags=header_result.flags,
            )
            header_risk = header_result.risk_score

            if header_result.is_suspicious:
                risk_factors.extend(header_result.flags[:3])

            analysis_layers.append("header_forensics")

        # ==========================================
        # COMBINED SCORING — 6-Layer Dynamic Weight Redistribution
        # ==========================================
        # Calibrated base weights for the full 6-layer pipeline:
        #   Text (DistilBERT):  20%  ← primary ML signal
        #   URL analysis:       20%  ← domain/SSL/VT intelligence
        #   Headers (forensics):15%  ← SPF/DKIM/DMARC + spoofing
        #   Links:              15%  ← redirect chain analysis
        #   Visual:             15%  ← fake login / brand impersonation
        #   Crawl:              10%  ← live page inspection
        #   Sender:              5%  ← homoglyph + display-name
        #                      ---
        #                      100%  (no reserved headroom — boost is additive)
        #
        # AI authorship is a signal modifier, not a primary layer:
        #   confirmed AI-generated phishing → +0.08 to combined risk
        #
        # Boost logic (additive, capped at 1.0):
        #   ≥ 2 layers flagged → +0.10
        #   ≥ 3 layers flagged → additional +0.05 (total +0.15)
        #
        # When a layer is absent, its weight is redistributed
        # proportionally among active layers so scores stay comparable.

        text_risk = confidence if is_phishing else (1 - confidence)

        # Base weights per layer (must sum to 1.0)
        BASE_WEIGHTS = {
            "text":    0.20,
            "url":     0.20,
            "headers": 0.15,
            "links":   0.15,
            "visual":  0.15,
            "crawl":   0.10,
            "sender":  0.05,
        }

        # Collect only active layers
        active_scores: dict = {}
        active_scores["text"] = (text_risk, BASE_WEIGHTS["text"])

        if url_response:
            active_scores["url"] = (max_url_risk, BASE_WEIGHTS["url"])

        if header_schema:
            active_scores["headers"] = (header_risk, BASE_WEIGHTS["headers"])

        if link_schema:
            active_scores["links"] = (link_risk, BASE_WEIGHTS["links"])

        if visual_schemas:
            active_scores["visual"] = (max_visual_risk, BASE_WEIGHTS["visual"])

        if crawl_schemas:
            active_scores["crawl"] = (crawl_risk, BASE_WEIGHTS["crawl"])

        if sender_schema:
            active_scores["sender"] = (sender_risk, BASE_WEIGHTS["sender"])

        # Normalise weights of active layers so they sum to 1.0
        total_base_weight = sum(w for _, w in active_scores.values())
        if total_base_weight > 0:
            combined_risk = sum(
                score * (weight / total_base_weight)
                for score, weight in active_scores.values()
            )
        else:
            combined_risk = text_risk

        # AI authorship modifier: confirmed AI-generated phishing adds signal
        if ai_result.is_ai_generated and is_phishing:
            combined_risk = min(1.0, combined_risk + 0.08)

        # Count how many distinct layers are flagging
        flagging_layers = sum([
            is_phishing,
            max_url_risk >= 0.35 if url_response else False,
            header_risk >= 0.25 if header_schema else False,
            link_risk >= 0.30 if link_schema else False,
            max_visual_risk >= 0.40 if visual_schemas else False,
            crawl_risk >= 0.40 if crawl_schemas else False,
            sender_risk >= 0.30 if sender_schema else False,
        ])

        # Graduated boost: 2 layers → +0.10, 3+ layers → +0.15
        if flagging_layers >= 3:
            combined_risk = min(1.0, combined_risk + 0.15)
        elif flagging_layers >= 2:
            combined_risk = min(1.0, combined_risk + 0.10)

        # Determine verdict
        if combined_risk >= 0.65:
            verdict = "PHISHING"
        elif combined_risk >= 0.30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        return DeepAnalysisResponse(
            text_analysis=text_result,
            urls_found=len(urls),
            urls_list=urls,
            url_analysis=url_response,
            crawl_results=crawl_schemas,
            visual_analysis=visual_schemas,
            link_analysis=link_schema,
            sender_analysis=sender_schema,
            header_analysis=header_schema,
            ai_authorship=ai_schema,
            xai_explanation=xai_schema,
            overall_verdict=verdict,
            overall_risk_score=round(combined_risk, 4),
            is_ai_generated=ai_result.is_ai_generated,
            ai_authorship_score=round(ai_result.ai_authorship_score, 4),
            risk_factors=list(dict.fromkeys(risk_factors)),  # Deduplicate
            analysis_layers=analysis_layers,
        )
        
    except Exception as e:
        logger.error(f"Deep analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error during deep analysis: {str(e)}"
        )
