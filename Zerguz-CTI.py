#!/usr/bin/env python3

import os, sys, hashlib, socket, time, ipaddress, argparse
import json, urllib.parse, threading
from pathlib import Path
from datetime import datetime

RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
BLUE   = "\033[94m"; CYAN   = "\033[96m"; WHITE  = "\033[97m"
BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"
BG_RED = "\033[41m"

THREATFOX_HOST     = "threatfox-api.abuse.ch"
THREATFOX_PATH     = "/api/v1/"
MALWAREBAZAAR_HOST = "mb-api.abuse.ch"
MALWAREBAZAAR_PATH = "/api/v1/"
FEODO_HOST         = "feodotracker.abuse.ch"
FEODO_PATH         = "/downloads/ipblocklist.json"
FIREHOL_HOST       = "raw.githubusercontent.com"
FIREHOL_PATH       = "/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
CINS_HOST          = "cinsscore.com"
CINS_PATH          = "/list/ci-badguys.txt"
SHODAN_HOST        = "api.shodan.io"
ABUSEIPDB_HOST     = "api.abuseipdb.com"

# API Anahtarlarını buraya doğrudan tırnak içine yapıştırabilirsin 
API_KEYS = {
    "shodan": "", 
    "abuseipdb": "", 
    "threatfox": "", 
    "malwarebazaar": "" 
}

_feodo_cache = _firehol_cache = _cinss_cache = None
_cache_time  = {}
CACHE_TTL    = 3600

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

def banner():
    print(f"""
{RED}{BOLD}
  ███████╗███████╗██████╗  ██████╗ ██╗   ██╗███████╗     ██████╗████████╗██╗
  ╚══███╔╝██╔════╝██╔══██╗██╔════╝ ██║   ██║╚══███╔╝    ██╔════╝╚══██╔══╝██║
    ███╔╝ █████╗  ██████╔╝██║  ███╗██║   ██║  ███╔╝     ██║        ██║   ██║
   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ███╔╝      ██║        ██║   ██║
  ███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝███████╗    ╚██████╗   ██║   ██║
  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝     ╚═════╝   ╚═╝   ╚═╝
{RESET}{DIM}
  [ ZERGUZ CTI v4.2 | ThreatFox · MalwareBazaar · Shodan · AbuseIPDB · Feodo · FireHOL · CINS ]
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
""")

def api_status_line():
    sh_ok = bool(API_KEYS["shodan"].strip())
    ab_ok = bool(API_KEYS["abuseipdb"].strip())
    tf_ok = bool(API_KEYS["threatfox"].strip())
    mb_ok = bool(API_KEYS["malwarebazaar"].strip())
    print(
        f"{'  ' + GREEN + '● ThreatFox ✔' if tf_ok else '  ' + YELLOW + '● ThreatFox (→Menü 6)'}{RESET}  "
        f"{'  ' + GREEN + '● MalwareBazaar ✔' if mb_ok else '  ' + YELLOW + '● MalwareBazaar (→Menü 6)'}{RESET}  "
        f"{GREEN}● Feodo  ● FireHOL  ● CINS{RESET}\n"
        f"{'  ' + GREEN + '● Shodan ✔' if sh_ok else '  ' + YELLOW + '● Shodan (→Menü 6)'}{RESET}  "
        f"{'  ' + GREEN + '● AbuseIPDB ✔' if ab_ok else '  ' + YELLOW + '● AbuseIPDB (→Menü 6)'}{RESET}\n"
    )

def sep(w=67): print(f"  {DIM}{'─'*w}{RESET}")

def threat_bar(n):
    c = RED if n>=8 else YELLOW if n>=5 else CYAN if n>=2 else GREEN
    return f"[{c}{'█'*int(n)}{RESET}{DIM}{'░'*(10-int(n))}{RESET}] {c}{BOLD}{n}/10{RESET}"

def threat_label(n):
    if   n == 0: return f"{GREEN}{BOLD}✅ TEMİZ{RESET}"
    elif n <= 2: return f"{CYAN}{BOLD}🔵 DÜŞÜK RİSK{RESET}"
    elif n <= 4: return f"{YELLOW}{BOLD}🟡 ŞÜPHELİ{RESET}"
    elif n <= 6: return f"{YELLOW}{BOLD}🟠 ORTA TEHDİT{RESET}"
    elif n <= 8: return f"{RED}{BOLD}🔴 YÜKSEK TEHDİT{RESET}"
    else:        return f"{BG_RED}{WHITE}{BOLD} ☠ KRİTİK TEHDİT ☠ {RESET}"

def stag(name, hit=True):
    return f"{BG_RED}{WHITE} {name} {RESET}" if hit else f"{DIM}[{name}]{RESET}"

def pbar(lbl, dur=0.8, n=25):
    sys.stdout.write(f"  {CYAN}{lbl}{RESET}  [")
    sys.stdout.flush()
    for _ in range(n):
        time.sleep(dur/n)
        sys.stdout.write(f"{CYAN}█{RESET}")
        sys.stdout.flush()
    print(f"] {GREEN}✔{RESET}")

# ─── HTTP CORE ───────────────────────────────────

try:
    import requests as _req
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

def _make_session():
    if not REQUESTS_OK:
        return None
    s = _req.Session()
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({
        "User-Agent":      UA,
        "Accept-Encoding": "gzip, deflate",
        "Accept":          "*/*",
        "Connection":      "keep-alive",
    })
    return s

_SESSION = None

def _session():
    global _SESSION
    if _SESSION is None:
        _SESSION = _make_session()
    return _SESSION

def _parse_json(raw):
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    try:
        return json.loads(raw)
    except Exception:
        return None

def _spinner_run(label, fn):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    res=[None]; err=[None]
    def worker():
        try:
            res[0] = fn()
        except Exception as e:
            err[0] = str(e)
    t = threading.Thread(target=worker)
    t.start(); i = 0
    while t.is_alive():
        sys.stdout.write(f"\r  {CYAN}{frames[i%len(frames)]}{RESET} {label}")
        sys.stdout.flush()
        time.sleep(0.08); i += 1
    t.join()
    ok = res[0] is not None
    sys.stdout.write(
        f"\r  {GREEN}✔{RESET} {label}{' '*20}\n" if ok
        else f"\r  {RED}✖{RESET} {label} — {err[0] or 'hata'}{' '*10}\n"
    )
    sys.stdout.flush()
    return res[0]

def api_post_json(label, host, path, payload_dict, extra_headers=None):
    url = f"https://{host}{path}"
    def fn():
        s = _session()
        if not s:
            raise Exception("requests modülü bulunamadı: pip install requests")
        hdrs = {"Content-Type": "application/json"}
        if extra_headers:
            hdrs.update(extra_headers)
        r = s.post(url, json=payload_dict, headers=hdrs, timeout=14, verify=True)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}: {r.text[:150]}")
        data = r.json()
        return data
    return _spinner_run(label, fn)

def api_post_form(label, host, path, payload_dict, extra_headers=None):
    url = f"https://{host}{path}"
    def fn():
        s = _session()
        if not s:
            raise Exception("requests modülü bulunamadı: pip install requests")
        hdrs = {}
        if extra_headers:
            hdrs.update(extra_headers)
        r = s.post(url, data=payload_dict, headers=hdrs, timeout=14, verify=True)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}: {r.text[:150]}")
        data = r.json()
        return data
    return _spinner_run(label, fn)

def api_get(label, host, path, extra_headers=None):
    url = f"https://{host}{path}"
    def fn():
        s = _session()
        if not s:
            raise Exception("requests modülü bulunamadı: pip install requests")
        hdrs = {}
        if extra_headers:
            hdrs.update(extra_headers)
        r = s.get(url, headers=hdrs, timeout=14, verify=True)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}: {r.text[:150]}")
        return r.text
    return _spinner_run(label, fn)

# ─── FEED LİSTELERİ ────────────────────────────────────────────

def _cache_ok(k): return k in _cache_time and (time.time()-_cache_time[k]) < CACHE_TTL

def load_feodo():
    global _feodo_cache
    if _cache_ok("feodo") and _feodo_cache is not None: return _feodo_cache
    raw = api_get("Feodo Tracker C2 listesi yukleniyor...", FEODO_HOST, FEODO_PATH)
    _feodo_cache = {}
    if raw:
        try:
            for e in json.loads(raw):
                ip = e.get("ip_address","")
                if ip: _feodo_cache[ip] = (e.get("malware","?"), e.get("status","?"))
            _cache_time["feodo"] = time.time()
            print(f"  {DIM}→ {len(_feodo_cache)} C2 IP yuklendi{RESET}")
        except Exception as ex:
            print(f"  {RED}Feodo parse: {ex}{RESET}")
    return _feodo_cache

def load_firehol():
    global _firehol_cache
    if _cache_ok("firehol") and _firehol_cache is not None: return _firehol_cache
    raw = api_get("FireHOL Level-1 yukleniyor...", FIREHOL_HOST, FIREHOL_PATH)
    _firehol_cache = set()
    if raw:
        _firehol_cache = {l.strip() for l in raw.splitlines()
                          if l.strip() and not l.startswith("#")}
        _cache_time["firehol"] = time.time()
        print(f"  {DIM}→ {len(_firehol_cache)} IP/CIDR yuklendi{RESET}")
    return _firehol_cache

def load_cins():
    global _cinss_cache
    if _cache_ok("cins") and _cinss_cache is not None: return _cinss_cache
    raw = api_get("CINS Score listesi yukleniyor...", CINS_HOST, CINS_PATH)
    _cinss_cache = set()
    if raw:
        _cinss_cache = {l.strip() for l in raw.splitlines()
                        if l.strip() and not l.startswith("#")}
        _cache_time["cins"] = time.time()
        print(f"  {DIM}→ {len(_cinss_cache)} IP yuklendi{RESET}")
    return _cinss_cache

def ip_in_firehol(ip, fset):
    if ip in fset: return True
    try:
        addr = ipaddress.ip_address(ip)
        for e in fset:
            if "/" in e:
                try:
                    if addr in ipaddress.ip_network(e, strict=False): return True
                except: pass
    except: pass
    return False

# ─── ThreatFox ─────────────────────────────────────────────────

def threatfox_hash(md5, sha256):
    best = None
    headers = {}
    # BURASI DÜZELTİLDİ: "API-KEY" yerine "Auth-Key" yapıldı
    if API_KEYS["threatfox"].strip():
        headers["Auth-Key"] = API_KEYS["threatfox"].strip()
        
    for h in [x for x in [sha256, md5] if x]:
        data = api_post_json(
            f"ThreatFox hash sorgulanıyor ({h[:18]}...)...",
            THREATFOX_HOST, THREATFOX_PATH,
            {"query": "search_hash", "hash": h},
            extra_headers=headers
        )
        if not data: continue
        st = data.get("query_status","")
        if st == "hash_found":
            for e in (data.get("data") or []):
                malware = e.get("malware_printable") or e.get("malware") or "Bilinmeyen"
                conf    = int(e.get("confidence_level") or 50)
                score   = min(10, int(conf/10) + 2)
                candidate = (score, malware, conf,
                             e.get("tags") or [],
                             e.get("threat_type_desc",""), h)
                if best is None or score > best[0]:
                    best = candidate
        elif st not in ("no_results", ""):
            print(f"  {YELLOW}ThreatFox yanit: {st}{RESET}")
    return best

def threatfox_ip(ip):
    headers = {}
    # BURASI DÜZELTİLDİ: "Auth-Key" yapıldı
    if API_KEYS["threatfox"].strip():
        headers["Auth-Key"] = API_KEYS["threatfox"].strip()
        
    data = api_post_json(
        "ThreatFox IP sorgulanıyor...",
        THREATFOX_HOST, THREATFOX_PATH,
        {"query": "search_ioc", "search_term": ip},
        extra_headers=headers
    )
    if not data: return None
    st = data.get("query_status","")
    if st == "no_results": return None
    if st not in ("ok", "hash_found"):
        print(f"  {YELLOW}ThreatFox IP yanit: {st}{RESET}"); return None
    best = None
    for e in (data.get("data") or []):
        malware = e.get("malware_printable") or e.get("malware") or "Bilinmeyen"
        conf    = int(e.get("confidence_level") or 50)
        score   = min(10, int(conf/10) + 3)
        if best is None or score > best[0]:
            best = (score, malware, conf, e.get("threat_type_desc",""), e.get("tags") or [])
    return best

# ─── MalwareBazaar ─────────────────────────────────────────────

def _mb_build(e, h):
    sig = e.get("signature") or ""
    if not sig:
        tags = e.get("tags") or []
        sig  = ", ".join(tags) if tags else "Bilinmeyen"
    if isinstance(sig, list): sig = ", ".join(sig)
    intel = e.get("intelligence") or {}
    return (9, sig,
            e.get("file_type","?"), e.get("file_size","?"),
            e.get("first_seen","?"), e.get("reporter","?"),
            e.get("tags") or [],
            intel.get("downloads","?"), intel.get("uploads","?"), h)

def malwarebazaar_hash(md5, sha256):
    headers = {}
    # BURASI DÜZELTİLDİ: "API-KEY" yerine "Auth-Key" yapıldı
    if API_KEYS["malwarebazaar"].strip():
        headers["Auth-Key"] = API_KEYS["malwarebazaar"].strip()
        
    for h in [x for x in [sha256, md5] if x]:
        data = api_post_form(
            f"MalwareBazaar get_info ({h[:18]}...)...",
            MALWAREBAZAAR_HOST, MALWAREBAZAAR_PATH,
            {"query": "get_info", "hash": h},
            extra_headers=headers
        )
        if not data: continue
        st = data.get("query_status","")
        if st == "ok":
            entries = data.get("data") or []
            if entries: return _mb_build(entries[0], h)
        elif st == "hash_not_found":
            print(f"  {DIM}hash_not_found → get_recent ile son yuklemeler aranıyor...{RESET}")
            data2 = api_post_form(
                "MalwareBazaar get_recent tarama...",
                MALWAREBAZAAR_HOST, MALWAREBAZAAR_PATH,
                {"query": "get_recent", "selector": "time"},
                extra_headers=headers
            )
            if data2 and data2.get("query_status") == "ok":
                for e in (data2.get("data") or []):
                    if any(e.get(k,"").lower() == h.lower()
                           for k in ["sha256_hash","md5_hash","sha1_hash"]):
                        print(f"  {GREEN}✔ Son yuklemelerde eslesmesi bulundu!{RESET}")
                        return _mb_build(e, h)
        elif st not in ("", None):
            print(f"  {YELLOW}MalwareBazaar yanit: {st}{RESET}")
    return None

# ─── Shodan ────────────────────────────────────────────────────

def shodan_ip(ip):
    key = API_KEYS["shodan"].strip()
    if not key: return None
    raw = api_get(
        "Shodan IP istihbarati sorgulanıyor...",
        SHODAN_HOST, f"/shodan/host/{ip}?key={key}"
    )
    if not raw: return None
    try:
        d = _parse_json(raw)
        if not d or "error" in d:
            print(f"  {YELLOW}Shodan: {(d or {}).get('error','hata')}{RESET}"); return None
        ports  = d.get("ports") or []
        vulns  = list((d.get("vulns") or {}).keys())
        tags   = d.get("tags") or []
        score  = 0; notes = []
        if vulns:
            score += min(len(vulns)*2, 6)
            notes.append(f"CVE aciklari: {', '.join(vulns[:5])}")
        dp = [p for p in ports if p in {21,22,23,25,110,135,139,445,1433,3306,3389,4444,5900,6379,27017}]
        if len(ports) > 10:
            score += 2; notes.append(f"Cok acik port: {len(ports)}")
        if dp:
            score += min(len(dp),3); notes.append(f"Tehlikeli portlar: {dp}")
        for t in tags:
            if any(s in t.lower() for s in ["tor","vpn","proxy","scanner","honeypot"]):
                score += 2; notes.append(f"Suphe etiketi: {t}")
        return (min(score,10), d.get("org","?"), d.get("country_name","?"),
                d.get("city","?"), d.get("isp","?"), d.get("asn","?"),
                ports, vulns, tags, d.get("hostnames") or [],
                d.get("last_update","?"), notes)
    except Exception as ex:
        print(f"  {YELLOW}Shodan parse: {ex}{RESET}"); return None

# ─── AbuseIPDB ─────────────────────────────────────────────────

def abuseipdb_ip(ip):
    key = API_KEYS["abuseipdb"].strip()
    if not key: return None
    path = f"/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose"
    raw  = api_get(
        "AbuseIPDB kötüye kullanim sorgusu...",
        ABUSEIPDB_HOST, path,
        extra_headers={"Key": key}
    )
    if not raw: return None
    try:
        d = _parse_json(raw)
        if not d: return None
        d = d.get("data",{})
        abuse = int(d.get("abuseConfidenceScore",0))
        return (min(10, int(abuse/10)), abuse,
                int(d.get("totalReports",0)),
                d.get("countryCode","?"), d.get("isp","?"),
                d.get("domain","?"), d.get("isWhitelisted",False),
                d.get("lastReportedAt"), d.get("usageType","?"))
    except Exception as ex:
        print(f"  {YELLOW}AbuseIPDB parse: {ex}{RESET}"); return None

# ─── Hash & Heuristik ──────────────────────────────────────────

def calc_hashes(fp):
    m, s1, s256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    try:
        with open(fp,"rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                m.update(chunk); s1.update(chunk); s256.update(chunk)
        return m.hexdigest(), s1.hexdigest(), s256.hexdigest()
    except PermissionError:
        print(f"  {RED}✖ Erisim reddedildi: {fp}{RESET}"); return None,None,None
    except Exception as ex:
        print(f"  {RED}✖ {ex}{RESET}"); return None,None,None

def heuristic(fp):
    score=0; reasons=[]
    name = Path(fp).name.lower()
    for ext in [".exe",".bat",".cmd",".vbs",".js",".ps1",".sh",".elf"]:
        if name.endswith(ext): score+=2; reasons.append(f"Tehlikeli uzanti ({ext})"); break
    if name.count(".")>=2: score+=2; reasons.append("Cift uzanti")
    for p in ["invoice","payment","crack","keygen","setup","install"]:
        if p in name: score+=1; reasons.append(f"Suphe isim ({p})"); break
    if name.startswith("."): score+=1; reasons.append("Gizli dosya")
    try:
        sz = os.path.getsize(fp)
        if sz==0: return 0,["Bos dosya"]
        if sz<512 and any(name.endswith(e) for e in [".exe",".elf",".sh"]):
            score+=1; reasons.append("Cok kucuk calistirabilir")
    except: pass
    try:
        if os.path.getsize(fp)<1_000_000:
            with open(fp,"rb") as f: c=f.read(4096)
            if c[:4]==b"\x7fELF": score+=1; reasons.append("ELF binary")
            for s in [b"/etc/passwd",b"chmod 777",b"curl |bash",b"wget -O-",b"base64 -d"]:
                if s in c: score+=2; reasons.append(f"Suphe komut: {s.decode(errors='replace')}")
    except: pass
    return min(score,10), reasons

def ip_basic(ip):
    score=0; reasons=[]
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:    return 0,["Ozel (yerel) ag — dahili"]
        if addr.is_loopback:   return 0,["Loopback adresi"]
        if addr.is_link_local: return 0,["Link-local — dahili"]
        if addr.is_multicast:  score+=2; reasons.append("Multicast")
        if addr.is_reserved:   score+=1; reasons.append("Ayrilmis blok")
    except ValueError:
        return 10,["Gecersiz IP"]
    try:
        hn = socket.gethostbyaddr(ip)[0]
        reasons.append(f"Hostname: {hn}")
        for sh in ["tor","proxy","vpn","anon","exit","relay","botnet","scan","attack"]:
            if sh in hn.lower(): score+=3; reasons.append(f"Suphe hostname: '{sh}'"); break
    except: reasons.append("Ters DNS: yok"); score+=1
    for port in [23,135,139,445,1433,3389,4444,5900,6666,31337][:6]:
        try:
            s=socket.socket(); s.settimeout(0.3)
            if s.connect_ex((ip,port))==0: score+=2; reasons.append(f"Acik suphe port: {port}")
            s.close()
        except: pass
    return min(score,10), reasons

# ─── Tarama Fonksiyonları ──────────────────────────────────────

def scan_file(fp):
    path = Path(fp)
    print(f"\n{BOLD}{BLUE}  📄 DOSYA TARANIYOR{RESET}"); sep()
    print(f"  {WHITE}Yol   :{RESET} {path}")
    print(f"  {WHITE}Boyut :{RESET} {os.path.getsize(fp):,} byte")
    print(f"  {WHITE}Zaman :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"); sep()
    pbar("Hash hesaplanıyor...")
    md5, sha1, sha256 = calc_hashes(fp)
    if not md5: return
    print(f"\n  {CYAN}MD5   :{RESET} {md5}")
    print(f"  {CYAN}SHA1  :{RESET} {sha1}")
    print(f"  {CYAN}SHA256:{RESET} {sha256}"); sep()
    print(f"\n  {BOLD}Canlı tehdit istihbaratı sorgulanıyor...{RESET}\n")
    tf = threatfox_hash(md5, sha256)
    mb = malwarebazaar_hash(md5, sha256)
    pbar("Heuristik analiz...")
    hs, hr = heuristic(fp)
    final = hs
    if tf: final = max(final, tf[0])
    if mb: final = max(final, mb[0])
    _show_file(final, tf, mb, hr)
    return final

def scan_hash(raw):
    raw = raw.strip().lower()
    hlen = len(raw)
    if hlen==32:   htype="MD5"
    elif hlen==64: htype="SHA256"
    else:
        print(f"\n  {RED}✖ Gecersiz hash uzunlugu ({hlen}). MD5=32, SHA256=64.{RESET}\n"); return
    print(f"\n{BOLD}{BLUE}  🔎 HASH SORGULANIYOR{RESET}"); sep()
    print(f"  {WHITE}Tur   :{RESET} {htype}")
    print(f"  {WHITE}Hash  :{RESET} {raw}")
    print(f"  {WHITE}Zaman :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"); sep()
    print(f"\n  {BOLD}Canlı tehdit istihbaratı sorgulanıyor...{RESET}\n")
    tf = threatfox_hash(raw if hlen==32 else None, raw if hlen==64 else None)
    mb = malwarebazaar_hash(raw if hlen==32 else None, raw if hlen==64 else None)
    final = 0
    if tf: final = max(final, tf[0])
    if mb: final = max(final, mb[0])
    print(f"\n  {BOLD}{'━'*67}{RESET}")
    print(f"  {BOLD}HASH SONUCU{RESET}"); print(f"  {'━'*67}")
    print(f"  {WHITE}Tur          :{RESET}  {htype}")
    print(f"  {WHITE}Hash         :{RESET}  {DIM}{raw}{RESET}")
    print(f"  {WHITE}Tehdit Skoru :{RESET}  {threat_bar(final)}")
    print(f"  {WHITE}Tehdit Duzey :{RESET}  {threat_label(final)}")
    if tf:
        s,malware,conf,tags,threat,matched = tf
        print(f"\n  {stag('ThreatFox')} {RED}{BOLD} TESPIT!{RESET}")
        print(f"    Zararli     : {RED}{BOLD}{malware}{RESET}")
        print(f"    Tehdit Turu : {threat}")
        print(f"    Guven       : %{conf}")
        print(f"    Eslesen Hash: {DIM}{matched}{RESET}")
        if tags: print(f"    Etiketler   : {', '.join(tags)}")
    else:
        print(f"\n  {stag('ThreatFox',False)} {GREEN}Esleme yok{RESET}")
    if mb:
        s,sig,ftype,fsize,first,rep,tags,dl,ul,matched = mb
        print(f"\n  {stag('MalwareBazaar')} {RED}{BOLD} TESPIT!{RESET}")
        print(f"    Imza / Aile : {RED}{BOLD}{sig}{RESET}")
        print(f"    Dosya Turu  : {ftype}  |  Boyut: {fsize} byte")
        print(f"    Ilk Gorulme : {first}  |  Raporlayan: {rep}")
        if tags: print(f"    Etiketler   : {', '.join(tags)}")
    else:
        print(f"\n  {stag('MalwareBazaar',False)} {GREEN}Esleme yok{RESET}")
    if final>=7:   print(f"\n  {BG_RED}{WHITE}{BOLD}  ⚠  TEHLIKELI! Dosyayi karantinaya alin.  {RESET}")
    elif final>=4: print(f"\n  {YELLOW}{BOLD}  ⚠  Supheli. Incelemeniz onerilir.{RESET}")
    else:
        print(f"\n  {YELLOW}ℹ Bilinen veritabaninda bulunamadi.{RESET}")
        print(f"  {DIM}  Temiz olabilir ya da henuz raporlanmamis.{RESET}")
    print(f"  {'━'*67}\n")

def scan_ip(inp):
    print(f"\n{BOLD}{BLUE}  🌐 IP / HOST TARANIYOR{RESET}"); sep()
    ip = inp
    if not _is_ip(inp):
        print(f"  {CYAN}Hostname cozumleniyor:{RESET} {inp}")
        ip = _resolve(inp)
        if not ip:
            print(f"  {RED}✖ Cozumlenemedi: {inp}{RESET}"); return
        print(f"  {WHITE}Cozumlenen IP:{RESET} {ip}")
    print(f"  {WHITE}Hedef :{RESET} {ip}")
    print(f"  {WHITE}Zaman :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"); sep()
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            print(f"\n  {CYAN}Dahili adres — harici sorgular atlanıyor{RESET}")
            sc, rs = ip_basic(ip); _show_ip(ip,sc,rs,[],None,None,None); return
    except: pass
    print(f"\n  {BOLD}Feed listeleri guncelleniyor...{RESET}\n")
    feodo=load_feodo(); fhol=load_firehol(); cins=load_cins()
    print(f"\n  {BOLD}API sorguları yapılıyor...{RESET}\n")
    tf = threatfox_ip(ip)
    sh = shodan_ip(ip)
    ab = abuseipdb_ip(ip)
    pbar("Temel IP analizi...")
    sc, rs = ip_basic(ip)
    feeds=[]
    if ip in feodo:
        m,st=feodo[ip]; sc=max(sc,9); feeds.append(f"Feodo C2 ({m}, {st})")
    if ip_in_firehol(ip,fhol):
        sc=max(sc,8); feeds.append("FireHOL Level-1")
    if ip in cins:
        sc=max(sc,7); feeds.append("CINS Score")
    if tf: sc=max(sc,tf[0])
    if sh: sc=max(sc,sh[0])
    if ab: sc=max(sc,ab[0])
    _show_ip(ip,sc,rs,feeds,tf,sh,ab)

def scan_dir(dirpath):
    directory = Path(dirpath)
    if not directory.is_dir():
        print(f"  {RED}✖ Gecersiz dizin: {dirpath}{RESET}"); return
    files = [f for f in directory.rglob("*") if f.is_file()]
    print(f"\n{BOLD}{BLUE}  📁 DIZIN TARANIYOR{RESET}"); sep()
    print(f"  {WHITE}Dizin   :{RESET} {directory}")
    print(f"  {WHITE}Dosyalar:{RESET} {len(files)} adet"); sep()
    results=[]
    
    # BURASI DÜZELTİLDİ: "Auth-Key" yapıldı
    tf_headers = {"Auth-Key": API_KEYS["threatfox"].strip()} if API_KEYS["threatfox"].strip() else {}
    mb_headers = {"Auth-Key": API_KEYS["malwarebazaar"].strip()} if API_KEYS["malwarebazaar"].strip() else {}
    
    for i,f in enumerate(files,1):
        sys.stdout.write(f"\r  {CYAN}[{i}/{len(files)}]{RESET} {str(f)[:55]:<55}")
        sys.stdout.flush()
        md5,sha1,sha256 = calc_hashes(str(f))
        if not md5: continue
        hs,_ = heuristic(str(f))
        tf_score=mb_score=0; tf_name=mb_name=None
        s = _session()
        for h in [x for x in [sha256,md5] if x]:
            try:
                r = s.post(f"https://{THREATFOX_HOST}{THREATFOX_PATH}",
                           json={"query":"search_hash","hash":h}, headers=tf_headers, timeout=10, verify=True)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("query_status")=="hash_found":
                        iocs = d.get("data") or []
                        if iocs:
                            conf = int(iocs[0].get("confidence_level") or 50)
                            cand = min(10, int(conf/10)+2)
                            if cand > tf_score:
                                tf_score=cand; tf_name=iocs[0].get("malware_printable","?")
            except Exception:
                pass
        for h in [x for x in [sha256,md5] if x]:
            try:
                r = s.post(f"https://{MALWAREBAZAAR_HOST}{MALWAREBAZAAR_PATH}",
                           data={"query":"get_info","hash":h}, headers=mb_headers, timeout=10, verify=True)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("query_status")=="ok":
                        entries = d.get("data") or []
                        if entries:
                            sig = entries[0].get("signature") or "?"
                            if isinstance(sig,list): sig=", ".join(sig)
                            mb_score=9; mb_name=sig
                    elif d.get("query_status")=="hash_not_found":
                        r2 = s.post(f"https://{MALWAREBAZAAR_HOST}{MALWAREBAZAAR_PATH}",
                                    data={"query":"get_recent","selector":"time"}, headers=mb_headers, timeout=10, verify=True)
                        if r2.status_code == 200:
                            d2 = r2.json()
                            if d2.get("query_status")=="ok":
                                for e in (d2.get("data") or []):
                                    if any(e.get(k,"").lower()==h.lower()
                                           for k in ["sha256_hash","md5_hash","sha1_hash"]):
                                        sig = e.get("signature") or "?"
                                        if isinstance(sig,list): sig=", ".join(sig)
                                        mb_score=9; mb_name=sig; break
            except Exception:
                pass
        final = max(hs,tf_score,mb_score)
        src   = "ThreatFox" if tf_score>=mb_score and tf_name else "MalwareBazaar" if mb_name else None
        name  = tf_name if tf_score>=mb_score and tf_name else mb_name
        results.append((str(f),md5,sha256,final,name,src))
    threats = sum(1 for *_,s,n,sr in results if s>=5)
    print(f"\n\n  {BOLD}{'━'*67}{RESET}")
    print(f"  {BOLD}DIZIN TARAMA RAPORU{RESET}"); print(f"  {'━'*67}")
    print(f"  Toplam : {len(results)}")
    print(f"  {RED if threats else GREEN}{BOLD}Tehdit : {threats}{RESET}\n")
    found = [(fp,m,s2,s,n,sr) for fp,m,s2,s,n,sr in results if s>=3]
    if found:
        print(f"  {YELLOW}Suphe/Zararli Dosyalar:{RESET}")
        for fp,m,s2,sc,name,src in sorted(found,key=lambda x:-x[3]):
            print(f"\n  {RED if sc>=7 else YELLOW}■{RESET} {Path(fp).name}")
            print(f"    Yol  : {DIM}{fp}{RESET}")
            print(f"    Skor : {threat_bar(sc)}")
            print(f"    Durum: {threat_label(sc)}")
            if name: print(f"    Tespit: {RED}{name}{RESET} ({src})")
    else:
        print(f"  {GREEN}✔ Hicbir tehdit tespit edilmedi.{RESET}")
    print(f"\n  {'━'*67}\n")

def _show_file(final, tf, mb, hr):
    print(f"\n  {BOLD}{'━'*67}{RESET}")
    print(f"  {BOLD}DOSYA SONUCU{RESET}"); print(f"  {'━'*67}")
    print(f"  {WHITE}Tehdit Skoru :{RESET}  {threat_bar(final)}")
    print(f"  {WHITE}Tehdit Duzey :{RESET}  {threat_label(final)}")
    if tf:
        s,malware,conf,tags,threat,matched = tf
        print(f"\n  {stag('ThreatFox')} {RED}{BOLD} TESPIT!{RESET}")
        print(f"    Zararli     : {RED}{BOLD}{malware}{RESET}")
        print(f"    Tehdit Turu : {threat}")
        print(f"    Guven       : %{conf}")
        print(f"    Eslesen Hash: {DIM}{matched}{RESET}")
        if tags: print(f"    Etiketler   : {', '.join(tags)}")
    else:
        print(f"\n  {stag('ThreatFox',False)} {GREEN}Esleme yok{RESET}")
    if mb:
        s,sig,ftype,fsize,first,rep,tags,dl,ul,matched = mb
        print(f"\n  {stag('MalwareBazaar')} {RED}{BOLD} TESPIT!{RESET}")
        print(f"    Imza        : {RED}{BOLD}{sig}{RESET}")
        print(f"    Tur/Boyut   : {ftype} / {fsize} byte")
        print(f"    Ilk Gorulme : {first}  |  Raporlayan: {rep}")
        if tags: print(f"    Etiketler   : {', '.join(tags)}")
    else:
        print(f"\n  {stag('MalwareBazaar',False)} {GREEN}Esleme yok{RESET}")
    if hr:
        print(f"\n  {YELLOW}Heuristik:{RESET}")
        for r in hr: print(f"    {DIM}•{RESET} {r}")
    if final>=7:   print(f"\n  {BG_RED}{WHITE}{BOLD}  ⚠  DOSYA TEHLIKELI! Karantinaya alin.  {RESET}")
    elif final>=4: print(f"\n  {YELLOW}{BOLD}  ⚠  Supheli. Incelemeniz onerilir.{RESET}")
    else:          print(f"\n  {GREEN}{BOLD}  ✔  Bilinen tehdit tespit edilemedi.{RESET}")
    print(f"  {'━'*67}\n")

def _show_ip(ip,score,reasons,feeds,tf,sh,ab):
    print(f"\n  {BOLD}{'━'*67}{RESET}")
    print(f"  {BOLD}IP SONUCU{RESET}"); print(f"  {'━'*67}")
    print(f"  {WHITE}IP           :{RESET}  {ip}")
    print(f"  {WHITE}Tehdit Skoru :{RESET}  {threat_bar(score)}")
    print(f"  {WHITE}Tehdit Duzey :{RESET}  {threat_label(score)}")
    if feeds:
        print(f"\n  {RED}{BOLD}⚠ Feed Eslesmeleri:{RESET}")
        for f in feeds: print(f"    {RED}▶{RESET} {f}")
    if tf:
        s,malware,conf,threat,tags=tf
        print(f"\n  {stag('ThreatFox')} {RED}{BOLD} TESPIT!{RESET}")
        print(f"    Zararli   : {RED}{BOLD}{malware}{RESET}")
        print(f"    Tur/Guven : {threat} / %{conf}")
        if tags: print(f"    Etiketler : {', '.join(tags)}")
    else:
        print(f"\n  {stag('ThreatFox',False)} {GREEN}Esleme yok{RESET}")
    if sh:
        s,org,country,city,isp,asn,ports,vulns,tags,hosts,upd,notes=sh
        print(f"\n  {stag('Shodan',s>0)} Bilgi")
        print(f"    Org/Konum    : {org} — {city}, {country}")
        print(f"    ISP/ASN      : {isp} / {asn}")
        print(f"    Acik Portlar : {ports[:15]}{'...' if len(ports)>15 else ''}")
        if vulns: print(f"    {RED}CVE          : {', '.join(vulns[:6])}{RESET}")
        if tags:  print(f"    Etiketler    : {', '.join(tags)}")
        for n in notes: print(f"    {YELLOW}⚠ {n}{RESET}")
    elif API_KEYS["shodan"].strip():
        print(f"\n  {stag('Shodan',False)} {YELLOW}Veri yok{RESET}")
    else:
        print(f"\n  {stag('Shodan',False)} {DIM}API key girilmedi → Menu 6{RESET}")
    if ab:
        s,abuse,total,country,isp,dom,wl,last,usage=ab
        c=RED if abuse>=50 else YELLOW if abuse>=20 else GREEN
        print(f"\n  {stag('AbuseIPDB',abuse>0)} Kötüye Kullanim")
        print(f"    Skor     : {c}{BOLD}%{abuse}{RESET}  |  Rapor: {total}")
        print(f"    Ulke/ISP : {country} / {isp}")
        print(f"    Kullanim : {usage}")
        if last: print(f"    Son Rapor: {last}")
        if wl:   print(f"    {GREEN}✔ Whitelist{RESET}")
    elif API_KEYS["abuseipdb"].strip():
        print(f"\n  {stag('AbuseIPDB',False)} {YELLOW}Veri yok{RESET}")
    else:
        print(f"\n  {stag('AbuseIPDB',False)} {DIM}API key girilmedi → Menu 6{RESET}")
    if reasons:
        print(f"\n  {YELLOW}Temel Analiz:{RESET}")
        for r in reasons: print(f"    {DIM}•{RESET} {r}")
    if score>=7:   print(f"\n  {BG_RED}{WHITE}{BOLD}  ⚠  BU IP TEHLIKELI! Baglantıyı kesin.  {RESET}")
    elif score>=4: print(f"\n  {YELLOW}{BOLD}  ⚠  Supheli. Dikkatli olunmasi onerilir.{RESET}")
    else:          print(f"\n  {GREEN}{BOLD}  ✔  Bilinen tehdit tespit edilemedi.{RESET}")
    print(f"  {'━'*67}\n")

def _is_ip(s):
    try: ipaddress.ip_address(s); return True
    except: return False

def _resolve(h):
    try: return socket.gethostbyname(h)
    except: return None

def api_key_setup():
    print(f"\n  {BOLD}API Anahtarı Yapılandırması{RESET}"); sep()
    print(f"  {DIM}ThreatFox    : https://threatfox.abuse.ch/api/{RESET}")
    print(f"  {DIM}MalwareBazaar: https://bazaar.abuse.ch/api/{RESET}")
    print(f"  {DIM}Shodan       : https://account.shodan.io{RESET}")
    print(f"  {DIM}AbuseIPDB    : https://www.abuseipdb.com/api{RESET}"); sep()
    
    tf = input(f"\n  {WHITE}ThreatFox API Key{RESET} (bos=degisiklik yok): ").strip()
    if tf: API_KEYS["threatfox"]=tf; print(f"  {GREEN}✔ ThreatFox ayarlandi.{RESET}")
    
    mb = input(f"  {WHITE}MalwareBazaar API Key{RESET} (bos=degisiklik yok): ").strip()
    if mb: API_KEYS["malwarebazaar"]=mb; print(f"  {GREEN}✔ MalwareBazaar ayarlandi.{RESET}")
    
    sk = input(f"  {WHITE}Shodan API Key{RESET} (bos=degisiklik yok): ").strip()
    if sk: API_KEYS["shodan"]=sk; print(f"  {GREEN}✔ Shodan ayarlandi.{RESET}")
    
    ak = input(f"  {WHITE}AbuseIPDB API Key{RESET} (bos=degisiklik yok): ").strip()
    if ak: API_KEYS["abuseipdb"]=ak; print(f"  {GREEN}✔ AbuseIPDB ayarlandi.{RESET}")
    print()

def menu():
    while True:
        print(f"""
{BOLD}  {RED}┌──────────────────────────────────────────────────┐{RESET}
  {RED}│{RESET}  {WHITE}1{RESET}  Dosya Tara      (ThreatFox + MalwareBazaar)  {RED}│{RESET}
  {RED}│{RESET}  {WHITE}2{RESET}  IP / Host Tara  (TF + Shodan + AbuseIPDB)    {RED}│{RESET}
  {RED}│{RESET}  {WHITE}3{RESET}  Dizin Tara      (Toplu)                      {RED}│{RESET}
  {RED}│{RESET}  {WHITE}4{RESET}  Hash Sorgula    (MD5 / SHA256)               {RED}│{RESET}
  {RED}│{RESET}  {WHITE}5{RESET}  Feed Guncelle                                {RED}│{RESET}
  {RED}│{RESET}  {WHITE}6{RESET}  API Anahtarlarini Ayarla                     {RED}│{RESET}
  {RED}│{RESET}  {WHITE}0{RESET}  Cikis                                        {RED}│{RESET}
  {RED}└──────────────────────────────────────────────────┘{RESET}""")
        api_status_line()
        ch = input(f"  {RED}➤{RESET} Seciminiz: ").strip()
        if   ch=="1":
            p=input(f"  {WHITE}Dosya yolu:{RESET} ").strip().strip("'\"")
            if os.path.isfile(p): scan_file(p)
            else: print(f"  {RED}✖ Dosya bulunamadi.{RESET}")
        elif ch=="2":
            ip=input(f"  {WHITE}IP / Hostname:{RESET} ").strip()
            if ip: scan_ip(ip)
            else:  print(f"  {RED}✖ Gecersiz.{RESET}")
        elif ch=="3":
            p=input(f"  {WHITE}Dizin yolu:{RESET} ").strip().strip("'\"")
            if os.path.isdir(p): scan_dir(p)
            else: print(f"  {RED}✖ Dizin bulunamadi.{RESET}")
        elif ch=="4":
            h=input(f"  {WHITE}Hash (MD5/SHA256):{RESET} ").strip()
            if h: scan_hash(h)
            else: print(f"  {RED}✖ Hash girilmedi.{RESET}")
        elif ch=="5":
            global _feodo_cache,_firehol_cache,_cinss_cache
            _feodo_cache=_firehol_cache=_cinss_cache=None; _cache_time.clear()
            print(f"\n  {CYAN}Feed onbellek temizlendi.{RESET}\n")
        elif ch=="6":
            api_key_setup()
        elif ch=="0":
            print(f"\n  {DIM}ZERGUZ CTI kapaniyor... Guvende kalin!{RESET}\n"); sys.exit(0)
        else:
            print(f"  {YELLOW}Gecersiz secim.{RESET}")

def main():
    ap = argparse.ArgumentParser(description="ZERGUZ CTI v4.2")
    ap.add_argument("-f","--file"); ap.add_argument("-i","--ip")
    ap.add_argument("-d","--dir");  ap.add_argument("-H","--hash")
    ap.add_argument("--shodan-key"); ap.add_argument("--abuseipdb-key")
    ap.add_argument("--threatfox-key"); ap.add_argument("--malwarebazaar-key")
    ap.add_argument("--no-banner",action="store_true")
    a = ap.parse_args()
    
    if a.shodan_key:        API_KEYS["shodan"]        = a.shodan_key
    if a.abuseipdb_key:     API_KEYS["abuseipdb"]     = a.abuseipdb_key
    if a.threatfox_key:     API_KEYS["threatfox"]     = a.threatfox_key
    if a.malwarebazaar_key: API_KEYS["malwarebazaar"] = a.malwarebazaar_key
    
    if not a.no_banner: banner()
    if a.hash:  scan_hash(a.hash);  sys.exit(0)
    if a.file:
        if os.path.isfile(a.file): scan_file(a.file)
        else: print(f"  {RED}✖ Dosya yok: {a.file}{RESET}")
        sys.exit(0)
    if a.ip:    scan_ip(a.ip);    sys.exit(0)
    if a.dir:
        if os.path.isdir(a.dir): scan_dir(a.dir)
        else: print(f"  {RED}✖ Dizin yok: {a.dir}{RESET}")
        sys.exit(0)
    menu()

if __name__ == "__main__":
    main()
