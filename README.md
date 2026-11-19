# jenkins-rce-check

Быстрый асинхронный чекер анонимной script-консоли Jenkins и подтверждения RCE через Groovy.

![Rust](https://img.shields.io/badge/Rust-1.8x%2B-orange) ![License](https://img.shields.io/badge/license-MIT-green) ![CI](https://github.com/Lolicks/jenkins-rce-check/actions/workflows/build.yml/badge.svg)

> ⚠️ Используйте только в рамках письменного разрешения и согласованного скоупа.

## Что делает

1. Нормализует цель (`host`, `http(s)://host:port`) и отправляет **одной волной** 9 запросов: `/`, 8 разведывательных эндпоинтов и `/crumbIssuer/api/json`.
2. Определяет Jenkins по заголовку `X-Jenkins`/`X-Hudson` или по телу страницы.
3. Ищет анонимную script-консоль (`name="script"` на `/script` или `/scriptText`).
4. Получает crumb + cookie и вторым запросом выполняет Groovy-пруф с уникальным **nonce**.
5. Выставляет вердикт и записывает **только подтверждённые** цели в `found.txt`.

### Валидация proof

`rce_confirmed` выставляется только если **все** условия выполнены:

- статус POST — **2xx** (403 больше не считается успехом);
- в ответе нет `Error 403`, `No valid crumb`, `Forbidden`, `Exception`, `Access denied`;
- вывод взят из `<pre>` (для `/script`) и содержит наш `RCEPROOF_<nonce>:`-маркер;
- для `id` дополнительно требуется `uid=` в выводе.

Благодаря nonce proof можно перепроверить другой командой с тем же маркером:

```powershell
jenkins-rce-check.exe target:8080 -c id --nonce abc123
jenkins-rce-check.exe target:8080 -c whoami --nonce abc123
```

### Вердикты

| Вердикт | Значение |
|---|---|
| `rce_confirmed` | Анонимная консоль есть, валидный proof с совпавшим nonce получен |
| `csrf_blocked` | crumb/сессия не проходят (403 / «No valid crumb») после повторов с той же сессией |
| `script_console_anonymous_proof_failed` | Консоль есть, но proof не получен/не прошёл валидацию |
| `no_anonymous_script_console` | Консоль недоступна анонимно |
| `not_jenkins` | Это не Jenkins |

## Запуск

Без аргументов открывается меню:

```
1) Проверить одну цель
2) Проверить список из targets.txt
3) Справка
0) Выход
```

`targets.txt` — по одной цели на строку, `#` — комментарий. Файл ищется в текущей папке, затем рядом с бинарником. Поддерживаются кодировки UTF-8 (с BOM), UTF-16 и Windows-1251.

### Опции

```
-l, --list <file>       список целей (по одной на строку, '#' — комментарий)
-o, --output <file>     записать все результаты в JSONL (удобно для jq)
-c, --command <name>    proof-команда: id, whoami, hostname, pwd, uname, date (по умолчанию id)
--nonce <str>           свой маркер proof (иначе генерируется автоматически)
--output-dir <dir>      куда писать found.txt (по умолчанию — текущая папка)
-p, --parallel <n>      параллельные цели (по умолчанию 8)
-rl, --rate-limit <n>   общий лимит HTTP-запросов в секунду (по умолчанию без лимита)
--no-color              не выводить ANSI и OSC-гиперссылки
-h, --help              справка
```

Примеры:

```powershell
# Одна цель, аккуратно: 4 потока, 10 запросов/сек, JSONL в файл
jenkins-rce-check.exe jenkins.example.com:8080 -p 4 -rl 10 -o results.jsonl

# Список командой из файла, свой output-dir
jenkins-rce-check.exe -l targets.txt -o results.jsonl --output-dir C:\reports

# Перепроверка другой командой с тем же nonce
jenkins-rce-check.exe jenkins.example.com:8080 -c whoami --nonce abc123

# Чистый вывод для парсинга (цвет выключен и через NO_COLOR=1, CLICOLOR=0, TERM=dumb)
$env:NO_COLOR=1; jenkins-rce-check.exe -l targets.txt -o results.jsonl | Tee-Object run.log
```

### jq

```powershell
jq -r 'select(.verdict=="rce_confirmed") | [.url,.command,.nonce,.proof] | @tsv' results.jsonl
```

## Отчёт

`found.txt` создаётся в `--output-dir` (по умолчанию — в текущей папке). Туда попадают только цели с валидным proof (`rce_confirmed`), по одной строке, без дублей между запусками:

```
http://jenkins.example.com:8080
```

`results.jsonl` (при `-o`) содержит по одной JSON-строке на цель в порядке завершения: `url`, `version`, `verdict`, `proof`, `command`, `nonce`, `endpoints`. Строки не содержат ANSI-кодов и гиперссылок.

## Сборка

Локально (Windows, нужен MinGW в `PATH` для `dlltool`; путь сборки должен быть без кириллицы, иначе GNU `ld` не может записать выходной файл):

```powershell
cargo build --release
```

CI при каждом пуше собирает Windows `.exe` и статический Linux `x86_64-unknown-linux-musl`, а по тегу `v*` публикует оба бинарника в релиз.

## Тесты

```powershell
cargo test --release
```

Покрывают отклонение 403/no-crumb страниц, маркеров ошибок, проверку `<pre>`, nonce и слияние cookie сессии.

## Оптимизации

- Один `reqwest::Client` с пулом соединений вместо нового `opener` на каждый запрос.
- Async/await (`tokio`): цели через `buffer_unordered`, разведка через `join!`.
- Crumb загружается в первой же волне → всего **две сетевые фазы** на цель (при CSRF-повторе — больше).
- 6 эндпоинтов опрашиваются только по статусу, без скачивания тела.
- Общий `-rl` — token-bucket на все цели, `-p` ограничивает параллелизм.
- Ручные парсеры вместо `regex`, лог буферизуется и пишется одним `write`.
- Релиз: `lto`, `codegen-units=1`, `panic=abort`, `strip`.

## Лицензия

MIT.
