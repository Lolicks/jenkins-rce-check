# jenkins-rce-check

Быстрый асинхронный чекер анонимной script-консоли Jenkins и подтверждения RCE через Groovy.
Порт оригинального `jenkins_rce_check.py` на Rust.

![Rust](https://img.shields.io/badge/Rust-1.8x%2B-orange) ![License](https://img.shields.io/badge/license-MIT-green) ![CI](https://github.com/OWNER/jenkins-rce-check/actions/workflows/build.yml/badge.svg)

> ⚠️ Используйте только в рамках письменного разрешения и согласованного скоупа.

## Что делает

1. Нормализует цель (`host`, `http(s)://host:port`) и отправляет **одной волной** 9 запросов: `/`, 8 разведывательных эндпоинтов и `/crumbIssuer/api/json`.
2. Определяет Jenkins по заголовку `X-Jenkins`/`X-Hudson` или по телу страницы.
3. Ищет анонимную script-консоль (`name="script"` на `/script` или `/scriptText`).
4. Получает crumb + cookie и вторым запросом выполняет Groovy-пруф `["id"].execute().text`.
5. Выставляет вердикт и записывает **только подтверждённые** цели в `found.txt`.

### Вердикты

| Вердикт | Значение |
|---|---|
| `rce_confirmed` | Анонимная консоль есть, вывод команды получен |
| `script_console_anonymous_proof_failed` | Консоль есть, но proof не получен |
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

Можно и напрямую:

```powershell
jenkins-rce-check.exe jenkins.example.com:8080
jenkins-rce-check.exe help
```

Опций больше нет — всё захардкожено разумными значениями: proof `id`, connect-timeout 1.5 с, total 5 с, 32 параллельные цели.

## Отчёт

`found.txt` создаётся рядом с бинарником. Туда попадают только `rce_confirmed`, по одной строке, без дублей между запусками:

```
http://jenkins.example.com:8080
```

## Сборка

Локально (Windows, нужен MinGW в `PATH` для `dlltool`):

```powershell
cargo build --release
```

CI при каждом пуше собирает Windows `.exe` и статический Linux `x86_64-unknown-linux-musl`, а по тегу `v*` публикует оба бинарника в релиз.

## Оптимизации

- Один `reqwest::Client` с пулом соединений вместо нового `opener` на каждый запрос.
- Async/await (`tokio`): цели через `buffer_unordered`, разведка через `join!`.
- Crumb загружается в первой же волне → всего **две сетевые фазы** на цель.
- 6 эндпоинтов опрашиваются только по статусу, без скачивания тела.
- Ручные парсеры вместо `regex`, лог буферизуется и пишется одним `write`.
- Релиз: `lto`, `codegen-units=1`, `panic=abort`, `strip`.

## Лицензия

MIT.
