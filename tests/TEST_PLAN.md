# Отчет test-engineer по расширению (29.09.2026)

Статус на 29.09.2026: дефекты D1-D13 исправлены, сценарии P0 1-21 реализованы (`tests/unit`, `tests/contract`, сценарий 21 в `tests/ui.spec.mjs`), live-тест переведен на проверки с кодом выхода и безопасные режимы записи (`tests/live/test_logic.mjs`). Открыты сценарии P1 22-38 и P2 39-42.

## Ревью существующих тестов

Прогоны: `npm run check` проходит (проверяет только app.js, cards.js, popup.js); `npx playwright test` 5 из 5 за 35 с; `tests/test_logic.mjs` не запускался (пишет в живой стенд), оценен по коду. Чистые функции проверены отдельно в node:vm с заглушками.

Итог: автоматической защиты от регрессий в логике нет. `test_logic.mjs` только логирует (нет assert, код выхода всегда 0). UI-тесты подменяют весь слой данных, logic.js в них не выполняется. Опасные сценарии (смена статусов, теги, Jira) не покрыты.

### CRITICAL
- `tests/test_logic.mjs:55-59`: `run()` глотает исключения, код выхода 0. Нужны `node:assert` и `process.exitCode = 1`.
- `tests/test_logic.mjs:128`: режим `v4` обращается к `a.groups`, которого в assetRisk v3 нет: TypeError, фикстуры v4 не пишутся.
- `tests/test_logic.mjs:8,13`: без `MP_HOST` скрипт идет на реальный стенд, TLS отключен для процесса. Требовать `MP_HOST` явно.
- `tests/test_logic.mjs:100-103`: режим `status` переводит экземпляр в «В работе» и «Новая» без учета исходного статуса: теряются `tillDate`, причина, комментарий. Читать исходное состояние и восстанавливать в `finally`.
- `tests/test_logic.mjs:147-153`: режим `tags` вешает тег на все узлы Windows 2022 и снимает по префиксу (заденет `auto:test-vr2`). Уникальное имя с runId, точное совпадение, один узел, флаг `MP_ALLOW_WRITE=1`.
- `tests/uitest/index.html`, `tests/ui.spec.mjs`: все `VR.*` подменены; кнопки `d-apply`, `a-tags`, `i-apply`, возврат из исключений, Jira, «В проект» не проверены; headless отклоняет `confirm()`. Нужны сценарии с `page.on('dialog')` и шпионами.
- Фикстуры: `tests/out/fixtures.json` и `tests/uitest/fixtures.json` копируются вручную и расходятся, оба в .gitignore: на чистом клоне UI-тесты не запустятся. Это результаты VR.*, а не сырые ответы PDQL.

### WARNING
- `npm run check` не проверяет logic.js, api.js, background.js, inject.js.
- UI проверяет количество KPI (12), но не значения.
- Снимки подменены на localStorage (5 МБ, синхронный); TTL 24 ч, битый снимок, снимок 2 МБ не проверены.
- Popup: fetch всегда успешен; черновик, 401/403, запасной путь через вкладку не покрыты.
- Карточки: нет проверки отсутствия дублей при повторных мутациях DOM; Jira и CSV из карточки не покрыты.
- `ui.spec.mjs:13-16`: `toBeEnabled()` сразу после клика может пройти до блокировки кнопки.

## Дефекты, найденные при разборе (каждый должен стать регрессионным тестом)

| # | Где | Что не так |
|---|---|---|
| D1 | logic.js targetVersionFromHowToFix | текущая 3.0.20, в тексте 3.0.15: вернет 3.0.15 (откат версии в задаче Jira) |
| D2 | там же | теряются суффиксы: `1.1.1k` дает 1.1.1, `2.34-0ubuntu3.1` дает 2.34 |
| D3 | там же | без текущей версии побеждают даты и IP («15.01.2024», «10.0.0.1») |
| D4 | logic.js buildJiraIssue, app.js plusDays | срок через setDate по местному времени и toISOString в UTC: в 00:30 по Москве «+1 день» дает сегодня |
| D5 | logic.js:501, app.js jiraLabelForGroup | для кириллических названий ПО метка Jira вырождается в `mpvm--`, «Найти существующие» показывает чужие задачи |
| D6 | logic.js projects({prefix}) | фильтр по Tags.Item до select без повторного filter после: в список попадают все теги тех же экземпляров |
| D7 | logic.js metrics, app.js drillFromMetrics | корзины возраста в KPI (`> now()-7d`) и в выборке по клику (`> now()-8d`) не совпадают |
| D8 | logic.js parseBdu | CSV: CVE на строке-продолжении теряется; XML: CVE из описания привязывается к записи; уровень по первому совпадению |
| D9 | logic.js groupCsv, app.js csv | нет защиты от формул в CSV (`=`, `+`, `-`, `@`), `\r` не экранируется; данные приходят из сканируемых узлов |
| D10 | logic.js changeStatus, app.js | при таймауте опроса частичный результат показывается как «готово: 10 из 100»; ошибка опроса превращается в null |
| D11 | logic.js assignAssetTags, applyAutoTags | в count входят неудачные PUT, `hasMatches=true` даже когда все упали; обрезка на 5000 без флага |
| D12 | logic.js:249 | сравнение только со строкой 'True': при boolean true трендовость теряется |
| D13 | logic.js exclusions, queueDetail | строки размножаются по CVE через CVEs.Item: `exclusions.total` и «закрывает N экземпляров» завышены |

Мелочи: `drillPdql('asset', arg)` без экранирования; `drillPdql('overdue')` без аргумента бросает TypeError; `trendTop` повторно использует псевдоним Score в group (на стенде работает, зафиксировать как разрешенное).

## План тестов

Структура без новых зависимостей (node:test + node:assert/strict):
```
tests/unit/_load.mjs           vm-контекст: api.js + logic.js, заглушки chrome.*, подмена Date/setTimeout
tests/unit/*.test.mjs
tests/unit/bg.test.mjs         background.js в vm: хранилище в памяти, заглушка fetch
tests/contract/pdql.test.mjs   статические инварианты PDQL
tests/contract/replay.test.mjs сырые ответы {records} из tests/contract/raw/*.json (обезличенные, в git)
tests/live/test_logic.mjs      бывший test_logic: assert, режимы чтения по умолчанию, запись по MP_ALLOW_WRITE=1
package.json: test:unit = node --test tests/unit tests/contract; check по всем *.js; test = check + unit + ui
```
Подмена: `VR.pdql/get/post/put/del/ext` переприсваиваются после загрузки; Date и setTimeout через глобальные объекты vm-контекста; confirm/prompt через page.on('dialog'). Режим `record` в live-тесте сохраняет `{pdql, response}` для контрактных тестов.

### Сценарии (P0 обязательны перед релизом)
| # | P | Уровень | Тест | Проверка |
|---|---|---|---|---|
| 1 | P0 | unit | targetVersion: не ниже текущей | 3.0.20 и «3.0.15» дает null или не ниже текущей (D1) |
| 2 | P0 | unit | targetVersion: выбор ветки | 3.0.2 и «3.0.15, 3.1.7, 3.2.3» дает 3.0.15; Windows 10.0.14393 дает 10.0.14393.4225; 24.07 дает 24.09 |
| 3 | P0 | unit | targetVersion: даты, IP, CVSS игнорируются | «15.01.2024», «10.0.0.1», «CVSS 9.8» рядом с 2.4.58 дают 2.4.58 (D3) |
| 4 | P0 | unit | targetVersion: суффиксы | 1.1.1k, deb 2.34-0ubuntu3.1, epoch (D2) |
| 5 | P0 | unit | buildJiraIssue: срок по местному времени | TZ Europe/Moscow 00:30, slaCritDays=1: dueDate завтра (D4) |
| 6 | P0 | unit | buildJiraIssue: матрица приоритетов | KEV, trend, 9, 7, 6.9, нет данных: P0, P0, P1, P2, P3; сроки из sla и по умолчанию |
| 7 | P0 | unit | buildJiraIssue: метки для кириллицы | «Яндекс Браузер» и «Касперский» дают разные непустые метки (D5) |
| 8 | P0 | unit | buildJiraIssue: truncated и нет целевой версии | «не менее N», «до актуальной версии вендора» |
| 9 | P0 | unit | changeStatus: таймаут опроса | результат отличим от завершенного, UI не пишет «готово» (D10) |
| 10 | P0 | unit | changeStatus: тело POST по командам | 4 команды x (tillDate, note, reason); пустые ids без POST |
| 11 | P0 | unit | changeStatus: формы operationId, ошибка опроса | {operationId}, {id}, строка, null; 500 при опросе видна |
| 12 | P0 | unit | assignAssetTags: дедупликация и счетчики | 2 уникальных узла, 1 PUT падает: puts=2, count без неудачных, failed=1 (D11) |
| 13 | P0 | unit | assignAssetTags: обрезка | выдача ровно limit дает truncated:true |
| 14 | P0 | unit | removeAutoTags: точный префикс | auto:x не задевает auto:x2 в тестовом режиме |
| 15 | P0 | contract | PDQL: повторный filter после select | все построители; должен упасть на projects(prefix) (D6) |
| 16 | P0 | contract | PDQL: then/else литералы, уникальные псевдонимы | trendTop как явное исключение |
| 17 | P0 | contract | PDQL: экранирование | названия с `"`, `\`, кириллицей, `%` не разрывают литерал |
| 18 | P0 | unit | computeMetrics: таблица | open = total - fixed - excluded; over исключает soon; bySev.open = over + soon + ok |
| 19 | P0 | unit | computeMetrics: пустые данные и типы | {}, не массив, T:true, Sev:"Critical" без throw (D12) |
| 20 | P0 | contract | корзины возраста KPI и выборки совпадают | «0-7» и «8-30» (D7) |
| 21 | P0 | ui | опасные действия: отмена и подтверждение | dismiss: 0 вызовов; accept: 1 вызов с d.ids и командой; кнопка заблокирована на время операции |
| 22 | P1 | unit | assetRisk: границы | risk в [0,1000], компоненты не выше потолков, зоны на 299/300/499/500/699/700, staleScan 29/31 день |
| 23 | P1 | unit | assetRisk: монотонность | +critical, +trend, H вместо M не уменьшают risk |
| 24 | P1 | unit | assetRiskKev: пересчет | kev, cT, risk, порядок, why |
| 25 | P1 | unit | parseBdu: таблица | XML с CVE в описании, CSV с кавычками и переносами, CRLF, строчные cve-, дубли (D8) |
| 26 | P1 | unit | CSV: инъекции | `=`, `+`, `-`, `@`, `;`, `"`, `\r\n`, BOM (D9) |
| 27 | P1 | unit | vulnGuid, num, rowVal | GUID из 3-й части, регистр, мусор; «4,1», «», «abc»; объект {displayName} |
| 28 | P1 | unit | queue: агрегация | группы по продукту, risk, сортировка, scope images, мусорный scope, minScore «7; x» |
| 29 | P1 | contract | replay сырых ответов | queue, queueDetail, exclusions, projects, metrics; экземпляр с 2 CVE дает total по уникальным id (D13) |
| 30 | P1 | unit | background verdict: таблица | KEV, trend, EPSS 0.5/0.49/0.1, SSVC active, score 9 |
| 31 | P1 | unit | background enrich: кэши и сбои | EPSS 101 CVE (2 батча), 500, KEV из кэша, NVD 429 |
| 32 | P1 | unit | background jira-create: повтор и ошибки | 400 с priority дает повтор без priority и duedate; 401 понятный текст |
| 33 | P1 | unit | cache-set/get 2 МБ, неизвестный op | полный возврат; {ok:false} |
| 34 | P1 | ui | снимки: TTL и восстановление | ts = now - 24ч +/- 1 мин, битый JSON |
| 35 | P1 | ui | popup: черновик, 401/403, запасной путь через вкладку | поля восстановлены, черновик удален после сохранения |
| 36 | P1 | ui | карточки: нет дублей | 5 мутаций DOM: ровно один блок на колонку |
| 37 | P1 | ui | XSS в данных | `<img onerror>` в host, soft, CVE, tag, summary: без выполнения |
| 38 | P1 | live | read с assert | форма результата каждого построителя; projects(prefix) без чужих тегов; KPI равно выборке |
| 39 | P2 | live | status с флагом записи | один экземпляр, 4 команды, восстановление |
| 40 | P2 | live | tags с флагом записи | один узел, уникальный тег, удаление в finally |
| 41 | P2 | ui | таблица на 1000 строк | время фильтра и сортировки, не больше 300 значений в списке |
| 42 | P2 | ui | экспорт CSV и PDF всех вкладок | BOM, заголовки, число строк |

## Минимальный порог перед релизом
1. Код выхода live-теста должен что-то значить: assert и исправление падения v4.
2. `node --test tests/unit tests/contract` проходит: сценарии 1-20, 22, 25, 26, 30-32; регрессионные тесты D1-D13 падают на текущем коде.
3. `npm run check` проверяет все *.js.
4. UI-сценарий 21 и существующие 5 на фикстурах, собираемых одной командой (record, затем копия).
5. Режимы записи только при MP_ALLOW_WRITE=1 и явном MP_HOST, только в тестовый экземпляр или узел с восстановлением в finally. Jira в автотестах только через заглушку fetch.

## Не покрыто тестами
Импорт БДУ, обновление KEV, теги зон риска, авто-теги, CSV всех вкладок, PDF, веса риска в настройках, Jira и CSV из карточки актива, «В проект» и закрытие проекта, возврат из исключений, выборка по клику с truncated.
