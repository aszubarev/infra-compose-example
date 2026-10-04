# Auth Demo Stack

Тестовый стенд для демонстрации аутентификации через **Keycloak** с проксированием
через **oauth2-proxy**, проверкой сессионных кук, получением токенов и их пробросом
в **backend**, где токен «расшифровывается» и проверяется публичным ключом Keycloak.

Компоненты:

| Компонент | Роль | Порт (внутри сети) |
|-----------|------|--------------------|
| **nginx** | Единая точка входа, терминирует TLS, делает `auth_request` | 443 (наружу) |
| **oauth2-proxy** | Проверяет куки/сессии, выполняет OIDC-flow, хранит сессии в Redis | 4180 |
| **keycloak** | Identity Provider. Стартует с готовым realm и клиентами | 8080 (внутри) |
| **redis** | Хранилище сессий oauth2-proxy | 6379 (внутри) |
| **backend** | Resource server: декодирует и валидирует access-token | 8000 (внутри) |

---

## 1. Архитектура

```
                         Browser
                            │
              https://auth.example.test:443
              https://keycloak.auth.example.test:443
                            │
                      ┌─────▼─────┐
                      │   nginx    │  TLS-терминация, маршрутизация,
                      │ (entrypoint)│  auth_request (Forward Auth)
                      └─┬───┬───┬──┘
          /oauth2/*    │   │   │    /api/* + static
        ┌──────────────┘   │   └──────────────┐
        │                  │                  │
 ┌──────▼────────┐   ┌─────▼──────┐    ┌──────▼──────┐
 │ oauth2-proxy  │   │  keycloak  │    │   backend   │
 │   (4180)      │   │  (8080)    │    │   (8000)    │
 │  auth_request │   │ realm=demo │    │ валидация   │
 │  OIDC-flow    │   │  + clients │    │ JWT по JWKS │
 └──────┬────────┘   └────────────┘    └─────────────┘
        │
 ┌──────▼──────┐
 │    redis    │  сессии oauth2-proxy
 │   (6379)    │
 └─────────────┘
```

Ключевые решения:

- **nginx — единственная точка входа.** Наружу проброшен только порт `443`.
- **TLS через mkcert.** Один SAN-сертификат на оба домена.
- **Forward Auth (`auth_request`).** nginx не пускает трафик напрямую, а спрашивает
  oauth2-proxy (`/oauth2/auth`): `202` — пропустить, `401` — редирект на логин.
- **Токен пробрасывается в backend.** oauth2-proxy кладёт `X-Auth-Request-Access-Token`
  (raw access_token) в ответ `auth_request`; nginx забирает его (`auth_request_set`),
  добавляет префикс `Bearer ` и передаёт в backend как `Authorization`.
- **Обмен кода на токен — по внутренней сети.** oauth2-proxy выкупает authorization code
  по `http://keycloak:8080/.../token` (Docker DNS), а не по внешнему домену.
- **Keycloak импортирует готовый realm** (`--import-realm`) с клиентами и тестовым пользователем.

---

## 2. Как работает стенд (flow аутентификации)

```
 Browser                nginx                oauth2-proxy            keycloak             backend/redis
    │                     │                       │                      │                    │
    │ GET / (или /api)    │                       │                      │                    │
    ├────────────────────►│  auth_request         │                      │                    │
    │                     ├──────────────────────►│ (нет/просрочена кука)│                    │
    │                     │◄────── 401 ───────────┤                      │                    │
    │◄── 302 /oauth2/start?rd=... ────────────────────────────────────────────────────────────┤
    │                     │                       │                      │                    │
    │ GET /oauth2/start   │                       │                      │                    │
    ├────────────────────►├──────────────────────►│                      │                    │
    │                     │                       │ 302 → login-url     │                    │
    │◄── 302 https://keycloak.auth.example.test/.../auth?client_id=demo-client&redirect_uri=...─┤
    │                     │                       │                      │                    │
    │ GET keycloak /auth  │                       │                      │                    │
    ├────────────────────►├───────────────────────┼─────────────────────►│  (форма логина)    │
    │   ввод demo / demo12345                                                                 │
    │◄── 302 redirect_uri=https://auth.example.test/oauth2/callback?code=...&state=...─────────┤
    │                     │                       │                      │                    │
    │ GET /oauth2/callback│                       │                      │                    │
    ├────────────────────►├──────────────────────►│                      │                    │
    │                     │                       │ POST redeem-url      │                    │
    │                     │                       ├─────────────────────►│  code → access/    │
    │                     │                       │◄── access_token, id_token, refresh_token ──┤
    │                     │                       │ (сессия в redis)     │                    │
    │                     │                       │ set-cookie           │                    │
    │◄── 302 rd (исходный URL) ────────────────────────────────────────────────────────────────┤
    │                     │                       │                      │                    │
    │ GET /api/... (с кукой)                      │                      │                    │
    ├────────────────────►│  auth_request         │                      │                    │
    │                     ├──────────────────────►│ (кука валидна)       │                    │
    │                     │◄── 202 + X-Auth-Request-Access-Token: <access_token>│             │
    │                     ├───────────────────────────────────────────────────────────────► backend
    │                     │                       │          backend валидирует JWT по JWKS  │
    │◄── 200 JSON ────────┤                       │                      │                    │
```

По шагам:

1. Браузер открывает `https://auth.example.test/`. nginx делает субрайз к
   `oauth2-proxy /oauth2/auth`. Куки нет → `401`.
2. nginx (`error_page 401 = @error401`) отдаёт `302` на `/oauth2/start?rd=…`.
3. oauth2-proxy (`/oauth2/start`) редиректит браузер на внешний Keycloak
   `login-url` с `client_id`, `redirect_uri`, `scope`, `state`, `nonce`.
4. Пользователь вводит `demo` / `demo12345`. Keycloak редиректит на
   `redirect_uri` (`https://auth.example.test/oauth2/callback?code=…&state=…`).
5. oauth2-proxy выкупает `code` по **внутреннему** `redeem-url`
   (`http://keycloak:8080/realms/demo/protocol/openid-connect/token`) и получает
   `access_token` + `id_token` + `refresh_token`. Сессия кладётся в **Redis**,
   в браузер ставится кука `_oauth2_proxy`.
6. oauth2-proxy редиректит на исходный `rd`.
7. Дальше каждый запрос: nginx → `auth_request` → oauth2-proxy отвечает `202`,
   добавляя в ответ `X-Auth-Request-Access-Token` (raw access_token). nginx
   забирает его и передаёт в backend как `Authorization: Bearer <access_token>`.
8. Backend извлекает `Bearer`-токен, декодирует его и проверяет RS256-подпись
   публичным ключом Keycloak из JWKS (`http://keycloak:8080/.../certs`), а также
   `iss` и `exp`.

---

## 3. Структура файлов

```
.
├── docker-compose.yml           # оркестрация всех сервисов
├── .env                         # секреты/пароли (демо-значения)
├── .env.example
├── scripts/
│   └── init-certs.sh            # генерация TLS-сертификатов через mkcert
├── nginx/
│   ├── nginx.conf               # базовый конфиг nginx
│   ├── conf.d/default.conf      # server-блоки: app + keycloak, auth_request
│   └── html/index.html          # демо-страница (визуализация)
├── keycloak/
│   └── realm-export.json        # realm "demo", клиенты, тестовый пользователь
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py                   # FastAPI: /api/token, /api/verify, /api/whoami, /api/keys
└── certs/                       # (генерируется) fullchain.pem + privkey.pem
```

---

## 4. Требования

- **Docker** + **Docker Compose** (v2).
- **mkcert** — для локальных TLS-сертификатов:
  ```bash
  brew install mkcert
  ```

---

## 5. Быстрый старт (2–3 команды)

### Шаг 0. Пропишите домены в `/etc/hosts` (один раз)

```bash
echo "127.0.0.1 auth.example.test" | sudo tee -a /etc/hosts
echo "127.0.0.1 keycloak.auth.example.test" | sudo tee -a /etc/hosts
```

### Шаг 1. Сгенерируйте сертификаты

```bash
./scripts/init-certs.sh
```

### Шаг 2. Запустите стенд

```bash
docker compose up -d --build
```

Откройте в браузере: **https://auth.example.test**

Проверить статус:

```bash
docker compose ps
docker compose logs -f oauth2-proxy keycloak
```

### Остановка / очистка

```bash
docker compose down            # остановить
docker compose down -v         # + удалить тома (сессии redis, БД keycloak)
```

---

## 6. Учётные данные

| Что | Значение |
|-----|----------|
| Тестовый пользователь | `demo` |
| Пароль пользователя | `demo12345` |
| Keycloak admin console | https://keycloak.auth.example.test/admin |
| Keycloak admin user | `admin` |
| Keycloak admin password | `admin` (см. `.env`) |
| Realm | `demo` |
| Клиент oauth2-proxy | `demo-client` (confidential) |
| Логический клиент-аудитория backend | `backend` (bearer-only) |

---

## 7. Как проверить стенд

После логина на странице доступны кнопки, вызывающие ручки backend (все идут через
nginx и потому требуют аутентификации):

- **`GET /api/whoami`** — кто я: данные из токена + заголовки `X-Auth-Request-*`,
  которые пробросил oauth2-proxy.
- **`GET /api/token`** — сырой `access_token` и его «расшифровка»
  (base64-decode header/payload без проверки подписи).
- **`GET /api/verify`** — валидация подписи публичным ключом Keycloak (JWKS),
  проверка `iss` и `exp`; показывает, каким `kid` подписан токен.
- **`GET /api/keys`** — список публичных ключей (JWKS), которыми подписаны токены.

Проверка «в лоб» (в браузере, после логина):

```
https://auth.example.test/api/token
https://auth.example.test/api/verify
https://auth.example.test/api/whoami
https://auth.example.test/api/keys
```

Проверка, что аутентификация действительно требуется (открыть в инкогнито или после
logout): запрос к `https://auth.example.test/` и `https://auth.example.test/api/token`
должен перенаправить на логин Keycloak.

---

## 8. Согласование параметров (сессии / куки / токены)

Значения подобраны так, чтобы oauth2-proxy и Keycloak работали согласованно:

| Параметр | Где | Значение | Комментарий |
|----------|-----|----------|-------------|
| Access Token Lifespan | Keycloak realm `accessTokenLifespan` | `300` (5 мин) | время жизни access-token |
| `--cookie-refresh` | oauth2-proxy | `3m` | кука обновляется (refresh_token) **раньше**, чем истечёт access-token |
| `--cookie-expire` | oauth2-proxy | `30m` | время жизни сессии oauth2-proxy |
| SSO Session Idle | Keycloak `ssoSessionIdleTimeout` | `1800` (30 мин) | == `cookie-expire` |
| Client Session Idle | Keycloak `clientSessionIdleTimeout` | `1800` (30 мин) | |
| SSO Session Max | Keycloak `ssoSessionMaxLifespan` | `36000` (10 ч) | жёсткий потолок SSO |
| Client Session Max | Keycloak `clientSessionMaxLifespan` | `0` | наследуется от SSO Max |
| Access Code Lifespan | Keycloak `accessCodeLifespan` | `60` | время жизни authorization code |
| `--cookie-secure` | oauth2-proxy | `true` | кука только по HTTPS |
| `--cookie-samesite` | oauth2-proxy | `lax` | защита от CSRF |
| `--session-store-type` | oauth2-proxy | `redis` | сессии переживают рестарт oauth2-proxy |
| `--redis-lock-timeout` | oauth2-proxy | `5s` | таймаут блокировки в Redis |

Связка главных таймаутов:

```
access token (5m)
      └── cookie-refresh (3m)  ← oauth2-proxy успевает обновить токен до его истечения

ssoSessionIdleTimeout (30m) == cookie-expire (30m)
ssoSessionMaxLifespan (10h)   ← абсолютный максимум, после него вход заново
```

> Публичные ключи для валидации backend берёт по внутреннему адресу
> `http://keycloak:8080/realms/demo/protocol/openid-connect/certs` (JWKS), так что
> проверка подписи тоже выполняется по межсервисному взаимодействию, без внешнего домена.

---

## 9. Конфигурация oauth2-proxy — пояснения

Ключевые флаги в `docker-compose.yml`:

| Флаг | Зачем |
|------|-------|
| `--upstream=static://202` | режим `auth_request`: отвечать `202`, а не проксировать upstream |
| `--set-xauthrequest=true` | класть `X-Auth-Request-User` / `X-Auth-Request-Email` в ответ `202` |
| `--pass-access-token=true` | вместе с `--set-xauthrequest` кладёт `X-Auth-Request-Access-Token` (raw access_token) в ответ `202`; nginx формирует из него `Authorization: Bearer …` |
| `--skip-oidc-discovery=true` | не ходить за `.well-known/openid-configuration`; все endpoint'ы заданы явно |
| `--oidc-issuer-url=...` | ожидаемое значение `iss` (совпадает с `KC_HOSTNAME`) |
| `--login-url=...` | **внешний** URL логина (куда редиректится браузер) |
| `--redeem-url=http://keycloak:8080/.../token` | **внутренний** URL обмена code → token |
| `--oidc-jwks-url=http://keycloak:8080/.../certs` | **внутренний** URL ключей для проверки подписи id_token |
| `--profile-url`, `--validate-url` | **внутренние** URL userinfo для ре-валидации сессии |
| `--redirect-url=https://auth.example.test/oauth2/callback` | OAuth callback (совпадает с `redirectUris` клиента) |
| `--backend-logout-url=http://keycloak:8080/.../logout?id_token_hint={id_token}` | серверный SSO-logout: oauth2-proxy сам завершает сессию Keycloak при `/oauth2/sign_out` |

> Важно: `--client-secret` в oauth2-proxy и поле `secret` у клиента `demo-client` в
> `keycloak/realm-export.json` должны совпадать. В демо используется
> `demo-client-secret-7b009d9f240afd30` (поменяйте в обоих местах, если нужно).

> ⚠️ Про `--redis-lock-timeout`: такого флага в oauth2-proxy **нет** (проверено в
> `v7.7.0` и `v7.8.1`). Ближайшие по смыслу параметры Redis-хранилища, которые
> используются в стенде: `--redis-connection-url`, `--redis-use-sentinel`,
> `--redis-connection-idle-timeout`. Отдельного таймаута блокировки сессии
> oauth2-proxy не предоставляет — блокировка при обновлении refresh-токена
> управляется внутри.

---

## 10. Устранение неполадок

**`docker compose up` падает из-за отсутствующих сертификатов**
nginx монтирует `./certs`. Сначала выполните `./scripts/init-certs.sh`.

**Страница не открывается / сертификат недоверенный**
Убедитесь, что выполнен `mkcert -install` (скрипт делает это автоматически), и что
`/etc/hosts` содержит оба домена. Проверьте: `curl -v https://auth.example.test`.

**Редирект на `http://` вместо `https://`**
Стенд использует только HTTPS. Проверьте, что в `/etc/hosts` оба домена указывают на
`127.0.0.1`, а не `::1` (IPv6). При необходимости добавьте только IPv4.

**Keycloak долго стартует**
Первый запуск импортирует realm. Смотрите `docker compose logs -f keycloak`; когда
появится `Running the server`, Keycloak готов. Healthcheck проверяет порт `8080`
(порт открывается только после импорта realm).

**Порт 443 занят**
Измените в `docker-compose.yml` маппинг на, например, `"8443:443"` и открывайте
`https://auth.example.test:8443` (и обновите `redirectUris`/`webOrigins` в realm и
`--redirect-url` oauth2-proxy).

**Хочется сменить секреты/пароли**
Отредактируйте `.env` (admin, cookie-secret). Для клиентского секрета поменяйте значение
в двух местах: `keycloak/realm-export.json` → `clients[].secret` и `docker-compose.yml` →
`--client-secret`.

---

## 11. Полезные ссылки (после запуска)

- Приложение: https://auth.example.test
- Keycloak admin console: https://keycloak.auth.example.test/admin
- Discovery Keycloak: https://keycloak.auth.example.test/realms/demo/.well-known/openid-configuration
- JWKS Keycloak: https://keycloak.auth.example.test/realms/demo/protocol/openid-connect/certs
