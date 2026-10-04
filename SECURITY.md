# Security Audit — схема аутентификации (nginx + oauth2-proxy + Keycloak + backend)

> Область аудита — **архитектурная схема и её идея**, а не конкретная реализация в
> `docker-compose.yml`. Здесь стенд; ниже рассуждаем так, будто та же схема
> разворачивается в production (на реальных хостах, без docker-compose).

---

## 1. Схема и границы доверия

```
                       ┌──────────────────────────────────────────────────────┐
                       │  Публичная сеть (HTTPS, untrusted)                   │
                       └───────────────┬──────────────────────────────────────┘
                                       │ TLS (mTLS-опционально)
                          ┌────────────▼──────────────┐
                          │   nginx (edge, TLS-term)  │  single entry point
                          └──┬──────────┬───────────┬─┘
                             │          │           │
              auth_request   │          │           │  /api/* + static
              (Forward Auth) │          │           │
                    ┌────────▼───┐  ┌───▼─────┐  ┌──▼─────────┐
                    │oauth2-proxy│  │ keycloak│  │  backend   │
                    │(session/   │  │ (IdP)   │  │(resource   │
                    │ OIDC flow) │  │         │  │ server)    │
                    └─────┬──────┘  └────▲────┘  └────┬───────┘
                          │ session      │ token  JWKS│ (public key)
                    ┌─────▼──────┐       │ exchange   │
                    │   redis    │       │ (internal) │
                    │(session    │       └────────────┘
                    │  store)    │
                    └────────────┘

        ──── = доверенная внутренняя сеть (в текущем стенде — plain HTTP)
```

Границы доверия (trust boundaries):

| # | Граница | Протокол в стенде | Что пересекает границу |
|---|---------|-------------------|------------------------|
| T1 | Browser ↔ nginx | HTTPS/TLS | куки, `authorization code` (в redirect), все запросы |
| T2 | nginx ↔ oauth2-proxy | внутренний HTTP | `auth_request`, кука сессии |
| T3 | nginx ↔ backend | внутренний HTTP | access token (Bearer), `X-Auth-Request-*` |
| T4 | oauth2-proxy ↔ keycloak | внутренний HTTP | code → token/refresh, JWKS (проверка id_token) |
| T5 | oauth2-proxy ↔ redis | внутренний HTTP | сессии |
| T6 | backend ↔ keycloak | внутренний HTTP | JWKS (публичные ключи) |

---

## 2. Что в схеме сделано правильно

1. **Единая точка входа (edge).** Наружу торчит только nginx; backend/oauth2-proxy/Keycloak/redis недоступны напрямую. Это правильная топология.
2. **Forward Auth.** Проверка аутентификации вынесена на edge (`auth_request`), backend остаётся **stateless** и не реализует редиректы/логин. Хорошее разделение ответственности и простое горизонтальное масштабирование.
3. **Проверка подписи, а не доверие заголовку.** Backend валидирует JWT публичным ключом (JWKS): `signature` + `iss` + `exp`. Он не «верит» тому, что ему передали в заголовке.
4. **Короткий access token.** access token живёт минуты; долгоживущее состояние — refresh-токен на стороне oauth2-proxy, а не в браузере.
5. **Куки сессии.** `Secure` + `HttpOnly` + `SameSite=Lax` — базовые флаги против кражи через XSS и CSRF на месте.
6. **Защита от open redirect.** `whitelist-domain` ограничивает, куда oauth2-proxy может вернуть пользователя после логина.
7. **Внутренний обмен code → token.** Token exchange идёт по внутренней сети (не через публичный домен Keycloak) — меньше поверхность атаки.
8. **RP-initiated logout.** Серверный logout (`backend-logout-url` с `id_token_hint`) действительно завершает SSO-сессию в Keycloak, а не только чистит куку.

---

## 3. Риски

Риски пронумерованы и далее связаны с рекомендациями в разделе 4.

### R1. Плоский внутренний трафик (HIGH)
Все внутренние границы (T2–T6) — plain HTTP без mTLS. Секрет: `authorization code`, `access_token`, `refresh_token`, `id_token`, сессии и сами **публичные ключи** ходят открытым текстом.
- Любая компрометация внутренней сети (или одного контейнера/хоста) позволяет пассивно читать токены и куки.
- Особенно опасно для **T6 (JWKS)** и **T5 (redis)**.

### R2. Backend не проверяет `aud` / назначение токена (HIGH)
Backend проверяет подпись, `iss` и `exp`, но **не `aud` и не `azp`**. Значит, любой валидный access token, выданный *любому* клиенту в этом realm, будет принят этим resource server.
- В проде обязательно валидировать **аудиторию** (или использовать token introspection): «этот токен выдан именно для меня».

### R3. Смешение типов токенов (MEDIUM)
Backend валидирует любой JWT с корректной подписью и `iss`. ID-token подписан тем же ключом, поэтому формально тоже «пройдёт», если его подсунуть как access token.
- Защита: проверять `typ: "Bearer"` / `azp` / `aud` (что это именно access token, а не id token).

### R4. JWKS по HTTP и без пининга (MEDIUM)
Backend (и oauth2-proxy) тянут JWKS по внутреннему HTTP. MITM на T6 может подменить ключи и подписывать произвольные токены.
- Защита: TLS для JWKS, **кэширование/пининг ключей**, контроль `kid`, fallback при недоступности IdP.

### R5. Доверие к заголовкам и достижимость backend (MEDIUM-HIGH)
Схема полагается на то, что `Authorization`/`X-Auth-Request-*` формирует **только nginx** (перезаписывая клиентские значения). Если backend случайно окажется достижим напрямую (минуя nginx), заголовки можно подделать/подставить, а проверку `auth_request` — обойти.
- Требуется: строгая сетевая изоляция + **стриппинг клиентских auth-заголовков** на edge (defense in depth).

### R6. Управление секретами (HIGH)
`cookie-secret` (шифрует сессию) и `client-secret` (OIDC-клиент) — статичные значения в конфиге.
- Компрометация `cookie-secret` = фабрика валидных сессий; `client-secret` = выдача токенов от имени клиента.
- Требуется: менеджер секретов (Vault/KMS), ротация, отсутствие секретов в git/логах.

### R7. Redis как единая точка хранения сессий (MEDIUM)
Все сессии oauth2-proxy живут в Redis. Компрометация Redis = компрометация всех активных сессий.
- Требуется: TLS + auth на Redis, изоляция (отдельная подсеть), резерв/отказоустойчивость.

### R8. Слабая аутентификация пользователей (MEDIUM)
`email-domain=*` допускает любой почтовый домен; парольная политика слабая; brute-force protection выключен.
- Требуется: ограничить домены организации, усилить политику паролей, включить brute-force detection, MFA/WebAuthn для чувствительных ролей.

### R9. Утечка токенов через логи/наблюдаемость (MEDIUM)
Access token и `X-Auth-Request-*` проходят через nginx и backend. Если их логировать в access/error-логи — токены утекут.
- Требуется: не логировать `Authorization`/куки; маскировать заголовки; короткое TTL токена.

### R10. Доступ к admin-консоли Keycloak (MEDIUM)
Admin-консоль (master realm) висит на том же hostname, что и логин пользователей.
- Требуется: отдельный hostname для admin, IP-allowlist, отдельные строгие учётки, MFA.

### R11. Поверхность OIDC-редиректов (LOW-MEDIUM)
Redirect/callback-эндпоинты (`/oauth2/start`, `/oauth2/callback`) — публичная поверхность. Защищают `whitelist-domain`, `state`/`nonce`, `SameSite`. Без них — open redirect и login-CSRF.
- Требуется: держать `whitelist-domain` минимальным, `state`/`nonce` включёнными, рассмотреть `SameSite=Strict` там, где не ломает flow.

---

## 4. Рекомендации (приоритезированы)

### P0 — критично для прода
1. **Внутренний TLS / mTLS (R1).** Поднять TLS (в идеале mTLS) на T2–T6: oauth2-proxy↔keycloak, backend↔keycloak (JWKS), oauth2-proxy↔redis. Как минимум — строгая сетевая сегментация (разные подсети/VPC для edge, app, IdP, data).
2. **Валидация `aud`/`azp` (R2, R3).** Выделить backend'у собственный audience (отдельный bearer-only клиент / audience mapper) и требовать его в токене; проверять `typ == "Bearer"`. Альтернатива — token introspection на oauth2-proxy/Keycloak.
3. **Секреты и ротация (R6).** `cookie-secret`, `client-secret` — в секрет-менеджере, с ротацией. Никаких секретов в git/логах.

### P1 — обязательно
4. **Изоляция и стриппинг заголовков (R5).** Backend/oauth2-proxy доступны только изнутри (и только через edge); на nginx явно удалять входящие `Authorization`, `X-Auth-Request-*`, `Cookie` от клиента перед проксированием.
5. **JWKS по TLS + кэш/пининг (R4).** Тянуть ключи по HTTPS, кэшировать (`Cache-Control`), доверять только по `kid`, логировать смену ключей; иметь fallback при недоступности IdP.
6. **Ограничить `email-domain` (R8).** Вместо `*` — домены организации.
7. **Brute-force / rate limiting (R8).** Включить brute-force detection в Keycloak; rate limiting и WAF на edge.
8. **Redis: TLS + auth + изоляция (R7).** Плюс мониторинг и отказоустойчивость (sentinel/cluster).

### P2 — желательно
9. **Не логировать токены (R9).** Маскировать `Authorization`, `Set-Cookie`, `X-Auth-Request-*` в access-логах nginx/backend.
10. **Отдельный admin-hostname для Keycloak (R10).** `admin.keycloak…` + IP-allowlist + MFA.
11. **Усилить парольную политику и MFA (R8).** Длиннее/сложнее пароли; WebAuthn/OTP для админов.
12. **SameSite=Strict (R11),** если редирект-флоу позволяет (для callback может понадобиться `Lax`).
13. **Короткие TTL и revocation (R3, R9).** access token — минуты; при необходимости — token revocation / blacklist по `jti`.

---

## 5. Итоговый чек-лист для прода

- [ ] Все внутренние вызовы — по TLS/mTLS или в строго изолированной сети.
- [ ] Backend валидирует `aud` + `azp` + `typ` (не только подпись/`iss`/`exp`).
- [ ] JWKS — по HTTPS, с кэшем и контролем `kid`.
- [ ] `cookie-secret`/`client-secret` — в секрет-менеджере, ротируются.
- [ ] `email-domain` ограничен организацией.
- [ ] Brute-force detection + rate limiting + WAF.
- [ ] Redis — TLS/auth/изоляция.
- [ ] Backend и oauth2-proxy недостижимы напрямую; edge стриппит auth-заголовки.
- [ ] Токены/куки не пишутся в логи.
- [ ] Admin-консоль Keycloak — на отдельном hostname с ограничением доступа.
- [ ] Парольная политика усилена, для админов — MFA.

---

## 6. Что НЕ меняет суть (замечания к текущей реализации)

- Конкретные значения TTL (5m/30m/10h), имена доменов `*.test`, учётки `demo/…` — это параметры стенда; в проде задаются политикой организации.
- `hostname:v2`/`proxy-headers`/`KC_BOOTSTRAP_ADMIN_*` — детали конкретной версии Keycloak (см. отдельные заметки), не меняют модель безопасности.
