---
name: MTProto Client Behavior Matrix
description: Version-pinned Telegram client connection behavior notes for proxy compatibility debugging.
---

# MTProto Client Behavior Matrix

Use this skill when behavior differs by platform (iOS/Android/Desktop) or when tuning handshake/relay expectations.

## Evidence Policy

- Do not publish behavior claims without evidence.
- Accept only reproducible local captures/logs, or direct client source links pinned to tag + commit.
- Mark each claim as `source-backed` or `field-capture`.

## Proxy Runtime Context

Current proxy runtime is a Linux single-thread `epoll` event loop with timer-driven stage control (`idle_timeout_sec`, `handshake_timeout_sec`). Interpret client behavior against that model, not legacy `poll` or thread-per-connection assumptions.

Current FakeTLS and MTProto handshake assumptions:

- ClientHello Session ID must be exactly 32 bytes; the proxy echoes it in the synthetic ServerHello. All ClientHello consumers share the same strict record/handshake/extension framing parser.
- The 64-byte MTProto obfuscation nonce may be split across TLS appdata records.
- Extra client appdata bytes after that 64-byte nonce may arrive in the same TLS record; the proxy buffers them and forwards them after upstream setup.

## iOS (Telegram iOS)

Version snapshot:

- Repo/tag: `TelegramMessenger/Telegram-iOS` `build-26855`
- Commit: `b16d9acdffa9b3f88db68e26b77a3713e87a92e3`

Source-backed behavior:

- TCP connect timeout: `12s`
- Response watchdog base: `MTMinTcpResponseTimeout = 12.0`
- Response timeout includes payload-dependent term and resets on partial reads
- Incoming message confirmations may be queued for a later transaction rather than producing an immediate client write, so a short server→client silence alone is not proof of a wedge
- Transport-level watchdog: `20s`
- Reconnect backoff: `1s`, then `4s`, then `8s`

References:

- https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L980
- https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L576
- https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L1339
- https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L1398
- https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpTransport.m#L312
- https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnectionBehaviour.m#L66

Field-capture behavior:

- Pre-warms multiple idle sockets.
- Can split the 64-byte obfuscation handshake across TLS records.
- May delay first payload after `ServerHello`.
- On affected iOS sessions, an unanswered fresh generic-DC exchange can repeat as a close/reconnect chain with upstream bytes delivered but no later client progress; the proxy cannot inspect the encrypted `bad_server_salt` message itself.

Proxy implications:

- Continue assembling MTProto handshake until full 64 bytes are collected.
- Preserve pipelined appdata after the 64-byte MTProto nonce; some clients can send early payload without waiting for a separate relay read.
- Do not treat short idle prewarmed sockets as protocol failure.
- Keep proxy-side wedge recovery limited to generic DC relays and treat it as an encrypted-stream heuristic. The relay cannot identify the client platform, so the enabled rule applies to the same timing pattern from any client. A request must reach upstream, a response must begin inside the source-backed 12-second window, and the response must drain to the client before silence timing starts. Any client progress cancels the candidate. Every recovery shares the internal per-real-IP/access-user/DC `T`/`2T`/`4T` budget; after those three waves, use normal idle timeout for 30 minutes from the most recent actual breaker close, without extending the cooldown for healthy matching traffic. Exclude media/DC203, masking, half-close, backpressure, and graceful shutdown. A continuation after an earlier delivered reply and at least 30 seconds in relay upgrades the candidate to `proven` for diagnostics, but never bypasses the group budget.

## Android (Telegram Android)

Version snapshot:

- Repo/ref: `DrKLO/Telegram` `master` (snapshot: `12.6.4 (6666)`)
- Commit: `009e97356f966bb81eceba113d210230bf383122`

Source-backed behavior:

- Enables `TCP_NODELAY`, switches socket to `O_NONBLOCK`, uses `connect(..., EINPROGRESS)` with edge-triggered epoll.
- Connect path chooses address family/static flags and sets per-type logical timeouts (`Proxy=5s`, `Generic=8/12s`, `Upload=25/40s`, `Push=20/30s`).
- Timeout model is logical/internal (`setTimeout` / `checkTimeout`).
- Explicit connection-type split (`Generic`, `Download`, `Upload`, `Push`, `Temp`, `Proxy`) and multiple parallel slots.

References:

- https://github.com/DrKLO/Telegram/blob/009e97356f966bb81eceba113d210230bf383122/TMessagesProj/jni/tgnet/ConnectionSocket.cpp#L618
- https://github.com/DrKLO/Telegram/blob/009e97356f966bb81eceba113d210230bf383122/TMessagesProj/jni/tgnet/Connection.cpp#L276
- https://github.com/DrKLO/Telegram/blob/009e97356f966bb81eceba113d210230bf383122/TMessagesProj/jni/tgnet/Connection.cpp#L368
- https://github.com/DrKLO/Telegram/blob/009e97356f966bb81eceba113d210230bf383122/TMessagesProj/jni/tgnet/ConnectionSocket.cpp#L1105
- https://github.com/DrKLO/Telegram/blob/009e97356f966bb81eceba113d210230bf383122/TMessagesProj/jni/tgnet/ConnectionSocket.cpp#L1115
- https://github.com/DrKLO/Telegram/blob/009e97356f966bb81eceba113d210230bf383122/TMessagesProj/jni/tgnet/Defines.h#L68
- https://github.com/DrKLO/Telegram/blob/009e97356f966bb81eceba113d210230bf383122/TMessagesProj/jni/tgnet/Defines.h#L26

Proxy implications:

- Expect parallel connection attempts and frequent connect churn.
- Keep accept/close path cheap and non-blocking.
- Subnet rate limiting groups IPv4-mapped IPv6 with native IPv4 `/24`; native IPv6 retains the complete `/48` prefix without a lossy 32-bit fold. Account for that when testing Android address-family races.

## Desktop (Telegram Desktop)

Version snapshot:

- Repo/tag: `telegramdesktop/tdesktop` `v6.7.2`
- Commit: `085c4ba65d1f8aa13abf0fd7fc8489f094552542`

Source-backed behavior:

- Builds multiple test connections and picks by priority.
- Wait-for-connected starts at `1000ms` and can grow after failures.
- TCP/HTTP transport full-connect timeout around `8s`.
- Resolver uses per-IP timeout `4000ms` and scales by resolved count.
- May wait `2000ms` for a better candidate after first success.

References:

- https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/session_private.cpp#L1010
- https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/session_private.cpp#L34
- https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/session_private.cpp#L1236
- https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/connection_tcp.cpp#L21
- https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/connection_http.cpp#L18
- https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/connection_resolving.cpp#L16
- https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/session_private.cpp#L33

Proxy implications:

- Candidate racing and early cancellation are expected patterns.
- Keep reconnect path cheap and avoid blocking work in event loop callbacks.
- Non-32-byte TLS Session IDs are not supported by the current FakeTLS template; investigate client-side TLS shape first if Desktop auth suddenly masks instead of authenticating.

## Practical Checklist

- If only one platform fails, compare that platform's timeout/race model first.
- Determine failure stage: pre-TLS, MTProto 64-byte assembly, or active relay.
- Confirm ClientHello Session ID length, SNI/tls_domain, and whether payload was pipelined after the nonce.
- Validate whether behavior is normal client racing vs proxy regression.
