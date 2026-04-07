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

## iOS (Telegram iOS)

Version snapshot:

- Repo/tag: `TelegramMessenger/Telegram-iOS` `build-26855`
- Commit: `b16d9acdffa9b3f88db68e26b77a3713e87a92e3`

Source-backed behavior:

- TCP connect timeout: `12s`
- Response watchdog base: `MTMinTcpResponseTimeout = 12.0`
- Response timeout includes payload-dependent term and resets on partial reads
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

Proxy implications:

- Continue assembling MTProto handshake until full 64 bytes are collected.
- Do not treat short idle prewarmed sockets as protocol failure.

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

## Practical Checklist

- If only one platform fails, compare that platform's timeout/race model first.
- Determine failure stage: pre-TLS, MTProto 64-byte assembly, or active relay.
- Validate whether behavior is normal client racing vs proxy regression.
