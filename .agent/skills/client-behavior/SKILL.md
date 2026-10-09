---
name: MTProto Client Behavior Matrix
description: Version-pinned Telegram client connection behavior notes for proxy compatibility debugging.
---

# MTProto Client Behavior Matrix

Use this skill when behavior differs by platform (iOS/Android/Desktop/macOS) or when tuning handshake/relay expectations.

## Evidence Policy

- Do not publish behavior claims without evidence.
- Accept only reproducible local captures/logs, or direct client source links pinned to tag + commit.
- Mark each claim as `source-backed` or `field-capture`.

## Proxy Runtime Context

Current proxy runtime defaults to one Linux `epoll` event loop; optional MTProto workers each own a connection from accept through close, with the same timer-driven stage control (`idle_timeout_sec`, `handshake_timeout_sec`). Interpret client behavior against that model, not legacy `poll` or thread-per-connection assumptions.

Current FakeTLS and MTProto handshake assumptions:

- ClientHello Session ID must be exactly 32 bytes; the proxy echoes it in the synthetic ServerHello. Authentication retains its strict parser's cipher and selected key share: PQ `0x11ec` (1216 client bytes) has priority over X25519 `0x001d` (32 bytes), and no supported share goes to masking. This is the proxy's acceptance contract, not a new platform behavior claim. WEB SNI routing keeps its independent bounds-checked walker for unrelated extensions.
- The 64-byte MTProto obfuscation nonce may be split across TLS appdata records.
- Reserved-prefix filtering applies to direct-obfuscated streams, including WEB backends. FakeTLS uses `fromAuthenticatedFakeTls` only after HMAC/replay validation, permitting arbitrary random prefixes while retaining authenticated-user key/tag and DC checks.
- Extra client appdata bytes after that 64-byte nonce may arrive in the same TLS record; the proxy buffers them and forwards them after upstream setup.

## iOS (Telegram iOS)

Version snapshot:

- Repo/tag: `TelegramMessenger/Telegram-iOS` `release-13.0.0`
- Commit: `f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838`
- Embedded Rust engine: `macosswift/mtproto-engine` `0de759a36cbb50c1e98560c1ffa38590d317b0fc`, C ABI 3. Check this iOS submodule pin when reading other engine revisions; the C ABI is not the proxy wire protocol.

Source-backed MtProtoKit behavior:

- TCP connect timeout: `12s`
- Response watchdog base: `MTMinTcpResponseTimeout = 12.0`
- Response timeout includes payload-dependent term and resets on partial reads
- Incoming message confirmations may be queued for a later transaction rather than producing an immediate client write, so a short server→client silence alone is not proof of a wedge
- Transport-level watchdog: `20s`
- Reconnect backoff: first retry is immediate, followed by `1s`, `4s`, then `8s` tiers

References:

- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTTcpConnection.m#L1127
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTTcpConnection.m#L677
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTTcpConnection.m#L1416
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTTcpConnection.m#L1475
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTProto.m#L1037
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTTcpTransport.m#L312
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTTcpConnectionBehaviour.m#L66

Source-backed WEB behavior shared by MtProtoKit and Rust:

- Both engines use the same Swift carrier and relay framing; Rust supplies an already obfuscated raw MTProto stream with explicit consumption/backpressure callbacks.
- Relay headers are 8 bytes, individual payloads are capped at 1 MiB, DATA is emitted in 64 KiB chunks, and native batches may reach 2 MiB including headers and 4096 frames. Both sides start with 4 MiB of credit per logical stream. Keep the message cap separate from the per-frame cap.
- One carrier serves all accounts in an application process. Carrier reconnect uses exponential delay from 1 to 30 seconds plus jitter, independently of the legacy TCP backoff above.
- Root/path capability HMAC contexts and marked base-path secrets match Desktop. The native bridge still uses the historical `android` fragment name; do not rename it for iOS.

Source-backed optional Rust behavior:

- In the pinned engine, online/previously busy read-disconnect delay is `3.5 * max(1.5 * RTT + 1, 2)` seconds; the online main-session ping-disconnect delay uses multiplier `2.5`. Offline/non-busy read-disconnect and other ping-disconnect paths use `135s + jitter`. These are not MtProtoKit's fixed response-watchdog base.
- `RustCarrierStreams` still uses a 12-second raw-stream open timeout. Distinguish opening the WEB stream from an established MTProto response watchdog.
- FakeTLS nonce generation permits arbitrary random prefixes. Direct-obfuscated generation excludes `0xef`, seven reserved first words and zero bytes 4..8; `PUT ` is not excluded.
- On iOS, the Debug Settings engine choice applies at the next launch; live engine switching is macOS-only. Preserve MtProtoKit as a separate profile rather than assigning Rust's timers to it.

References:

- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/WebProxyTransport/Sources/WebProxyFrame.swift#L3
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/WebProxyTransport/Sources/WebProxyWebViewCarrier.swift#L139
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/WebProxyTransport/Sources/WebProxyDemandSet.swift#L3
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/WebProxyTransport/Sources/WebProxyTransport.swift#L331
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/WebProxyTransport/Sources/WebProxyConfiguration.swift#L198
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MTProtoRustEngine/Sources/MTProtoRustEngine/RustCarrierStreams.swift#L15
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MTProtoRustEngine/Sources/MTProtoRustEngine/RustEngineRuntime.swift#L161
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/TelegramCore/Sources/Network/Network.swift#L658
- https://github.com/macosswift/mtproto-engine/blob/0de759a36cbb50c1e98560c1ffa38590d317b0fc/crates/mtproto-core/src/session/mod.rs#L1267
- https://github.com/macosswift/mtproto-engine/blob/0de759a36cbb50c1e98560c1ffa38590d317b0fc/crates/mtproto-core/src/transport/obfuscation.rs#L23

Field-capture behavior (historical MtProtoKit sessions, not Rust captures):

The earlier source snapshot was `build-26855`, commit `b16d9acdffa9b3f88db68e26b77a3713e87a92e3`; retain these observations as historical context rather than evidence of Rust behavior.

- Pre-warms multiple idle sockets.
- Can split the 64-byte obfuscation handshake across TLS records.
- May delay first payload after `ServerHello`.
- On affected iOS sessions, an unanswered fresh generic-DC exchange can repeat as a close/reconnect chain with upstream bytes delivered but no later client progress; the proxy cannot inspect the encrypted `bad_server_salt` message itself.

Proxy implications:

- Continue assembling MTProto handshake until full 64 bytes are collected.
- Preserve pipelined appdata after the 64-byte MTProto nonce; some clients can send early payload without waiting for a separate relay read.
- Do not treat short idle prewarmed sockets as protocol failure.
- The existing 12-second recovery eligibility window derives from MtProtoKit and remains an engine-agnostic proxy heuristic. Do not describe it as Rust's watchdog or infer the client engine from timing; the relay carries opaque encrypted bytes.
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

## Native WEB Bridge Batching

Source-backed bridge snapshots, separate from the historical TCP profiles above:

- Android `12.10.6 (7112)`, commit `f2908b14133bbffbf7ab04f641ecb5bfaf533242`:
  the WebView posts a binary ArrayBuffer to one carrier executor, and `processFrames`
  loops over every complete frame in it. Individual payloads are limited to 1 MiB.
- Desktop `v7.3.0`, commit `42f8a36d43b8c805bc821905bea4cfeb3af1d41d`:
  the shared native script encodes binary messages as base64 with a one-byte prefix.
  `kMaxMessageBytes = 2 MiB` limits that encoded string on Windows and macOS, not
  decoded bytes. After a lone WELCOME, the transport parses all frames in each message.
  Its pinned macOS `lib_webview` backend forwards the same script strings through
  `WKScriptMessageHandler`.
- The iOS `release-13.0.0` Swift carrier pinned above also has a macOS WebKit path.
  It accepts up to 2 MiB of decoded binary data; its frame decoder loops over the
  complete frames, with at most 4096 decoded frames per append. This is evidence for
  that shared implementation, not a version claim for every separate macOS app.

Proxy implications:

- Keep native downlink groups at complete frame boundaries with a 64 KiB target.
  A single larger frame may retain its original 1 MiB payload plus 8-byte header;
  its base64 form and Desktop prefix still fit the encoded 2 MiB limit. Never pass
  arbitrary 2 MiB raw batches to Desktop's native bridge.
- Validate the whole WebSocket message before any native delivery, keep WELCOME
  alone, preserve DATA/WINDOW/CLOSE ordering, and do not wait for another message.
  The loopback-iframe path still transfers the whole original buffer.
- This reduces native calls for batches of small frames. It is not evidence of a
  measured throughput, latency or battery improvement on any client platform.

References:

- https://github.com/DrKLO/Telegram/blob/f2908b14133bbffbf7ab04f641ecb5bfaf533242/TMessagesProj/src/main/java/org/telegram/utils/proxy/WebProxyTransport.java#L531
- https://github.com/DrKLO/Telegram/blob/f2908b14133bbffbf7ab04f641ecb5bfaf533242/TMessagesProj/src/main/java/org/telegram/utils/proxy/WebProxyTransport.java#L580
- https://github.com/telegramdesktop/tdesktop/blob/42f8a36d43b8c805bc821905bea4cfeb3af1d41d/Telegram/SourceFiles/mtproto/web_proxy/web_proxy_webview.cpp#L28
- https://github.com/telegramdesktop/tdesktop/blob/42f8a36d43b8c805bc821905bea4cfeb3af1d41d/Telegram/SourceFiles/mtproto/web_proxy/web_proxy_transport.cpp#L973
- https://github.com/desktop-app/lib_webview/blob/d6e2e0b8b171a104cd7b63bd351f056563e964b0/webview/platform/mac/webview_mac.mm#L307
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/WebProxyTransport/Sources/WebProxyWebViewCarrier.swift#L222
- https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/WebProxyTransport/Sources/WebProxyFrame.swift#L100

## Practical Checklist

- If only one platform fails, compare that platform's timeout/race model first.
- Determine failure stage: pre-TLS, MTProto 64-byte assembly, or active relay.
- Confirm ClientHello Session ID length, SNI/tls_domain, and whether payload was pipelined after the nonce.
- Validate whether behavior is normal client racing vs proxy regression.
