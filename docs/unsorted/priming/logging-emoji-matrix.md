---
title: Pyvider Logging Emoji Matrix
scope: Structured logging prefixes for Pyvider RPC plugin.
format: [Domain] → [Action] → [Status]
purpose: Compact tagging for log messages, improving observability.
usage: Prepend log entries with a 3-emoji prefix to classify logs.
retrieval_tags: ["pyvider", "logging", "emoji", "rpc", "observability"]
---

D:
  🛎️: Server
  🙋: Client
  🔌: Plugin
  🌐: TCP
  📞: Unix
  🤝: Handshake
  🔐: Security
  ⚙️: Config
  📡: Protocol
  🧰: Utils
  ❗: Exception
  🛰️: Telemetry
  💉: DI

A:
  🚀: Start
  🤝: Handshake
  🕵️: Connect
  🕹: Listen
  📖: Read
  📤: Write
  📥: Receive
  🔒: Close
  🔍: Parse
  📝: Build
  🔁: Retry
  🧪: Test
  📜: Cert
  🔑: Key
  🛡️: Encrypt

S:
  ✅: Success
  ❌: Error
  🚫: Fail
  ⚠️: Warn
  🛑: Stop
  👍: Affirm
  👀: Monitor
  💥: Crash
  ⭕: None
  ⏸️: Suspend
  ▶️: Resume
  ⏳: Pending
  💤: Idle
  🔄: Ongoing
