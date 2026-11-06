# Security

If you find a security problem in this code, please tell us privately first, so we can fix it before it can hurt anyone.

## How to report

- Use **Report a vulnerability** on this repository's Security tab (GitHub's private reporting), or
- email **security@thehubs.gg**.

Please include what you found, how to reproduce it, and which part of the code it touches (`typescript/`, `rust/` or the protocol itself). A failing test or a test vector is the most useful thing you can send.

We read every report. We will tell you when we have confirmed the problem, keep you updated while we fix it, and credit you when the fix ships unless you would rather we didn't.

## What counts

Anything that lets someone read private messages they shouldn't, forge or change messages, add or hide a device in a conversation, defeat the safety code or key change alert, get around disappearing messages, or forge a report. Weaknesses in the protocol design count too, not only bugs in the code.

The limits listed in [docs/threat-model.md](docs/threat-model.md) are known. A new way to exploit one of them is still worth reporting.

## What doesn't

Problems in the rest of Hubs (the website, the apps or the server outside this code) are welcome too, but please send them to the same address rather than opening an issue here.

Please don't test against other people's accounts or conversations, and don't run load or denial of service tests against our servers.
