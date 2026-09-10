# Causpan Threat Model

## Trusted

- Linux host kernel.
- Kernel/eBPF instrumentation (when eBPF collector is implemented).
- The defender controls or can instrument the relevant application/runtime.

## Untrusted / Adversarial

- Logical requests may be benign or malicious.
- AI-generated actions may be untrusted (relevant when extending to MCP).
- Application code may cause arbitrary file, network, and process side effects.
- Multiple logical requests may execute concurrently, potentially intentionally.

## Attacker Capabilities

Attackers may attempt to exploit attribution ambiguity:

1. **Attribution confusion**: A malicious request deliberately overlaps its kernel activity with a benign request to defeat time-window correlation.
2. **Subprocess laundering**: A logical request causes a child process to perform malicious behavior and tests whether request-level causality survives.
3. **Context forgery** (future): Manipulate application-level request identity to impersonate another RPC.
4. **Timing manipulation** (future): Deliberately control operation timing to cause attribution errors.

## Out of Scope (Initial)

- Compromised kernel / rootkits.
- Hardware-level attacks.
- Network-level adversaries between hosts.
- Container escape.

## Eventually In Scope

- Application-provided request identity forgery or manipulation.
- Cross-process and cross-container attribution.
- Subprocess causality survival.
