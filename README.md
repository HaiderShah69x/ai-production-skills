# AI Production Skills (`SKILL.md`)

A structured benchmark suite and production guardrail library designed to prevent Gemini, Antigravity, and AI coding agents from defaulting to shallow, "happy-path" implementations.

## The Problem
When tasked with building APIs, CLI tools, or backend handlers, default AI agents consistently exhibit critical production blind spots:
1. **Lost-Update Data Races:** Checking and updating shared state non-atomically (e.g., button spam bypasses).
2. **Unbounded Payload Allocation:** Trusting client `Content-Length` headers without streaming limits, risking OOM crashes.
3. **Leaked Connections:** Omitting network deadlines and timeouts, leaving sockets stalled.
4. **The "Exit Code 0" Illusion:** Running passive unit tests without negative assertions, passing solely because the runtime did not crash.

## Repository Layout
- `skills/`: Reusable `SKILL.md` packages for Gemini and agentic IDEs.
- `fixtures/`: Intentionally vulnerable baseline implementations demonstrating default agent code.
- `attacks/`: Adversarial shell test suites that exploit these vulnerabilities.
