---
name: concurrency-and-resource-bounds
description: >-
  Enforces atomicity on shared-state mutations, strict streaming request-body
  caps, and network connection deadlines to prevent race conditions and resource
  exhaustion. Activate this skill whenever the agent is implementing APIs, CLI
  tools, queue consumers, or any backend handler that touches shared mutable
  state, ingests external payloads, or manages network connections.
---

# Concurrency and Resource Bounds

## Core Objective

Prevent two classes of silent production failure:

1. **Data-loss race conditions** — lost updates, double-spend, button-spam
   bypasses — caused by non-atomic check-then-act sequences on shared mutable
   state.
2. **Unconstrained resource consumption** — OOM crashes from unbounded payload
   reads, and hung sockets from missing network deadlines or slow-drip resource exhaustion.

---

## Invariant 1 — Atomic Check-and-Act

### Rule

Every read-modify-write on shared mutable state (balances, quotas, inventory,
rate-limit counters, idempotency keys) **must** be atomic from the perspective
of concurrent callers.

### Deployment Scope: Single-Process vs Multi-Process / Distributed

- **Multi-Process OS Concurrency Verification:** In multi-process and multi-worker
  architectures, concurrency benchmarks **must not** rely on thread-pool illusions (`ThreadPoolExecutor`).
  Adversarial harnesses **MUST** spawn distinct operating system processes (`ProcessPoolExecutor` or `multiprocessing.Process`)
  with separate PIDs that each independently establish raw TCP loopback socket connections.
  This ensures real kernel-level TCP backlog contention, socket buffer pressure, and true
  multi-process SQLite database lock contention.
- **Process-local mutexes explicitly rejected for multi-process topologies:** In-memory
  synchronization primitives (e.g., `threading.Lock()`, `sync.Mutex`, Java `synchronized`)
  are **strictly forbidden** as synchronization controls in multi-process architectures
  (such as Gunicorn/Uvicorn multi-worker setups, Docker containers, Kubernetes replicas,
  or serverless workers). Mutexes only guard threads inside a single memory address space;
  concurrent OS processes bypass in-memory locks completely.
- **Mandatory database-level atomic conditional updates:** Multi-worker and distributed
  deployments **MUST** enforce state mutations directly in the database or storage engine via
  atomic conditional queries:
  ```sql
  UPDATE stock
  SET remaining = remaining - 1, sold = sold + 1
  WHERE id = :id AND remaining > 0;
  ```
  The caller must inspect the affected row count (`rowcount == 1` confirms reservation;
  `rowcount == 0` signals exhaustion). Alternatively, strict transactional isolation
  (`SELECT ... FOR UPDATE` under `SERIALIZABLE` or `REPEATABLE READ`) or distributed lock managers
  with explicit leases may be used.
- **SQLite Concurrency Requirements:** When SQLite is employed as the datastore across
  concurrent workers, it **must** be configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL;`)
  and a non-zero busy timeout (`PRAGMA busy_timeout=5000;`) to avoid instantaneous `database is locked`
  failures during concurrent write contention.
- **Explicit Worker Rejection Signals & Crash Prevention:** Concurrent callers that
  fail to acquire a reservation (`cursor.rowcount == 0`) **MUST** receive an explicit,
  deterministic rejection signal (e.g., HTTP 409 Conflict with `{"error": "out_of_stock"}`,
  or domain `False`) rather than suffering unhandled database lock timeouts, silent drops,
  or worker process termination crashes. Database engine exceptions (such as busy timeouts
  or lock contention) must be caught explicitly and surfaced cleanly as structured transient
  backoff responses (e.g., HTTP 503 / 429) rather than crashing the worker process.
- **Quota Integrity vs Duplicate Submissions:** Atomicity guarantees quota and state
  integrity (e.g., never selling beyond 0 or double-spending), but does **not**
  prevent a user from intentionally or accidentally submitting duplicate requests.
  Protection against duplicate submissions (e.g. repeated payment button clicks)
  requires an **Idempotency Key** mechanism alongside atomic checks.

### Requirements

- **Lock or reserve first, perform I/O after.** Acquire the lock / issue the
  atomic DB update *before* any network call, file write, or external side
  effect. Release only after the side effect is confirmed.
- **Use atomic DB primitives.** Prefer `UPDATE … WHERE balance >= amount
  RETURNING …`, `SELECT … FOR UPDATE`, Redis `EVAL` Lua scripts, or
  compare-and-swap over application-level read → compute → write sequences.
- **Forbid non-atomic check-then-update.** The pattern
  `if resource.available(): resource.consume()` is prohibited when `resource`
  is shared across goroutines, threads, or processes without a surrounding
  critical section.
- **Critical section scope.** The critical section must span the check **and**
  the mutation. I/O that is not part of the invariant (e.g., sending a
  confirmation email) must be moved *outside* the critical section to avoid
  holding locks during slow operations.

### Canonical Pattern (pseudo-code)

```python
# WRONG — non-atomic check-then-act
balance = db.get("balance")
if balance >= amount:
    db.set("balance", balance - amount)   # race: another request runs here

# CORRECT (Single-Process) — thread-safe lock with I/O outside critical section
with state_lock:
    if stock["remaining"] < amount:
        raise SoldOutError()
    stock["remaining"] -= amount
send_confirmation_email()  # slow I/O strictly outside the lock

# CORRECT (Multi-Process / Distributed) — DB atomic update
rows_updated = db.execute(
    "UPDATE accounts SET balance = balance - ? "
    "WHERE id = ? AND balance >= ?",
    amount, account_id, amount
)
if rows_updated == 0:
    raise InsufficientFundsError()
```

---

## Invariant 2 — Strict Ingress Resource Bounds

### Rule

No handler may read an unbounded amount of client-supplied data into memory.

### Requirements

- **Define `MAX_BODY_SIZE` as a named constant** (not an inline magic number)
  at the module or configuration level.
- **Reject oversized requests upfront with explicit HTTP 413.** If the `Content-Length` header is
  present and exceeds `MAX_BODY_SIZE`, respond immediately with an RFC-compliant
  **HTTP 413 Payload Too Large** response (`Connection: close`, flushed body) before reading any body bytes.
  Do **NOT** drop or reset the socket with an unhandled TCP RST (status 0).
- **Mandate incremental streaming byte-counting caps.** When `Content-Length` is
  absent, chunked (`Transfer-Encoding: chunked`), or streaming/decompressed (e.g., gzip/zlib bombs),
  the handler **must** maintain a running byte counter during chunked reads.
  The stream must be aborted immediately with an explicit **HTTP 413** response and flushed buffer the instant accumulated
  bytes exceed `MAX_BODY_SIZE`.
- **Strict RFC Compliance Over Raw Resets:** Both declared Content-Length overflows and unannounced
  chunked stream exhaustion **MUST** yield an explicit HTTP 413 response rather than an unhandled TCP RST (status 0).
- **Forbid unbounded `.read()` / `ioutil.ReadAll` / `body.text()` calls.**
  Any call that reads an entire body into RAM without an explicit size cap is a
  critical production defect.

### Canonical Pattern (pseudo-code)

```python
MAX_BODY_SIZE = 1 * 1024 * 1024  # 1 MiB — tune per handler
CHUNK_SIZE = 64 * 1024           # 64 KiB read chunks

def read_bounded_body(request):
    raw_len = request.headers.get("Content-Length")
    if raw_len is not None and int(raw_len) > MAX_BODY_SIZE:
        raise HttpError(413, "Payload Too Large")

    buf = bytearray()
    total_bytes = 0
    # Stream in chunks regardless of whether Content-Length or chunked encoding is used
    while True:
        want = min(CHUNK_SIZE, MAX_BODY_SIZE - total_bytes + 1)
        chunk = request.read_chunk(want)
        if not chunk:
            break
        buf.extend(chunk)
        total_bytes += len(chunk)
        if total_bytes > MAX_BODY_SIZE:
            raise HttpError(413, "Payload Too Large")
    return bytes(buf)
```

---

## Invariant 3 — Bounded Socket Lifecycles & Absolute Deadlines

### Rule

Every network connection — inbound or outbound — must have explicit deadlines
and must be released on disconnect, idle timeout, or cumulative deadline breach.

### Requirements

- **Enforce Dual Deadlines (Idle Timeout + Absolute Request Deadline):**
  - **Per-read/write Idle Timeout (`READ_TIMEOUT`):** Reclaims dead sockets when no bytes
    are received within an idle window (e.g., 2.0s).
  - **Absolute Cumulative Request Deadline (`ABSOLUTE_REQUEST_TIMEOUT`):** Limits the total
    wall-clock lifetime of the entire request/transfer (e.g., 4.0s). This is strictly required
    to eliminate **slow-drip (Slowloris) attacks**, where an adversary sends 1 byte just
    frequently enough to reset an idle timer while exhausting server workers.
- **Abort stalled connections.** A connection that breaches either deadline must be terminated:
  respond with **HTTP 408 Request Timeout** (for inbound) or surface a timeout error
  (for outbound), then close the raw socket.
- **Guarantee resource release.** Use `defer conn.Close()`, `try/finally`,
  `using` statements, or equivalent RAII patterns so that file descriptors are
  reclaimed on normal exit, timeout, *and* exception paths.
- **Handle resets cleanly.** Handle `ConnectionResetError`, `BrokenPipeError`, and connection
  aborts without leaking unhandled tracebacks or crashing daemon threads.

### Canonical Pattern (pseudo-code)

```python
READ_TIMEOUT             = 2.0  # seconds between packet chunks
ABSOLUTE_REQUEST_TIMEOUT = 4.0  # seconds maximum total duration

def handle_connection(conn):
    start_time = time.monotonic()
    conn.set_timeout(READ_TIMEOUT)
    try:
        while True:
            elapsed = time.monotonic() - start_time
            if elapsed >= ABSOLUTE_REQUEST_TIMEOUT:
                raise TimeoutError("Cumulative deadline exceeded")
            
            # Dynamic window bounds individual reads to the remaining absolute deadline
            remaining = ABSOLUTE_REQUEST_TIMEOUT - elapsed
            conn.set_timeout(min(READ_TIMEOUT, remaining))
            
            chunk = conn.recv(CHUNK_SIZE)
            if not chunk:
                break
            process_chunk(chunk)
    except TimeoutError:
        conn.sendall(b"HTTP/1.1 408 Request Timeout\r\n\r\n")
    finally:
        conn.close()
```

---

## Verification Requirements

The agent **must** include the following tests alongside any implementation.
Test suites that do not exercise failure paths are considered incomplete.

### 1. Concurrent Quota / Shared-State Test

Execute **N concurrent worker requests** via distinct operating system processes
(`ProcessPoolExecutor` with unique PIDs) that each independently connect over live TCP loopback
sockets to attempt to consume from a quota of **Q** (where N > Q). Assert:

- Exactly Q requests succeed (HTTP 200).
- Exactly N − Q requests receive bounded rejection signals (HTTP 409 Conflict).
- Zero unhandled worker crashes (`crash_count == 0`).
- Final stored value equals 0 (fully consumed but never negative, sold equals Q).

### 2. Oversized Payload & Chunked Stream Test

Send requests exceeding `MAX_BODY_SIZE`:
- **Declared Content-Length Overflows:** Send a request declaring Content-Length > `MAX_BODY_SIZE`. Assert the server responds with **HTTP 413** (status 0 / connection reset is rejected as a test failure).
- **Chunked Ingress Exhaustion:** Send an unannounced chunked stream (`Transfer-Encoding: chunked`) exceeding `MAX_BODY_SIZE`. Assert the server enforces the rolling byte cap, terminates ingestion, and responds with **HTTP 413**.
- The server does **not** read beyond `MAX_BODY_SIZE` into memory.
- The server does **not** crash or hang.

### 3. Idle Timeout & Slow-Drip Test

- **Idle Stall Test:** Open a connection, send partial headers/body, and halt. Verify
  the server closes the socket within `READ_TIMEOUT` + grace window.
- **Slow Drip Test:** Send 1 byte periodically right under the `READ_TIMEOUT` threshold.
  Verify the server enforces the `ABSOLUTE_REQUEST_TIMEOUT` and terminates the connection.

### Anti-Patterns Forbidden in Tests

- **Empty `catch` / `except` blocks** that swallow exceptions silently.
- **Positive-only assertions** — every test must include at least one assertion
  on a *rejected* or *failed* path.
- **Sequential-only concurrency tests** — use threads, `asyncio.gather`,
  `goroutines`, or equivalent to produce genuine simultaneous contention.

---

## Checklist (apply before marking a task complete)

- [ ] All shared-state mutations are atomic (DB-level for multi-worker, lock-guarded for single process).
- [ ] Idempotency keys specified for duplicate submission handling where applicable.
- [ ] `MAX_BODY_SIZE` constant defined and enforced upfront via `Content-Length`.
- [ ] Incremental byte-counting streaming loop active for chunked/streaming/decompressed payloads.
- [ ] Dual timeouts active: idle read/write timeout AND absolute request deadline.
- [ ] `defer` / `finally` / `using` guarantees connection cleanup on all paths.
- [ ] Concurrent quota test included and passing.
- [ ] HTTP 413 oversized payload test included and passing.
- [ ] Idle stall test (B2) and slow-drip test (B3) included and passing.
- [ ] No empty `catch` blocks in test or production code.
