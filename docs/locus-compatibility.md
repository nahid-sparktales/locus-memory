# Locus compatibility reference

This document records what the Locus host currently does with memory. It is meant to let `locus-memory` read existing data, keep the behavior that clients depend on, and change defective behavior on purpose rather than by accident.

It is built from read-only audits of the three repositories listed below, plus a small number of behavior probes run on scratchpad copies. Nothing in the inspected repositories was modified, and no user database, key or vault was opened.

Companion document: [ownership-and-extraction.md](ownership-and-extraction.md). It covers who owns each responsibility after extraction, the full data-store inventory, and the host call sites mapped to adapter actions.

---

## 1. Inspected sources

| Repository | Path | Commit | Working tree | Why it matters |
|---|---|---|---|---|
| Locus | `/Users/nahid/Documents/locus` | `b332e4554e72956f949506207ffa034749360d79`, branch `main` | clean | The host. It owns every store and code path that this package replaces or wraps. |
| Agent Dispatcher | `/Users/nahid/Documents/agent-skills` | `d68446fe33c4e2162c1eb4d4d15bb663a3040888` | 2 uncommitted user edits: `decision/redact.py`, `tests/test_retrieval_security.py` | Reference design for repository intelligence, experience records and governed procedural learning. A copy is bundled into Locus as `agent/ollama_code/builtin_skills/agent-dispatcher`. |
| langgraph-workflow | `/Users/nahid/Documents/langgraph-workflow` | `52799242a53d80ed067797d0cbb6e1c83363214e` (package `langgraph-workflow` 0.4.1) | not recorded | Workflow executor that runs in-process with Locus or as a Locus plugin. It would consume memory through the host. |

Scope notes:

- A commit referenced earlier in this project, `c2d0e75b4fc1dc3995966808e88e91e177457b25`, is older than the current Locus HEAD. Every Locus citation in this document is against `b332e455`.
- The files `agent/build/lib/ollama_code/{memory,memory_runtime,continuity,api/continuity,api/knowledge}.py` are gitignored (`.gitignore:46`) and byte-identical to the sources. They are not separate callers, and extraction tooling must not pick them up.
- Locus `.claude/worktrees/` is excluded via `.git/info/exclude:18` and was not audited. The same is true of agent-skills `.claude/worktrees/warm-improvements/`, which contains divergent code such as `skill_intelligence.py`.
- Under `~/.ollama-code` and `~/Library/Application Support/{Locus,LocusX}`, only file names and modes were listed. No file there was opened.

## 2. Runtime facts (verified directly)

| Fact | Value | Source |
|---|---|---|
| Minimum Python for the Locus agent | `>=3.10`; ruff target `py310` | `agent/pyproject.toml` |
| Bundled interpreter | CPython 3.14.6, python-build-standalone tag `20260728` | `/Applications/Locus.app`; `Tools/PrepareAgentRuntime.sh` |
| Bundled SQLite | 3.53.1, compiled with `ENABLE_FTS5` and `TEMP_STORE=1` | bundled interpreter |
| AEAD library | `cryptography==50.0.0` | `agent/requirements-runtime.lock` |
| Install method | `pip --target` into `AgentRuntime/site-packages` from a hashed lock | runtime build |
| Interpreter used for probes | project venv, Python 3.14.6 with cryptography 50.0.0 | scratchpad copies only |
| langgraph-workflow pins | `langgraph==1.2.2`, `langgraph-checkpoint==4.2.0`, `langgraph-checkpoint-sqlite==3.1.1`, `langgraph-sdk==0.3.15`, `mcp==2.0.0`; Python `>=3.10` | `constraints.txt:9-14`; `pyproject.toml:10-25` |
| langgraph-workflow plugin lock (private venv) | `cryptography==50.0.1`, `websockets==17.1` for py>=3.11, `sqlite-vec==0.1.9` | `plugin/requirements.lock:314,1375,1104` |
| Locus websockets pin | `websockets==17.0`, which caps langgraph at 1.2.2 | `agent/requirements-runtime.in:7-8`; langgraph-workflow `constraints.txt:1-4` |

What this means for the package:

- Support Python 3.10 through 3.14.
- Stay compatible with `AESGCM` from `cryptography` 50.0.0.
- FTS5 exists in the bundled SQLite. It must be feature-detected on any other interpreter; availability on system Pythons was not verified.
- Do not add `sqlite-vec` without coordinating with langgraph-workflow. Its checkpoint package already pulls in `sqlite-vec` 0.1.9 when the two are co-installed.

## 3. Conventions

- Python paths with no directory refer to `agent/ollama_code/` in Locus. For example, `memory.py:20` means `agent/ollama_code/memory.py` line 20, and `api/continuity.py` means `agent/ollama_code/api/continuity.py`. Tests are written `agent/tests/...`. Swift paths start with `Locus/`, `LocusTests/` or `RuntimeHelper/`.
- In the Agent Dispatcher and langgraph-workflow sections, paths are relative to those repositories.
- When two audit passes reported slightly different line ranges for the same symbol, both are shown, for example `server.py:369-401/406`. Treat line numbers as accurate to within a few lines.
- Evidence labels:
  - **CONFIRMED (probe)**: reproduced on a scratchpad copy or with a test client.
  - **By reading**: established from source only.
  - **Plausible**: not reproduced.

---

## 4. Encrypted memory vault (`memory.py`, 854 lines)

### 4.1 Symbols

| Symbol | Location | Summary |
|---|---|---|
| `VALID_SCOPES`, `VALID_STATUSES`, `VALID_KINDS`, `CANDIDATE_TTL_SECONDS`, `MAX_MEMORY_CONTENT` | `memory.py:20-24` | `{personal, workspace, agent}`; `{candidate, approved}`; `{preference, fact, decision, procedure, relationship}`; `2_592_000` seconds (30 days); `32_000` characters |
| `class MemoryError(RuntimeError)` | `memory.py:27` | Shadows the builtin `MemoryError` in every module that imports it: `memory_runtime.py:8`, `server.py:66`, `tools.py:1169,1196`, `api/continuity.py:14`, `api/knowledge.py:15` |
| `memory_database() -> Path` | `memory.py:31-32` | `paths.APP_DIR/'memory'/'memory.sqlite3'`, resolved on every call. Also used by `continuity.py:92` |
| `_fallback_key(path=None) -> bytes` | `memory.py:35-71` | Loads or creates the key file (§4.8) |
| `_master_key(key=None, fallback_path=None) -> bytes` | `memory.py:74-78` | Returns `key or _fallback_key(fallback_path)`; the length must be 32. Called by `MemoryVault.__init__` (`memory.py:110`) and `ContinuityStore.__init__` (`continuity.py:94`) |
| `_target(scope, *, workspace='', agent_id='') -> str` | `memory.py:81-97` | Scope target hash (§4.7) |
| `MemoryVault.__init__(path=None, *, key=None, fallback_key_path=None)` | `memory.py:101-113` | Creates the parent directory (no mode set), loads the key, builds `AESGCM`, creates a per-instance `threading.RLock`, then calls `_initialize()` |
| `MemoryVault._connect()` | `memory.py:115-119` | `sqlite3.connect(path, timeout=10)` with a Row factory and `PRAGMA busy_timeout=10000`. Callers use `with self._connect() as c`, which commits or rolls back but never closes the connection |
| `MemoryVault._initialize()` | `memory.py:121-173` | Sets `journal_mode=WAL`, runs the DDL and the ad hoc column migrations (158-169), then chmods the DB to 0600 (171) |
| `MemoryVault._aad(...)` (staticmethod) | `memory.py:175-179` | Builds the AAD bytes (§4.4) |
| `MemoryVault._seal(payload, *, identifier, status, scope, target_hash, revision)` | `memory.py:181-197` | Returns `(nonce, ciphertext)` |
| `MemoryVault._open_payload(row)` / `_open(row)` | `memory.py:199-242` | Decrypts a row and builds the public record shape (§4.6) |
| `save(value, memory_id='', *, workspace='', agent_id='', default_status='approved') -> dict` | `memory.py:244-361` | Validates, upserts, and attaches `conflicts` |
| `approve(memory_id, *, workspace='', agent_id='', resolution='keep_both') -> dict` | `memory.py:363-401` | §4.12 |
| `expire_candidates(*, workspace='', agent_id='') -> int` | `memory.py:403-419` | §4.12 |
| `list(*, workspace='', agent_id='', status='', scopes=None) -> list[dict]` | `memory.py:421-460` | §4.13 |
| `_topic_tokens(...)`, `conflicts_for(memory, *, workspace='', agent_id='') -> list[dict]` | `memory.py:462-502` | §4.14 |
| `_store_embedding(row, payload, model, vector)` | `memory.py:504-527` | Compare-and-swap reseal (§4.16) |
| `search(query, *, workspace='', agent_id='', scopes=None, limit=8, approved_only=True, embedding_model='', ollama_host='http://127.0.0.1:11434') -> list[dict]` | `memory.py:529-633` | §4.15 |
| `delete(memory_id) -> bool` | `memory.py:635-639` | §4.18 |
| `delete_all(*, workspace='', agent_id='', scopes=None) -> int` | `memory.py:641-651` | §4.18 |
| `feedback(memory_id, outcome) -> dict` | `memory.py:653-681` | §4.17 |
| `record_event(stage, outcome, *, workspace='', agent_id='', session_id='', run_id='', reason_code='', memory_id='') -> None` | `memory.py:683-712` | §4.19 |
| `diagnostics(*, workspace='', agent_id='') -> dict` | `memory.py:714-744` | §4.19 |
| `maintain(*, workspace='', agent_id='') -> dict` | `memory.py:746-779` | §4.20 |
| `status(*, workspace='', agent_id='') -> dict` | `memory.py:781-804` | §4.20 |
| `export(*, workspace='', agent_id='') -> dict` | `memory.py:806-812` | §4.21 |
| `import_values(document, *, workspace='', agent_id='') -> int` | `memory.py:814-835` | §4.21 |
| `format_memory_results(results) -> str` | `memory.py:838-849` | §4.22 |

### 4.2 Location

`memory_database()` returns `APP_DIR/memory/memory.sqlite3`, and the key lives at `APP_DIR/memory/master.key`. `APP_DIR` is `$OLLAMA_CODE_HOME` (stripped, then expanduser) if that is set and non-empty, otherwise `~/.ollama-code` (`paths.py:8-14`). See §11 for the per-edition values.

The same SQLite file also holds the `ContinuityStore` tables `context_snapshots` and `skill_observations` (§6), and those tables use the same key.

On this machine `~/.ollama-code/memory/` contains `master.key`, `memory.sqlite3`, `memory.sqlite3-wal` and `memory.sqlite3-shm`, all `-rw-------`. Only names and modes were listed. `~/Library/Application Support/Locus/Agent/memory` does not exist.

### 4.3 Schema

The column definitions below come from the audit (`memory.py:126-169`). Exact whitespace, `IF NOT EXISTS` clauses and statement order are not reproduced; compare with the source before using this as a fixture.

```sql
-- memories
id           TEXT PRIMARY KEY
status       TEXT NOT NULL CHECK (status IN ('candidate','approved'))
scope        TEXT NOT NULL CHECK (scope IN ('personal','workspace','agent'))
target_hash  TEXT NOT NULL
nonce        BLOB NOT NULL
ciphertext   BLOB NOT NULL
pinned       INTEGER NOT NULL DEFAULT 0
stale        INTEGER NOT NULL DEFAULT 0
revision     INTEGER NOT NULL DEFAULT 1
created_at   REAL NOT NULL
updated_at   REAL NOT NULL
expires_at   REAL
-- added by ALTER TABLE ... ADD COLUMN when PRAGMA table_info shows them missing (memory.py:158-169)
last_used_at REAL
use_count    INTEGER NOT NULL DEFAULT 0
superseded_by TEXT
-- index
memories_lookup_idx ON memories(status, scope, target_hash, pinned, updated_at)

-- memory_events
id            INTEGER PRIMARY KEY AUTOINCREMENT
workspace_hash TEXT NOT NULL
agent_hash    TEXT NOT NULL
session_id    TEXT
run_id        TEXT
stage         TEXT NOT NULL
outcome       TEXT NOT NULL
reason_code   TEXT NOT NULL DEFAULT ''
memory_id     TEXT
occurred_at   REAL NOT NULL
-- index
memory_events_target_idx ON memory_events(workspace_hash, agent_hash, occurred_at DESC)
```

- Final column order of `memories`, checked with `PRAGMA table_info`: id, status, scope, target_hash, nonce, ciphertext, pinned, stale, revision, created_at, updated_at, expires_at, last_used_at, use_count, superseded_by.
- There is no `PRAGMA user_version` and no schema-version table. Migrations are ad hoc `ADD COLUMN` statements.
- The `memories` table before v2 had 12 columns. In a single process, opening such a database adds the three columns idempotently. Concurrent first opens can race (D25).
- Pragmas: `journal_mode=WAL` and `busy_timeout=10000`. The file is chmodded to 0600. SQLite creates the WAL and SHM files with the database's mode.

### 4.4 Crypto envelope

These details are a persisted wire format. Existing databases stay readable only if they are reproduced byte for byte.

- Cipher: AES-256-GCM, using `cryptography`'s `AESGCM` with a 32-byte key (`memory.py:111`).
- Nonce: 12 random bytes per seal, from `secrets.token_bytes(12)`, stored in the `nonce` column.
- Ciphertext: `AESGCM.encrypt(nonce, plaintext, aad)`. The 16-byte tag is appended; the measured overhead is exactly 16 bytes.
- Plaintext: `json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')`.
- AAD:

  ```text
  f"memory-v1|{id}|{status}|{scope}|{target_hash}|{revision}".encode()
  e.g. id='abc', status='approved', scope='personal', target='personal', revision=1
       -> b'memory-v1|abc|approved|personal|personal|1'
  ```

- The AAD binds id, status, scope, target_hash and revision. It does not bind pinned, stale, created_at, updated_at, expires_at, last_used_at, use_count or superseded_by. Tampering with pinned and use_count went undetected (CONFIRMED (probe)). Because status is bound, editing the database cannot promote a candidate to approved.
- Any decrypt failure raises `MemoryError('a memory record could not be decrypted')`. A payload that is not a dict raises `MemoryError('a memory record is malformed')`.

### 4.5 Encrypted payload fields (`memory.py:295-314`)

| Field | Rule |
|---|---|
| `title` | At most 160 characters; default `'Memory'` |
| `content` | Stripped, at most 32,000 characters, must not be empty |
| `tags` | Lowercased, stripped, each at most 40 characters, deduplicated, sorted, at most 24. A string value is iterated character by character, so `'abc'` becomes `['a','b','c']` (CONFIRMED (probe)) |
| `reason` | At most 2,000 characters |
| `source_session_id`, `source_run_id` | String or None. Not truncated |
| `provenance` | Dict or `{}`. Size is unbounded |
| `kind` | Must be in `VALID_KINDS`; default `'fact'` |
| `confidence` | Clamped to [0, 1]; default 1.0. NaN is stored as NaN (CONFIRMED (probe)); inf clamps to 1.0 |
| `valid_from`, `valid_until`, `last_confirmed_at` | Float Unix timestamp or None. `valid_until` must be after `valid_from` |
| `supersedes` | At most 32 items, each at most 128 characters |
| `embedding` | `list[float]` |
| `embedding_model` | At most 256 characters |
| `feedback` (optional) | `{helpful, ignored, incorrect}: int`. Added only by `feedback()` |

When an existing row is updated, keys that were missing from the previous payload are written back as null. For example, `feedback` becomes `null`.

### 4.6 Public record shape (`_open`, `memory.py:218-242`)

The record returned by `_open` has these keys: `id, status, scope, title, content, tags, reason, source_session_id, source_run_id, provenance, kind, confidence, valid_from, valid_until, last_confirmed_at, supersedes, embedding_model, pinned, stale, last_used_at, use_count, superseded_by, revision, created_at, updated_at, expires_at`.

- `save`, `approve` and `list(status='candidate')` also add `conflicts`, a list of `{id, title, content, kind, confidence}`.
- `search` also adds `retrieval_reason` and `score`.
- `embedding` and `feedback` are never returned.

### 4.7 Scope targets (`_target`, `memory.py:81-97`)

| Scope | Target hash | Error |
|---|---|---|
| `personal` | the literal string `'personal'`, shared by every agent and every workspace | none |
| `workspace` | `'workspace:' + sha256(str(Path(ws).expanduser().resolve()).encode()).hexdigest()` | blank workspace raises `'workspace memory requires an active workspace'`; resolve failure raises `'workspace memory target is invalid'` |
| `agent` | `'agent:' + sha256(agent_id.strip().encode()).hexdigest()` | blank agent id raises `'agent memory requires an agent id'` |
| any other value | n/a | `'memory scope must be personal, workspace, or agent'` |

- The agent target is not tied to any workspace.
- The hashes are unsalted. `agent:sha256('primary')` is trivially reversible, and workspace paths can be guessed.
- The workspace path is resolved but never checked for existence.

### 4.8 Key sourcing (`memory.py:35-78`)

- Production code never passes `key=`. Every production constructor is `MemoryVault()` (`memory_runtime.py:13`, `tools.py:1181`, `tools.py:1198`) or `ContinuityStore()` (`server.py:358,392`, `api/continuity.py:33`, `tools.py:1266,1293`). Only tests inject a key: `test_memory.py:14` uses `b'k'*32`, plus `test_continuity.py:16` and `test_backend.py:69`.
- The key file defaults to `APP_DIR/memory/master.key`, even when a custom DB path is passed (checked).
- File creation:
  1. Chmod the directory to 0700 (`memory.py:40`).
  2. Generate 32 bytes with `secrets.token_bytes(32)`.
  3. Open with `O_WRONLY|O_CREAT|O_EXCL` and mode 0600, write, and fsync.
  4. On `FileExistsError`, re-read the file and adopt the winner's key if it is 32 bytes.
- Reading an existing file: a 32-byte file is chmodded back to 0600 (`memory.py:47,55`) and used. A file of the wrong length is never overwritten; it raises `'the memory encryption key is invalid'`. If the re-read fails, the error is `'the memory encryption key is unavailable'`.
- `key=b''` falls back to the file. A 16-byte key raises `'memory encryption requires a 256-bit key'`.
- Race behavior: across 30 trials of 8 concurrent first-run processes, all processes always got one shared key. A small window remains in which the winner has created the file but not yet written it; a loser then sees a short file and raises `'invalid'`. That failure is transient. If `os.write` fails after the create, an empty key file is left behind, and every later open raises `'invalid'`.
- If the key file is missing but the DB exists, a new key is generated silently (CONFIRMED (probe)). Construction succeeds, but `list`, `status`, `export` and `search` all raise `'a memory record could not be decrypted'`. A save with a new id still commits its row and then raises from `conflicts_for`, so the vault ends up with rows under two keys. Nothing detects the key mismatch: there is no canary and no key id.
- The Keychain is never used. `agent/PROTOCOL.md:269-272` documents this ("Memory never accesses the macOS Keychain"), as does `README.md:143-146`. Test `test_memory_uses_a_user_only_local_key_without_keychain` (`agent/tests/test_memory.py:58-70`) pins it.

### 4.9 IDs and `save()` defaults (`memory.py:244-275`)

- An id must match `[A-Za-z0-9_-]{1,128}` exactly (`memory.py:253-255`). The default id is `uuid.uuid4().hex`, and `memory_id=''` also generates one. Only `save` validates ids. `delete`, `approve` and `feedback` accept any string, passed through parameterized SQL.
- `status = (value.status or default_status).lower()`.
- `scope = (value.scope or 'workspace').lower()` (`memory.py:256-259`). This means a save without a workspace raises an error.
- `kind` defaults to `'fact'` (`memory.py:269-271`).
- On insert, revision is 1 and `created_at` = `updated_at` = now.
- `expires_at` is now + 2,592,000 for a candidate and NULL for an approved record (`memory.py:331-333`).
- The upsert runs under the per-instance lock. Conflicts are attached after commit, by calling `conflicts_for` (`memory.py:358`).

### 4.10 Update merge semantics (`memory.py:316-353`)

When the id already exists:

- **Kept from the previous payload if absent from the input:** `reason, source_session_id, source_run_id, provenance, last_confirmed_at, supersedes, embedding, embedding_model, feedback` (`memory.py:322-328`).
- **Reset to the default if absent from the input:** title (`'Memory'`), tags (`[]`), kind (`'fact'`), confidence (1.0), `valid_from` and `valid_until` (None), pinned and stale (False), scope (`'workspace'`), status (`default_status`).
- **Never touched by the `ON CONFLICT` update:** `created_at`, `last_used_at`, `use_count`, `superseded_by`.
- The `revision` the client sends is ignored (`memory.py:329`). The last writer wins.
- The embedding is kept even when content or title changes, so recall uses a stale vector (CONFIRMED (probe), D24).
- The id is upserted under the caller's scope and target. That re-targets an existing record (D2).

### 4.11 Revision semantics

| Write | Bumps `revision` | Changes `updated_at` |
|---|---|---|
| `save()` insert | sets 1 | yes |
| `save()` upsert (memory_update, import over an existing id, legacy re-migration) | +1 | yes |
| `approve(resolution='keep_both')` | +1 | yes |
| `approve(resolution='replace')` with conflicts | +2 (two saves, `memory.py:379-391`) | yes |
| approve's `UPDATE stale=1, superseded_by=?` on the conflicting rows (`memory.py:392-396`) | no | no |
| `feedback()` reseal (`memory.py:668-677`) | no | no |
| `_store_embedding` CAS reseal (`memory.py:511-527`) | no | no |
| `maintain()` `UPDATE stale=1` (`memory.py:757-761`) | no | no |
| `search()` `UPDATE last_used_at, use_count+1` (`memory.py:628-632`) | no | no |
| expiry deletes | n/a (row removed) | n/a |

### 4.12 Candidates, approval and expiry

- Every save of a candidate resets `expires_at` to now + 30 days. Edits, imports and re-migrations therefore extend the TTL (checked).
- Expiry is enforced lazily. Every `list()` call first runs `expire_candidates()` (`memory.py:429`). That function deletes every candidate with `expires_at < now` in every target, then records an `expiration/expired` event for each deleted row under the **caller's** workspace and agent (`memory.py:403-419`). It returns the delete rowcount.
- `approve` (`memory.py:363-401`):
  - Loads the row by id only. It checks neither target nor status.
  - Sets `status=approved` and `last_confirmed_at=now`, computes conflicts, then saves using the caller's workspace and agent_id. That save re-targets the record (checked: approving a ws1 candidate from ws2 moves it to ws2).
  - With `resolution='replace'` and conflicts present, it saves a second time with `supersedes=<conflict ids>`, then runs `UPDATE stale=1, superseded_by=<id>` on those conflicts.
  - Any other resolution raises `'memory conflict resolution must be keep_both or replace'`.
  - A missing id raises `'memory candidate not found'`; the route returns that as 422, not 404.
  - On a row that is already approved, approve re-confirms it: it refreshes `last_confirmed_at` and bumps the revision.
- Rejection has no status of its own. It is a hard delete plus a `rejection/recorded` event (`api/continuity.py:252-270`).
- Other lifecycle state lives outside the `status` column:
  - `stale`: set by feedback `'incorrect'`, by `maintain()` when `valid_until` has passed, and by approve with `replace`.
  - `pinned`, `superseded_by`, `use_count`, `last_used_at`.
  - Feedback counts, stored inside the ciphertext.

### 4.13 Listing (`memory.py:421-460`)

- `list()` calls `expire_candidates()` first, so every read also writes.
- Scopes are `scopes or ('personal','workspace','agent')`, then filtered by `VALID_SCOPES`. As a result, **`scopes=[]` and `scopes=None` both mean all three scopes** (`memory.py:430-433`, D1). If `_target` raises for a scope, that scope is skipped silently. `scopes=['bogus']` returns `[]`.
- The query is an OR of `(scope=? AND target_hash=?)` clauses. A status filter is added only when the status is valid, so `status='bogus'` means no filter.
- Order is `pinned DESC, updated_at DESC`. Every row is decrypted, and one undecryptable row raises for the whole list (`memory.py:454`).
- For `status='candidate'`, each row also gets `conflicts`.

### 4.14 Conflict heuristic (`memory.py:462-502`)

1. Topic tokens are `re.findall(r'[a-z0-9_.-]+', (title + ' ' + ' '.join(tags)).lower())`, keeping tokens longer than 2 characters.
2. Overlap is `|A∩B| / max(min(|A|,|B|), 1)` and must be at least 0.5.
3. Content is normalized with `re.sub(r'\s+', ' ', content.strip().lower())`, and the two normalized contents must differ.
4. Candidates come from `list(status='approved', scopes=[memory.scope])`, using the caller's workspace and agent_id. The memory itself and stale rows are excluded. At most 12 conflicts are returned. An empty topic returns `[]`.

Untitled memories all share the token `memory`, so they all conflict with each other (checked). The same happens with other default titles: `'Memory'` (`memory.py:264`), `'From selected chat'` (`api/continuity.py:478`) and `'Suggested memory'` (`tools.py:1225`).

### 4.15 Search (`memory.py:529-633`)

- `value = query.strip().lower()[:2000]`. An empty query raises `'memory search requires a query'`.
- `terms = re.findall(r'[\w.-]+', value)`, keeping terms longer than 1 character, capped at 24.
- Candidates come from `list(status='approved' if approved_only else '', scopes)`. No caller sets `approved_only=False`.
- Per memory:
  - `haystack = (title + ' ' + content + ' ' + ' '.join(tags)).lower()`.
  - `phrase = 4.0` if `value` occurs in the haystack.
  - `matches = Σ haystack.count(term)`. This counts substrings, not whole words.
  - The memory is skipped if it has no phrase match, no term matches and `semantic < 0.2`.
- Score:

  ```text
  score = phrase + min(matches, 8) * 0.8 + semantic * 5.0 + (2.0 if pinned) + confidence + 1 / (1 + age_days / 30)
  age_days from updated_at
  valid_from in the future   -> excluded
  valid_until in the past    -> score * 0.15
  stale                      -> score * 0.4
  ```

- Results are sorted by `(-score, id)`. The limit is clamped to [1, 20].
- `retrieval_reason` is a comma-joined list of: `'exact phrase'` or `'N matching term(s)'`; `'semantic similarity NN%'`; `'pinned'`; `'NN% confidence'`.
- Side effects after ranking: each returned row gets `last_used_at=now` and `use_count+1` (`memory.py:627-632`). This update runs without the lock, does not touch the AAD and does not bump the revision. The returned dicts show the **pre-increment** `use_count` (`test_memory.py:196-197`). `use_count` and feedback are never used in ranking. Automatic recall increments rows even when the character budget later truncates them out of the prompt (`server.py:337-338`).

### 4.16 Semantic recall and the embedding cache (`memory.py:551-586`, `504-527`)

- Semantic recall runs only when `embedding_model` is non-empty.
- The embedder input is `[query] + [f'{title}\n{content}\n{" ".join(tags)}' ...]`. A memory is included only if its payload's `embedding_model` differs from the requested model or its embedding is empty.
- The embedder is `knowledge.embed_texts`, imported lazily. It is loopback-only, with `timeout=120` (`knowledge.py:599-640`).
- Semantic score is `max(cosine, 0)` when the dimensions match. Any exception sets `semantic = {}`, and the search falls back to lexical-only recall silently.
- Vectors are stored only inside the ciphertext. `_store_embedding` reseals the payload under the same revision with `UPDATE ... WHERE id=? AND revision=? AND nonce=? AND ciphertext=?`, and it changes neither `revision` nor `updated_at`.
- Where the embedding settings come from: the model and host are read from the per-workspace `KnowledgeStore` settings (`server.py:325`, `api/continuity.py:282`, `tools.py:1174-1180`). Memory recall therefore depends on the knowledge store (D39).

### 4.17 Feedback (`memory.py:653-681`)

- The outcome must be one of `helpful`, `ignored` or `incorrect`; otherwise the error is `'memory feedback must be helpful, ignored, or incorrect'`.
- Feedback increments `payload['feedback'][outcome]` and reseals under the **same revision** with a new nonce. The write is `UPDATE ... WHERE id=?`, with no compare-and-swap on the revision.
- `incorrect` sets `stale=1`.
- Neither the revision nor `updated_at` changes. Feedback counts are never returned and are not used in ranking.
- The SELECT and the UPDATE are not atomic across connections. If another instance saves in between, the row's `revision` column moves to r+1 while its ciphertext AAD still says r, and the row is permanently undecryptable (CONFIRMED (probe), D23).
- The route calls `memory_vault()` with no workspace (`api/continuity.py:339`), so the feedback event lands in the `('', '')` bucket.

### 4.18 Deletion

- `delete(id)` runs `DELETE FROM memories WHERE id=?` and returns `rowcount == 1`. There is no scope or target check; a probe deleted another workspace's memory by id (CONFIRMED (probe)). It does not clean up `superseded_by` or `supersedes` references or events. There is no secure wipe.
- `delete_all(workspace, agent_id, scopes)` calls `list(...)` and then runs `executemany` DELETE by id. Default scopes are all three, so it also removes **global personal memories** (checked). The Swift toast acknowledges this (`WorkspaceKnowledgeModel.swift:581`).
  - `DELETE /api/memory` calls it with all scopes (`api/continuity.py:205`).
  - `DELETE /api/knowledge` calls it with `scopes=['workspace']` (`api/knowledge.py:160`).
- The `DELETE /api/memory/{id}` route records `rejection` (when `outcome=reject`) or `deletion`, both with outcome `recorded`.

### 4.19 Events and diagnostics (`memory.py:683-744`)

- `record_event` inserts a content-free row:
  - `workspace_hash` is `sha256(raw workspace string)`. It is **not** the resolved path that `_target` uses, and it is `''` when the workspace is empty.
  - `agent_hash` is `sha256(agent_id)`, or `''`.
  - Truncation: session_id and run_id to 160 characters, stage and outcome to 64, reason_code and memory_id to 128. Empty values become NULL.
- Retention, applied on every insert: events older than 90 days are deleted globally, and only the newest 5,000 per `(workspace_hash, agent_hash)` are kept. `PROTOCOL.md:286-289` documents these values.
- Stage/outcome values seen in code:
  - `policy/evaluated`
  - `proposal/{accepted, rejected, deduplicated}`
  - `candidate/created`
  - `approval/accepted`
  - `rejection/recorded`
  - `deletion/recorded`
  - `recall/{matched, empty}`
  - `expiration/expired`
  - `feedback/recorded`

  Sources: `tools.py:1205-1249`; `api/continuity.py:185,240,263,294,341,465,496`; `memory.py:415,766`.
- `diagnostics()` returns `status()` merged with:
  - the newest 100 events for the bucket;
  - `counts` as `{'stage:outcome': n}`;
  - `last_proposal` (the first event with stage `proposal`);
  - `last_approval` (stage `approval`, outcome `accepted`);
  - `history_available`.

### 4.20 Maintenance and status

- `maintain()` (`memory.py:746-779`):
  - Marks rows stale where `valid_until < now`, using `UPDATE stale=1` with no revision bump, and records `expiration/expired` events.
  - Computes conflicts for approved rows that were not already stale.
  - Returns `{ok, expired_marked_stale, conflict_count: sum(len)//2, conflicts: {id: [...]}}`.
- `status()` (`memory.py:781-804`) returns `{encrypted: True, cipher: 'AES-256-GCM', approved_count, candidate_count, candidate_ttl_days: 30, stale_count, expired_count, conflict_count, semantic_encrypted: True, memory_version: 2}`.
  - `candidate_ttl_days` is hard-coded rather than derived from the constant.
  - `conflict_count` is the number of approved rows with at least one conflict.
  - The cost is O(N²): `conflicts_for` calls `list()`, which decrypts every row, once per approved item.
  - Measured: 200 saves took 0.53 s, and `status()` then took 0.56 s. For 200 memories titled `'Topic N note'`, `status()` reported `conflict_count=200`.

### 4.21 Export and import (`memory.py:806-835`)

- Export document: `{"format": "locus-memory-export", "version": 2, "exported_at": <float>, "memories": [<public record>...]}`. It covers every status and scope for the target, has no embedding or feedback, and is plaintext JSON on purpose (`PROTOCOL.md:279-280`).
- Import:
  - Requires `format == 'locus-memory-export'` and a version of 1 or 2. Otherwise the error is `'memory import format is not supported'`.
  - `memories` must be a list of at most 10,000 items. Otherwise the error is `'memory import is malformed or too large'`.
  - Entries that are not dicts are skipped.
  - Each item is saved with its own id and `default_status` taken from its raw status. That preserves ids, status, scope, pinned and stale, overwrites existing ids, and lets an imported file insert approved records without Inbox review.
  - There is no transaction, so a mid-import error leaves a partial import.

### 4.22 Prompt formatting (`format_memory_results`, `memory.py:838-849`)

- No results: `'No approved memory matched that query.'`. It never returns an empty string.
- With results: the header `'Approved memory results (local user-controlled context):'`, then for each item `'\n## {title} [{kind} · {scope}{ · stale}]\nWhy recalled: {retrieval_reason or "matched the request"}\n{content}'`. The joined text is capped at 30,000 characters.

### 4.23 Concurrency, atomicity and connections

- The RLock belongs to the instance (`memory.py:112`), but `memory_vault()` builds a new instance on every call, sometimes twice per request (`api/continuity.py:179,185,234,240`). Safety across instances and processes rests only on SQLite transactions and the `_store_embedding` CAS.
- `save` commits before `conflicts_for` runs. A decrypt error inside `conflicts_for` returns 422 to the client even though the row was persisted (CONFIRMED (probe)).
- `import_values` is not transactional.
- Connections are never closed. On Python 3.14 this emits `ResourceWarning`, and handles and WAL readers are only released when garbage collection runs.
- Each construction runs the DDL, the chmod and a key-file read.

### 4.24 Exact error strings

```text
the memory encryption key is unavailable
the memory encryption key is invalid
memory encryption requires a 256-bit key
workspace memory requires an active workspace
workspace memory target is invalid
agent memory requires an agent id
memory scope must be personal, workspace, or agent
a memory record could not be decrypted
a memory record is malformed
memory id is invalid
memory status or scope is invalid
memory content cannot be empty
memory type must be preference, fact, decision, procedure, or relationship
memory confidence must be between 0 and 1
memory {name} must be a Unix timestamp
memory valid-until date must be after its valid-from date
memory candidate not found
memory conflict resolution must be keep_both or replace
memory search requires a query
memory feedback must be helpful, ignored, or incorrect
memory not found
memory import format is not supported
memory import is malformed or too large
```

### 4.25 Callers

| Method | Callers |
|---|---|
| `MemoryVault()` constructor | `memory_runtime.py:13`; `tools.py:1181` (search); `tools.py:1198` (propose); tests `test_memory.py:14,61,69`, `test_product_backend.py:228` |
| `save` | `memory_runtime.py:22` (legacy migration); `api/continuity.py:179` (create), `:216` (update), `:476` (reprocess); `api/knowledge.py:117,133`; `tools.py:1223` (propose_memory); `approve` (379, 385); `import_values` (830) |
| `approve` | `api/continuity.py:234` |
| `list` | `api/continuity.py:167,446`; `api/knowledge.py:103`; internal: `conflicts_for`, `search`, `delete_all`, `maintain`, `status`, `export` |
| `search` | `server.py:326` (automatic recall); `api/continuity.py:284`; `tools.py:1181` |
| `delete` | `api/continuity.py:261`; `api/knowledge.py:149` |
| `delete_all` | `api/continuity.py:205` (all scopes); `api/knowledge.py:160` (`['workspace']`) |
| `feedback` | `api/continuity.py:340` |
| `record_event` | `api/continuity.py:185,240,263,294,341,465,496`; `tools.py:1205,1211,1215,1219,1242,1244,1247`; `expire_candidates` (415); `maintain` (763) |
| `diagnostics` / `maintain` / `status` / `export` / `import_values` | `api/continuity.py:369 / 357 / 156 / 312 / 324`; `status` also from `test_agent_config.py:161` |
| `format_memory_results` | `server.py:337`; `tools.py:1192` |

---

## 5. Memory runtime and the legacy plaintext migration (`memory_runtime.py`)

| Symbol | Location | Behavior |
|---|---|---|
| `memory_vault(workspace='') -> MemoryVault` | `memory_runtime.py:11-32` | Opens `MemoryVault()` on every call. When the workspace is non-blank, it migrates the legacy plaintext workspace notes (below). |
| `memory_workspace(service, workspace='') -> str` | `memory_runtime.py:35-36` | Returns `workspace.strip()`, else `service.core.workspace_root`, else `service.core.cwd`. The client-supplied value is trusted as given. |

How the migration works:

1. `KnowledgeStore(workspace)` opens the knowledge DB. This requires an existing directory (otherwise `KnowledgeError`) and **creates** `APP_DIR/knowledge/<sha256(resolved)[:24]>/knowledge.sqlite3` as a side effect (`knowledge.py:52-72`).
2. For each legacy row from `list_memories()`, it calls `vault.save({**memory, 'scope': 'workspace', 'status': 'approved'}, 'legacy-' + sha256(f'{Path(ws).resolve()}|{legacy_id}'.encode()).hexdigest()[:40], workspace=ws)`. The resulting id is 47 characters. The path is resolved without `expanduser`.
3. It then calls `legacy.delete_memory(legacy_id)`. A legacy row is deleted only after the encrypted save succeeds.
4. It catches only `KnowledgeError`, `MemoryError` and `OSError`. The first such error aborts the loop.

Legacy row format: the `KnowledgeStore.memories` table has columns `id, title, content, tags_json, source_session_id, source_run_id, pinned, stale, created_at, updated_at` (`knowledge.py:120-131`).

A scratchpad run of the migration produced these results:

- The migrated row had id `legacy-acaeb97c79f07…`, revision 1, `pinned=True` preserved, `kind` `fact` and `confidence` 1.0. **`created_at` and `updated_at` were set to the migration time**; the original timestamps are lost (`memory.py:330`). The legacy table was empty afterwards.
- Running it again with no legacy rows is a no-op, apart from opening and listing the `KnowledgeStore`.
- **Crash between save and delete, then retry.** The same deterministic id is upserted again, so there is no duplicate. But the revision is bumped, and any user edits made in between are overwritten with the legacy title, content, tags, pinned and stale (reproduced: an edit `'USER EDITED'` was replaced).
- **One invalid legacy row**, such as one with blank content, raises `MemoryError`. The error is swallowed, the loop stops, every later row never migrates, and the same failure repeats silently on every call.
- **`sqlite3.Error` is not caught** (`issubclass(sqlite3.OperationalError, OSError)` is False). A locked or corrupt knowledge DB raises out of `memory_vault()` and out of `server._automatic_memory_context`, which catches only `(MemoryError, KnowledgeError)`.
- **Physical deletion did not happen.** The legacy DELETE is a plain SQL DELETE in WAL mode with `secure_delete=0` (`knowledge.py:83,545-547`). The plaintext canary was still in `knowledge.sqlite3-wal` right after migration, and still in `knowledge.sqlite3` after `PRAGMA wal_checkpoint(TRUNCATE)`.

Coverage gaps:

- `tools.py` builds `MemoryVault()` directly and never migrates.
- The feedback route calls `memory_vault()` with no workspace (`api/continuity.py:339`), so it never migrates either.
- Until a migrating route has run for a workspace, `KnowledgeStore.search` keeps returning the legacy plaintext rows as `kind='memory'`, `source='approved_memory'` (`knowledge.py:477-488`, checked).

How often it runs: on every `memory_vault(workspace)` call. That includes every `/api/memory*` and `/api/knowledge/memories*` request and every chat turn through `server.py:326`, and sometimes happens twice per request.

No current code path inserts into the legacy table. It is still read by `KnowledgeStore.search`, by `list_memories` and by `settings().memory_count` (`knowledge.py:162`).

---

## 6. Continuity: context snapshots and skill observations (`continuity.py`, 548 lines)

### 6.1 Symbols

| Symbol | Location | Summary |
|---|---|---|
| `ContinuityError(RuntimeError)` | `continuity.py:28` | The single error type |
| `SNAPSHOT_TTL_SECONDS`, `MAX_SNAPSHOTS_PER_WORKSPACE` | `continuity.py:21-22` | 2,592,000 (30 days); 50 |
| `VALID_OBSERVATION_STATUSES` | `continuity.py:25` | `{'OPEN','ACTIONED','DECLINED'}` |
| `_workspace_target(workspace) -> str` | `continuity.py:32-39` | `sha256(str(Path(ws).expanduser().resolve()).encode()).hexdigest()`, with no prefix and no salt. A blank workspace raises `'cross-chat context requires an active workspace'`; an `OSError` or `RuntimeError` raises `'workspace path is invalid'` |
| `_bounded_text(value, limit=8000)` | `continuity.py:42-43` | `str(value or '').strip()[:limit]` |
| `_tokens(value) -> set[str]` | `continuity.py:46-50` | `[a-z0-9_./-]{2,}` on lowercased text, minus the stopwords `{the, and, for, with, from, this, that, into}` |
| `workspace_changed_files(workspace) -> list[str]` | `continuity.py:53-79` | Runs `git -C ws status --porcelain=v1 -z` with `proxy.sanitized_child_environment()` and a 5 s timeout. Returns at most 100 paths of at most 1,000 characters each, or `[]` on error or a non-zero exit |
| `ContinuityStore(path=None, *, key=None, fallback_key_path=None)` | `continuity.py:82-515` | Uses `memory_database()` and `_master_key`; WAL; runs DDL on every construction; chmods to 0600 |
| `_snapshot_aad` / `_observation_aad` | `continuity.py:144-150` | AAD builders (below) |
| `save_snapshot(workspace, session_id, payload, *, pinned=False)` | `continuity.py:172-242` | Rolling upsert |
| `_prune_snapshots(conn, target, now)` | `continuity.py:244-263` | TTL and cap |
| `list_snapshots(workspace, *, exclude_session='', limit=50)` | `continuity.py:265-290` | Prunes first. Limit is clamped to 1-100. Undecryptable rows are skipped |
| `search_snapshots(query, workspace, *, exclude_session='', limit=2)` | `continuity.py:292-316` | Lexical ranking. Limit is clamped to 0-10 |
| `delete_snapshot` / `set_snapshot_pinned` / `clear_snapshots` | `continuity.py:318-361` | Scoped to the workspace. `clear_snapshots` also removes pinned rows |
| `record_observation(workspace, payload)` | `continuity.py:384-437` | Numbers the observation under `BEGIN IMMEDIATE` |
| `list_observations(workspace, *, status='', limit=200)` | `continuity.py:439-461` | Limit is clamped to 1-1000. Ordered by `number DESC`. Undecryptable rows are skipped |
| `set_observation_status` / `delete_observation` / `export_observations` | `continuity.py:463-515` | `set_observation_status` re-encrypts |
| `format_context_snapshots(results, max_tokens) -> str` | `continuity.py:518-542` | Prompt block |

### 6.2 Schema and envelope

```sql
-- context_snapshots (continuity.py:110-123)
id TEXT PRIMARY KEY, session_id TEXT NOT NULL, workspace_hash TEXT NOT NULL,
nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, pinned INTEGER NOT NULL DEFAULT 0,
created_at REAL NOT NULL, updated_at REAL NOT NULL, expires_at REAL,
UNIQUE(session_id, workspace_hash)
-- index context_snapshots_lookup_idx ON (workspace_hash, pinned, updated_at DESC)

-- skill_observations (continuity.py:124-136)
id TEXT PRIMARY KEY, number INTEGER NOT NULL, workspace_hash TEXT NOT NULL,
status TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
created_at REAL NOT NULL, updated_at REAL NOT NULL,
UNIQUE(workspace_hash, number)
-- index skill_observations_lookup_idx ON (workspace_hash, status, number DESC)
```

- Snapshot AAD: `f"locus-context-v1|{id}|{session_id}|{workspace_hash}".encode()` (`continuity.py:146`). `pinned` and the timestamps are not authenticated.
- Observation AAD: `f"locus-observation-v1|{id}|{number}|{workspace_hash}|{STATUS}".encode()` (`continuity.py:150`). Because status is bound, any status change requires re-encryption.
- Plaintext is `json.dumps(document, separators=(',', ':'))`, using the default `ensure_ascii=True` and **without** `sort_keys`. This differs from `MemoryVault`.
- The nonce is 12 random bytes, and ids are 32-character hex.
- There are three near-duplicate seal and open implementations: `MemoryVault._seal/_open_payload` and two inside `ContinuityStore`.
- There is no schema version and there are no migrations for these tables.

### 6.3 Context snapshots (the closest thing to episodes)

Payload fields and limits (`continuity.py:181-204`):

| Field | Limit |
|---|---|
| `session_id` | 160 characters; empty raises `'context snapshot requires a session id'` |
| `goal` | 4,000 characters |
| `outcome` | 8,000 characters |
| `mode` | 32 characters |
| `plan` | kept only if it is a dict; **size not bounded** |
| `todos` | first 100 dict items, each `{content ≤1000, status ≤32}`; items with empty content are dropped |
| `checkpoint` | kept only if it is a dict; **size not bounded** |
| `changed_files` | first 100, each ≤1,000 characters |
| `pending` | 4,000 characters |

How snapshots are written and kept:

- **Rolling upsert** keyed by `UNIQUE(session_id, workspace_hash)`. The existing id, `created_at` and `pinned` are preserved, so the `pinned` argument only takes effect for new rows (D31).
- **Expiry.** Unpinned rows get `expires_at = now + 30d`; pinned rows get NULL.
- **Pruning** happens on every save and every list. Expired unpinned rows are deleted in **all** workspaces, then each workspace keeps only its newest 50 unpinned rows by `updated_at`. Pinned rows have no cap.
- **Search.** Each snapshot scores `overlap*10 + 4*pinned - min(age_days,30)/30`, with `updated_at` as the tiebreak, over the top 50 listed rows. Overlap is counted against goal, outcome, pending and changed_files. **There is no minimum score**, so the most recent snapshots are returned even when nothing overlaps.
- **Formatting.** Returns `''` for no results or for `max_tokens <= 0`. Otherwise it starts with the 103-character header `'Cross-chat workspace context (local encrypted session snapshots; verify against the current workspace):'`, then a `'## Prior session {session_id}'` block per snapshot with Goal, Outcome, Pending, Changed files (first 30, joined with `', '`) and Open steps (first 20 non-completed todos, joined with `'; '`). The whole string is cut at `max_tokens*4` characters.
- **Decrypted record shape.** The payload keys come first, then the row fields override them: `{id, session_id, pinned: bool, created_at, updated_at, expires_at}`.

Where snapshots come from:

- **Automatic capture.** `_capture_continuity_snapshot` (`server.py:369-401/406`) runs in the solo turn's `finally` when the turn completed and is neither just_chat nor private identity (`server.py:760-768`). It also runs for a team on `terminal_reason == 'complete'` (`server.py:1256-1281`). The fields are:
  - `goal`: the raw user text.
  - `outcome`: `_latest_assistant_output(core)` (`server.py:2171-2180/2181`). With a task journal bound, that is `json.dumps({execution_receipts: [last 100], assistant_claims})`, up to 120k characters.
  - `plan`: `tool_ctx.plan_document`.
  - `todos`: `tool_ctx.todos`.
  - `checkpoint`: `run_store.latest_checkpoint(run_id)`.
  - `changed_files`: from git.
  - `pending`: the open todos joined.
  - Errors are swallowed.
- **Explicit capture.** The `capture_context_snapshot` tool (`tools.py:1279/1280-1310`) does the same upsert from model-written fields.

### 6.4 Skill observations (procedural candidates)

Validation and defaults (`continuity.py:386-407`):

- `issue`, `suggested_improvement` and `principle` are required unless `payload['checkpoint_only'] is True`. Otherwise the error is `'skill observations require issue, suggested improvement, and principle'`.
- Default title is `'Skill observation'`, or `'Observation checkpoint'` when checkpoint_only.
- `skill` defaults to `'All skills'`.
- `type` is `'internal'` when `str(type).lower() == 'internal'`, else `'open-source'`.
- Limits: title 200; session_context 2,000; skill 200; phase_area 500; issue, suggested_improvement and principle 4,000 each; source ids 160.

Numbering and status:

- `number = MAX(number) + 1` per workspace under `BEGIN IMMEDIATE`. Deleting the highest-numbered observation lets the next one reuse its number (D33).
- New observations start as `OPEN`. Status input is upper-cased. An invalid status raises `'invalid observation status'`.

Other:

- Export document: `{format: 'locus-skill-observations', version: 1, exported_at, observations[≤1000]}`. There is no import.
- The only writer is the `record_skill_observation` tool (`tools.py:1255/1256-1277`). It adds `source_session_id`/`source_run_id` from the tool context, which overwrite any model-supplied values. The HTTP API has list, status, delete and export, but no create route.
- No code turns observations into skill changes, and nothing reads them back into prompts.

### 6.5 Coupling with `MemoryVault`

`ContinuityStore` never reads or writes the `memories` or `memory_events` tables, and snapshots and observations are never promoted into memory candidates. The coupling is limited to:

- the shared DB file and key;
- the shared API module (`api/continuity.py`);
- the shared `MemoryPolicy` dataclass.

`recall_enabled` does not gate continuity; only `cross_chat_context_enabled` does (`server.py:317-318` vs `349-354`).

---

## 7. Workspace knowledge index and documents (`knowledge.py`, 690 lines)

### 7.1 Symbols

| Symbol | Location | Summary |
|---|---|---|
| `KnowledgeStore(workspace, path=None)` | `knowledge.py:65` | One SQLite DB per canonical workspace, with a process-wide RLock per DB path (`_LOCKS`, 44-45, 70-71). Construction creates the directory and schema, migrates columns and rewrites `settings.workspace` |
| `canonical_workspace(ws) -> Path` | `knowledge.py:52` | `Path(ws).expanduser().resolve()`. Raises `'workspace is not an existing directory'`. Accepts `/` |
| `workspace_database(ws) -> Path` | `knowledge.py:59-62` | `APP_DIR/knowledge/sha256(str(resolved))[:24]/knowledge.sqlite3` |
| `settings()` | `knowledge.py:157` | `{workspace, enabled, documents_enabled, embedding_model, ollama_host, exclusions, vector_generation, last_indexed, last_error, document_count, chunk_count, memory_count, vector_available: True, vector_backend: 'local_exact'}`. `memory_count` counts the legacy plaintext table |
| `configure(...)` | `knowledge.py:174-216` | Changing the model bumps `vector_generation` and nulls all embeddings. The host must be loopback. Exclusions are normalized. Disabling deletes non-text documents at once |
| `reindex(changed_paths=None)` | `knowledge.py:218-310` | Full or partial reindex (§7.3) |
| `_candidate_paths` / `_eligible` | `knowledge.py:312-368` | Enumeration and admission |
| `index_extracted_document` / `remove_document_chunks` / `has_document_hash` / `document_path_allowed` | `knowledge.py:370-412` | Ingestion API used by the document library |
| `_embed_missing(model, host)` | `knowledge.py:414-437` | Up to 2,000 chunks per call, in batches of 32. Native-endian float32. Takes no lock and does not re-check the generation before writing |
| `search(query, limit=8)` | `knowledge.py:439-501` | Hybrid search (§7.4) |
| `_vector_search(...)` | `knowledge.py:503-536` | Pure-Python exact cosine scan |
| `list_memories` / `delete_memory` / `_memory` | `knowledge.py:538-557` | Legacy plaintext notes |
| `delete_all()` | `knowledge.py:559-566` | Clears `chunks_fts`, `chunks`, `documents` and `memories`, and resets `last_indexed`/`last_error`. Settings and the DB file stay |
| `_chunks(content)` | `knowledge.py:569-587` | Line-based chunks of at least 6,000 characters with an 8-line overlap; line numbers are 1-based and inclusive |
| `cosine_similarity(left, right)` | `knowledge.py:590-596` | `zip(strict=True)`. Returns 0.0 when either norm is 0. Shared with `MemoryVault.search` (`memory.py:584`) |
| `embed_texts(model, host, inputs)` | `knowledge.py:599-624` | `POST {host}/api/embed {model, input}` with `timeout=120` |
| `_validate_local_ollama_host(host)` | `knowledge.py:627-642` | http or https; hostname `localhost` (trailing dot stripped) or any loopback IP; no userinfo, query or fragment |
| `_exclusion_patterns(values)` | `knowledge.py:645` | First 200 values; stripped; `\` replaced with `/`; at most 512 characters; empties dropped; deduped and sorted |
| `format_search_results(results)` | `knowledge.py:654-683` | Model-facing evidence (§7.4) |
| `knowledge_store(service, workspace='')` | `knowledge_runtime.py:7-19` | Uses the explicit workspace, else `core.workspace_root`, else `cwd` |

### 7.2 Schema (`knowledge.py:84-155`)

- **`settings`**: `singleton INTEGER PK CHECK = 1`, `workspace`, `enabled DEFAULT 1`, `embedding_model DEFAULT ''`, `ollama_host DEFAULT 'http://localhost:11434'`, `exclusions_json DEFAULT '[]'`, `vector_generation DEFAULT 0`, `last_indexed REAL`, `last_error TEXT`, and the added column `documents_enabled DEFAULT 0`.
- **`documents`**: `path PK`, `content_hash`, `size`, `mtime`, `indexed_at`, and the added column `format DEFAULT 'text'`.
- **`chunks`**: `id INTEGER PK AUTOINCREMENT`, `path` (FK to `documents(path)` `ON DELETE CASCADE`), `line_start`, `line_end`, `content`, `content_hash`, `embedding BLOB`, `embedding_dimension`, `vector_generation`, and the added column `locator_json`. Indexed by `chunks_path_idx`.
- **`chunks_fts`**: `USING fts5(content, path UNINDEXED, chunk_id UNINDEXED, tokenize='unicode61')`.
- **`memories`** (legacy plaintext): `id TEXT PK`, `title`, `content`, `tags_json DEFAULT '[]'`, `source_session_id`, `source_run_id`, `pinned`, `stale`, `created_at`, `updated_at`.

Migrations are additive `ALTER TABLE` statements gated on `PRAGMA table_info` (`knowledge.py:134-148`), with no `user_version`. The DB uses WAL and is chmodded to 0600 after initialization (`knowledge.py:152-155`). The parent directory is created with the default umask, which produced 0755 in a probe and on disk; `~/.ollama-code` itself is 0700.

### 7.3 Indexing behavior

- **Limits** (`knowledge.py:25-43`): `MAX_FILE_BYTES` 2 MiB, `MAX_FILES` 20,000, `MAX_CHUNKS` 100,000, `CHUNK_CHARS` 6,000, `CHUNK_OVERLAP_LINES` 8.
- **Rejected paths:**
  - symlinks;
  - `SKIPPED_DIRECTORIES` (`.git, .hg, .svn, .venv, venv, node_modules, dist, build, .next, .build, target, vendor, Pods, DerivedData, __pycache__`);
  - any hidden directory component;
  - `SECRET_NAMES` (`.env*`, `id_rsa`/`dsa`/`ecdsa`/`ed25519`, `*.pem|key|p12|pfx|cer|crt`, `credentials*`, `secrets*`);
  - user glob exclusions, matched with `fnmatchcase` on the relative POSIX path.

  Hidden files are allowed if their extension is allowed. pdf, docx, xlsx, csv and tsv are eligible only when `documents_enabled` is on. A NUL byte in the first 8,192 bytes marks a file binary. Text is decoded as UTF-8 with `errors='replace'`.
- **Enumeration:** `git ls-files -z --cached --others --exclude-standard` with a sanitized environment and a 30 s timeout. If git fails, `os.walk(followlinks=False)` is used instead. `changed_paths` are capped at 5,000; each is resolved, and any outside the root is dropped.
- **Reindex steps:**
  1. Files whose SHA-256 is unchanged are skipped.
  2. For each changed file, old chunks and FTS rows are deleted and new ones inserted, all in **one write transaction held across all file I/O**.
  3. A full reindex then removes stored text documents that were not seen.
  4. `last_indexed` is set and the transaction commits.
  5. Missing chunks are embedded. An embedding failure is written to `last_error`, and FTS stays usable.
  6. When documents are enabled, `DocumentStore.reconcile()` and submission run.
- **Response shape:** a disabled store returns settings plus `{updated: 0, removed: 0, duration_ms: 0}` with no `embedded` key. An enabled store adds `embedded`.

### 7.4 Search and output

- The query is trimmed and cut to 2,000 characters; empty raises `'knowledge search requires a query'`. The limit is clamped to 1-20. A disabled store returns `[]`. A store that has never been indexed runs a **synchronous** full reindex first.
- FTS query: terms matching `[\w.-]+` with length >1, at most 16, each double-quoted with internal quotes doubled, joined with `' OR '`. The query fetches `limit*4` rows, ranked by bm25, but each hit's score is positional, `1/(pos+1)`.
- Legacy notes are matched with `LIKE` (unescaped, so `%` matches every note) and score `1.2/(pos+1)`. They come back as `{id:'memory:<id>', kind:'memory', source:'approved_memory', title, snippet, path:'', line_start:0, line_end:0, score, freshness, stale}`.
- Vector scores are added to file hits and set `source` to `'hybrid'`. Vector errors are swallowed.
- File result shape: `{id:'file:<chunk_id>', kind:'file', source:'text'|'vector'|'hybrid', path, line_start, line_end, snippet(≤6000), score, freshness, locator, content_hash, format}`.
- `format_search_results`:
  - Header: `'Workspace knowledge results (untrusted evidence; verify before acting):'`.
  - Each result: `'\n## {location} [{source}]\n{snippet}'`. Location is `path:start-end`, a `locus-workspace://open/<path>?locator=<json>&hash=<sha256>` markdown link for pdf, paragraph and sheet locators, or `'approved memory: <title>'`.
  - Capped at 30,000 characters. Snippets are not escaped.
  - Empty: `'No workspace knowledge matched that query.'`.

### 7.5 Embedding transport

- Request: `requests.post(host.rstrip('/') + '/api/embed', json={'model', 'input'}, timeout=120)`. The response must contain `embeddings` with the same length as the inputs, and every vector must be non-empty and float-castable.
- Errors: `'Ollama returned an invalid embedding batch'`, `'...invalid embedding vector'`, `'...empty embedding vector'`. HTTP errors propagate as `requests.HTTPError`.
- An empty model or empty input returns `[]` without any HTTP call.
- **Redirects are followed.** A probe confirmed that a 307 re-POSTs the request body to the redirect target. The response size is unbounded.
- The embedding host is never added to `NO_PROXY`. Only `core.py:354,1393` call `ensure_no_proxy_host`, and only for the core Ollama host. The app's default `NO_PROXY` is `localhost,127.0.0.1,::1` (`LocusTests/FeatureLogicTests.swift:2862`).
- Default host strings differ: `http://localhost:11434` in the knowledge settings, but `http://127.0.0.1:11434` in the server, route and tool fallbacks.

### 7.6 Capability gate and documents

- `LOCUS_CAPABILITY_WORKSPACE_KNOWLEDGE` is on by default. The values 0, false, no, off and disabled turn it off (`capabilities.py:18,28-35`).
- When it is off:
  - `/api/knowledge/{status,settings,reindex,changes,search}`, `DELETE /api/knowledge` and every document route return 404 `'capability is disabled: workspace_knowledge'`.
  - The `search_workspace_knowledge` tool is hidden (`tool_registry.py:69-76,1788-1789`).
  - `/api/knowledge/memories*` still return 200; they are not gated.
  - Automatic memory recall breaks (D39).
- The document library (`document_library.py`) stores `document-library.sqlite3` and `document-jobs/<id>/{source,result.json}` in the same per-workspace knowledge directory. Files are 0600 and directories 0700, and **the extracted text is plaintext**. It publishes into the index through `index_extracted_document` (`document_library.py:438`). Extraction limits are in `document_extract.py:18-24`: 100 MB source, 5 MB text, `EXTRACTOR_VERSION='locus-documents-1'`.
- `DELETE /api/knowledge` does not remove `library_documents` rows or `result.json` files.

---

## 8. Sessions, transcript search and prompt decoration

### 8.1 Session archive (`sessions.py`)

- **File layout.** One append-only JSONL file per conversation at `APP_DIR/sessions/<YYYYmmdd-HHMMSS-mmm>-<slug(cwd)[-40:]>[-N].jsonl`, created exclusively, with `-1`…`-999` suffixes on collision (`sessions.py:579-592`). The first line is `{"type":"meta", cwd, model, provider, account, account_id, started}`.
- **Record types:** `meta, message, model, chatgpt_thread, agent_activity, compacted_context, pending_task_input, native_tool_observation, approved_task_plan, task_plan, response_parts_staged, verification_observation, session_started, detached_session_created, schedule_session_created, schedule_side_chat_created, agent_target_created, agent_side_chat_created`.
- **Message keys:** `role, content, run_id, team_run_id, _item_id, _reasoning_format, _phase, _display_only, _display_reasoning, _display_reasoning_sections, _response_parts, _locus_context, _compaction_summary, _activity_label, tool_calls, tool_call_id, name, media, attachments, event_trigger, solo_swarm, identity_mode, _identity_source_refs`.
- **Message identity.** The address is a positional `message_index` that counts every `type == 'message'` record with a dict payload. Only assistant messages carry a stable id: `_item_id = uuid4().hex` (`core.py:2084`), or the provider item id. User and tool messages have no id. Provenance today is `session_id + run_id` (`tools.py:1234-1235`).
- **Durability.** User messages, and any message written while a goal or capsule runtime is active, use `append_strict` with fsync (`sessions.py:621-631`; `core.py:2112-2113`). Other writes use `append`, which silently drops `OSError` (`sessions.py:610-619`).
- **Limits:** `MAX_SESSION_BYTES` 64 MiB, `MAX_SESSION_LINE_BYTES` 2 MiB, `MAX_SESSION_MESSAGES` 20,000, and 4 MiB for the metadata and organization files (`sessions.py:30-34`).
- **Plaintext** UTF-8 with `ensure_ascii=False`. Image bytes are left out of classic user messages (`core.py:3098-3108`).
- **Loading.** `load_context` replays the messages after the last `compacted_context` record. Any unmatched `pending_task_input` steers are appended as one synthetic `_locus_context` user message (`sessions.py:765-787`). `context_records` and `load_context` open files without `errors='replace'`, so corrupt UTF-8 raises an error. `load()` is tolerant of it.
- **Prompt decoration.** `strip_prompt_decoration(content)` (`sessions.py:1562-1572`) applies only when `content.lstrip()` starts with `'[Locus mode:'`. It returns the text after the **last** `'User request:'` marker, or `''` if the marker is missing. `split_parity_prompt` is in the same block (1562-1596). This is a contract with the Swift `decoratedPrompt` (`Locus/AppModel+ChatWorkers.swift:831-946`), which wraps the user's text as follows: `'[Locus mode: X]'`, the mode instruction, `'Use this explicitly selected context:'` with full file contents, attachment text, and finally `'User request:'`.

### 8.2 Transcript search index (`transcript_search.py`)

- **Location:** `APP_DIR/transcript-index.sqlite3`, bound at import (`transcript_search.py:25,36`). WAL, chmod 0600, **plaintext**.
- **Schema:**
  - `settings(singleton=1, schema_version INT DEFAULT 2, built_at)`
  - `sessions(session_id PK, mtime, size, indexed_bytes, message_count, indexed_at)`
  - `messages_fts USING fts5(content, session_id UNINDEXED, message_index UNINDEXED, role UNINDEXED, phase UNINDEXED, item_id UNINDEXED, reasoning_sections UNINDEXED, tokenize='unicode61')`

  A schema-version mismatch drops all three and recreates them (`transcript_search.py:83-90`).
- **Sync:** a stat-diff on `(mtime, size)` runs before every search.
  - A file that grew is tail-parsed from `indexed_bytes`.
  - A file that shrank is forgotten and re-read.
  - A torn last line stops parsing for that file.
  - Removed sessions are forgotten.
  - When more than 8 MiB is pending, the build moves to a daemon thread and the response reports `indexing: true` (`transcript_search.py:122-194`).
- **Indexed content:** only user and assistant roles. User text goes through `strip_prompt_decoration`. Empty assistant content falls back to the joined `_display_reasoning_sections`. Each row is cut to 100,000 characters (`transcript_search.py:252-275`). `_locus_context`, `_display_only` and `identity_mode` messages are **not** filtered out.
- **Query:**
  - Cut to 500 characters. Terms match `[\w.-]+` with length >1; the first 16 are quoted and OR-joined.
  - `ORDER BY bm25 LIMIT limit*6`, at most 3 hits per session, score `1/(pos+1)`, limit clamped to 1-50.
  - Snippets are 24 tokens, with `\x01`/`\x02` sentinels turned into `highlights [[start, len]]` counted in code points, and `'…'` ellipses.
  - Response: `{query, indexing, duration_ms, results}` (`transcript_search.py:301-375`).
- **Singleton:** `session_runtime.transcript_index()` (`session_runtime.py:20-31`) is one per process and is rebuilt when `DEFAULT_PATH` changes.
- `DELETE /api/sessions` calls `delete_all()` (`api/sessions.py:363-367`). Deleting a single session relies on the next sync to remove it.

---

## 9. Prompt and context assembly

### 9.1 Automatic recall before the model call

| Symbol | Location | Behavior |
|---|---|---|
| `_automatic_memory_context(core, query, configuration, *, just_chat, agent_id='primary') -> str` | `server.py:309-338/339` | Returns `''` when `recall_enabled` is false or `max_automatic_memories` is 0. `just_chat` removes the `workspace` scope (`server.py:320`); returns `''` if no scope remains. Reads `embedding_model` and `ollama_host` from `_knowledge_store(workspace).settings()` (325), which raises `HTTPException` when the capability is off. Calls `memory_vault(ws).search(..., limit=max_automatic_memories)` (326). Returns `format_memory_results(...)[:max_automatic_tokens*4]` (337-338). Catches only `MemoryError` and `KnowledgeError` (335/336-337). |
| `_automatic_continuity_context(core, query, configuration, *, just_chat) -> str` | `server.py:341-366` | Returns `''` for just_chat, when `cross_chat_context_enabled` is false, or when either max is 0. Otherwise `ContinuityStore().search_snapshots(query, workspace_root or cwd, exclude_session=<current>, limit=max_automatic_context_snapshots)` (358), formatted with `max_automatic_context_tokens` (366). Errors are swallowed and give `''`. |
| `_capture_continuity_snapshot(svc, *, goal, mode, configuration, run_id, plan=None, todos=None)` | `server.py:369-401/406/408` | End-of-turn capture (§6.3). Never raises. |
| `_latest_assistant_output(core)` | `server.py:2171-2180/2181` | Without a journal: the last assistant content, cut to 20k characters. With a journal: receipt JSON, cut to 120k. |

Call sites:

- **Solo turn** (`_run_user_turn`, `server.py:453-791`):
  - `start_run` at 502-516 and `TaskJournal.bind` at 517-518.
  - `tool_ctx.memory_session_id` and `memory_run_id` set at 553-554.
  - `parity_turn` computed at 565-570 (chatgpt, native mode, and supports parity).
  - Recall at 571-573 and continuity at 574. Both are skipped for parity turns and private identity.
  - `configure_agent(memory_context, continuity_context, agent_id=agent_profile.id)` at 577-587.
  - `core.run_turn` at 711.
  - Capture in `finally` at 760-768.
  - `memory_run_id` cleared at 791. **`core.memory_context` is never cleared.**
  - **Recall runs before the turn's `try` block, which starts at 685.**
  - **Recall is called without `agent_id`, so it defaults to `'primary'` even on profile turns (D40).**
- **Team turn:** for each manifest profile, `raw_profile['_memory_context']` is set to memory plus continuity joined by a blank line, with `agent_id=profile.id` (`server.py:891-916`; memory at 902, continuity at 909). `AgentProfile.memory_context` is parsed from `_memory_context` and capped at 24,000 characters (`orchestration.py:191,219`). It is rendered under **`'Approved memory'`** by `AgentProfile.system_prompt` (`orchestration.py:257-267`).
- **Team writer slot:** memory only, no continuity (`server.py:2079-2089`; recall at 2082). Writer-route snapshot and restore are at `server.py:2211-2212` and `2296-2304`.
- **Helpers:** collaboration helpers get `configure_agent(agent_id=spec.agent_id)`, `memory_workspace` set to the parent root, and session and run ids (`collaboration_bridge.py:194-207, 279-281`). They receive no automatic `memory_context`.
- **Evaluation:** evaluation cores are configured without memory (`evaluation_runtime.py:109`).

### 9.2 Prompt composition

- `AgentCore.configure_agent(value, *, mode='work', memory_context='', continuity_context='', fallback_name='Locus', fallback_instructions='', role_contract='', agent_id='primary')` (`core.py:824-873`):
  - Stores `memory_context[:24000]` (848) and `continuity_context[:24000]`, which is `''` in ask mode (849-851).
  - Sets `self.agent_id` to `str(agent_id or 'primary')[:128]` (842).
  - Sets `tool_ctx.memory_workspace`, `memory_agent_id`, `memory_scopes` (with `workspace` removed in ask mode, 853-858), `memory_search_enabled`, `memory_proposals_enabled` and `cross_chat_context_enabled` (false in ask mode, 863-865).
  - Ends with `reset_system_message`.
- `compose_system_prompt(locked_prompt, configuration, *, mode, role_contract='', project_context=None, memory_context='', continuity_context='')` (`agent_config.py:251-298/299`) emits these layers in order:
  1. Locked runtime rules
  2. Locked role and access contract (optional)
  3. Locked answer contract (not in ask mode)
  4. Editable agent behavior
  5. Saved specialist method (optional)
  6. **`Approved memory`**, when `memory_context.strip()` is non-empty (283-284)
  7. **`Cross-chat workspace context`**, when not in ask mode (285-286)
  8. `Workspace instructions from <name>`

  Each layer renders as `'## {title}\n{content}'`. Layers are separated by a blank line, with a trailing newline.
- `AgentCore.system_message(mode=None)` (`core.py:875-933`) uses this composition (898-906). In identity mode it returns `IDENTITY_SYSTEM_PROMPT` instead.
- **Delivery paths:**
  - Classic route: `messages[0]` in `_request_messages` (`core.py:3811-3850`, sent at 3934).
  - Non-parity managed route (claude_plan, or chatgpt with native mode off): `instructions = system_message` (`core.py:2289`), passed as `start_thread(base_instructions=...)` (`core.py:2452-2457`). The instructions text is hashed into the thread fingerprint (`core.py:2295-2303`), so **any change in recall forks a new native thread**.
  - ChatGPT native parity: `_parity_developer_instructions` (`core.py:1834-1860`) is memory-free on purpose, because it is fingerprinted. `parity_schemas` (`tool_registry.py:1478-1530`) omit `search_memory` and `propose_memory`.
- **Compaction** never summarizes the system message. It starts a **non-ephemeral** native thread with `base_instructions=messages[0]` (`context_preservation.py:150`), which includes the memory layer.
- `memory_context` is never written to JSONL, because `messages[0]` is assigned directly (`core.py:994-999`).
- **Stale context.** After a turn, `memory_context` stays set. `retry_last` (`server.py:2833-2841`), `/init` (`core.py:4817`) and `/api/response-preview` (`api/system.py:283-284`) reuse the previous turn's recall. Only `enable_identity_mode` clears it (`core.py:4727`).
- `solo_profile_boundary` (`agent_profile_runtime.py:41-71`) snapshots and restores `memory_context` and `continuity_context` around profile turns.
- **Context meter.** `context_breakdown` (`context_usage.py:7-95`) puts the `Approved memory` and `Cross-chat workspace context` layers in the `memory` category, with tokens counted as `len('## {name}\n{content}')//4`. In identity mode or parity it returns a single `provider_context` category instead.

### 9.3 Memory policy (`agent_config.py:54-65`, parsed at `129-196`)

| Field | Default | Range |
|---|---|---|
| `recall_enabled` | True | bool |
| `proposals_enabled` | True | bool |
| `search_enabled` | True | bool |
| `scopes` | `('personal','workspace','agent')` | Filtered to `VALID_MEMORY_SCOPES` (`agent_config.py:16`) and deduped in order. A non-list value means all three; `[]` means an empty tuple. |
| `max_automatic_memories` | 8 | 0-20 |
| `max_automatic_tokens` | 1200 | 0-4000 |
| `cross_chat_context_enabled` | True | bool |
| `max_automatic_context_snapshots` | 2 | 0-10 |
| `max_automatic_context_tokens` | 1200 | 0-4000 |

- The client supplies the policy with every message, inside `user_message.agent_config.memory_policy` (`server.py:2472`; `PROTOCOL.md:877`).
- The Swift mirror is `AgentMemoryPolicy` (`Locus/AgentTeams.swift:147-205`), with identical bounds.

### 9.4 Token budgeting

All limits are character-based truncation:

| Where | Limit |
|---|---|
| Recall output | `max_automatic_tokens*4` (`server.py:338`) |
| Continuity output | `max_automatic_context_tokens*4` (`continuity.py:542`) |
| Stored by `configure_agent` | 24,000 characters (`core.py:848-851`) |
| Team profile | 24,000 characters (`orchestration.py:219`) |
| `format_memory_results` | 30,000 characters |

Memory is not budgeted on its own; compaction counts it only as part of `messages[0]` (`core.py:1922,3200-3203`). Three token estimators disagree:

- `core.approx_tokens`: `chars//4` (`core.py:1950`)
- `context_usage`: `len//4` (`context_usage.py:55`)
- `context_preservation.token_estimate`: `(utf8_bytes+2)//3` (`context_preservation.py:191-193`)

---

## 10. Agent tools

| Tool | Implementation | Behavior |
|---|---|---|
| `search_memory {query, scopes?, limit?}` | `tools.py:1160-1192` | Filters the requested scopes against `ctx.memory_scopes` (1166-1168). **The filtered list can be `[]`, which the vault treats as all scopes (D1).** Reads the embedding settings from `KnowledgeStore(ctx.memory_workspace or ctx.cwd)` and ignores errors (1172-1180). Uses `MemoryVault().search` directly, so no migration runs. Returns `format_memory_results`. |
| `propose_memory {title, content, scope, reason, tags?, kind?, confidence?, valid_until?}` | `tools.py:1195-1253` | Checks policy and scope. Saves `status='candidate'` with `default_status='candidate'`, title default `'Suggested memory'` (1225) and source ids taken from ctx (1234-1235). Records `policy`, `proposal` and `candidate` events. Uses `MemoryVault()` directly. |
| `record_skill_observation {title, session_context, skill, type, phase_area, issue, suggested_improvement, principle, checkpoint_only}` | `tools.py:1255/1256-1276/1277` | No policy flag. Writes to `ctx.memory_workspace or ctx.cwd`. Returns `'Skill observation #{n} recorded for user review. No skill was changed automatically.'` or the checkpoint message. |
| `capture_context_snapshot {goal, outcome, pending?, mode in [work, plan, grill, build], pinned?}` | `tools.py:1279/1280-1310` | Gated by `ctx.cross_chat_context_enabled`; returns `'Error: cross-chat context is disabled for this agent.'` when off. Returns `'Encrypted context handoff saved for session {id}.'` |
| `search_workspace_knowledge {query, limit?}` | `tools.py:1140-1157` | `KnowledgeStore(ctx.cwd).search`; in a task checkout that is the **worktree** path. The schema (`tools.py:1470`) and the prompt (`core.py:3780-3781`) say it covers approved memories, but it only reads legacy plaintext notes. |

Schemas are at `tools.py:1406-1476`. The memory fields of `ToolContext` are at `tools.py:101-108`: `memory_workspace`, `memory_agent_id='primary'`, `memory_scopes`, `memory_search_enabled`, `memory_proposals_enabled`, `memory_session_id`, `memory_run_id` and `cross_chat_context_enabled`.

How the tools are classified:

- `SAFE_TOOLS` (never prompt the user, `tools.py:52-60`) includes `search_memory`, `propose_memory`, `record_skill_observation` and `capture_context_snapshot`. `_base_schemas` keeps `SAFE_TOOLS` even under the read_only access ceiling (`tool_registry.py:64-70`).
- `search_memory` is read-only and parallel-safe (`tool_registry.py:51-61`), even though it writes (§4.15).
- Root-only: `_SOLO_ROOT_ONLY_TOOLS` (`core.py:113-131`) and `_NON_DELEGABLE_TOOLS` (`solo_swarm.py:41-51`) exclude `propose_memory`, `capture_context_snapshot` and `record_skill_observation`. `search_memory` is delegable.
- `BASE_SYSTEM_PROMPT` rule 8 tells the model to call `propose_memory` (`core.py:269`). `JUST_CHAT_SYSTEM_PROMPT` mentions approved personal and agent memory (`core.py:283`).

---

## 11. Keys, data roots, editions and identity flow

### 11.1 Data roots

| Runtime | `APP_DIR` (memory lives in `APP_DIR/memory/`) | Source |
|---|---|---|
| Locus app (standard edition) | `~/.ollama-code`, because `OLLAMA_CODE_HOME` is not set. This is shared with the standalone CLI. | `Locus/AppEdition.swift:57-65`; `LocusTests/AppEditionTests.swift:56-57` |
| LocusX app | `~/Library/Application Support/LocusX/Agent` | `Locus/AppEdition.swift:61-63` |
| Per-chat worker backends | same as the app; same `APP_DIR` | `Locus/AppModel+ChatWorkers.swift:28-78` |
| Independent runtime (Locus only) | `~/.ollama-code`; the helper sets `LOCUS_CODEX_HOME` but not `OLLAMA_CODE_HOME` | `RuntimeHelper/main.swift:7-31`; `runtime.py:460-488` |
| Remote SSH-installed runtime | `<root>/profile` (`OLLAMA_CODE_HOME`), so the key is at `<root>/profile/memory/master.key` | `runtime_install.py:192-200` |
| Tests | session temp dir; per-test `tmp_path/'dot-ollama-code'` | `agent/tests/conftest.py:41-90` |

- `BackendProcess` merges the edition environment last, so an inherited shell `OLLAMA_CODE_HOME` cannot move LocusX elsewhere (`BackendProcess.swift:145-147`).
- It also sets `LOCUS_EDITION`, which no Python code reads.
- LocusX refuses to launch without its bundled runtime (`BackendProcess.swift:49-54,114-116`).
- `APP_DIR` is bound at import (`paths.py:14`). `memory.py`, `knowledge.py` and `document_library.py` read `paths.APP_DIR` on every call, while `transcript_search.py` and `config.py` bind it at import.

### 11.2 Secrets handoff and auth

- **Memory key:** nothing memory-specific crosses from Swift to Python: no key, no path, no environment variable. The key is the file described in §4.8.
- **Existing secret channels:**
  - `LOCUS_AGENT_TOKEN` in the environment, popped at startup (`BackendProcess.swift:91`; `server.py:3040`).
  - The proxy credential as stdin JSON `{"proxy_credential": ...}` when `LOCUS_BOOTSTRAP_SECRETS_STDIN=1` (`BackendProcess.swift:149-198`; `proxy.py:86-102`).
  - Provider API keys in the `POST /api/provider` body, held only in memory.
  - Workers also get `LOCUS_CODEX_BROKER_TOKEN` in the environment (`AppModel+ChatWorkers.swift:44-45`).
  - A code comment notes that environment variables are readable through `KERN_PROCARGS2` (`BackendProcess.swift:149-153`).
- **Auth middleware** `block_browser_origins` (`server.py:241-260`):
  - Returns 403 for an `Origin` that is not allowlisted.
  - Returns 401 unless `x-locus-token` equals `app.state.auth_token`. The comparison uses `!=`, not a constant-time compare.
  - A standalone loopback server without `LOCUS_AGENT_TOKEN` has **no auth**. A non-loopback `--host` requires a token (`server.py:3040-3044`).
- There is no per-user or per-workspace authorization. The service comes from `app.state` (`api/dependencies.py:8-19`).
- **Keychain patterns already in Locus** (to copy if the key moves): `KeychainIdentityVaultKeyProvider` (`Locus/IdentityVaultStore.swift:12-44`) stores a generic-password item with service `<bundle>.identity-vault.v1`, account `identity-vault-master-key-v1` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. It generates 32 bytes with `SecRandomCopyBytes` and re-reads on `errSecDuplicateItem`. The browser autofill key works the same way (`Locus/BrowserPrivacy.swift:258-316`). Service names follow `<bundleId>.<suffix>` (`AppEdition.swift:48-50`).

### 11.3 Workspace identity flow

The workspace reaches the backend in three ways:

1. The launch argument `--cwd <workspaceRoot>` (`BackendProcess.swift:71-76`).
2. The WebSocket message `{type:'set_cwd', path}` (`server.py:2868-2876`).
3. A REST `workspace` query or body field set to `AppModel.workspacePath` (`AppModel.swift:1147`; `WorkspaceKnowledgeModel.swift:92,316,...`).

Python uses the value as given, or falls back to `core.workspace_root` or `cwd`. Task checkouts set `workspace_root` to the source root (`core.py:1738-1775`; `server.py:1634-1637`), but `tool_ctx.cwd` points at the worktree (`core.py:1744-1757`).

**No route checks the workspace against workspaces the user has opened.** Knowledge routes accept any existing directory, including `/` (CONFIRMED (probe)). Vault scope accepts any non-empty string.

The same workspace is hashed in many different ways:

| Store | Hash |
|---|---|
| Vault target | `'workspace:' + sha256(str(Path(ws).expanduser().resolve()))` (full hex) |
| `memory_events.workspace_hash` | `sha256(raw workspace string)` |
| Continuity | `sha256(str(Path(ws).expanduser().resolve()))`, no prefix |
| Knowledge directory | `sha256(str(resolved))[:24]` |
| Legacy migration id | `sha256(f'{Path(ws).resolve()}\|{id}')[:40]`, no expanduser |
| Sessions store | `expanduser().resolve(strict=False)` (`sessions.py:201-202`) |
| Swift boards and crew chat | `sha256(workspace)` (`BoardStore.swift:128-136`; `AgentCrewChatModel.swift:82-88`) |
| langgraph-workflow plugin | `digest(str(workspace))[:12]` (`mcp_server.py:463-469`) |
| Agent Dispatcher state dir | `sha256({path, dev, ino})` (`repo_store.py:56`) |

### 11.4 Agent identity flow

- The default principal is `'primary'` everywhere (`core.py:438,834`; `tools.py:102`; `api/continuity.py:152,162,182,...`; Swift default parameters).
- A `user_message` frame carries `agent_profile.id = AgentProfile.id.uuidString`, an uppercase UUID (`AppModel+AgentWorld.swift:107-118`; `AppModel+SendPipeline.swift:414-437`).
- The server checks it against the session-bound `agent_profile_id` or `agent_world_profile_id`, case-insensitively (`server.py:2420-2437,2536-2538`).
- `parse_solo_profile` requires the profile's model to equal `core.model` (`agent_profile_runtime.py:10-18`). The id then flows through `configure_agent(agent_id=profile.id)`, which sets `tool_ctx.memory_agent_id` (`server.py:2542-2546,577-587`; `core.py:842,857`).
- Profile ids must be non-empty, at most 128 characters, and contain no `/`, `\` or NUL (`orchestration.py:196-200,3399-3403`).
- REST memory calls send the "Memory owner" picker value, which is `'primary'` or the profile UUID (`AgentTeamsSettingsView.swift:3100-3111`).
- `/remember` always saves with `'primary'` (`LocusApp.swift:1141-1148`).
- Agent ids are hashed case-sensitively (`memory.py:93-96`). Normalizing them (for example to lowercase) would orphan existing agent-scope memories.
- Personal memories go to every agent whose policy includes `personal` (`server.py:891-913`; `agent_config.py:58`). The UI says personal is "Available to the primary agent across workspaces" (`AgentTeamsSettingsView.swift:3619`).

---

## 12. Procedural learning, episodes, evaluation and recovery (adjacent systems)

These systems sit next to the memory domain. They are listed so their contracts are known; most remain Locus-owned (see the ownership document).

| System | Files | What matters for memory |
|---|---|---|
| Reusable checks (procedural constraints learned from corrections) | `reusable_checks.py:14-239`; `reusable_check_runtime.py`; `api/reusable_checks.py:20-186` | Stored in `agent-runs.sqlite3` (migration 17) as plaintext and include the correction text, up to 240k characters. Lifecycle: proposed → approved or dismissed. Editing an approved check creates a new proposed version. Disable works only on an active check. Reviews are revision-checked ('This check changed. Reload before reviewing it.'). Proposals are created only by an explicit `POST /api/reusable-checks/propose`. Frozen at admission into `task_records`. |
| Task state and verification receipts | `task_state.py:22-360` | `CHECK_SCHEMA` and `normalize_checks`: kinds `file_exists`, `file_contains`, `json_value`, `command`, `human_review`; ≤64 checks; timeout 1-600 s, default 120. `encoded()` is `json.dumps(sort_keys=True, ensure_ascii=False, separators=(',',':'), allow_nan=False)` and `digest()` is the sha256 of that. Receipts are written only by `TaskVerifier` after real tool execution. Completion statuses: passed, failed, needs_review, accepted, not_applicable. |
| Task journal | `task_journal.py:41-179` | Task id is chosen from the owners `run:`, `capsule:`, `goal:`, `session:`. Returns None in identity mode. Plans are immutable per id. Every routed tool call writes a `task_observations kind='tool'` row with `result[-8000:]` (`core.py:4270-4290`). Milestones are deduplicated by `sha256(encoded([kind, evidence]))`. The `task_reviews` table is never used. |
| Usage ledgers | `usage_ledger.py:131-351`; `task_usage_ledger.py:78-196`; `model_usage.py:14-156`; `pricing.py:9-32` | Two classes are both named `UsageLedger`. The two price tables diverge. A memory engine that makes model calls (embeddings, summaries) would need to report usage into them. |
| Capsules and recovery | `capsules.py:213-424` (APP_DIR/task-capsules.sqlite3); `capsule_progress.py:53-460` | Execution state, not memory. Each revision keeps the plan and recipe. |
| Goals | `goals.py`; `goal_runtime.py:147-190` | `goals.py:280-290` writes `task_records` directly. |
| Evaluations | `evaluations.py:32-515`; `evaluation_runtime.py:32-435`; `api/evaluations.py` | Agent-task evaluation, not memory-retrieval evaluation. It has pure helpers (`grade_case`, `summarize_results`, `compare_results`, `configuration_fingerprint` with secret scrubbing) that could be copied. Cores run with `skip_permissions=True` (`evaluation_runtime.py:103-108`). |
| Skills catalog and activation | `extensions.py:191-239,795-903,1470-1754,2296-2323`; `tool_registry.py:1203-1241,1851-1892` | `APP_DIR/extensions/state.json` version 3. Activation is per turn and not stored: `$name` mentions (regex at `extensions.py:72`). `skill_index` is limited to `min(ctx*8%, 8000)` characters. Builtin skills are always explicit-activation. |
| Selected-chat memory review | `api/continuity.py:399-527` | Regex extraction with no model call. Details below. |
| Routing samples | `runstore.py:3936-3975`; `model_router.py:83` | Outcome learning that belongs to provider routing, not memory. |
| Run DB schema | `runstore.py:53,154-185,745-777,4095-4124` | `SCHEMA_VERSION=20`. A backup is written before each upgrade (`agent-runs.sqlite3.schema-N.backup`). A newer schema on disk makes the store read-only. `prune` removes only runs (90 days or 2 GiB); task, usage, capsule-attempt and reusable-check rows are never pruned. |

How `memory_reprocess` (`POST /api/memory/reprocess`) works:

1. `SessionStore.path_for(session_id)`. Returns 404 `'session not found'` if missing; `SessionTooLargeError` becomes 413.
2. Starts a `RunStore` run with `run_kind='memory_review'` and `state='running'`, and appends a `memory_review_started` event.
3. Scans user messages only. Each text goes through `strip_prompt_decoration`, then is skipped if it is empty, longer than 4,000 characters, has no cue match, or has a secret match.
   - Cue regex: `\b(?:remember|always|never|prefer|preference|decided|decision|do not|don't|must|should use|confirmed|that worked|fixed|resolved)\b`, case-insensitive.
   - Secret regex: `(?i)(?:api[_-]?key|authorization|password|secret|bearer\s+[A-Za-z0-9])`.
4. Collapses whitespace and cuts to 2,000 characters, then dedupes case-insensitively against every existing memory for the workspace and agent (any status, all scopes). A duplicate records `proposal/deduplicated` with reason `existing_memory`.
5. Saves `{title:'From selected chat', reason:'Explicit durable wording found during selected-chat review.', scope:'workspace', status:'candidate', kind:'preference', confidence:0.8, source_session_id, source_run_id}`. A `MemoryError` from the save is skipped. Records `proposal/accepted`.
6. Stops at 20 candidates. Appends `memory_review_completed {candidate_count, outcome: candidates_created|no_durable_memories}` and sets the run to completed with `recoverable=False`.

It does not check the session's `identity_mode`, and it does not check that the session belongs to the target workspace. If the vault fails after `start_run`, the run is left in the running state (D13).

---

## 13. HTTP and WebSocket route contract

All routes need `x-locus-token` when a token is set. The route snapshot `agent/tests/fixtures/server-routes.txt` pins every route listed here: about lines 22-55 for continuity, knowledge and memory, line 82 for `/api/sessions/search`, and 219-231 for documents. `test_app_factory.py:121-124` compares it after sorting. Registration is in `api/continuity.py:530-584` and `api/knowledge.py:249-274`.

### 13.1 Memory (`api/continuity.py`)

| Method and path | Handler | Request | Response and notes |
|---|---|---|---|
| `GET /api/memory/status` | `:150 memory_status` | query `workspace=''`, `agent_id='primary'` | `status()` dict (§4.20). An uncaught `MemoryError` gives 500 |
| `GET /api/memory` | `:159 memory_list` | `workspace`, `agent_id`, `status` (an invalid value means no filter) | `{memories:[record (+conflicts for candidates)]}`. Uncaught `MemoryError` gives 500 |
| `POST /api/memory` | `:173 memory_create` | body: record fields plus `workspace`, `agent_id`, `scope` (default workspace), `status` (default **approved**) | `{ok:true, memory: record+conflicts}`. Records `approval` or `proposal` with outcome `accepted`. Builds the vault twice. 422 on `MemoryError` |
| `DELETE /api/memory` | `:199 memory_delete_all` | `workspace`, `agent_id` | `{ok:true, deleted}`. Covers all scopes, **including global personal**. Does not touch snapshots or observations |
| `PUT /api/memory/{memory_id}` | `:209 memory_update` | full record plus `workspace`, `agent_id` (Swift sends the encoded `WorkspaceMemory` plus `valid_until: null`) | `{ok:true, memory}`. **Omitting `status` approves the record**, with no approval event and no conflict resolution. 422 |
| `POST /api/memory/{memory_id}/approve` | `:227 memory_approve` | `{workspace, agent_id, resolution: keep_both\|replace}` | `{ok:true, memory}`. Records `approval/accepted`. A missing id gives 422 `'memory candidate not found'` |
| `DELETE /api/memory/{memory_id}` | `:252 memory_delete` | `workspace`, `agent_id`, `outcome=delete\|reject` | `{ok:true, id}` or 404 `'memory not found'`. Deletion is **not scoped** |
| `GET /api/memory/search` | `:273 memory_search` | `query` (1-2000), `workspace`, `agent_id`, `limit` 1-20 (default 8) | `{results:[record+retrieval_reason+score]}`. Records `recall/matched\|empty` with reason `approved_only`. **404 when workspace_knowledge is off.** No Swift caller |
| `GET /api/memory/export` | `:306 memory_export` | `workspace`, `agent_id` | export document (§4.21) |
| `POST /api/memory/import` | `:315 memory_import` | `{workspace, agent_id, document}` | `{ok:true, imported}`. 422 `'memory import requires a document'` |
| `POST /api/memory/{memory_id}/feedback` | `:334 memory_feedback` | `{outcome: helpful\|ignored\|incorrect}` | `{ok:true, memory}`. Not scoped; the event goes to the empty bucket. No Swift caller |
| `POST /api/memory/maintenance/run` | `:352 memory_maintenance` | `{workspace, agent_id}` | `{ok, expired_marked_stale, conflict_count, conflicts}` |
| `GET /api/memory/diagnostics` | `:363 memory_diagnostics` | `workspace`, `agent_id` | diagnostics plus `{proposal_policy: enabled\|disabled, enabled_scopes, propose_memory_available, indexed_files, search_chunks, embedding_model, embedding_error}`. Catches only `KnowledgeError` and `OSError` (370-373) |
| `POST /api/memory/reprocess` | `:399 memory_reprocess` | `{session_id, workspace?, agent_id?}` | `{ok, run_id, state:'completed', candidate_count, memories}`. 404 or 413 |

### 13.2 Continuity (`api/continuity.py`)

| Method and path | Handler | Request | Response and notes |
|---|---|---|---|
| `GET /api/context-snapshots` | `:38` | `workspace`, `limit` 1-100 (default 50) | `{snapshots:[...]}`. 422 on `ContinuityError` or `MemoryError` |
| `PUT /api/context-snapshots/{id}` | `:50` | `{workspace?, pinned: bool}` | `{ok, snapshot}`. A non-bool `pinned` gives 422. **Any `ContinuityError`, including an invalid workspace, gives 404** |
| `DELETE /api/context-snapshots/{id}` | `:67` | `workspace` | `{ok}` or 404 `'context snapshot not found'` |
| `DELETE /api/context-snapshots` | `:82` | `workspace` | `{ok, deleted}`. Also removes pinned rows |
| `GET /api/skill-observations` | `:93` | `workspace`, `status` | `{observations:[...]}`. An invalid status gives 422 |
| `PUT /api/skill-observations/{id}` | `:109` | `{workspace?, status}` | `{ok, observation}`. **Not found gives 422** |
| `DELETE /api/skill-observations/{id}` | `:124` | `workspace` | `{ok}` or 404 `'skill observation not found'` |
| `GET /api/skill-observations/export` | `:139` | `workspace` | `{format:'locus-skill-observations', version:1, exported_at, observations}` |

`_continuity_store()` (`api/continuity.py:31-35`) builds a new store for each request. Tests monkeypatch it. A third copy of `_knowledge_store` lives at `api/continuity.py:22`.

### 13.3 Knowledge and documents (`api/knowledge.py`)

| Method and path | Handler | Notes |
|---|---|---|
| `GET /api/knowledge/status` | `:31` | settings dict. 404 when the capability is off; 422 for a workspace that is not a directory |
| `POST /api/knowledge/settings` | `:38` | `{workspace?, enabled?, embedding_model?, ollama_host?, exclusions?, documents_enabled?}`. Non-list exclusions give 422. **An invalid or non-loopback host gives 500, from an uncaught `KnowledgeError`.** Disabling calls `DocumentStore.cancel_persistent()` (62-63) |
| `POST /api/knowledge/reindex` | `:67` | settings plus counters |
| `POST /api/knowledge/changes` | `:74` | `{paths: [...]}`, first 5,000; non-array gives 422 `'paths must be an array'`. No Swift caller |
| `GET /api/knowledge/search` | `:85` | `query` 1-2000, `limit` 1-20 |
| `GET /api/knowledge/memories` | `:97` | Legacy route: approved workspace-scope vault records. Not capability-gated. Runs the migration. No Swift caller |
| `POST /api/knowledge/memories` | `:111` | Forces `scope=workspace`, `status=approved`. Writes no events. No Swift caller |
| `PUT /api/knowledge/memories/{id}` | `:126` | Forces `workspace/approved` on **any** id: re-scopes personal or agent records and approves candidates. Full replace. No Swift caller |
| `DELETE /api/knowledge/memories/{id}` | `:143` | Unscoped delete by id. 404 `'workspace memory not found'`. No Swift caller |
| `DELETE /api/knowledge` | `:154` | `KnowledgeStore.delete_all()` plus `vault.delete_all(scopes=['workspace'])`. 404 when the capability is off, and then the vault is not touched |
| `GET /api/documents`, `DELETE /api/documents/{id}`, `POST /api/documents/{id}/exclude`, `GET/POST /api/document-jobs`, `POST /api/document-jobs/upload` (100 MB, streamed), `GET /api/document-jobs/{id}`, `GET /api/document-jobs/{id}/result`, `POST /api/document-jobs/{id}/cancel` | `:169-241` | Delegate to `DocumentStore(str(store.root))` |

`_knowledge_store` exists three times: `api/knowledge.py:22`, `api/continuity.py:22` and `server.py:278`. Each applies the capability gate (404) and turns a construction `KnowledgeError` into 422.

### 13.4 Sessions and others

| Route | Handler | Notes |
|---|---|---|
| `GET /api/sessions/search` | `api/sessions.py:176` (registered at 955) | `query` 1-500 (missing or empty gives 422), `limit` 1-50. 404 when `transcript_search` is off |
| `DELETE /api/sessions` / `DELETE /api/sessions/{id}` / `POST /api/sessions/restore` / `POST /api/sessions/{id}/duplicate` / `POST /api/sessions/{id}/resume` / `POST /api/sessions/{id}/handoff` / `POST /api/sessions/new` | `api/sessions.py:349,373,517,651,797,844,187` | Session boundaries. None of them cascades to memory-derived stores |
| `POST /api/response-preview` | `api/system.py:300` (layers at 283-284) | Shows the stale memory layer and mutates `core.agent_configuration` |
| WS `user_message` | `server.py:2412-2594` | `{type, text, mode, agent_config (with memory_policy), agent_profile?, conversation_profile_id?, identity_mode?, team?, attachments?, approved_plan?, capsule_context?, run_id?}` |
| WS `set_cwd`, `new_session`, `clear`, `retry_last`, `resume`, `compact` | `server.py:2833-2909` | Session boundaries |
| WS `question_response` / `question_async_response` / `question_editing` | `server.py:2395-2397,2618-2630` | Durable question answers (§15) |
| WS `notes_action_request`/`result`, `board_action_request`/`result`, `set_notes_control` | `chat_service.py:1143-1172`; `AppModel+PermissionsAndCapabilities.swift:223-340`; `server.py:2733-2738` | Notes and board memory channels (§15) |

### 13.5 Swift client contract

`WorkspaceKnowledgeModel` (`Locus/WorkspaceKnowledgeModel.swift`) is a `@MainActor` `ObservableObject`:

- Its refresh calls seven endpoints: `/api/knowledge/status`, `/api/memory` twice, `/api/memory/status`, `/api/memory/diagnostics`, `/api/context-snapshots` and `/api/skill-observations` (87-137). `LocusTests/WorkspaceKnowledgeModelTests.swift` pins this.
- Actions:
  - remember (300-341, posts status `approved`)
  - forget (344-370; candidates get `outcome=reject`)
  - update (373-401; sends the full object plus explicit `valid_until: null`)
  - approve (403-430)
  - reprocess (453-485)
  - export (486-512, `NSSavePanel`, plaintext)
  - import (529)
  - delete-all (545-563; toast at 581)
  - snapshot and observation actions (139-250)
  - settings (254-278; always sends `ollamaHostProvider()`)
  - watcher-driven full reindex with a 650 ms debounce (54-85)

Codable DTOs in `Locus/AgentTeams.swift`:

| DTO | Lines | Fields (JSON keys) |
|---|---|---|
| `AgentMemoryScope` | 123-130 | `personal`, `workspace`, `agent` |
| `MemoryKind` | 132-145 | `preference`, `fact`, `decision`, `procedure`, `relationship` |
| `AgentMemoryPolicy` | 147-205 | mirrors `MemoryPolicy` (§9.3) |
| `WorkspaceKnowledgeStatus` | 2013-2043 | `workspace, enabled, documents_enabled?, embedding_model, ollama_host, exclusions?, vector_generation, last_indexed?, last_error?, document_count, chunk_count, memory_count, vector_available, vector_backend` |
| `ContextSnapshot` | 2045-2066 | `id, session_id, goal, outcome, mode, changed_files, pending, pinned, created_at, updated_at, expires_at?`. `goal`, `outcome`, `mode`, `changed_files` and `pending` are non-optional. `plan`, `todos` and `checkpoint` are not decoded |
| `SkillObservation` | 2077-2106 | `id, number, status, title, session_context, skill, type, phase_area, issue, suggested_improvement, principle, checkpoint_only, source_session_id, source_run_id, created_at, updated_at`. The source ids must be strings |
| `WorkspaceMemory` | 2129-2182 | `id, status?, scope?, title, content, tags, source_session_id?, source_run_id?, pinned, stale, reason?, revision?, expires_at?, kind?, confidence?, valid_from?, valid_until?, last_confirmed_at?, last_used_at?, use_count?, superseded_by?, supersedes?, retrieval_reason?, conflicts?, created_at, updated_at`. `provenance` and `embedding_model` are not decoded. Computed: `resolvedScope` (default workspace), `resolvedKind` (default fact), clamped `resolvedConfidence` |
| `MemoryConflict` | 2184-2190 | `id, title, content, kind?, confidence?` |
| `MemoryVaultStatus` | 2192-2215 | `encrypted, cipher, approved_count, candidate_count, candidate_ttl_days, stale_count?, expired_count?, conflict_count?, semantic_encrypted?, memory_version?` |
| `MemoryPipelineEvent` | 2217-2235 | `session_id?, run_id?, stage, outcome, reason_code, memory_id?, occurred_at`. The id is derived as `"\(occurredAt)-\(stage)-\(memoryID ?? "")"` |
| `MemoryDiagnosticReport` | 2237-2272 | `approved_count, candidate_count, stale_count?, expired_count?, indexed_files, search_chunks, embedding_model, embedding_error (string), history_available, proposal_policy?, enabled_scopes?, propose_memory_available?, last_proposal?, last_approval?, events, counts` |
| `MemoryReprocessResponse` | 2274-2286 | `ok, run_id, state, candidate_count, memories` |
| `MemoryMaintenanceResponse` | 2337-2347 | `ok, expired_marked_stale, conflict_count` |

`Locus/Models/BackendResponses.swift:272-296` defines `WorkspaceMemoriesResponse`, `WorkspaceMemoryResponse {ok, memory}`, `MemoryExportDocument {format, version, exported_at, memories}` and `MemoryImportResponse {ok, imported}`.

`Locus/Models/TranscriptModels.swift:868-935` defines the transcript-search hit and response. Highlight offsets are indexed in Unicode scalars, which matches Python's code points.

UI surfaces:

- Settings page "Memory & Knowledge" (`AgentTeamsSettingsView.swift:3085-3520`): Memory owner picker (3100-3111); Inbox with Reject, Approve, Keep Both and Replace Older (3146-3186); saved-memory menu (3462-3487); handoffs (3224-3262); advanced index settings (3320-3368); backup and maintenance (3370-3387); skill observations (3389-3428); Analyze Selected Chat (3430-3451).
- `WorkspaceMemoryEditor` (3522-3624).
- The agent behavior editor's MEMORY section (1371-1411, 1477-1485, 2249-2273).
- `RememberConfirmationView` for `/remember` (`LocusApp.swift:1091-1163`). The command is defined at `SlashCommands.swift:140-142`, and the argument handling is at `AppModel+Commands.swift:69-75`.

---

## 14. Other memory-bearing stores found in the completeness sweep

These stores hold memory-like or memory-derived content but are not part of the vault. The full inventory, with locations and owners, is in the ownership document. Summary:

- **Native provider thread state, plaintext.** Decrypted recalled memory and continuity reach native runtimes as `base_instructions`:
  - `APP_DIR/claude-accounts/<account_id>/locus-sessions/<thread>.json` holds an `instructions` field (`claude_runtime.py:224-247`).
  - The Codex helper's non-ephemeral threads go under `LOCUS_CODEX_HOME` or `APP_DIR/codex` (`codex_app_server.py:79-106,595-623`; `ephemeral=True` only in `complete()` at 845).
  - Compaction threads (`context_preservation.py:150`).
  - Team-member `broker.complete` calls on claude_plan (`orchestration.py:2891-2911`).
- **`questions.sqlite3`** (`question_service.py:107-275`): user answers and delivery texts, plaintext, never deleted.
- **`collaboration.sqlite3`** (`collaboration.py:103-474`; `collaboration_bridge.py:655-700`): helper transcripts plus the parent's last 50 messages (up to 80k characters), plaintext, never deleted. `search_memory` is delegable, so recalled memory can end up here.
- **Runtime install backups** (`runtime_install.py:252-268,371`): copies of every `profile/**/*.sqlite3`, including `memory.sqlite3` (the key is not copied), never pruned.
- **`runtime_*` tables** in `agent-runs.sqlite3` (`runtime_store.py:23-49,136-160`): event and command payloads that include prompts, never pruned.
- **Swift stores:**
  - Notes: plaintext `.txt`/`.styled` per workspace, chat or global; agents read and write them via `notes_read`/`notes_update` (`NotesDocument.swift:671-720`; `tool_registry.py:731-764`).
  - Workspace Boards (`BoardStore.swift:33,128-136`).
  - AgentCrewChat ledger, hard-coded to the `Locus/` folder for both editions (`AgentCrewChatModel.swift:110-113`).
  - UserDefaults: `Locus.promptHistory` (last 50 prompts) and `Locus.checkpoints` (full transcripts, re-injected as "Restored session context:" via `AppModel+ChatWorkers.swift:942-943`); `Locus.sessionOverviewStates.v1`; `Locus.AgentWorld.*`.
- **Project memory files:** `AGENTS.md`, `OLLAMA.md`, `CLAUDE.md` loaded into the system prompt (`core.py:131-133,780-789`). `/init` writes `OLLAMA.md` (`core.py:296-302,4816-4818`).
- **Learned model windows** in `config.json` (`core.py:1197-1285`).
- **Dispatcher project map** `<project>/.agent-dispatcher/project-map.json`, read via `dispatcher_runtime.py:309-323`.
- **Orphans with no writer at HEAD:**
  - `~/.ollama-code/history` (REPL history; `app.py` was removed in `e09f41bb`)
  - `~/.ollama-code/langgraph/{runs.sqlite, workflows/}` (Locus-native LangGraph runtime reverted in `518df429`/`cd47af5e`)
  - `~/Library/Application Support/Locus/Agent/agent-runs.sqlite3`
  - the legacy `model-call-leases.sqlite3`, which the sweeper's glob never matches (`orchestration.py:547`)

---

## 15. Agent Dispatcher (`agent-skills` @ `d68446fe`) contracts

Paths in this section are relative to `/Users/nahid/Documents/agent-skills`. No live `experience.sqlite`, `learning.sqlite` or `repository-index.sqlite` exists on this machine. Only `state-v1/<id>/working-memory/` and the project map and graph JSON were found, by name.

### 15.1 Packaging

There is no importable package. Each module loads its siblings with `exec(compile(source))` into private namespaces (`repository_intelligence.py:30-36`, `experience.py:55-61`, `learning.py:93-99`, `repo_store.py:50-53`). The stable consumer contracts are the CLI `--json` outputs and the context packet (schema_version 1, `context.py:1724`). The packet has optional `repository_intelligence`, `memory` and `learning` sections (`context.py:1747-1759`).

### 15.2 Stores

| Store | Location | Schema |
|---|---|---|
| Deep index | `~/.cache/agent-dispatcher/state-v1/<sha256({path,dev,ino})>` or `id-<sha256({identity})>` `/repository-index.sqlite` | `meta.schema='1'`. Tables: meta, generations, files, terms, symbols (`id = sha256(lang\0path\0qualname\0kind\0occurrence)[:20]`), symbol_aliases, edges, commits, partners, inferences (`repo_store.py:206-231`) |
| Experience | `.../experience.sqlite` | `events(id, task_id, recorded, outcome, status current\|retired\|superseded, superseded_by, record JSON)`, `corrections(id, event_id, path, verdict relevant\|irrelevant, note, created)` (`repo_store.py:570-577`). More than 2,000 current events causes the oldest to be retired |
| Learning | `.../learning.sqlite`; global profile at `~/.cache/agent-dispatcher/learning-v1/profile-<digest32>/learning.sqlite` | Tables: meta, revisions, lifecycle, reviews, evaluations, approvals, generations, observations, enrollments, tombstones (`learning.py:349-367`). Transitions are enforced (`learning.py:44-63`) |
| Episodic and semantic memory | `.../repository-memory.json` (≤24 MiB), `.../memory-semantic.json` (≤8 MiB) | JSON with `schema: 1`. Not HMAC-signed |
| Working memory | `.../working-memory/<sha256(task_id)[:24]>.json` | Schema 1 digest, ≤64 KiB |
| Parser cache | `~/.cache/agent-dispatcher/parser-v1/` | HMAC-signed; the key file sits beside it |

Common properties:

- Hardening: owner-only 0700 directories, regular 0600 files with nlink 1 owned by the uid, read-only opens that create no side files (`repo_store.py:88-120`; `parser_cache.py:102-135`).
- No encryption at rest. Deletion is logical.
- `IndexStore` and `ExperienceStore` share one `SCHEMA=1`. A mismatch raises `'Repository index schema is incompatible; rebuild it.'`, and experience data cannot be rebuilt. No migrations exist.

### 15.3 Experience record (version 1, `experience.py:132-172`)

- Keys: `version, task_id, recorded, task{digest, terms, symbols, paths, summary}, role, config_id, baseline, final{files, digest}, retrieved, inspected (null means unobserved), edited[{path, sha256, association}], checks{observations[]}, outcome, outcome_reason, source, resources, notes?, tests_changed?, id`.
- `id = sha256({task: task_id, final: final.digest, outcome})`.
- Outcomes (`experience.py:22-35`): `checked_success, accepted, grader_passed, exit_code_only, zero_tests, stale_checks, unresolved, failed_checks, infrastructure_error, cancelled, insufficient_evidence, reverted_or_invalidated`.
- Asserting `checked_success`, `grader_passed` or `verified_scoped_success` raises an error.
- Aliases: `unknown→insufficient_evidence`, `in_progress/partial→unresolved`, `abandoned→cancelled`, `failed_verification→failed_checks`, `user_accepted→accepted`.
- Receipt mapping (only `observed_execution` counts):

  | Receipt | Outcome |
  |---|---|
  | `tests_passed` + current | `checked_success` |
  | `tests_passed` + other freshness | `stale_checks` |
  | `tests_failed` / `command_failed` | `failed_checks` |
  | `zero_tests` | `zero_tests` |
  | `command_succeeded` / `executed_unknown` | `exit_code_only` |
  | `timeout` / `denied` / `launch_failed` / `not_run` | `infrastructure_error` |

- Associations: `changed_in_checked_task, changed_in_accepted_task, changed_in_task, user_correction`.

### 15.4 Exports

- `repository_intelligence.py export` (`repository_intelligence.py:337-352`): `{document:'repository-intelligence-export', note, generated, coverage, snapshot (without policy), counts, inferences[]}`. It is **unversioned**, contains summary data only, and is never read back.
- `learning.py export-generation` (`learning.py:1539-1545`): `{schema_version:1, exported, generation_id, policy_digest, revisions[...], note}`. Its importer (`learning.py:1564-1610`) re-validates and re-derives each revision, installs it as `experimental_canary`, and never carries approvals across.
- `revision_identity` = sha256 of the canonical record without `created, creation_cost, revision_id, state, state_reason, runtime_state, runtime_reason, experiment` (`learning_compose.py:636-639`).
- There is **no exporter** for experience events, corrections, episodic or semantic stores, working memory, index records or learning observations.

### 15.5 Defects and risks (reference repository, not the Locus host)

- CONFIRMED (probe): credential-named paths (`.env`, `secrets.yaml`) are stored **by name** in experience records. `build_event` filters only with `_safe_path` and never with `context._skip` (`experience.py:149`).
- CONFIRMED (probe): `repository_memory.load_store` reads an **in-project** legacy file `.agent-dispatcher/repository-memory.json` when no private state exists (`project_map.py:533-550,584`). A forged file can surface as memory hits, and a refresh persists it.
- Redaction gaps, probed on both HEAD and the worktree: `DB_PASSWORD = "..."`, `client_secret: "..."` and JSON `"api_key": "..."` are not redacted (`decision/redact.py:47-48`). The user's uncommitted edit additionally stops redacting unquoted letters-only values.
- Policy and package digests hash the **source bytes** of Dispatcher modules (`repo_builder.py:82-90`; `learning.py:281-337`; `context.py:161-170`). Any code move invalidates every index, episodic store and learned revision.
- Two overlapping experience settings vocabularies: `repo_builder.py:50` and `repository_memory.py:56-57`.
- `prune --retired` leaves orphan corrections (`repository_intelligence.py:326-333`).
- Approval identity is a free-text label plus uid (`learning.py:1093-1110`).
- Working-memory writes race on a fixed `.tmp` name opened with `O_TRUNC`.

---

## 16. langgraph-workflow (`52799242`) integration

Paths are relative to `/Users/nahid/Documents/langgraph-workflow`.

- **Port.** `WorkflowHost` (`src/langgraph_workflow/ports.py:37-92`) has nine methods: `capabilities, admit, revalidate, execute, lookup, cancel, verify, authorize_decision, publish`. `CAPABILITIES = {jobs.read, jobs.write, verify, decisions, events, cancel}` (`ports.py:25-34`). There is **no memory method and no memory capability**. The docstring hands memory authority to the host (`ports.py:5-6`).
- **No long-term store.** Graphs compile with a checkpointer only and no LangGraph `BaseStore` (`executor.py:250-255`). "Scoped memory view / memory candidates" is listed as deferred (`docs/implementation-status.md:146`; `docs/locus-integration-map.md:47`).
- **In-process adapter `LocusHost`** (`integrations/locus/adapter_reference.py:88-345`, harness only, not shipped):
  - Read jobs run through `TeamOrchestrator.run_read_job`, which is patch 0001 and not upstream; it applies cleanly to `b332e455`.
  - Write jobs run through `AgentCore.run_turn`.
  - `verify` goes through `TaskVerifier`.
  - `publish` writes `RunStore` `workflow_event` rows with `execution_engine='langgraph_workflow'`.
  - **It never computes or injects memory.** The reader `AgentProfile` has no `_memory_context`, and `AgentCore` is built without `configure_agent(memory_context=...)` (`integrations/locus/harness.py:105-107,115-118`).
  - `RESPONSE_CONTRACT` and `ROLE` have no `'task'` key, so custom workflows would raise `KeyError` (`adapter_reference.py:60-69`).
- **Plugin mode** (shipped): an MCP stdio server whose jobs are carried out by the Locus agent in ordinary chat turns. Locus's own automatic recall therefore applies implicitly. Plugin data under `LGW_DATA=${PLUGIN_DATA}`:
  - `workspaces/<key>/{agent-host.sqlite3, checkpoints.sqlite3}`
  - `definitions/<id>.json`
  - `workspaces.json`
  - `locus-settings.json`
- **Encryption.** The executor accepts an optional LangGraph `CipherProtocol`, with fail-closed tags of the form `'{kind}+{cipher}'` (`checkpoints.py:76-106`). The plugin passes none (`mcp_server.py:224`). `agent-host.sqlite3` has no encryption option, and its file mode follows the umask (`agent_host.py:73-80`).
- **Ids memory provenance could reference without importing the package:**
  - `operation_id = f'{attempt_id}/{key}'`
  - `event_id = sha256(json([attempt_id, kind, operation_id, key]))[:32]`
  - plugin `attempt_id = run_id = task_id = 'lgw-{key12}-{hex10}'`
  - `LocusHost` job ids `'{operation_id}#{input_fingerprint}'`
  - the identifier regex `^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}$`, with `..` rejected (`contracts.py:57,72-75`)
- **Event schema** `langgraph-workflow.event/1` (`events.py:18`). Redaction covers secret-shaped keys and values, truncates strings at 2,000 characters, and keeps at most 64 items to depth 6 (`events.py:34-66`).
- **What it would need from `locus-memory`:**
  1. A per-job recall and context-compile call that the production `LocusHost` can use to set the reader's `memory_context`, with policy and private-identity gating left to Locus.
  2. Optionally, candidate ingestion from verified workflow outcomes: `AttemptStatus.result {status, blocker, plan_digest, verification, evidence[], jobs{}}` (`state.py:119-129`) and research claims (`research.py:230-231`).
  3. A decision on whether `workflow_event` rows are indexed by the history archive.

---

## 17. Locus tests that touch memory (inventory and gaps)

| File | What it covers |
|---|---|
| `agent/tests/test_memory.py` | `test_database_inspection_includes_uncheckpointed_wal`, `test_memory_content_is_authenticated_ciphertext_at_rest`, `test_memory_uses_a_user_only_local_key_without_keychain`, `test_memory_scope_boundaries_and_just_chat_scope_selection`, `test_candidates_require_approval_and_expire`, `test_memory_export_import_round_trip`, `test_memory_v2_detects_and_resolves_conflicting_decisions`, `test_memory_v2_hybrid_recall_keeps_vectors_encrypted`. Uses a fixed key `b'k'*32` and WAL-aware file inspection (17-25) |
| `agent/tests/test_continuity.py` | Snapshot encryption, rolling upsert, relevance, cap, TTL; observation lifecycle. Its ciphertext check reads only the main DB file, not the WAL (42-44) |
| `agent/tests/test_knowledge.py` | Indexing, exclusions, incremental updates, the tool's output format, the local-host check, exclusion globs |
| `agent/tests/test_transcript_search.py` | 10 tests: lazy build, `message_index` parity, tail sync, trash and restore, decoration stripping, per-session cap, `delete_all`, schema rebuild, torn tail |
| `agent/tests/test_backend.py` | Continuity routes (64-110); `propose_memory` mentioned in the prompt (6160); transcript-search route (6313-6341); diagnostics and reprocess (6529-6575); the memory row in context breakdown (9331) |
| `agent/tests/test_agent_config.py` | Policy bounds (12-35); layer order (58); memory tools without the knowledge capability (153-161); team profile memory (174-188) |
| `agent/tests/test_app_factory.py` | Route snapshot (121-124); per-app isolation (54-95) |
| `agent/tests/test_product_backend.py` | The staged `memory.py` contains `AESGCM` (89-90); per-product key and vault separation (209-271); HTTP isolation (274-375) |
| `agent/tests/test_identity_vault.py:214-223` | Identity mode never calls recall or capture |
| `agent/tests/test_proxy.py:805-817,820` | Credential-stripped git environments for continuity and knowledge |
| `agent/tests/test_capabilities.py:45-53` | Disabling knowledge removes the tool |
| `agent/tests/test_solo_swarm.py:426,826` | `propose_memory` is never given to workers |
| `agent/tests/test_document_library.py` | Document opt-in, migration and citations |
| `agent/tests/test_isolation.py` | `APP_DIR` constants and writes are contained |
| `agent/tests/conftest.py` | Isolation layers. The tripwire audit hook does **not** watch the `sqlite3.connect` event (133-197) |
| Seam stubs | `test_goal_runtime.py:297-299,404-406`, `test_task_reliability.py:71-72`, `test_verified_tasks.py:572-574`, `test_agent_world.py:251-253`, `test_capsule_execution.py:308-310` monkeypatch the server functions **by name** |
| Swift | `LocusTests/WorkspaceKnowledgeModelTests.swift`, `TranscriptSearchModelTests.swift`, `AppEditionTests.swift`, `NotebookStorageTests.swift`, `BoardStoreTests.swift`, `AgentCrewChatTests.swift`, `IdentityVaultStoreTests.swift:136-140` |

No test covers any of the following:

- `memory_runtime` legacy migration
- feedback, `maintain`, `delete_all` and event retention
- the `keep_both` resolution
- `valid_from`/`valid_until` filtering
- the HTTP memory CRUD, approve, export/import and maintenance routes
- `GET /api/memory/search` and `/feedback`
- the `/api/knowledge/memories*` routes
- the tool implementations (`tools.py:1160-1310`)
- the recall, continuity and capture functions themselves, which are always stubbed
- empty-scope fallback, wrong profile agent_id, capability-off recall
- key loss and corruption at the API level
- multi-process key race
- consistency between event hashes and target hashes
- `embed_texts` HTTP contract and redirects
- the vector-generation race and the chunk cap
- `memory_reprocess` heuristics beyond one case
- the transcript index excluding identity-mode and `_locus_context` content
- the instructions-at-rest content in Claude `locus-sessions`

---

## 18. Classification

Status values: **existing** = keep as is in its current owner; **reuse** = extract nearly verbatim; **extend** = extract and change; **new** = absent today; **unknown** = not determined.

| Responsibility | Status | Evidence | Notes |
|---|---|---|---|
| Memory record schema (memories, memory_events) and connection handling | extend | `memory.py:115-173` | Copy the DDL as is for compatibility. Add `user_version`, tolerate or lock against duplicate-column races, close connections, make read-modify-write transactional |
| AES-256-GCM envelope with memory-v1 AAD and canonical JSON | reuse | `memory.py:175-214` | Must be byte-exact. A v2 AAD that also binds pinned, stale, expires_at and superseded_by would be new |
| Continuity envelope (locus-context-v1, locus-observation-v1 AADs) | reuse | `continuity.py:144-170,213-218` | Different JSON canonicalization from memory-v1 (no sort_keys, ensure_ascii True). Unify into one codec that keeps both byte formats |
| Master key sourcing (master.key, O_EXCL, 0600/0700) | extend | `memory.py:35-78` | The package should take an injected key or KeyProvider (`key=` exists but is unused). Keep a file provider for CLI and headless use. Add key-mismatch detection |
| Keychain-held key and rotation | new | none; `IdentityVaultStore.swift:12-44` is the pattern | Locus owns this. Requires reversing `PROTOCOL.md:269-272` and `README.md:143-146` |
| Scope target hashing | reuse | `memory.py:81-97` | Byte-compatible. Unsalted |
| Canonical WorkspaceRef across stores | new | §11.3 table | Nine hashing variants today |
| Record validation, normalization and merge | extend | `memory.py:244-361` | Fix NaN confidence, string tags, unbounded provenance and source ids, the stale embedding after an edit. Make the omitted-fields contract explicit. Add an optimistic revision check |
| Candidate lifecycle (approve, TTL, expiry) | extend | `memory.py:331-333,363-419` | Approval must check the target and must not re-target. Expiry should be per target or moved out of `list()`. Decide whether edits extend the TTL |
| Scope-filtered listing | extend | `memory.py:421-460` | `scopes=[]` must mean no scopes. Isolate rows that fail to decrypt |
| Conflict heuristic | extend | `memory.py:462-502` | Generic titles cause false positives; O(N²) |
| Hybrid retrieval and scoring | extend | `memory.py:529-633` | Pin it with tests first. Counts substrings. Writes use stats inside search. Decrypts every row per query |
| Embedding provider (Ollama `/api/embed`, loopback guard, cosine) | extend | `knowledge.py:590-642` | An Embedder protocol, with a default loopback adapter. Do not follow redirects, bound the response, handle proxies |
| Encrypted embedding cache (CAS reseal) | reuse | `memory.py:504-527` | Invalidate on content, title or tag edits |
| Feedback signal | extend | `memory.py:653-681` | Needs a revision CAS. Currently write-only |
| Pipeline events, retention, diagnostics | reuse | `memory.py:683-744` | Hash the resolved workspace. Attribute expirations correctly |
| Maintenance (valid_until → stale, conflict summary) | reuse | `memory.py:746-779` | Locus triggers or schedules it |
| Vault status report | reuse | `memory.py:781-804` | Consumed by `MemoryVaultStatus`. Derive the TTL days from the constant |
| Export/import `locus-memory-export` v1/v2 | reuse | `memory.py:806-835` | Make import transactional. Stop overwriting or re-targeting foreign ids. Imports should go through review |
| Prompt formatting `format_memory_results` | reuse | `memory.py:838-849` | Return `''` for zero results in automatic mode |
| Legacy plaintext note migration | extend | `memory_runtime.py:11-32` | Run once behind a marker. Skip invalid rows. Keep `created_at`. Never clobber edits. Purge physically. Catch `sqlite3.Error` |
| Workspace resolution from the live session | existing | `memory_runtime.py:35-36` | Locus. Should authorize the workspace instead of trusting the client string |
| REST surface `/api/memory*`, `/api/knowledge/memories*` | existing | `api/continuity.py:150-584`; `api/knowledge.py:97-274` | Thin Locus adapters over the package. Add consistent `MemoryError` handling |
| Agent tools search/propose/observe/capture | extend | `tools.py:1140-1310` | Locus owns the schemas. Fix the empty-scope bypass. The engine must fail closed |
| Automatic per-turn recall orchestration | extend | `server.py:309-366` | Decouple from the knowledge capability, use the correct agent_id, clean the query, return empty when nothing is recalled, catch errors |
| MemoryPolicy | existing | `agent_config.py:55-64,129-196` | Shared contract; Locus resolves it and passes scopes and limits |
| Selected-chat candidate extraction | extend | `api/continuity.py:399-527` | A pure extractor would move to the package. Session loading and run bookkeeping stay in Locus |
| Context snapshots (episodes) | extend | `continuity.py:105-361` | Fix the ignored `pinned`, the lack of `BEGIN IMMEDIATE`, the unbounded plan and checkpoint, decoration in goal, receipt JSON in outcome, and the missing relevance floor |
| Snapshot compilation | reuse | `continuity.py:518-542` | Share the estimator and compiler with memory |
| Skill observations (procedural candidates) | reuse | `continuity.py:124-136,363-515` | Make numbering stable; no import exists |
| Repository observation: git changed files | extend | `continuity.py:53-79` | Rename parsing bug. Inject the environment or runner |
| Workspace knowledge index | reuse/extend | `knowledge.py` | Fix the chunk-cap removal, the generation race, stale oversized chunks, the 500 on settings, the LIKE escaping. Plaintext |
| Document extraction jobs | existing | `document_library.py`, `document_extract.py` | Locus. Publishes through the index ingestion API |
| Transcript FTS index (history archive) | reuse | `transcript_search.py` | Inject a session-source adapter. Filter identity-mode and synthetic messages. Decide on encryption |
| Session JSONL contract | existing (shared-contract) | `sessions.py:567-1515` | Versioned record shapes and `message_index` semantics |
| Prompt decoration contract | reuse (shared-contract) | `sessions.py:1562-1596`; `AppModel+ChatWorkers.swift:831-946` | Needed to clean recall queries and snapshots |
| Prompt layer composition | existing | `agent_config.py:251-299`; `core.py:875-933` | Locus. Layer titles are a contract with `context_usage.py:49` |
| Token estimate utilities | reuse (shared-contract) | `context_preservation.py:191-204` | One estimator for both packages |
| Compaction and protected context | existing | `context_preservation.py` | Locus |
| Native-thread delivery of memory (base_instructions) | new (contract) | `core.py:2289,2452-2457`; `claude_runtime.py:242-247` | Memory should not be persisted in helper state; deliver it per turn |
| Stable message ids for user and tool messages | new | `core.py:2084` (assistant only) | Shared contract |
| Committed-message hook | new | not found (natural seam `core.py:2072-2116`) | Locus call site |
| Session-boundary memory hooks | new | not found | Locus emits, package consumes |
| Automatic candidate extraction at turn, task or session end | new | not found | Package |
| Unified erase across memory, snapshots, observations and derived stores | new | not found | Package API plus Locus cascade |
| Retrieval-quality evaluation harness | new | signals only: feedback, `recall` events | Package |
| Reusable checks (correction-derived) | extend | `reusable_checks.py`; migration 17 | Possibly the package's procedural store; plaintext today |
| Verification receipts, task journal, usage ledgers, capsules, goals | existing | `task_state.py`, `task_journal.py`, `usage_ledger.py`, `task_usage_ledger.py`, `capsules.py`, `goals.py` | Locus. The package references them only as provenance |
| Usage reporting for the package's own model calls | new | none | Shared contract (callback) |
| Skills catalog and activation | existing | `extensions.py`; `tool_registry.py` | Locus |
| Questions, collaboration, provider homes, install backups, runtime_* tables, Notes, Boards, crew ledger, UserDefaults stores | existing | §14 | Locus. These must be part of the erase and retention inventory |
| Codex helper `memories_1.sqlite` | unknown | names only | External binary. Contents not verified |
| knowledge_indexing progress event | unknown | `PROTOCOL.md:1346`, no emitter | Decide whether to keep it |
| Agent Dispatcher experience, episodic, semantic and learning engines | reuse/extend (reference) | agent-skills §15 | Design reference. Bound to the Dispatcher catalog and to source-byte digests |
| langgraph-workflow checkpoint sidecar | existing (external) | `checkpoints.py` | Not memory. Must not be merged into package storage |

---

## 19. Defects and risks found in current host code (Locus)

IDs are referenced from other sections. Severity is a judgment call.

### 19.1 Security, privacy and consent

- **D1 (high, CONFIRMED (probe)). Scope bypass.** `MemoryVault.list/search` treat `scopes=[]` as all scopes (`memory.py:430-433`). `search_memory` can produce `[]` after filtering, for example when an ask-mode tool asks for `['workspace']` or when the policy has no scopes (`tools.py:1166-1168`). Workspace memory then leaks into Just Chat, and policy-denied scopes leak in general. Automatic recall is guarded (`server.py:321-322`); the tool path is not.
- **D2 (high, CONFIRMED (probe)). Id-addressed operations are not checked against the target.**
  - `delete` (`memory.py:635-639`), `approve` (re-targets, `memory.py:363-401`), `feedback` (`memory.py:653-681`, no workspace), and `save` by id (re-targets, `memory.py:338-353`) all act on any id.
  - `PUT /api/knowledge/memories/{id}` forces workspace/approved on any id.
  - `import_values` overwrites foreign ids.
  - Probes deleted another workspace's memory, re-scoped a personal memory, and moved a ws1 candidate to ws2.
- **D3 (high, CONFIRMED (probe)). The server does not enforce approval.**
  - `PUT /api/memory/{id}` without `status` approves the record (`api/continuity.py:216-221`; `memory.py:251,256`), with no event and no conflict resolution.
  - `POST /api/memory` defaults to approved.
  - Import keeps whatever status the file says.
  - "Candidate until approved" therefore depends on the client.
- **D4 (high, by reading). Decrypted memory is persisted in plaintext outside the vault.**
  - claude_plan turns write it to `claude-accounts/<id>/locus-sessions/<thread>.json` `instructions` (`claude_runtime.py:242-247`).
  - Non-parity chatgpt turns send it as `baseInstructions` with `ephemeral=False` (`codex_app_server.py:617-623`).
  - Compaction does the same (`context_preservation.py:150`), as do team members on claude_plan (`orchestration.py:2905-2911`).
  - Each distinct recall set forks a new thread (`core.py:2295-2303`), creating another copy.
  - Deleting a memory does not erase these copies.
- **D5 (high, CONFIRMED (probe)). Legacy plaintext is still recoverable after migration.** The data remains in the WAL and the main file because `secure_delete` is off (`knowledge.py:83,545-547`).
- **D6 (high, CONFIRMED (probe)). Losing the key bricks the vault.** If `master.key` is missing, a new key is created silently. Every read then fails, and new writes use the new key, so the vault holds rows under two keys. There is no canary and no recovery path except a previous plaintext export.
- **D7 (medium). The key sits next to the ciphertext.** `master.key` is in the same 0700 directory as the DB. Any backup or sync of `~/.ollama-code` exposes both. Install backups copy the DB without the key (`runtime_install.py:252-268`).
- **D8 (medium, CONFIRMED (probe)). Metadata is not authenticated.** pinned, stale, expires_at, use_count, last_used_at, superseded_by and the timestamps are outside the AAD. Tampering can pin records, clear staleness, extend TTLs or reorder recall without detection.
- **D9 (low). The hashes are unsalted.** Workspace and agent target hashes, event hashes and continuity hashes can be dictionary-guessed. `agent:sha256('primary')` is trivial.
- **D10 (medium, CONFIRMED (probe)). Workspace identity is asserted by the client.** Knowledge routes accept any directory, including `/`. That triggers `git ls-files` or a filesystem-wide `os.walk`, copies up to 20,000 files into plaintext SQLite, and serves them back through search (`knowledge_runtime.py:11-16`; `memory_runtime.py:35-36`).
- **D11 (medium, by reading). Snapshot goals contain the decorated prompt.** That includes selected file contents and attachments (`server.py:763-764`; `AppModel+ChatWorkers.swift:831-870`). The text is persisted and later injected into other chats' system prompts. With no relevance floor (`continuity.py:306-316`), the two most recent snapshots are injected into every Work, Plan and Grill turn. The outcome field is mostly receipt JSON (`server.py:2177-2180`).
- **D12 (medium, by reading). Team continuity is presented as approved memory.** Snapshots are joined into `_memory_context` and rendered under `## Approved memory` (`server.py:900-916`; `orchestration.py:219,263-266`).
- **D13 (medium, by reading). `memory_reprocess` does not check identity mode or the workspace.** It can mine Private Identity chats, and it can create workspace candidates from another workspace's chat (`api/continuity.py:404-411`). If the vault fails after `start_run`, the run is left running.
- **D14 (medium). Plaintext copies outside the vault:**
  - transcript index (`transcript_search.py`)
  - knowledge DB and document `result.json`
  - `questions.sqlite3`
  - `collaboration.sqlite3`
  - `runtime_events` and `runtime_commands`
  - UserDefaults `Locus.promptHistory` and `Locus.checkpoints`
  - Notes
  - AgentCrewChat ledger
  - install backups of the plaintext DBs
- **D15 (medium, CONFIRMED (probe)). `embed_texts` follows redirects, and the embedding host is not added to NO_PROXY.** A process on a loopback port could redirect embedding requests, and the workspace text with them, off the machine (`knowledge.py:609-613`; `proxy.py:207-232`).
- **D16 (medium). A standalone server without `LOCUS_AGENT_TOKEN` has no auth.** Any local process can then call `GET /api/memory/export` (`server.py:256-259,3040-3044`).
- **D17 (medium). Prompt-injection surface.** Knowledge snippets are interpolated after `## ` headers without fencing (`knowledge.py:682`). Snapshot and memory content enters the system prompt as trusted text.
- **D18 (low). `record_skill_observation` is an ungated SAFE tool.** It works under the read_only ceiling (`tools.py:52-59`; `tool_registry.py:64-70`).
- **D19 (low). The knowledge secret-name filter misses common credential files** such as `service-account.json` and `*-credentials.json` (`knowledge.py:39-43`).
- **D20 (low).** The token comparison is not constant-time (`server.py:258`).
- **D21 (medium). Edition isolation defect.** LocusX writes the crew chat ledger into `Locus/AgentCrewChat`, with default permissions (`AgentCrewChatModel.swift:110-113`).
- **D22 (medium). Deletes do not cascade.** Session delete or clear (`api/sessions.py:349-401`) leaves questions, collaboration rows, snapshots, provider-home state, runtime events, UserDefaults checkpoints and the crew ledger. `DELETE /api/memory` and `DELETE /api/knowledge` leave snapshots, observations and document results.

### 19.2 Integrity and concurrency

- **D23 (high, CONFIRMED (probe)). `feedback()` can leave a row permanently undecryptable.** It does SELECT then UPDATE with no revision CAS, so a concurrent save can move the revision while the ciphertext AAD keeps the old one (`memory.py:657-677`). Because `list()` fails on any bad row, every list, search and status call for that target fails afterwards.
- **D24 (medium, CONFIRMED (probe)). Stale semantic vector after an edit.** After the content changed from Toronto to Montreal, a query for "toronto" still matched at 100% semantic similarity (`memory.py:322-328,568`).
- **D25 (medium, CONFIRMED (probe)). Schema migration race.** Concurrent first opens of a pre-v2 DB raised `duplicate column name` in 3 of 160 opens (`memory.py:158-169`). The error is an uncaught `sqlite3.OperationalError`, which produces a 500 and breaks recall.
- **D26 (medium, CONFIRMED (probe)). `save` commits before `conflicts_for`, and import is non-transactional.** A failure after commit returns 422 for a write that persisted, and an import failure leaves a partial import.
- **D27 (medium). No optimistic concurrency.** Swift sends `revision` and the server ignores it. Swift's comment that omitted fields stay unchanged (`WorkspaceKnowledgeModel.swift:383-384`) contradicts the reset semantics in §4.10.
- **D28 (medium, CONFIRMED (probe)). Legacy migration hazards** (§5): an invalid row aborts the migration; a retry overwrites edits; `created_at` is lost; `sqlite3.Error` escapes; it runs on every call; it creates knowledge DBs as a side effect; the tools never migrate; `KnowledgeStore.search` still serves unmigrated rows as `approved_memory`.
- **D29 (medium, CONFIRMED (probe)). Conflict false positives** come from generic titles. `approve(replace)` then marks unrelated memories stale.
- **D30 (low, CONFIRMED (probe)). Events are misattributed.** Expirations from every target are logged under the caller. Raw-string workspace hashes split buckets. Feedback events land in the empty bucket.
- **D31 (medium, by reading). Snapshot pin and overwrite.** The `pinned` argument is ignored for existing rows. The automatic end-of-turn capture overwrites an explicit `capture_context_snapshot` from the same turn. The read-then-upsert runs outside `BEGIN IMMEDIATE`, so a concurrent pin can be lost.
- **D32 (low, CONFIRMED (probe)). `workspace_changed_files` mis-parses renames under `-z`.** `original_name.txt` becomes `ginal_name.txt` (`continuity.py:68-76`).
- **D33 (low).** Observation numbers are reused after the highest-numbered one is deleted.
- **D34 (medium, CONFIRMED (probes)). Knowledge index defects:**
  - Generation race: a model change during backfill leaves old vectors that are never re-embedded.
  - Chunk cap: hitting it during a full reindex deletes unreached documents, which come back on the next run.
  - Files that grow past 2 MiB or become binary keep their stale chunks.
  - The settings route returns 500 for an invalid host.
  - LIKE wildcards are not escaped.
  - Reindex holds one write transaction across all file I/O.
- **D35 (low, CONFIRMED (probe)). Validation gaps:** NaN confidence, string tags split into characters, unbounded provenance and source ids.
- **D36 (low).** Connections are never closed (`ResourceWarning`).
- **D37 (low).** `memory.MemoryError` shadows the builtin.
- **D38 (low). Reads mutate state.** `list`, `status`, `export`, `search` and `diagnostics` expire candidates and write events. Search writes use stats and embeddings. Yet `search_memory` is classed as read-only and parallel-safe.

### 19.3 Recall correctness and availability

- **D39 (high, CONFIRMED (probe) at the function level; turn failure plausible). Recall depends on the knowledge capability.** With `LOCUS_CAPABILITY_WORKSPACE_KNOWLEDGE=0`, `_automatic_memory_context` raises `HTTPException(404)`: `_knowledge_store` calls `_require_capability`, and only `MemoryError` and `KnowledgeError` are caught. The call is outside the turn's `try` block, so every recall-enabled solo turn probably fails with "internal error" after `start_run`, leaving `active_run_id` set. A workspace path that is not a directory skips all recall, personal and agent included. This contradicts the intent of `test_memory_tools_do_not_depend_on_workspace_indexing`. `/api/memory/search` and `/api/memory/diagnostics` also return 404.
- **D40 (medium, by reading). Wrong agent principal on profile turns.** Automatic recall is called without `agent_id` on profile turns (`server.py:571-573`), so saved agents recall the primary agent's agent-scope memories and never their own.
- **D41 (low). Empty recall is not empty.** It still injects `## Approved memory` with "No approved memory matched that query." (`memory.py:839-840`).
- **D42 (medium). The recall query is the decorated prompt**, plus the approved-plan JSON (`server.py:526`). Truncation to 2,000 characters and 24 terms often excludes the real request.
- **D43 (medium). Stale `memory_context` across turns.** `retry_last`, `/init` and `/api/response-preview` reuse the previous recall, including memories deleted since.
- **D44 (medium). Prompt churn forks native threads**, causing a full transcript replay (`core.py:2396-2458`).
- **D45 (medium). Uncaught `MemoryError` gives 500** on status, list, delete-all, export, maintenance and diagnostics.
- **D46 (medium). Per-turn latency.** A synchronous Ollama embed call with a 120 s timeout runs before the model call, once per team member. The legacy migration, candidate expiry, use-count writes and two `ContinuityStore` inits also run every turn.
- **D47 (medium). O(N²) status and diagnostics** (§4.20), called on every Swift refresh. An import of 10,000 records runs `conflicts_for` per record.
- **D48 (low).** Budgeting is character-based, cuts records mid-content, and the estimators disagree (§9.4).
- **D49 (low). No memory on ChatGPT native parity turns**, which is the default ChatGPT route, while snapshots are still captured.
- **D50 (low). `search_workspace_knowledge` uses `ctx.cwd`.** Every task worktree gets its own DB with default settings and a synchronous full index, and nothing garbage-collects them. Its description claims it covers approved memories.
- **D51 (low).** Helpers use `spec.agent_id` and cannot see the parent profile's agent memories.
- **D52 (low).** `/remember` always saves under `'primary'`. The delete-all toast always says "primary-agent".
- **D53 (medium). Personal scope: UI and backend disagree** (§11.4).
- **D54 (low). Mid-turn steers do not refresh recall** (`core.py:559-597`).

### 19.4 Operations, tests and documentation

- **D55. Documentation drift.**
  - `PROTOCOL.md` has no sections for `/api/context-snapshots`, `/api/skill-observations`, `/api/memory/status`, `/maintenance/run`, `/feedback`, `/api/knowledge/memories*` or `DELETE /api/knowledge`.
  - Its transcript-search example omits `phase`, `item_id` and `reasoning_sections`.
  - The `knowledge_indexing` event (`PROTOCOL.md:1346`) has no emitter.
  - `README.md:143-146` and `PROTOCOL.md:269-272` promise a file key with no Keychain.
- **D56.** The test tripwire misses `sqlite3.connect` (`conftest.py:133-197`).
- **D57.** `test_continuity`'s ciphertext check ignores the WAL.
- **D58.** `test_product_backend.py:89-90` requires the staged `memory.py` to contain `AESGCM`. `Tools/StageBackendEdition.py` copies only the `ollama_code` tree, so an external package needs its own bundling.
- **D59. Inconsistent error codes.** Snapshot PUT maps every error to 404. Observation PUT returns 422 for not-found. Approve returns 422 for a missing id.
- **D60.** Install backups are never pruned.
- **D61. Orphaned files** with no writer at HEAD (§14).

### 19.5 Risks in the reference repositories

- Agent Dispatcher: see §15.5.
- langgraph-workflow:
  - Recalled memory echoed into job outputs is stored in a plaintext checkpoint sidecar and in `agent-host.sqlite3`, which has no encryption option.
  - `agent-host.sqlite3` and `workspaces.json` are created with umask permissions.
  - `AgentHost` rows and `blocked:*` attempts are never pruned.
  - The compatibility record (`integrations/locus/compatibility.json`) covers package 0.1.0 against Locus `5ac5b5b1`, not 0.4.1 against `b332e455`.
  - `langsmith` is imported directly (`executor.py:18`) but not declared.

---

## 20. Unknown or not verified

- **Codex helper stores.** Whether the pinned Codex app-server derives anything from Locus threads into `memories_1.sqlite`, and whether its rollout files keep `baseInstructions` verbatim. The files were not opened. Locus's `config.toml` (`codex_app_server.py:240-275`) has no memories or history setting.
- **Turn failure with the capability off.** That a whole turn fails when `workspace_knowledge` is disabled is plausible from the call structure. Only the function-level `HTTPException` was reproduced.
- **Persistence of the system prompt.** Whether the composed system prompt with `## Approved memory` is persisted anywhere besides the native provider stores. `server.py:2211` keeps it in an in-memory snapshot, and `orchestration.py:191` claims it is not persisted. `sessions.py` was not checked for this.
- **Prompt decoration in snapshots.** That snapshot goals include decoration follows from reading the call chain. It was not reproduced end to end, and one audit pass left it open.
- **Other hosts.** Whether the CLI, schedules, event triggers and automation workflows decorate prompts the way the GUI does.
- **Legacy rows on other installs.** Whether any shipped install still has rows in `APP_DIR/knowledge/*/knowledge.sqlite3` memories. User DBs were not opened.
- **Orphan origin.** Where `~/Library/Application Support/Locus/Agent/agent-runs.sqlite3` came from.
- **AgentHomes.** What `~/Library/Application Support/Locus/AgentHomes` contains, and how per-agent homes interact with the vault.
- **CI.** Whether Swift tests run in CI alongside pytest.
- **System Pythons.** FTS5 and SQLite versions on non-bundled interpreters.
- **PDF locators.** The shape `{kind:'pdf', page, page_index, bounds?}` comes from the native Swift helper and is documented only in `PROTOCOL.md:217-219`.
- **langgraph-workflow compatibility.** Whether 0.4.1 works with Locus `b332e455`. The integration suite was not re-run.
- **Unrun tests.** Agent Dispatcher's `tests/test_retrieval_security.py` (uncommitted edits) was not run. No Locus tests were run in this audit; only scratchpad probes were.
- **Exact DDL text.** §4.3 and §6.2 give column definitions, not the literal SQL. Compare with the source before generating fixtures.
- **Line ranges.** Where audit passes disagreed (`server.py:309-338/339`, `369-401/406/408`; `tools.py:1255/1256`; `continuity.py` call sites `server.py:401/402`), the exact boundaries were not reconciled.
- **Swift line numbers.** The lines for `reviewMemoryHealth` and the separate `deleteAllMemory` function were not recorded; only the toast line (581) is known.
- **Swift rendering.** Whether `MemoryDiagnosticReport` tolerates `embedding_error: null` from the server. The DTO declares it as a string, but the Python side was not checked for null.

---

## 21. Characterization cases

Write these against the current behavior first, using disposable fixtures: an explicit `tmp_path`, a fixed key `b'k'*32`, and WAL-inclusive byte inspection. Cases marked **(defect pin)** document behavior that should change. Change them on purpose, as an expected-failure flip.

### Crypto and format
1. The memory AAD for `('abc', 'approved', 'personal', 'personal', 1)` is exactly `b'memory-v1|abc|approved|personal|personal|1'`. Decrypting with any field changed raises `'a memory record could not be decrypted'`.
2. `len(nonce) == 12`. `len(ciphertext) == len(canonical_json) + 16`, where canonical JSON is `sort_keys`, `ensure_ascii=False`, `separators=(',',':')`, UTF-8.
3. A DB fixture written by the current code decrypts with the extracted package under the same key.
4. The snapshot AAD is `b'locus-context-v1|'+id+'|'+session_id+'|'+sha256(resolved ws)`. The observation AAD is `b'locus-observation-v1|{id}|{number}|{hash}|{STATUS}'`. After `set_observation_status('actioned')`, the row decrypts only under the `ACTIONED` AAD. Continuity plaintext uses `separators=(',',':')` with `ensure_ascii` left at True.
5. Plaintext canaries never appear in the DB, WAL or SHM bytes.
6. Tampering with `pinned` or `use_count` does not cause a decrypt error **(defect pin, D8)**.

### Targets, ids and keys
7. `_target('personal') == 'personal'`. The workspace target is `'workspace:'+sha256(str(Path(p).expanduser().resolve()))`, and symlink and trailing-slash variants collapse to it. `_target('agent', agent_id=' a ') == 'agent:'+sha256(b'a')`. A blank workspace or agent raises the exact message.
8. Ids matching `[A-Za-z0-9_-]{1,128}` are accepted. `'a'*129`, `'a b'` and `'../x'` raise `'memory id is invalid'`. `memory_id=''` generates a 32-character uuid4 hex.
9. An absent key file is created with 32 bytes, mode 0600, in a 0700 directory, and reopening reuses it. A key file of the wrong length raises `'invalid'` and is left untouched. `key=b''` uses the file. A 16-byte key raises `'requires a 256-bit key'`. N concurrent first-run processes share one key.
10. Delete `master.key` and reopen: `list()` raises `'could not be decrypted'` and a new key file exists **(defect pin, D6)**.

### save, merge, revision and TTL
11. Insert defaults: title `'Memory'`, kind `'fact'`, confidence 1.0, scope `'workspace'` (raises without a workspace), revision 1. `expires_at` is NULL when approved and now+2,592,000 (±1 s) for a candidate.
12. Update merge: reason, provenance, supersedes, source ids, embedding and feedback are kept when omitted. Title, tags, kind, confidence, `valid_until`, pinned and stale reset. `created_at`, `use_count`, `last_used_at` and `superseded_by` are untouched.
13. Revisions: insert sets 1; save +1; `keep_both` +1; `replace` with conflicts +2; feedback, embedding CAS, search and maintain leave it unchanged. Only `save()` changes `updated_at`.
14. Every save of a candidate resets its TTL. `list()` deletes expired candidates in every target and logs `expiration/expired` under the caller's hashes.
15. Confidence `'nan'` is stored as NaN, and tags `'abc'` become `['a','b','c']` **(defect pin, D35)**.
16. After a content edit the old embedding is kept, and a query for the old content still matches semantically **(defect pin, D24)**.

### Scopes, listing and lifecycle
17. `list(scopes=[])` and `list(scopes=None)` both return all three scopes **(defect pin, D1)**. `scopes=['bogus']` returns `[]`. `status='bogus'` applies no filter.
18. Ask mode with `search_memory(scopes=['workspace'])` returns workspace records **(defect pin, D1)**.
19. `delete(id)` succeeds for another workspace's record. `delete_all(workspace)` with default scopes also removes personal memories. Approving from another workspace re-targets the record **(defect pins, D2)**.
20. `PUT /api/memory/{id}` on a candidate with no status returns status `approved` **(defect pin, D3)**. `POST /api/memory/{missing}/approve` returns 422 `'memory candidate not found'`. `DELETE /api/memory/{missing}` returns 404.
21. Two approved memories with the same title and different content conflict. Identical normalized content does not. Stale rows and the memory itself are excluded, and at most 12 are returned. Two untitled memories conflict. `approve(replace)` sets `stale=1` and `superseded_by` on the conflict and `supersedes` on the winner.
22. Feedback `'incorrect'` sets `stale=1`. Counts accumulate inside the ciphertext. `feedback` is absent from the returned dict. An invalid outcome raises the exact message.
23. Two vault instances, `feedback` interleaved with `save`: the row becomes undecryptable and `list()` fails **(defect pin, D23)**.

### Search and recall
24. Single memory, query equal to its title, not pinned, confidence 1.0, updated now: score is `4.0 + min(matches,8)*0.8 + 1.0 + 1.0`. A past `valid_until` multiplies by 0.15, stale by 0.4. A future `valid_from` excludes the memory. No lexical match with semantic < 0.2 excludes it. Ties sort by id. Limit 0 becomes 1 and 50 becomes 20.
25. `retrieval_reason` strings, for example `'exact phrase, 100% confidence'` or `'2 matching terms, pinned, 90% confidence'`.
26. The returned `use_count` is the pre-increment value; the next `list()` shows +1 and sets `last_used_at`. Only returned rows are incremented.
27. The embedding input is `f'{title}\n{content}\n{" ".join(tags)}'` with `vectors[0]` as the query. Rows already embedded with the same model are not re-embedded. The CAS is a no-op if the revision or ciphertext changed.
28. `format_memory_results([])` returns `'No approved memory matched that query.'`, and automatic recall injects it **(defect pin, D41)**. The rendered format and the 30,000-character cap are exact.
29. `_automatic_memory_context` returns `''` when recall is disabled, max is 0, or no scope is left after just_chat. Otherwise the output is cut at `max_automatic_tokens*4`.
30. With `LOCUS_CAPABILITY_WORKSPACE_KNOWLEDGE=0`, `_automatic_memory_context` raises `HTTPException(404)` **(defect pin, D39)**.
31. A profile turn calls recall with `agent_id='primary'` **(defect pin, D40)**.
32. In parity, identity or just_chat turns, recall functions are not called. Use a monkeypatch that fails if called, as in `test_identity_vault.py:217`.

### Events, status and export
33. `record_event` truncates to 160/160/64/64/128/128 and turns blanks into NULL. It purges events older than 90 days and keeps the newest 5,000 per bucket. `workspace_hash` is `sha256(raw string)`.
34. `diagnostics` returns the status keys plus `events` (≤100, newest first), `counts`, `last_proposal`, `last_approval` and `history_available`. `status` returns exactly `{encrypted:True, cipher:'AES-256-GCM', approved_count, candidate_count, candidate_ttl_days:30, stale_count, expired_count, conflict_count, semantic_encrypted:True, memory_version:2}`.
35. Export is `{'format':'locus-memory-export','version':2,'exported_at':float,'memories':[...]}`. Import accepts versions 1 and 2, raises the exact messages for an unsupported format or more than 10,000 items, skips non-dicts, and preserves ids, status, scope, pinned and stale.

### Schema and migration
36. `PRAGMA table_info(memories)` lists the 15 columns in order, and both indexes exist. A 12-column pre-v2 DB gains the 3 columns idempotently in a single process. Concurrent opens can raise `duplicate column name` **(defect pin, D25)**.
37. Legacy migration:
    - The id is `'legacy-'+sha256(f'{Path(ws).resolve()}|{id}')[:40]` (47 characters), with scope workspace, status approved and pinned preserved. `created_at` becomes now. The legacy table is emptied.
    - A rerun is idempotent.
    - A retry after a crash restores the legacy content over a user edit **(defect pin)**.
    - A blank-content row stops the rest of the migration **(defect pin)**.
    - A locked knowledge DB raises `sqlite3.OperationalError` **(defect pin)**.
    - The canary remains in the knowledge DB and WAL bytes **(defect pin, D5)**.
    - `KnowledgeStore.search` returns unmigrated rows with `source='approved_memory'`.

### Continuity
38. A second save for the same `(session, ws)` keeps the id, `created_at` and pinned state. A different workspace gets a new row. `exclude_session` works.
39. `save_snapshot(pinned=True)` on an existing unpinned row leaves it unpinned **(defect pin, D31)**. A new row is pinned with `expires_at` None.
40. An unpinned `expires_at` equals `updated_at + 2,592,000`. With 55 saves, the newest 50 unpinned rows remain. Expired rows in other workspaces are removed by any save or list.
41. Field bounds: goal 4,000, outcome 8,000, mode 32, pending 4,000, session_id 160, todos 100×(1,000/32), changed_files 100×1,000. plan and checkpoint pass through only when they are dicts.
42. `search_snapshots` scoring formula and tokenizer. A query with no overlapping tokens still returns the most recent snapshots **(defect pin)**. The limit clamps to 0-10.
43. `format_context_snapshots([], n) == ''`. The exact 103-character header and field labels. Length ≤ `max_tokens*4`.
44. Observations: without evidence the call raises `'require issue'`. `checkpoint_only=True` gives the title `'Observation checkpoint'` and skill `'All skills'`. Type normalization. Numbers 1, 2, 3; delete #3; the next is #3 **(defect pin, D33)**. Each workspace numbers independently. Invalid status raises. The export shape.
45. A row encrypted under another key is skipped silently by `list_snapshots`, `list_observations` and export. Single-record operations on it raise.
46. `workspace_changed_files` on a non-git directory returns `[]`. A rename returns `[new, mangled-old]` **(defect pin, D32)**. The cap is 100, and the environment is sanitized.

### Knowledge and transcript
47. `workspace_database(ws)` path formula. A workspace that is not a directory raises `'workspace is not an existing directory'`. A fresh schema has the settings defaults, and the DB is mode 0600.
48. Eligibility table: `.env`, `server.pem`, `id_ed25519`, `credentials.json`, `secrets.yaml`, `build/`, `node_modules/` and `.hidden/` are excluded; symlinks, files over 2 MiB and NUL-containing files are skipped; document formats need `documents_enabled`; the glob `'Generated/**'` excludes.
49. `_chunks('a\nb\n') == [(1, 2, 'a\nb')]`. A 7,000-character line followed by 10 short lines yields 2 chunks.
50. FTS query construction. Scores: file hits `1/(pos+1)`, legacy notes `1.2/(pos+1)`, vector scores added with source `hybrid`.
51. Host validation table: `localhost`, `localhost.`, `127.0.0.2` and `[::1]` are accepted. Credentials, LAN IPs and `ftp` are rejected with the exact messages. A 307 redirect is followed **(defect pin, D15)**.
52. `embed_texts` wire contract and error messages. An empty model or empty input returns `[]` without HTTP.
53. The transcript index's `message_index` equals the position in `SessionStore.load`. At most 3 hits per session. Decoration is stripped. A torn tail is skipped until it is completed. A schema-version mismatch triggers a rebuild. Highlights are `[start, len]` in code points.
54. `/api/sessions/search`: missing or empty query gives 422 before the capability check. Capability 0 gives 404. limit 1-50.

### Policy, prompt and tools
55. `MemoryPolicy.parse` bounds and defaults (§9.3). Scopes are deduplicated and filtered. A non-list value means all three scopes.
56. `compose_system_prompt` layer order and titles. `## Approved memory` is present only when the memory context is non-blank. Cross-chat context is omitted in ask mode.
57. `configure_agent` truncates to 24,000 characters, drops the workspace scope and blanks continuity in ask mode, and truncates `agent_id` to 128 characters.
58. `context_breakdown` puts both memory layers in the `memory` category, with tokens counted as `len//4`.
59. A claude_plan turn with a recalled `'CANARY'` memory: the thread file's `instructions` contain the canary **(defect pin, D4)**. On a non-parity chatgpt turn, `thread/start` has `baseInstructions` with memory and `ephemeral=false`. `CodexAppServer.complete` passes `ephemeral=True`.
60. Tool strings for `record_skill_observation` and `capture_context_snapshot` (enabled and disabled).
61. `memory_reprocess` golden case: `'Please remember that I prefer compact progress updates.'` yields one candidate `{title:'From selected chat', kind:'preference', scope:'workspace', status:'candidate', confidence:0.8}`. A rerun yields 0 plus `proposal:deduplicated:existing_memory`. Decorated text before the marker is ignored. Messages over 4,000 characters or matching the secret regex are skipped. At most 20 candidates are produced.

### Route and client contracts
62. The route snapshot lines for memory, knowledge, continuity and session search are unchanged. Route modules do not reference `handlers.*` (`test_reviewability_report.py:75-110`).
63. Swift decoding: a `/api/memory/status` payload with only the required keys decodes. Diagnostics must include `approved_count`, `candidate_count`, `indexed_files`, `search_chunks`, `embedding_model`, `embedding_error` (string), `history_available`, `events` and `counts`. `ContextSnapshot` requires `goal`, `outcome`, `mode`, `changed_files` and `pending`.
64. The Swift refresh fans out to 7 endpoints, with `/api/memory` called twice.
65. Snapshot PUT with `pinned='yes'` gives 422. An unknown snapshot gives 404. An unknown observation PUT gives 422 **(pin; inconsistent)**. Observation export is not captured by the `{id}` routes.

### Native app stores (optional, Swift)
66. `AgentCrewChatModel.defaultStorageDirectory` ends with `Locus/AgentCrewChat` under LocusX **(defect pin, D21)**.
67. `recordPrompt` keeps at most 50 entries and moves a repeat to the front. `createCheckpoint` keeps at most 12. Restoring prepends `'Restored session context:'` to the next prompt.
