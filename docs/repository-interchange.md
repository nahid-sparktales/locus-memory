# Repository interchange format (`locus-memory.repository-interchange` v1)

A portable JSON document that carries one repository's inventory and observations between
`locus-memory` and other tools. This document describes the format, its validation rules, the
producer protocol, the safety rules, and a proposed mapping from Agent Dispatcher stores.

Code: `src/locus_memory/repository/interchange.py` (format, validator, producer protocol),
`src/locus_memory/repository/interchange_schema.json` (machine-readable schema),
`src/locus_memory/repository/service.py` (`RepositoryService.export_interchange`,
`RepositoryService.import_interchange`, `RepositoryService.import_from_provider`) and
`src/locus_memory/repository/scanner.py` (path checks and exclusions).

---

## 1. Status

| Part | Status | Evidence |
|---|---|---|
| Format v1, strict validator | implemented | `tests/test_repository.py::test_interchange_validator_rejects_malformed_documents`, `::test_interchange_validator_bounds_and_json_hygiene`, `::test_interchange_schema_file_matches_validator` |
| Export from a registered, snapshotted repository | implemented | `tests/test_repository.py::test_interchange_round_trip` |
| Import as untrusted data (candidates only) | implemented; several branches untested (§5.3) | `tests/test_repository.py::test_imported_summaries_are_candidates_never_approved`, `::test_import_applies_repository_exclusions_and_hash_algorithm`, `::test_interchange_round_trip` |
| `RepositoryIntelligenceProvider` protocol | implemented as a contract | exercised only with the test stand-in `SyntheticRepositoryProducer` |
| A real producer (Agent Dispatcher or other) | **not implemented** | §8 |
| CLI commands for interchange | **none**; library API only | `cli.py` has `repo register/snapshot/status/observations` only |

The format is **provisional** in the sense of R13.5: no real exporter exists to validate it against,
so it is backed by a provisional schema and synthetic tests. The version field exists so it can change.

---

## 2. Document format

```json
{
  "format": "locus-memory.repository-interchange",
  "version": 1,
  "producer": {"name": "locus-memory", "version": "0.1.0", "kind": "observer"},
  "repository_id": "repo-a",
  "hash_algorithm": "sha1",
  "generated_at": 1800000000.0,
  "since_snapshot": null,
  "records": [
    {"type": "repository", "repository_id": "repo-a", "object_format": "sha1", "initial_commit": "<40 hex>"},
    {"type": "snapshot", "snapshot_id": "s1", "state": "complete", "head": "<40 hex>", "dirty": false, "created_at": 1800000000.0},
    {"type": "file", "path": "pkg/widgets.py", "blob": "<40 hex>", "size": 812, "language": "python", "support": "parsed"},
    {"type": "symbol", "path": "pkg/widgets.py", "blob": "<40 hex>", "name": "Widget", "symbol_kind": "class", "line": 3, "extraction": "ast"},
    {"type": "import", "path": "pkg/widgets.py", "blob": "<40 hex>", "module": "dataclasses", "names": ["dataclass"], "extraction": "ast"},
    {"type": "observation", "path": "pkg/widgets.py", "blob": "<40 hex>", "text": "...", "extraction": "ast", "language": "python"},
    {"type": "summary", "text": "...", "title": "...", "source_hashes": [["pkg/widgets.py", "<40 hex>"]],
     "producer": "some-tool", "model": "some-model", "basis": "model_interpretation"}
  ]
}
```

`<40 hex>` stands for a git object id and `...` for text; the example is illustrative, not a valid
document as written.

Top-level fields:

| Field | Required | Rule |
|---|---|---|
| `format` | yes | exactly `locus-memory.repository-interchange` (`interchange.FORMAT`) |
| `version` | yes | an integer in `interchange.SUPPORTED_VERSIONS`, currently `(1,)`; a boolean is rejected |
| `producer` | yes | object; `name` (label ≤128) and `kind` (`observer`, `tool` or `model`) required; optional `version` (label ≤64) and `models` (list of ≤16 labels ≤128) |
| `repository_id` | yes | `[A-Za-z0-9_-]{1,128}` |
| `hash_algorithm` | yes | `sha1` or `sha256`: the repository's **git object format**, not a content hash |
| `generated_at` | no | finite timestamp between 0 and year 3000 |
| `since_snapshot` | no | `[A-Za-z0-9_-]{1,128}` or `null` |
| `records` | yes | list of at most 100,000 records |

No other top-level field is accepted.

---

## 3. Record types

Hashes (`blob`, `head`, `initial_commit`, source blobs) are git object ids: lowercase hex, 40 characters
for `sha1` and 64 for `sha256`, and they must match the document's `hash_algorithm`. Paths follow the
rules in §7.1. Every record type rejects unknown fields.

| `type` | Required fields | Optional fields | Constraints | What import does with it |
|---|---|---|---|---|
| `repository` | `repository_id`, `object_format` | `initial_commit` | exactly one per document; `repository_id` equals the document's; `object_format` equals `hash_algorithm` | rejects the whole document if `initial_commit` differs from the registered repository's |
| `snapshot` | `snapshot_id`, `state` | `head`, `dirty`, `created_at` | at most one per document; `state` is `complete` or `partial`; `dirty` boolean (default `false`) | counted (`snapshots_described`); not stored |
| `file` | `path`, `blob` | `size`, `language`, `support` | `size` integer ≥0; `language` label ≤64; `support` is `parsed`, `heuristic` or `unsupported` | verified against stored snapshots and counted (`files_verified` / `files_unverified`); not stored |
| `symbol` | `path`, `blob`, `name`, `symbol_kind` | `line`, `extraction` | `name` label ≤200; `symbol_kind` is `class`, `function` or `async_function`; `line` integer ≥1; `extraction` is `ast`, `heuristic` or `tool` | verified and counted (`symbols_*`); not stored |
| `import` | `path`, `blob`, `module` | `names`, `extraction` | `module` label ≤300; `names` list of ≤32 labels ≤200 | verified and counted (`imports_*`); not stored |
| `observation` | `path`, `blob`, `text` | `extraction`, `language` | `text` ≤32,000 characters | may become an unapproved candidate, kind `repository_observation`, basis `source_attributed` (§5.2) |
| `summary` | `text`, `source_hashes`, `producer`, `model`, `basis` | `title` | `basis` must be `model_interpretation`; `source_hashes` is 1-64 `[path, blob]` pairs; `title` ≤160 characters; `producer` and `model` labels ≤128 | may become an unapproved candidate, kind `summary`, basis `model_interpretation` (§5.2) |

`summary` records are model output by definition. A summary that claims any other basis is rejected,
and a summary always names the producer and model that wrote it.

---

## 4. Validation rules

`interchange.validate_document(document, *, exclusions=None)` is the authoritative check. It is
stdlib-only and strict, and it returns a normalized copy or raises `errors.InterchangeInvalid`.

1. **Parsing** (`interchange.load_document`). Bytes and text are limited to 16 MiB
   (`MAX_DOCUMENT_BYTES`) before parsing. Bytes must be UTF-8. JSON `NaN`, `Infinity` and `-Infinity`
   are rejected. The result must be a JSON object.
2. **Header.** Exact `format`; supported integer `version`; required top-level fields present and no
   others; valid `hash_algorithm`, `repository_id` and `producer`; finite, in-range `generated_at`;
   well-formed `since_snapshot`.
3. **Records.** A list of at most 100,000 (`MAX_RECORDS`) objects with a known `type`, exactly the
   required fields, and only the optional fields listed in §3.
4. **Cardinality.** Exactly one `repository` record, matching the document's `repository_id` and
   `hash_algorithm`; at most one `snapshot` record.
5. **Values.** Labels and text are stripped of surrounding whitespace and must then be non-empty, within
   their length bound and free of NUL (`validation.check_text`); labels must also contain no character
   in a Unicode `C*` category: control, format, private-use, surrogate or unassigned
   (`validation.check_label`). Integers must be real integers (not booleans) in range; timestamps must
   be finite and in range; enumerations must match exactly. An optional field given as explicit `null`
   is treated as absent, except `dirty`, which must be a boolean when present.
6. **Hashes.** Lowercase hex of the exact length for the declared algorithm.
7. **Paths.** Each `path` (and each path inside `source_hashes`) must pass
   `scanner.check_repo_path` and must not be excluded (§7). One bad or excluded path rejects the whole
   document.
8. **Size budget.** Besides the raw-byte limit, every label, text and path is charged against a
   cumulative 16 MiB budget (`interchange._Budget`). Hashes, ids and enumeration values are not
   charged; their patterns bound them instead.
9. **No echo.** Error messages name the field and record index but never repeat document content
   (`tests/test_repository.py::test_interchange_validator_bounds_and_json_hygiene` checks that a canary
   in a rejected path does not appear in the error).

The JSON Schema file is descriptive and does not express every rule.
`tests/test_repository.py::test_interchange_schema_file_matches_validator` checks that its `format`,
`version`, record types and per-type field sets match `interchange.RECORD_FIELDS`. The two differ in
both directions:

* The validator additionally enforces hash length per `hash_algorithm`, the exclusion list, the
  cumulative size budget, Unicode format, private-use and surrogate characters and drive letters in
  paths, rejection of whitespace-only labels and text and of `C*`-category characters in labels, and
  timestamp bounds on `created_at`.
* The validator is more lenient than the schema on `null`: it accepts explicit `null` for `language`,
  `support`, `extraction`, `names`, the summary `title`, `producer.version`, `producer.models` and
  `generated_at`, all of which the schema types as non-null.

---

## 5. Export and import

### 5.1 Export

`MemoryEngine.export_repository_interchange(access, repository_id)` →
`RepositoryService.export_interchange`:

* requires `Operation.EXPORT`, and the repository registration must be visible to the caller
  (otherwise `NotFound`);
* emits the `repository` record, the current snapshot (if any), a `file` record for every non-excluded
  `file` entry of the current snapshot that has a blob id, and, for every current observation of a
  non-excluded path, its `symbol` and `import` records and one `observation` record with the
  observation text;
* sets `producer` to `{"name": "locus-memory", "version": <package version>, "kind": "observer"}` and
  `generated_at` to the host clock;
* validates its own output with the repository's exclusions before returning it.

The returned document is **plaintext** (observation text included). The package never writes it to a
file; where it goes is the host's decision.

### 5.2 Import

`MemoryEngine.import_repository_interchange(access, document)` → `RepositoryService.import_interchange`.
The document is untrusted data: it can never approve memory, change access or waive verification.

1. Requires `Operation.PROPOSE`. On this path the engine checks canonical ownership up front
   (`MemoryEngine._fence`), and the candidate write re-checks it inside the transaction
   (`core.CoreService._check_owner`), so imports are fenced while legacy storage is authoritative.
   `RepositoryService.import_from_provider` has only the second check (§6). Neither is tested (§5.3).
2. The repository must be registered and visible to the caller.
3. The document is validated with the repository's exclusions (defaults + host patterns + the
   registration's patterns). Its `hash_algorithm` must equal the repository's object format.
4. All records are processed in one write transaction. A document-level error (for example a
   mismatched `initial_commit`) rolls everything back.
5. `file`, `symbol` and `import` records are only checked: a `(path, blob)` pair is *verified* when a
   stored observation or snapshot file row of this repository has the same keyed path and blob tokens.
   They are counted, never stored.
6. `observation` and `summary` records become candidates only if **every** cited `(path, blob)` pair is
   verified; otherwise they are counted as `*_rejected_unverified`. Then:
   * text flagged by the sensitive-category scan is rejected (`*_rejected_sensitive`);
   * secrets are redacted and markup is neutralized; instruction-like text is kept but flagged
     `extra.flags = ["instruction_like"]`;
   * a candidate whose evidence source was forgotten, or whose text an earlier forget, rejection or
     correction suppressed, is not created (`forgetting.ForgettingService.blocked_reason`;
     `*_suppressed`);
   * text that duplicates an existing candidate or approved record in the same scope is skipped
     (`*_duplicates`). Unlike `core.CoreService.propose`, which ignores candidates past their
     `expires_at`, this check has no expiry filter: text that matches an *expired* candidate is also
     skipped as a duplicate.
7. Each created candidate has: lifecycle `candidate`; the repository registration's scope; tags
   `repository`, `imported`; confidence value unknown (method `model_uncalibrated` when a model is named,
   otherwise `unknown`); one `blob_range` source per distinct blob, with actor `provider` and extraction
   version `locus-memory.repository-interchange/1`; `validity.source_hashes` = the cited pairs; durable
   retention with a candidate expiry of `EngineConfig.candidate_ttl_seconds` (30 days by default); and
   `extra` naming the proposer (`interchange:<producer>`), producer kind and version, model and summary
   producer.
8. The receipt (operation `repository_import`, status `ok` or `noop`) lists the created record ids (up
   to 256), the counts, the producer name, and three limitations: imported observations and summaries
   are unapproved candidates; file, symbol and import records are verified but not stored; summaries are
   model output with unknown confidence.

Approval goes through the normal review path (`MemoryEngine.approve`, which needs `APPROVE` and a
host-attested reviewer). Nothing in a document can set a lifecycle: an extra `lifecycle` field makes the
record invalid (`tests/test_repository.py::test_imported_summaries_are_candidates_never_approved`).

Re-importing a document that `locus-memory` exported itself is a no-op: file and symbol records verify,
and observations are duplicates (`tests/test_repository.py::test_interchange_round_trip`).

### 5.3 Test coverage of the import path

Tested (all in `tests/test_repository.py`): the export/import round trip
(`::test_interchange_round_trip`); exclusions and the hash-algorithm check
(`::test_import_applies_repository_exclusions_and_hash_algorithm`); unverified summaries, the rejection
of an extra `lifecycle` field, and `PROPOSE` being required
(`::test_imported_summaries_are_candidates_never_approved`); a summary imported through a provider and
then removed by forgetting its blob source
(`::test_forgetting_a_blob_source_removes_inventory_and_derived_summary`); and the validator bounds
(`::test_interchange_validator_rejects_malformed_documents`, `::test_interchange_validator_bounds_and_json_hygiene`).

Implemented but untested (described from the code only):

* sensitive-text rejection (`*_rejected_sensitive`);
* suppression through `forgetting.ForgettingService.blocked_reason` at import time (`*_suppressed`);
* a duplicate of an expired candidate (the round trip covers only an ordinary duplicate);
* rejection of a document whose `initial_commit` differs from the registered repository's;
* a provider exception mapped to `ProviderError` in `import_from_provider`;
* the `repository_id` mismatch check in `import_from_provider`;
* ownership fencing of imports, on both the `MemoryEngine.import_repository_interchange` path and the
  `import_from_provider` path (§6).

---

## 6. The `RepositoryIntelligenceProvider` protocol

```python
@runtime_checkable
class RepositoryIntelligenceProvider(Protocol):
    def describe(self) -> dict[str, Any]: ...      # {"name", "version", "kind", "models"}
    def export(self, repository_id: str, since_snapshot: str | None) -> dict[str, Any]: ...  # a v1 document
```

`RepositoryService.import_from_provider(access, provider, repository_id, *, since_snapshot=None)` pulls
a document from an optional deep producer and imports it. It is not a `MemoryEngine` method; hosts
reach it through `MemoryEngine.services(access).repository`. It:

* refuses an object that does not implement the protocol (`ValidationError`) and an invalid
  `repository_id`;
* calls `describe()` and then `export(repository_id, since_snapshot)`. Any exception other than a
  package error becomes `ProviderError("the repository intelligence provider failed")`, without the
  provider's message, which could contain content;
* refuses a document whose `repository_id` differs from the one requested;
* then runs the same import as §5.2 (`RepositoryService.import_interchange`), but without the engine's
  up-front fence: it does not go through `MemoryEngine`, so `MemoryEngine._fence` never runs.
  Ownership is enforced only inside the transaction, by `core.CoreService._check_owner`, when a
  candidate is actually written. While the package is fenced, a document that yields no candidates (for
  example, all duplicates or unverified) therefore returns a `noop` receipt instead of raising `OwnershipFenced`.

Authorization (`PROPOSE` and a visible repository registration) is checked only inside
`import_interchange`, after the provider has already been called. Hosts should authorize the caller
before calling `import_from_provider`.

Two current limitations:

* `describe()` is called but its result is not used; the document's own `producer` block is what gets
  recorded.
* `since_snapshot` is passed to the provider and validated in the document, but import does not
  interpret it. Every record is evaluated on its own merits, and nothing is deleted because a record is
  missing from a document.

`interchange.SyntheticRepositoryProducer` is a deterministic stand-in **for tests only**. It reads no
files, calls no model, and labels its summaries with the synthetic model name `synthetic-model-0`.

---

## 7. Safety rules

### 7.1 Paths and traversal

`scanner.check_repo_path` accepts only repository-relative, `/`-separated paths of at most 4,096
characters, and rejects:

* empty, `.` and `..` components (so `a//b`, `./a`, `../a` and a trailing `/`);
* absolute paths and drive-letter paths (`C:...`);
* backslashes and NUL;
* control, format (bidi overrides, zero-width), surrogate and private-use characters.

Interchange import never opens the work tree. It compares keyed path and blob tokens with rows written
by `locus-memory`'s own snapshots, so a document cannot cause a file read, a symlink traversal or a git
command.

### 7.2 Exclusions

`scanner.Exclusions` combines `scanner.DEFAULT_EXCLUSIONS`, the host's
`HostCapabilities.repository_exclude_patterns` and the registration's `exclude_patterns`. Extra patterns
can only add exclusions (at most 128 patterns of at most 256 characters, no control characters). The
defaults cover:

* environment and credential files: `.env`, `.env.*`, `*.env`, `.envrc`, `.pgpass`, `.netrc`, `.npmrc`,
  `.pypirc`, `.git-credentials`, `.htpasswd`;
* keys and keystores: `id_rsa*`, `id_ed25519*`, `id_dsa*`, `id_ecdsa*`, `*.ppk`, `*.pem`, `*.key`,
  `*.p12`, `*.pfx`, `*.keystore`, `*.jks`, `*.kdbx`;
* anything named as a secret or credential: `credentials*`, `*secret*`;
* infrastructure state: `*.tfvars`, `*.tfvars.json`, `terraform.tfstate*`;
* directories: `.aws/`, `.ssh/`, `.gnupg/`, `.git/`.

Patterns match any path component, a directory name, or a path prefix. Matching is caseless under both
`str.lower()` and Unicode case folding and normalization (`scanner.fold_name`), so names that a
case-insensitive filesystem treats as the same file are excluded too. In interchange:

* validation rejects the **whole document** if any `path` or source path is excluded;
* export never emits an excluded path.

### 7.3 Registration roots

Repositories are registered (`MemoryEngine.register_repository`) only under
`HostCapabilities.allowed_repository_roots`; with no allowed roots, repository memory is disabled. A
root must resolve inside an allowed root and is never the filesystem root, the home directory or an
ancestor of it (`scanner.check_root`; tests:
`tests/test_repository.py::test_registration_through_symlink_escaping_allowed_root_denied`). Import
requires a registered repository, so a document cannot introduce a repository by itself.

### 7.4 Content

* Document text is data. Observation and summary text is redacted for secrets, neutralized for markup,
  and flagged when instruction-like before it is stored, and it is stored encrypted like every record.
* A candidate never reaches the hot context until it is approved (R12.1;
  `tests/test_context.py::test_only_approved_current_records_are_injected`).
* Summary confidence is never treated as calibrated; the basis `model_interpretation` stays on the record.

---

## 8. Agent Dispatcher: no exporter exists

No real Agent Dispatcher exporter for this format exists, and no Agent Dispatcher integration exists in
`locus-memory`. This was established by the read-only audit of Agent Dispatcher at
`d68446fe33c4e2162c1eb4d4d15bb663a3040888` ([locus-compatibility.md §15.4](locus-compatibility.md),
[ownership-and-extraction.md §3.8](ownership-and-extraction.md)) and is repeated in the
`repository.interchange` module docstring:

* `repository_intelligence.export` writes a `repository-intelligence-export` document with **no schema
  version**. It carries coverage counters, a git snapshot summary, store counts, and current inference
  text with evidence paths, but no record bodies and no content or blob hashes, and nothing reads it
  back.
* `learning.export_generation` is versioned and round-trippable, but it exports procedural-learning
  revisions, not repository intelligence.
* Nothing exports Dispatcher's index records (files, symbols, edges, commits), experience events,
  corrections, episodic or semantic stores, working memory, or learning observations.

Dispatcher has no importable package either (modules load siblings with `exec(compile(...))`), so a
provider would have to be new code: either a Dispatcher CLI command that writes this format, or a
host-side adapter that reads Dispatcher's stores under a versioned schema contract (R4.5 forbids
undocumented access to private tables).

---

## 9. Proposed mapping from Dispatcher stores (future work)

Nothing in this section is implemented or tested. It records what a future exporter would have to do,
based on the audit and on reading Dispatcher's `repo_store.py`, `repo_builder.py` and `repo_index.py`
at `d68446fe`.

### 9.1 Two blockers first

1. **Hash semantics.** Dispatcher's `files.sha256` is the SHA-256 of the file text as decoded by its
   policy reader (`repo_builder.Builder._read`; `experience.file_hashes` does the same). The interchange
   `blob` is a git object id over the raw bytes (`blob <size>\0<bytes>`; see
   `repository.scanner.git_blob_id`). The two cannot be converted into each other. An exporter must take
   blob ids from git (`git ls-files -s`) or hash the raw bytes itself. Without git object ids, every
   record would be unverified, and every observation and summary would be rejected.
2. **Exclusions.** One excluded path rejects a whole document, and Dispatcher's withholding rules
   (`context._skip`) differ from `scanner.DEFAULT_EXCLUSIONS`. The exporter must drop every path that
   `locus-memory` excludes for that registration, including host and registration patterns, before
   writing the document. The host would have to pass those patterns to the provider. It must also never
   read Dispatcher's in-project `.agent-dispatcher/` fallback state, which a cloned repository can forge
   ([locus-compatibility.md §15.5](locus-compatibility.md)).

### 9.2 Record mapping

| Dispatcher source | v1 record | Mapping | Gaps |
|---|---|---|---|
| Locus's registration of the work tree | `repository` | `repository_id` is the id Locus registered with `register_repository`, not Dispatcher's state-directory id (`sha256({path,dev,ino})`); `object_format` and `initial_commit` from git | the host owns the id mapping |
| `repository-index.sqlite` `generations` (published), its `snapshot` and `coverage` JSON | `snapshot` | `snapshot_id` derived from the generation id; `state` `complete` only when coverage is complete, else `partial`; `head` from the snapshot; `dirty` from `worktree_changes` | Dispatcher's coverage semantics have not been mapped in detail |
| `files` (`path`, `size`, `lang`, `status`) | `file` | `path`; `size`; `language` from `lang`; `support` by language | needs the git blob id (§9.1); rows with status `oversized`, `binary` or `failed` have no hash and are skipped |
| `symbols` (`path`, `name`, `qualname`, `kind`, `line`) | `symbol` | `name` (or `qualname` within 200 characters); `symbol_kind` `class` → `class`, `function` → `function`; `line`; `extraction` `ast` for Python, `heuristic` for the regex-parsed languages | Dispatcher's kinds `method` and `constant` have no v1 equivalent (drop them, or map `method` to `function` and lose the distinction) |
| `edges` with `kind = 'imports'` | `import` | source file → `path`; target → `module` | whether Dispatcher's targets are module names or resolved paths was not checked; `calls`, `references`, `inherits` and `tested_by` edges have no v1 type |
| per-file `record` JSON (`defs`, `imports`, `calls`, `bases`) | `observation` | a deterministic rendering per file; `extraction` as for symbols | becomes a `source_attributed` candidate and must pass the secret and sensitive scans |
| `inferences` (`kind = 'model_inference'`, `producer`, `text`, `evidence`, `model`, `status`) | `summary` | `text`; `producer`; `model`; `basis = "model_interpretation"`; `source_hashes` from `evidence` paths, with git blob ids | only `status = 'current'`; the evidence hashes have the §9.1 problem; a row with a null `model` cannot form a valid summary |
| `memory-semantic.json` records with `origin: model` | `summary` | as for inferences, up to 64 source pairs | same hash problem |
| `memory-semantic.json` records with `origin: deterministic` | none | v1 `summary` is model output only, and labelling deterministic text as a model interpretation would be false | needs a new record type in a later version |
| `commits`, `partners`; `repository-memory.json` events, lineage, hotspots | none | v1 has no history record type; `locus-memory` reads bounded git history itself (`RepositoryService.history`) | possible later version |
| `experience.sqlite` events and corrections | none | not repository intelligence; candidates for host-mediated `record_episode` instead (see [integration-workflows.md §4.7](integration-workflows.md)) | Dispatcher stores credential-named paths by name; fix that first |
| `learning.sqlite`, `export_generation` documents | none | procedural candidates, not repository intelligence | see [integration-workflows.md §4.7](integration-workflows.md) |
| `working-memory/*.json` | none | task-local digests that Dispatcher's own retrieval never reads | out of scope |
| `repository-intelligence-export` documents | none | unversioned, and inferences carry evidence paths without hashes, so `source_hashes` cannot be formed | — |

### 9.3 What a v1 import would actually keep

Under v1, `file`, `symbol` and `import` records are verified and counted but **not stored**, so
Dispatcher's deep index would add nothing durable beyond what `locus-memory`'s own snapshots already
hold. Only `observation` and `summary` records become (unapproved) candidates. A future version that
stores producer-supplied symbols or edges would need its own provenance (basis `observed` from a
`tool` producer, never `user_stated`) and invalidation by blob id.

### 9.4 Other exporter obligations

* Split large repositories into several documents (each with its `repository` record) to stay under 16
  MiB and 100,000 records. This is safe because import evaluates records independently.
* Report a semantic producer `version`, not Dispatcher's source-byte policy digests, so a code move does
  not change the producer identity.
* Use producer `kind` `tool` for parsed facts. Put model output only in `summary` records, with the real
  model label.
* Apply secret redaction before export. `locus-memory` redacts again on import, but an exporter must not
  rely on that, because the document itself is plaintext.

---

## 10. Open questions

* Should v2 add record types for commits and lineage, deterministic multi-file summaries, non-import
  edges, and experience?
* Should `since_snapshot` gain incremental semantics, including deletions of observations that a
  producer no longer reports?
* Should the host pass its exclusion patterns to a provider through the protocol, rather than out of
  band?
* Should a CLI command expose export and import for operators?
