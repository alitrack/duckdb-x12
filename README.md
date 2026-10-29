# duckdb-x12

**ANSI X12 / UN-EDIFACT EDI, in SQL.** Sniff the transaction type, read the
interchange's own delimiter set, count segments, and pull out any segment's data
elements — right in DuckDB, no external EDI tooling.

Built with the [quack-rs] C-API extension template. The engine (`x12_core/`) is a
verbatim port of the pure-compute core of Query-farm's `vgi-x12` worker (MIT) — a
structural X12/EDIFACT parser (envelope + segments + delimiters, `serde` only, no
I/O, no network) — with only the Arrow IPC transport swapped for direct C-API
vector I/O.

```sql
INSTALL 'x12' FROM 'target/release/x12.duckdb_extension';
LOAD 'x12';

-- First ST01 (X12) / UNH02 (EDIFACT) transaction type code, NULL if not EDI
SELECT x12_transaction_type('ISA*00*...~GS*HP*...~ST*835*0001~...');  -- 835

-- The interchange's sniffed delimiter set + family
SELECT x12_delimiters('ISA*...~')
-- {element:'*', segment:'~', component:':', repetition:'^', release:NULL, family:'x12'}

-- Total body segments (ST..SE) across all transactions (-1 when not EDI)
SELECT x12_segment_count('ISA*...~...');                              -- 5

-- The Nth segment's data elements (0-based, document order)
SELECT x12_elements('ISA*...~...ST*835*0001~...', 0);                 -- [835, 0001]
```

## Functions

| Function | Returns | Notes |
|----------|---------|-------|
| `x12_transaction_type(content)` | `VARCHAR` | First ST01 (X12) / UNH02 (EDIFACT) type code; `NULL` when not EDI. |
| `x12_delimiters(content)` | `STRUCT(element, segment, component, repetition, release, family)` | Sniffed delimiter bytes (single-char) + `family` in `{x12, edifact, unknown}`. `repetition`/`release` are `NULL` when the family has none. |
| `x12_segment_count(content)` | `BIGINT` | Body segments (ST..SE inclusive) across all transactions; `-1` when not EDI. |
| `x12_elements(content, index)` | `LIST(VARCHAR)` | The Nth segment's positional data elements; `NULL` when out of range / not EDI. |

`content` is a VARCHAR holding the interchange bytes (BLOB callers: `CAST` to
VARCHAR). X12 delimiters are sniffed from the fixed-width ISA; EDIFACT from the
UNA (or UNB defaults).

## Semantics

- **Sniffing is total** — input that is neither X12 (`ISA…`) nor EDIFACT
  (`UNA`/`UNB…`) yields `NULL` (type/elements), an `unknown`-family struct, or
  `-1` (count). Never a SQL error.
- **Malformed but family-detected** input parses as far as it can; the envelope
  is best-effort, so counts/elements reflect what was recovered.
- A **LIST row** is capped (4096 elements); an overflowing row is a clean error.

## Deferred (documented)

The worker's 5 **table** functions (`segments`, `segments_elements`, `envelope`,
`edifact_segments`, `edifact_envelope`, `shaped_*`) read a **file path / glob
source** (the VGI host exposes files; a loadable extension has no such surface)
and return LIST/nested-STRUCT columns. The underlying `x12_core` parse is fully
available in-process — the scalars above reuse it — but the file-glob tables are
not ported in v1.

## Building

```bash
make            # requires a local duckdb build (see the quack-rs template)
make test       # SQL-level integration tests (LOAD the built extension in-memory)
```

[quack-rs]: https://github.com/duckdb/quack-rs
