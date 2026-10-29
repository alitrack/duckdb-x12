// DuckDB loadable extension: ANSI X12 / UN-EDIFACT EDI sniffing — transaction
// type, delimiter sets, segment counts, and element extraction, in SQL.
//
// Thin quack-rs binding layer over `x12_core` (verbatim from Query-farm's
// vgi-x12 x12-core crate, MIT — a pure-compute EDI parser with only `serde`;
// no I/O, no network, no Arrow). Only the Arrow IPC transport was replaced
// with direct C-API vector I/O.
//
// Function surface (v1 — scalars, no file/glob source):
//
//   x12_transaction_type(content)  -> VARCHAR   first ST01 (X12) / UNH02 (EDIFACT)
//                                                           type code, NULL if none
//   x12_delimiters(content)        -> STRUCT(element, segment, component, repetition,
//                                                           release, family)
//   x12_segment_count(content)     -> BIGINT    total body segments (ST..SE) across
//                                                           all transactions
//   x12_elements(content, index)   -> LIST(VARCHAR)  the Nth segment's data elements
//
// `content` is a VARCHAR or BLOB holding the interchange bytes. Sniffing is
// total: input that is neither X12 (`ISA…`) nor EDIFACT (`UNA`/`UNB…`) yields
// NULL (transaction_type) / an Unknown-family struct / -1 (count) / NULL
// (elements) — never a SQL error. Malformed but family-detected input parses
// as far as it can; the envelope is best-effort.

use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::{ScalarFunctionBuilder, ScalarFunctionInfo};
use quack_rs::types::{LogicalType, TypeId};
use quack_rs::vector::{ListBuilder, VectorReader, VectorWriter};

use x12_core::delimiters::{self, Family};
use x12_core::envelope::parse_x12;

const MAX_ELEMENTS_PER_CALL: usize = 4096;

/// Read a content cell (VARCHAR or BLOB) into bytes. Returns None when the row
/// is NULL/invalid.
unsafe fn content_bytes(value: &VectorReader, row: usize) -> Option<Vec<u8>> {
    if !value.is_valid(row) {
        return None;
    }
    // VARCHAR path first (text content); fall back to BLOB.
    // VectorReader::read_str is only valid for VARCHAR columns; read_blob for BLOB.
    // We probe by trying str then blob based on the logical type at registration,
    // but the simplest total approach: try read_str; if the column is BLOB it
    // would have been registered as Blob. We register the param as Varchar, so
    // callers pass VARCHAR; BLOB callers CAST to VARCHAR. See registration below.
    let s = value.read_str(row);
    Some(s.as_bytes().to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// x12_transaction_type(content) -> VARCHAR
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(transaction_type_fn, |_info, input, output| {
    unsafe {
        let value = VectorReader::new(input, 0);
        let row_count = value.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match content_bytes(&value, row) {
                Some(bytes) => {
                    let t = x12_core::envelope::first_transaction_type(&bytes);
                    if t.is_empty() {
                        writer.set_null(row);
                    } else {
                        writer.write_varchar(row, &t);
                    }
                }
                None => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// x12_delimiters(content) -> STRUCT(element, segment, component, repetition,
//                                        release, family)
// element/segment/component/release are single chars; repetition NULL when the
// family has none. family in {'x12','edifact','unknown'}.
// ─────────────────────────────────────────────────────────────────────────────

const DELIM_FIELDS: &[(&str, TypeId)] = &[
    ("element", TypeId::Varchar),
    ("segment", TypeId::Varchar),
    ("component", TypeId::Varchar),
    ("repetition", TypeId::Varchar),
    ("release", TypeId::Varchar),
    ("family", TypeId::Varchar),
];

fn byte_str(b: u8) -> String {
    String::from_utf8(vec![b]).unwrap_or_else(|_| format!("\\x{b:02x}"))
}

fn family_str(f: &Family) -> &'static str {
    match f {
        Family::X12 => "x12",
        Family::Edifact => "edifact",
        Family::Unknown => "unknown",
    }
}

quack_rs::scalar_callback!(delimiters_fn, |_info, input, output| {
    unsafe {
        let value = VectorReader::new(input, 0);
        let row_count = value.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, DELIM_FIELDS.len());
        for row in 0..row_count {
            let bytes = content_bytes(&value, row);
            let fam = match &bytes {
                Some(b) => delimiters::detect_family(b),
                None => Family::Unknown,
            };
            let d = match (fam, &bytes) {
                (Family::X12, Some(b)) => delimiters::sniff_x12(b),
                (Family::Edifact, Some(b)) => delimiters::sniff_edifact_una(b),
                _ => None,
            };
            match d {
                Some(d) => {
                    sw.write_varchar(row, 0, &byte_str(d.element));
                    sw.write_varchar(row, 1, &byte_str(d.segment));
                    sw.write_varchar(row, 2, &byte_str(d.component));
                    match d.repetition {
                        Some(r) => sw.write_varchar(row, 3, &byte_str(r)),
                        None => sw.set_null(row, 3),
                    }
                    match d.release {
                        Some(r) => sw.write_varchar(row, 4, &byte_str(r)),
                        None => sw.set_null(row, 4),
                    }
                    sw.write_varchar(row, 5, family_str(&fam));
                }
                None => {
                    sw.set_null(row, 0);
                    sw.set_null(row, 1);
                    sw.set_null(row, 2);
                    sw.set_null(row, 3);
                    sw.set_null(row, 4);
                    sw.write_varchar(row, 5, family_str(&fam));
                }
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// x12_segment_count(content) -> BIGINT  (-1 when family unknown)
// ─────────────────────────────────────────────────────────────────────────────

fn segment_count(bytes: &[u8]) -> i64 {
    match delimiters::detect_family(bytes) {
        Family::X12 => {
            let n = parse_x12(bytes)
                .iter()
                .flat_map(|i| i.groups.iter())
                .flat_map(|g| g.transactions.iter())
                .map(|t| t.segments.len())
                .sum::<usize>();
            n as i64
        }
        Family::Edifact => {
            let n = x12_core::edifact::parse_edifact(bytes)
                .iter()
                .flat_map(|i| i.messages.iter())
                .map(|m| m.body().len())
                .sum::<usize>();
            n as i64
        }
        Family::Unknown => -1,
    }
}

quack_rs::scalar_callback!(segment_count_fn, |_info, input, output| {
    unsafe {
        let value = VectorReader::new(input, 0);
        let row_count = value.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match content_bytes(&value, row) {
                Some(bytes) => writer.write_i64(row, segment_count(&bytes)),
                None => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// x12_elements(content, index) -> LIST(VARCHAR)
// The Nth (0-based, across all transactions in document order) segment's data
// elements. NULL when index out of range or family unknown.
// ─────────────────────────────────────────────────────────────────────────────

fn all_segments(bytes: &[u8]) -> Vec<(String, Vec<String>)> {
    match delimiters::detect_family(bytes) {
        Family::X12 => parse_x12(bytes)
            .iter()
            .flat_map(|i| i.groups.iter())
            .flat_map(|g| g.transactions.iter())
            .flat_map(|t| t.segments.iter())
            .map(|s| (s.id().to_string(), s.data_elements().to_vec()))
            .collect(),
        Family::Edifact => x12_core::edifact::parse_edifact(bytes)
            .iter()
            .flat_map(|i| i.messages.iter())
            .flat_map(|m| m.body().iter())
            .map(|s| (s.id().to_string(), s.data_elements().to_vec()))
            .collect(),
        Family::Unknown => Vec::new(),
    }
}

quack_rs::scalar_callback!(elements_fn, |info, input, output| {
    unsafe {
        let content = VectorReader::new(input, 0);
        let index = VectorReader::new(input, 1);
        let row_count = content.row_count();
        let fn_info = ScalarFunctionInfo::new(info);
        let mut builder = ListBuilder::new(output).with_element_limit(MAX_ELEMENTS_PER_CALL);
        for row in 0..row_count {
            let idx = if index.is_valid(row) { index.read_i64(row) } else { -1 };
            let segs: Vec<(String, Vec<String>)> = match content_bytes(&content, row) {
                Some(bytes) => all_segments(&bytes),
                None => Vec::new(),
            };
            let elems = segs.get(idx as usize).map(|(_, e)| e.clone());
            match elems {
                None => {
                    builder.push_row(row, 0, |_, _| {});
                    VectorWriter::from_vector(output).set_null(row);
                }
                Some(items) => {
                    let n = items.len();
                    builder.push_row(row, n, |w, base| {
                        for (i, s) in items.iter().enumerate() {
                            w.write_str(base + i, s.as_str());
                        }
                    });
                }
            }
        }
        if builder.overflowed() {
            fn_info.set_error(&format!(
                "x12_elements: a row produced more than {MAX_ELEMENTS_PER_CALL} elements"
            ));
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    con.register_scalar(
        ScalarFunctionBuilder::new("x12_transaction_type")
            .param(TypeId::Varchar)
            .returns(TypeId::Varchar)
            .function(transaction_type_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("x12_delimiters")
            .param(TypeId::Varchar)
            .returns_logical(LogicalType::struct_type(DELIM_FIELDS))
            .function(delimiters_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("x12_segment_count")
            .param(TypeId::Varchar)
            .returns(TypeId::BigInt)
            .function(segment_count_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("x12_elements")
            .param(TypeId::Varchar)
            .param(TypeId::BigInt)
            .returns_logical(LogicalType::list(TypeId::Varchar))
            .function(elements_fn),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(x12_init_c_api, |con| register_all(con));
