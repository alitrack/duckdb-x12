//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full function surface (4 scalars).
//!
//! Run: `cargo test --release` (after the cdylib is built and stamped).
//!
//! Bundled test DuckDB is v1.1.0. `content` is passed as a VARCHAR literal; the
//! X12 test interchange uses `*`/`~` delimiters (no `$`, so no CLI/harness
//! quoting surprises). STRUCT `-> 'field'` on v1.1.0 returns a JSON-typed value,
//! so field assertions CAST to VARCHAR and match the exact rendering.

use quack_rs::testing::InMemoryDb;

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/x12.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display())).expect("load extension");
    d
}

/// A minimal but well-formed 835 claim interchange: ISA + GS + ST..SE + GE + IEA.
fn body() -> String {
    [
        "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *240101*1200*^*00501*000000001*0*P*:~",
        "GS*HP*SEND*RECV*20240101*1200*1*X*005010X221A1~",
        "ST*835*0001~",
        "BPR*I*1000*C*ACH~",
        "TRN*1*TRACE123*1234567890~",
        "CLP*PCN1*1*500*400*100*MC*CLAIM9*11~",
        "SE*5*0001~",
        "GE*1*1~",
        "IEA*1*000000001~",
    ]
    .concat()
}

#[test]
fn transaction_type() {
    let d = db();
    let t: String = d
        .query_one(&format!("SELECT x12_transaction_type('{b}')", b = body()))
        .unwrap();
    assert_eq!(t, "835");

    // Not EDI -> NULL.
    let nul: Option<String> = d.query_one("SELECT x12_transaction_type('not edi')").unwrap();
    assert!(nul.is_none());
}

#[test]
fn delimiters_struct() {
    let d = db();
    // element '*', segment '~', component ':', repetition '^', release NULL, family 'x12'.
    let element: String = d
        .query_one(&format!(
            "SELECT CAST(x12_delimiters('{b}') -> 'element' AS VARCHAR)", b = body()
        ))
        .unwrap();
    let segment: String = d
        .query_one(&format!(
            "SELECT CAST(x12_delimiters('{b}') -> 'segment' AS VARCHAR)", b = body()
        ))
        .unwrap();
    let family: String = d
        .query_one(&format!(
            "SELECT CAST(x12_delimiters('{b}') -> 'family' AS VARCHAR)", b = body()
        ))
        .unwrap();
    assert_eq!(element, "\"*\""); // v1.1.0 renders a varchar field with quotes
    assert_eq!(segment, "\"~\"");
    assert_eq!(family, "\"x12\"");

    // Not EDI -> family 'unknown'; the delimiter fields are null (the struct
    // itself is still a value, so -> 'family' is readable).
    let fam2: String = d
        .query_one("SELECT CAST(x12_delimiters('nope') -> 'family' AS VARCHAR)")
        .unwrap();
    assert_eq!(fam2, "\"unknown\"");
    // A null delimiter field renders as JSON null on v1.1.0.
    let el2: String = d
        .query_one("SELECT CAST(x12_delimiters('nope') -> 'element' AS VARCHAR)")
        .unwrap();
    assert_eq!(el2, "null");
}

#[test]
fn segment_count() {
    let d = db();
    // The ST..SE body holds ST,BPR,TRN,CLP,SE = 5 segments.
    let n: i64 = d
        .query_one(&format!("SELECT x12_segment_count('{b}')", b = body()))
        .unwrap();
    assert_eq!(n, 5);

    // Not EDI -> -1.
    let m: i64 = d.query_one("SELECT x12_segment_count('nope')").unwrap();
    assert_eq!(m, -1);
}

#[test]
fn elements() {
    let d = db();
    // Read the LIST back as a comma-joined VARCHAR (array_to_string), which
    // query_one can fetch. Segment 0 is ST: [835, 0001]; segment 2 is TRN.
    let st: String = d
        .query_one(&format!(
            "SELECT array_to_string(x12_elements('{b}', 0), chr(44))", b = body()
        ))
        .unwrap();
    assert_eq!(st, "835,0001");
    let trn: String = d
        .query_one(&format!(
            "SELECT array_to_string(x12_elements('{b}', 2), chr(44))", b = body()
        ))
        .unwrap();
    assert_eq!(trn, "1,TRACE123,1234567890");

    // Out of range -> NULL list -> NULL joined string.
    let oob: Option<String> = d
        .query_one(&format!(
            "SELECT array_to_string(x12_elements('{b}', 99), chr(44))", b = body()
        ))
        .unwrap();
    assert!(oob.is_none());

    // NULL index -> NULL.
    let nulidx: Option<String> = d
        .query_one(&format!(
            "SELECT array_to_string(x12_elements('{b}', NULL), chr(44))", b = body()
        ))
        .unwrap();
    assert!(nulidx.is_none());
}
