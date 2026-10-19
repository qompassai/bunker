//! Runs the shared canonicalization conformance vectors in
//! `tests/vectors/`. These files are the estate's reference set:
//! signer and executor code both answer to them (pilot brief
//! Stage A).

use std::path::PathBuf;

use signed_approval::canonical::canonicalize;

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    input: String,
    canonical: Option<String>,
    #[serde(default)]
    reject: bool,
}

#[test]
fn conformance_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("vectors dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no conformance vectors found");
    for file in files {
        let text = std::fs::read_to_string(&file).expect("vector readable");
        let vector: Vector = serde_json::from_str(&text).expect("vector parses");
        let result = canonicalize(vector.input.as_bytes());
        if vector.reject {
            assert!(
                result.is_err(),
                "vector '{}' ({}) must reject, got {:?}",
                vector.name,
                file.display(),
                result.map(|b| String::from_utf8_lossy(&b).into_owned())
            );
        } else {
            let expected = vector
                .canonical
                .unwrap_or_else(|| panic!("vector '{}' needs canonical or reject", vector.name));
            let actual = result
                .unwrap_or_else(|e| panic!("vector '{}' must canonicalize: {e}", vector.name));
            assert_eq!(
                String::from_utf8_lossy(&actual),
                expected,
                "vector '{}' canonical mismatch",
                vector.name
            );
        }
    }
}
