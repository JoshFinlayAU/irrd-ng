//! `-t` templates against v4's output in `parity/reference/templates/`.
//!
//! The reference files are whois responses: the template body followed by
//! the RIPE-style response framing (three newlines), which belongs to the
//! query layer. The body must be byte-identical.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::Path;

#[test]
fn templates_match_v4() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../parity/reference/templates");
    assert_eq!(rpsl::OBJECT_CLASSES.len(), 19);
    for class in rpsl::OBJECT_CLASSES {
        let path = dir.join(format!("{}.txt", class.name));
        let expected =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let body = expected
            .strip_suffix("\n\n\n")
            .unwrap_or_else(|| panic!("{}: unexpected framing", path.display()));
        assert_eq!(
            class.generate_template(),
            body,
            "template for {}",
            class.name
        );
    }
}
