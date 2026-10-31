//! The messages in `messages.rs` match v4's catalogue
//! (`parity/reference/v4-strings.tsv`), rendered with v4's own
//! placeholder names.

use std::path::Path;

use nrtm::messages;

fn catalogue() -> Vec<String> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../parity/reference/v4-strings.tsv");
    std::fs::read_to_string(p)
        .expect("v4-strings.tsv")
        .lines()
        .filter_map(|l| l.splitn(4, '\t').nth(3).map(|t| t.replace("\\n", "\n")))
        .collect()
}

#[test]
fn file_import_messages_are_v4s() {
    let c = catalogue();
    let has = |s: String| assert!(c.contains(&s), "not in v4's catalogue: {s}");
    has(messages::starting_file_import(
        "{self.source}",
        "{self.filename}",
    ));
    has(messages::starting_update_import(
        "{self.source}",
        "{self.filename}",
    ));
    has(messages::unknown_object_class("{e.rpsl_object_class}"));
    has(messages::parsing_errors_log(
        "{self.source}",
        "{obj.messages.errors()}",
        "{rpsl_text}",
    ));
    has("Ignored {self.obj_unknown} objects found in import for {self.source} due to unknown object classes: {unknown_formatted}".to_string());
    assert_eq!(
        messages::unknown_classes_report(1, "S", "x"),
        "Ignored 1 objects found in import for S due to unknown object classes: x"
    );
    // The report line is built from the "{prefix}: ..." template.
    let report = messages::file_import_report("{x}", 0, 0, 0, 0);
    let tail = report.split_once(": ").expect("prefix").1;
    assert!(c.iter().any(|t| {
        t.ends_with(
            &tail
                .replacen("0 objects read", "{self.obj_parsed} objects read", 1)
                .replacen("0 objects inserted", "{obj_successful} objects inserted", 1)
                .replacen(
                    "ignored 0 due to errors",
                    "ignored {self.obj_errors} due to errors",
                    1,
                )
                .replacen(
                    "ignored 0 due to object_class_filter",
                    "ignored {self.obj_ignored_class} due to object_class_filter",
                    1,
                ),
        )
    }));
}

#[test]
fn store_messages_are_v4s() {
    let c = catalogue();
    let has = |s: String| assert!(c.contains(&s), "not in v4's catalogue: {s}");
    has(store::messages::no_row_matched("{user_identifier}"));
    has(store::messages::suspend_missing("{pk_uuid}"));
    assert!(
        c.contains(
            &store::messages::force_reload_set("{source}", true)
                .replace("will be True", "will be {synchronised_serials}")
        )
    );
}
