//! `SourceExportRunner` (`irrd/mirroring/mirror_runners_export.py`): a
//! gzipped dump of a source and its `CURRENTSERIAL` file.
//!
//! The export is written to a temporary file (so its gzip header names
//! that file, as v4's does) and then moved into place. Objects come in
//! v4's query order (`ip_first`, `asn_first`, `rpsl_pk`), without the
//! suppressed ones, with password hashes removed and dummified, except in
//! `export_destination_unfiltered`.

use std::io::Write as _;
use std::path::Path;

use query::order::OrderKey;
use store::{ReadView, Store};

use crate::messages;
use crate::mirror::pyerr::os_error_text;
use crate::mirror::settings::SourceMirrorSettings;
use crate::serve::files;

/// v4's logger name.
pub const LOG_TARGET: &str = "irrd.mirroring.mirror_runners_export";

/// `EXPORT_PERMISSIONS`
pub const EXPORT_PERMISSIONS: u32 = 0o644;

/// The scheduler's name for the runner.
pub const EXPORT_RUNNER: &str = "SourceExportRunner";

/// Object ids of a source's visible objects, in v4's query order.
pub fn visible_ids_in_v4_order(view: &ReadView<'_>, source: &str) -> store::Result<Vec<u64>> {
    let mut keys = Vec::new();
    for item in view.objects(Some(source), None)? {
        let (id, o) = item?;
        if o.is_visible() {
            keys.push(OrderKey::of(id, &o));
        }
    }
    keys.sort_unstable_by(OrderKey::v4_cmp);
    Ok(keys.into_iter().map(|k| k.id).collect())
}

/// An object's text as it is served: auth hashes removed and dummified
/// unless `unfiltered`.
pub fn served_text<'t>(
    text: &'t str,
    object_class: &str,
    rpsl_pk: &str,
    settings: &SourceMirrorSettings,
    unfiltered: bool,
) -> std::borrow::Cow<'t, str> {
    if unfiltered {
        return std::borrow::Cow::Borrowed(text);
    }
    match rpsl::text::remove_auth_hashes(text) {
        std::borrow::Cow::Borrowed(t) => {
            rpsl::text::dummify_object_text(t, object_class, rpsl_pk, &settings.dummify)
        }
        std::borrow::Cow::Owned(t) => std::borrow::Cow::Owned(
            rpsl::text::dummify_object_text(&t, object_class, rpsl_pk, &settings.dummify)
                .into_owned(),
        ),
    }
}

/// `SourceExportRunner(source).run()`.
pub fn run_export(store: &Store, settings: &SourceMirrorSettings) {
    let source = settings.name.as_str();
    match export_all(store, settings) {
        Ok(()) => {}
        Err(e) => {
            tracing::error!(target: LOG_TARGET, "{}", messages::export_failed(source, &e));
        }
    }
}

fn export_all(store: &Store, settings: &SourceMirrorSettings) -> Result<(), String> {
    let source = settings.name.as_str();
    let mut exported = Vec::new();
    if let Some(dest) = &settings.export_destination {
        tracing::info!(target: LOG_TARGET, "{}", messages::export_starting(source, dest));
        exported.push(export_one(store, settings, dest, false)?);
    }
    if let Some(dest) = &settings.export_destination_unfiltered {
        tracing::info!(target: LOG_TARGET, "{}", messages::export_starting_unfiltered(source, dest));
        exported.push(export_one(store, settings, dest, true)?);
    }
    if exported.is_empty() {
        return Ok(());
    }
    let src = source.to_owned();
    store
        .write(move |tx| {
            for serial in &exported {
                tx.record_serial_exported(&src, *serial)?;
            }
            Ok(())
        })
        .map_err(|e| e.to_string())
}

/// `_export(export_destination, ...)`: returns the serial recorded.
fn export_one(
    store: &Store,
    settings: &SourceMirrorSettings,
    destination: &str,
    unfiltered: bool,
) -> Result<Option<i64>, String> {
    let source = settings.name.as_str();
    let filename_export = files::py_path_join(
        destination,
        &format!("{}.db.gz", rpsl::python::lower(source)),
    );
    let tmp = files::named_temporary_file().map_err(|e| os_error_text(&e, None))?;
    let filename_serial = files::py_path_join(
        destination,
        &format!("{}.CURRENTSERIAL", rpsl::python::upper(source)),
    );
    // On an error the temporary file stays behind, as v4's
    // NamedTemporaryFile(delete=False) does.
    let serial = write_export(store, settings, &tmp, unfiltered)?;
    let tmp_str = tmp.to_string_lossy().into_owned();
    files::chmod(&tmp, EXPORT_PERMISSIONS).map_err(|e| os_error_text(&e, Some(&tmp_str)))?;
    for f in [&filename_export, &filename_serial] {
        if Path::new(f).exists() {
            std::fs::remove_file(f).map_err(|e| os_error_text(&e, Some(f)))?;
        }
    }
    files::shutil_move(&tmp, Path::new(&filename_export))
        .map_err(|e| os_error_text(&e, Some(&filename_export)))?;
    if let Some(serial) = serial {
        std::fs::write(&filename_serial, serial.to_string())
            .map_err(|e| os_error_text(&e, Some(&filename_serial)))?;
        files::chmod(Path::new(&filename_serial), EXPORT_PERMISSIONS)
            .map_err(|e| os_error_text(&e, Some(&filename_serial)))?;
    }
    let serial_text = serial.map_or_else(|| "None".to_owned(), |s| s.to_string());
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        messages::export_complete(source, &serial_text, &filename_export, &filename_serial)
    );
    Ok(serial)
}

/// Write the gzipped export to `path`; returns `serial_newest_seen`.
fn write_export(
    store: &Store,
    settings: &SourceMirrorSettings,
    path: &Path,
    unfiltered: bool,
) -> Result<Option<i64>, String> {
    let source = settings.name.as_str();
    let path_str = path.to_string_lossy().into_owned();
    let io = |e: std::io::Error| os_error_text(&e, Some(&path_str));
    let txn = store.read_long().map_err(|e| e.to_string())?;
    let view = txn.view();
    let serial = view
        .database_status(source)
        .map_err(|e| e.to_string())?
        .and_then(|s| s.serial_newest_seen);
    let ids = visible_ids_in_v4_order(&view, source).map_err(|e| e.to_string())?;
    let mut gz = files::PyGzipWriter::create(path).map_err(io)?;
    for id in ids {
        let Some(o) = view.object_by_id(id).map_err(|e| e.to_string())? else {
            continue;
        };
        let text = served_text(
            o.object_text,
            o.object_class,
            o.rpsl_pk,
            settings,
            unfiltered,
        );
        gz.write_all(text.as_bytes()).map_err(io)?;
        gz.write_all(b"\n").map_err(io)?;
    }
    gz.write_all(b"# EOF\n").map_err(io)?;
    gz.finish().map_err(io)?;
    Ok(serial)
}
