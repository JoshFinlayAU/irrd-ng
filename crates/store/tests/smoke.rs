mod common;

use common::*;
use store::JournalEntryOrigin;

#[test]
fn upsert_read_back_and_reopen() {
    let dir = TempDir::new("smoke");
    {
        let store = open(&dir, settings(&[]));
        store
            .write(|tx| {
                tx.upsert_rpsl_object(
                    &route(
                        "192.0.2.0/24AS65537",
                        "TEST",
                        "192.0.2.0/24",
                        65537,
                        "MNT-A",
                    ),
                    JournalEntryOrigin::Mirror,
                    None,
                    None,
                )
            })
            .expect("write");
        let r = store.read().expect("read");
        let v = r.view();
        let o = v
            .object("TEST", "route", "192.0.2.0/24AS65537")
            .expect("get")
            .expect("present");
        assert_eq!(o.object_text, "object-text");
        assert_eq!(
            v.ids_by_lookup("mnt-by", Some("MNT-A"))
                .expect("lookup")
                .len(),
            1
        );
        assert_eq!(
            v.routes_for_origin("TEST", 65537, Some(4))
                .expect("origin")
                .len(),
            1
        );
    }
    let store = open(&dir, settings(&[]));
    let r = store.read().expect("read");
    assert_eq!(r.view().object_count().expect("count"), 1);
}
