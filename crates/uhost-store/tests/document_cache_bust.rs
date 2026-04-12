use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use time::OffsetDateTime;
use tokio::fs;
use uhost_store::{DocumentCollection, DocumentStore, StoredDocument};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Example {
    name: String,
}

fn stored_example(name: &str, version: u64) -> StoredDocument<Example> {
    StoredDocument {
        version,
        updated_at: OffsetDateTime::now_utc(),
        deleted: false,
        value: Example {
            name: String::from(name),
        },
    }
}

#[tokio::test]
async fn same_path_handles_share_cache_busts_without_explicit_reload() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let path = temp.path().join("docs.json");
    let store_a = DocumentStore::<Example>::open(&path)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let store_b = DocumentStore::<Example>::open(&path)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    store_a
        .create(
            "alpha",
            Example {
                name: String::from("one"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let loaded = store_b
        .get("alpha")
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing alpha record"));
    assert_eq!(loaded.value.name, "one");
}

#[tokio::test]
async fn opening_a_new_handle_republishes_out_of_band_rewrites() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let path = temp.path().join("docs.json");
    let store_a = DocumentStore::<Example>::open(&path)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    store_a
        .create(
            "alpha",
            Example {
                name: String::from("safe"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let external = DocumentCollection {
        schema_version: 1,
        revision: 1,
        compacted_through_revision: 0,
        records: std::collections::BTreeMap::from([(
            String::from("alpha"),
            stored_example("external", 2),
        )]),
        changes: Vec::new(),
    };
    fs::write(
        &path,
        serde_json::to_vec(&external).unwrap_or_else(|error| panic!("{error}")),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));

    let stale = store_a
        .get("alpha")
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing alpha record"));
    assert_eq!(stale.value.name, "safe");

    let _store_b = DocumentStore::<Example>::open(&path)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let refreshed = store_a
        .get("alpha")
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing alpha record"));
    assert_eq!(refreshed.value.name, "external");
}

#[tokio::test]
async fn reload_from_disk_reports_out_of_band_corruption() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let path = temp.path().join("docs.json");
    let store = DocumentStore::<Example>::open(&path)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    store
        .create(
            "alpha",
            Example {
                name: String::from("safe"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    fs::write(&path, b"{broken-json")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let error = store
        .reload_from_disk()
        .await
        .expect_err("external corruption should fail explicit reload");
    assert!(
        error
            .to_string()
            .contains("failed to decode document collection")
    );
}
