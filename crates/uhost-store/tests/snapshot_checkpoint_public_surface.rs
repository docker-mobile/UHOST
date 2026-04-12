use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use uhost_store::{
    CellDirectoryCollection, CellDirectoryRecord, CellDirectorySnapshotCheckpoint,
    CellParticipantRecord, CellServiceGroupDirectoryCollection,
    CellServiceGroupDirectorySnapshotCheckpoint, DocumentSnapshotCheckpoint, DocumentStore,
    LeaseRegistrationCollection, LeaseRegistrationRecord, LeaseRegistrationSnapshotCheckpoint,
    MetadataCollection, MetadataSnapshotCheckpoint, RegionDirectoryRecord,
    resolve_cell_service_group_directory,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Example {
    name: String,
}

#[tokio::test]
async fn crate_root_snapshot_checkpoint_exports_cover_public_surface() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let region = RegionDirectoryRecord::new("local", "Local");

    let document_store = DocumentStore::<Example>::open(temp.path().join("document.json"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    document_store
        .create(
            "alpha",
            Example {
                name: String::from("document"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let document_checkpoint: DocumentSnapshotCheckpoint<Example> = document_store
        .snapshot_checkpoint()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(document_checkpoint.records.len(), 1);

    let lease_collection = LeaseRegistrationCollection::open_local(temp.path().join("lease.json"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    lease_collection
        .create(
            "controller:node-a",
            LeaseRegistrationRecord::new(
                "controller:node-a",
                "runtime_process",
                "controller:node-a",
                "controller",
                Some(String::from("node-a")),
                15,
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let lease_checkpoint: LeaseRegistrationSnapshotCheckpoint = lease_collection
        .snapshot_checkpoint()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(lease_checkpoint.records.len(), 1);

    let metadata_collection =
        MetadataCollection::<Example>::open_local(temp.path().join("metadata.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    metadata_collection
        .create(
            "alpha",
            Example {
                name: String::from("metadata"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let metadata_checkpoint: MetadataSnapshotCheckpoint<Example> = metadata_collection
        .snapshot_checkpoint()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(metadata_checkpoint.records.len(), 1);

    let participant = CellParticipantRecord::new(
        "controller:node-a",
        "runtime_process",
        "controller:node-a",
        "controller",
    )
    .with_node_name("node-a")
    .with_service_groups(["control"]);
    let cell_directory = CellDirectoryRecord::new("local:cell-a", "cell-a", region.clone())
        .with_participant(participant);

    let cell_directory_collection =
        CellDirectoryCollection::open_local(temp.path().join("cell-directory.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    cell_directory_collection
        .create("local:cell-a", cell_directory.clone())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let cell_directory_checkpoint: CellDirectorySnapshotCheckpoint = cell_directory_collection
        .snapshot_checkpoint()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(cell_directory_checkpoint.records.len(), 1);

    let service_group_directory_collection = CellServiceGroupDirectoryCollection::open_local(
        temp.path().join("service-group-directory.json"),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let service_group_directory = resolve_cell_service_group_directory(&cell_directory);
    service_group_directory_collection
        .create("local:cell-a", service_group_directory)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let service_group_directory_checkpoint: CellServiceGroupDirectorySnapshotCheckpoint =
        service_group_directory_collection
            .snapshot_checkpoint()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(service_group_directory_checkpoint.records.len(), 1);
}
