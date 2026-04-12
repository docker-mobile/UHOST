#[path = "support/storage_runtime_harness.rs"]
mod storage_runtime_harness;

use storage_runtime_harness::{
    DEFAULT_BOOTSTRAP_ADMIN_TOKEN, assert_error_envelope, issue_workload_identity,
    request_json_with_admin_token_and_status, request_with_admin_token, request_with_bearer_token,
    required_string, spawn_test_runtime,
};

#[test]
fn operator_storage_inspection_error_envelopes_are_preserved_through_uhostd() {
    let Some(runtime) = spawn_test_runtime(
        "storage-inspection-errors",
        "storage-inspection-errors-test-node",
    ) else {
        eprintln!(
            "skipping operator_storage_inspection_error_envelopes_are_preserved_through_uhostd: loopback bind not permitted"
        );
        return;
    };

    let created_volume = request_json_with_admin_token_and_status(
        runtime.address,
        "POST",
        "/storage/volumes",
        Some(r#"{"name":"operator-http-check","size_gb":8}"#),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        201,
    );
    let volume_id = required_string(&created_volume, "id").to_owned();
    let missing_volume_id = "vol_aaaaaaaaaaaaaaaaaaaaaaaaaa";
    let missing_restore_action_id = "aud_abcdefghijklmnopqrstuv";

    let workload_token = issue_workload_identity(
        runtime.address,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        "svc:storage-inspector",
        &["storage"],
        900,
    );

    assert_error_envelope(
        request_with_bearer_token(
            runtime.address,
            "GET",
            format!("/storage/volumes/{volume_id}/snapshot-policy").as_str(),
            None,
            &workload_token,
        ),
        403,
        "forbidden",
        "route request class `operator_read` requires operator principal",
        None,
    );

    let invalid_volume_detail = ["expected id prefix `vol`"];
    assert_error_envelope(
        request_with_admin_token(
            runtime.address,
            "GET",
            "/storage/volumes/bkt_aaaaaaaaaaaaaaaaaaaaaaaaaa/recovery-point",
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        400,
        "invalid_input",
        "invalid volume_id",
        Some(&invalid_volume_detail),
    );

    assert_error_envelope(
        request_with_admin_token(
            runtime.address,
            "GET",
            format!("/storage/volumes/{missing_volume_id}/recovery-history").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        404,
        "not_found",
        "volume does not exist",
        None,
    );

    assert_error_envelope(
        request_with_admin_token(
            runtime.address,
            "GET",
            format!("/storage/volumes/{missing_volume_id}/restore-actions").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        404,
        "not_found",
        "volume does not exist",
        None,
    );

    let invalid_restore_action_detail = ["expected id prefix `aud`"];
    assert_error_envelope(
        request_with_admin_token(
            runtime.address,
            "GET",
            "/storage/restore-actions/bkt_aaaaaaaaaaaaaaaaaaaaaaaaaa",
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        400,
        "invalid_input",
        "invalid restore_action_id",
        Some(&invalid_restore_action_detail),
    );

    assert_error_envelope(
        request_with_admin_token(
            runtime.address,
            "GET",
            format!("/storage/restore-actions/{missing_restore_action_id}").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        404,
        "not_found",
        "volume restore action does not exist",
        None,
    );
}

#[test]
fn missing_restore_action_ids_return_not_found_through_uhostd() {
    let Some(runtime) = spawn_test_runtime(
        "storage-missing-restore-action",
        "storage-missing-restore-action-test-node",
    ) else {
        eprintln!(
            "skipping missing_restore_action_ids_return_not_found_through_uhostd: loopback bind not permitted"
        );
        return;
    };

    assert_error_envelope(
        request_with_admin_token(
            runtime.address,
            "GET",
            "/storage/restore-actions/aud_abcdefghijklmnopqrstuv",
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        404,
        "not_found",
        "volume restore action does not exist",
        None,
    );
}
