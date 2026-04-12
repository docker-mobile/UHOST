use std::fs;
use std::net::SocketAddr;

use serde_json::json;

#[path = "support/storage_runtime_harness.rs"]
mod storage_runtime_harness;

use storage_runtime_harness::{
    DEFAULT_BOOTSTRAP_ADMIN_TOKEN, assert_error_envelope, blob_path, blob_sidecar_path,
    finish_response, open_request_with_token_and_headers, read_response_head,
    request_json_with_token_and_status, request_with_token_and_headers, required_string,
    spawn_test_runtime,
};

#[test]
fn ranged_object_downloads_stream_through_uhostd() {
    let Some(runtime) =
        spawn_test_runtime("storage-streamed-reads", "storage-streamed-range-test-node")
    else {
        eprintln!(
            "skipping ranged_object_downloads_stream_through_uhostd: loopback bind not permitted"
        );
        return;
    };

    let object_digest = create_completed_single_part_object(
        runtime.address,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        "range-runtime-bucket",
        "objects/runtime-range.txt",
        b"hello world",
    );
    let sidecar_path = blob_sidecar_path(&runtime.state_dir, &object_digest);
    fs::remove_file(&sidecar_path)
        .unwrap_or_else(|error| panic!("failed to remove object sidecar before download: {error}"));
    assert!(
        !sidecar_path.is_file(),
        "range download precondition should remove the integrity sidecar"
    );

    let response = request_with_token_and_headers(
        runtime.address,
        "GET",
        format!("/storage/objects/{object_digest}").as_str(),
        None,
        &[("Range", String::from("bytes=6-10"))],
        Some(DEFAULT_BOOTSTRAP_ADMIN_TOKEN),
    );
    let expected_etag = format!("\"{object_digest}\"");
    assert_eq!(response.status, 206);
    assert_eq!(
        response.headers.get("accept-ranges").map(String::as_str),
        Some("bytes")
    );
    assert_eq!(
        response.headers.get("content-range").map(String::as_str),
        Some("bytes 6-10/11")
    );
    assert_eq!(
        response.headers.get("content-length").map(String::as_str),
        Some("5")
    );
    assert_eq!(
        response.headers.get("etag").map(String::as_str),
        Some(expected_etag.as_str())
    );
    assert_eq!(response.body, b"world");
    assert!(
        sidecar_path.is_file(),
        "range downloads should restore missing integrity sidecars through uhostd"
    );
}

#[test]
fn corrupted_full_object_downloads_keep_200_headers_and_buffered_body_through_uhostd() {
    let Some(runtime) =
        spawn_test_runtime("storage-streamed-reads", "storage-corrupt-stream-test-node")
    else {
        eprintln!(
            "skipping corrupted_full_object_downloads_keep_200_headers_and_buffered_body_through_uhostd: loopback bind not permitted"
        );
        return;
    };

    let object_body = b"0123456789abcdef".repeat(32 * 1024);
    let object_digest = create_completed_single_part_object(
        runtime.address,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        "corrupt-stream-runtime-bucket",
        "objects/corrupt-stream-runtime.bin",
        &object_body,
    );
    let blob_path = blob_path(&runtime.state_dir, &object_digest);
    let expected_etag = format!("\"{object_digest}\"");
    let expected_content_length = object_body.len().to_string();

    let mut stream = open_request_with_token_and_headers(
        runtime.address,
        "GET",
        format!("/storage/objects/{object_digest}").as_str(),
        None,
        &[],
        Some(DEFAULT_BOOTSTRAP_ADMIN_TOKEN),
    )
    .unwrap_or_else(|error| panic!("request GET /storage/objects/{object_digest} failed: {error}"));
    let response_head = read_response_head(&mut stream)
        .unwrap_or_else(|error| panic!("failed to read response headers: {error}"));

    assert_eq!(response_head.status, 200);
    assert_eq!(
        response_head
            .headers
            .get("content-type")
            .map(String::as_str),
        Some("application/octet-stream")
    );
    assert_eq!(
        response_head
            .headers
            .get("accept-ranges")
            .map(String::as_str),
        Some("bytes")
    );
    assert_eq!(
        response_head
            .headers
            .get("content-length")
            .map(String::as_str),
        Some(expected_content_length.as_str())
    );
    assert_eq!(
        response_head.headers.get("etag").map(String::as_str),
        Some(expected_etag.as_str())
    );

    fs::OpenOptions::new()
        .write(true)
        .open(&blob_path)
        .unwrap_or_else(|error| panic!("failed to open blob for truncation: {error}"))
        .set_len(0)
        .unwrap_or_else(|error| panic!("failed to truncate blob after headers: {error}"));

    let response = finish_response(stream, response_head)
        .unwrap_or_else(|error| panic!("failed to read truncated response body: {error}"));

    assert_eq!(response.status, 200);
    // Current runtime contract: full-object downloads are materialized into
    // `ApiBody` before the client observes the response head, so late blob
    // truncation leaves the in-flight response at `200 OK` with the buffered
    // octet body rather than converting it into a late JSON error or early EOF.
    assert_eq!(response.body.len(), object_body.len());
    assert_eq!(response.body, object_body);
}

#[test]
fn corrupted_multipart_completion_failures_return_full_error_envelope_through_uhostd() {
    let Some(runtime) = spawn_test_runtime(
        "storage-streamed-reads",
        "storage-corrupt-complete-test-node",
    ) else {
        eprintln!(
            "skipping corrupted_multipart_completion_failures_return_full_error_envelope_through_uhostd: loopback bind not permitted"
        );
        return;
    };

    let bucket_id = create_bucket(
        runtime.address,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        "corrupt-runtime-bucket",
    );
    let upload_id = create_upload(
        runtime.address,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        &bucket_id,
        "objects/corrupt-runtime.txt",
    );
    let part_digest = upload_part(
        runtime.address,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        &upload_id,
        1,
        b"hello world",
    );

    let sidecar_path = blob_sidecar_path(&runtime.state_dir, &part_digest);
    let corrupted_sidecar = serde_json::to_vec(&json!({
        "algorithm": "sha256",
        "digest": part_digest,
        "size": 999_u64,
    }))
    .unwrap_or_else(|error| panic!("failed to encode corrupted sidecar: {error}"));
    fs::write(&sidecar_path, corrupted_sidecar)
        .unwrap_or_else(|error| panic!("failed to corrupt part sidecar: {error}"));

    let response = request_with_token_and_headers(
        runtime.address,
        "POST",
        format!("/storage/uploads/{upload_id}/complete").as_str(),
        None,
        &[],
        Some(DEFAULT_BOOTSTRAP_ADMIN_TOKEN),
    );
    let expected_upload_detail = format!("upload_id={upload_id}");
    let expected_detail_fragments = [
        expected_upload_detail.as_str(),
        "blob integrity sidecar mismatch",
    ];
    assert_error_envelope(
        response,
        503,
        "storage_corruption",
        "failed to assemble upload object",
        Some(&expected_detail_fragments),
    );
}

fn create_completed_single_part_object(
    address: SocketAddr,
    token: &str,
    bucket_name: &str,
    object_key: &str,
    body: &[u8],
) -> String {
    let bucket_id = create_bucket(address, token, bucket_name);
    let upload_id = create_upload(address, token, &bucket_id, object_key);
    let _part_digest = upload_part(address, token, &upload_id, 1, body);
    let completed = request_json_with_token_and_status(
        address,
        "POST",
        format!("/storage/uploads/{upload_id}/complete").as_str(),
        None,
        &[],
        Some(token),
        200,
    );
    required_string(&completed, "object_digest").to_owned()
}

fn create_bucket(address: SocketAddr, token: &str, name: &str) -> String {
    let bucket = request_json_with_token_and_status(
        address,
        "POST",
        "/storage/buckets",
        Some((
            "application/json",
            json!({
                "name": name,
                "owner_id": "prj_demo",
            })
            .to_string()
            .into_bytes(),
        )),
        &[],
        Some(token),
        201,
    );
    required_string(&bucket, "id").to_owned()
}

fn create_upload(address: SocketAddr, token: &str, bucket_id: &str, object_key: &str) -> String {
    let upload = request_json_with_token_and_status(
        address,
        "POST",
        "/storage/uploads",
        Some((
            "application/json",
            json!({
                "bucket_id": bucket_id,
                "object_key": object_key,
            })
            .to_string()
            .into_bytes(),
        )),
        &[],
        Some(token),
        201,
    );
    required_string(&upload, "id").to_owned()
}

fn upload_part(
    address: SocketAddr,
    token: &str,
    upload_id: &str,
    part_number: u32,
    body: &[u8],
) -> String {
    let response = request_json_with_token_and_status(
        address,
        "PUT",
        format!("/storage/uploads/{upload_id}/parts/{part_number}").as_str(),
        Some(("application/octet-stream", body.to_vec())),
        &[],
        Some(token),
        200,
    );
    required_string(&response, "digest").to_owned()
}
