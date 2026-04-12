//! Low-level HTTP helpers shared by service crates.

use std::collections::BTreeMap;
use std::io;

use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_TYPE, ETAG};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use serde::Serialize;
use serde::de::DeserializeOwned;

use uhost_core::{ErrorCode, PlatformError, Result};

/// Response body type used across the platform.
pub type ApiBody = UnsyncBoxBody<Bytes, io::Error>;

/// Default maximum JSON request size accepted by shared parsing helpers.
pub const DEFAULT_MAX_JSON_BODY_BYTES: usize = 1_048_576;

/// Default maximum raw request body size accepted by shared helpers.
pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1_048_576;

/// Serialize a JSON response.
pub fn json_response<T>(status: StatusCode, payload: &T) -> Result<Response<ApiBody>>
where
    T: Serialize,
{
    let body = serde_json::to_vec(payload).map_err(|error| {
        PlatformError::new(ErrorCode::Internal, "failed to encode json response")
            .with_detail(error.to_string())
    })?;
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(body)))
        .map_err(|error| {
            PlatformError::new(ErrorCode::Internal, "failed to build response")
                .with_detail(error.to_string())
        })
}

/// Build a plain-text response.
pub fn text_response(status: StatusCode, body: impl Into<String>) -> Result<Response<ApiBody>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(body.into())))
        .map_err(|error| {
            PlatformError::new(ErrorCode::Internal, "failed to build text response")
                .with_detail(error.to_string())
        })
}

/// Build an empty response.
pub fn empty_response(status: StatusCode) -> Result<Response<ApiBody>> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .map_err(|error| {
            PlatformError::new(ErrorCode::Internal, "failed to build empty response")
                .with_detail(error.to_string())
        })
}

/// Map a platform error to an HTTP response.
pub fn error_response(error: &PlatformError) -> Response<ApiBody> {
    let status = match error.code {
        ErrorCode::InvalidInput => StatusCode::BAD_REQUEST,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ErrorCode::Conflict => StatusCode::CONFLICT,
        ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
        ErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::StorageCorruption => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };

    let payload = serde_json::json!({
        "error": {
            "code": error.code,
            "message": error.message,
            "detail": error.detail,
            "correlation_id": error.correlation_id,
        }
    });

    match json_response(status, &payload) {
        Ok(response) => response,
        Err(_) => {
            let mut response = Response::new(full_body(Bytes::from_static(
                br#"{"error":{"code":"internal","message":"unrenderable error"}}"#,
            )));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response.headers_mut().insert(
                CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            response
        }
    }
}

/// Parse a JSON request body.
pub async fn parse_json<T, B>(request: Request<B>) -> Result<T>
where
    T: DeserializeOwned,
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let bytes = collect_body_with_limit(request.into_body(), DEFAULT_MAX_JSON_BODY_BYTES).await?;
    serde_json::from_slice(&bytes).map_err(|error| {
        PlatformError::invalid("failed to decode request json").with_detail(error.to_string())
    })
}

/// Collect a request body as bytes.
pub async fn read_body<B>(request: Request<B>) -> Result<Bytes>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    collect_body_with_limit(request.into_body(), DEFAULT_MAX_BODY_BYTES).await
}

async fn collect_body_with_limit<B>(mut body: B, max_bytes: usize) -> Result<Bytes>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            PlatformError::invalid("failed to read request body").with_detail(error.to_string())
        })?;
        if let Ok(chunk) = frame.into_data() {
            if collected.len().saturating_add(chunk.len()) > max_bytes {
                return Err(
                    PlatformError::invalid("request body exceeds maximum allowed size")
                        .with_detail(format!("max_bytes={max_bytes}")),
                );
            }
            collected.extend_from_slice(&chunk);
        }
    }
    Ok(collected.freeze())
}

/// Box one streaming-capable response body for shared API use.
pub fn box_body<B>(body: B) -> ApiBody
where
    B: Body<Data = Bytes, Error = io::Error> + Send + 'static,
{
    body.boxed_unsync()
}

/// Build one in-memory API body from raw bytes.
pub fn full_body(body: impl Into<Bytes>) -> ApiBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Build an empty API body.
pub fn empty_body() -> ApiBody {
    full_body(Bytes::new())
}

/// Split a request path into cleaned segments.
pub fn path_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
}

/// Parse a query string into a deterministic map.
pub fn parse_query(query: Option<&str>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Some(query) = query {
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            map.insert(decode_query_component(key), decode_query_component(value));
        }
    }
    map
}

fn decode_query_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let first = from_hex(bytes[index + 1]);
                let second = from_hex(bytes[index + 2]);
                if let (Some(first), Some(second)) = (first, second) {
                    output.push((first << 4) | second);
                    index += 3;
                } else {
                    output.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    match String::from_utf8(output) {
        Ok(value) => value,
        Err(_) => input.to_owned(),
    }
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Build a response with an ETag header.
pub fn with_etag(
    mut response: Response<ApiBody>,
    etag: impl AsRef<str>,
) -> Result<Response<ApiBody>> {
    let value = http::HeaderValue::from_str(etag.as_ref()).map_err(|error| {
        PlatformError::invalid("invalid ETag value").with_detail(error.to_string())
    })?;
    response.headers_mut().insert(ETAG, value);
    Ok(response)
}

/// Convenience matcher for simple method and path routing.
pub fn route_matches<B>(request: &Request<B>, method: Method, path: &str) -> bool {
    request.method() == method && request.uri().path() == path
}

#[cfg(test)]
mod tests {
    use super::parse_query;
    use super::text_response;
    use super::with_etag;
    use super::{DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_JSON_BODY_BYTES, collect_body_with_limit};
    use bytes::BytesMut;
    use http::StatusCode;
    use http::header::ETAG;
    use hyper::body::Incoming;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn parse_query_decodes_percent_encoded_pairs() {
        let query = parse_query(Some(
            "source_identity=svc%3Aapi&since=2026-03-19T12%3A00%3A00Z",
        ));
        assert_eq!(
            query.get("source_identity").map(String::as_str),
            Some("svc:api")
        );
        assert_eq!(
            query.get("since").map(String::as_str),
            Some("2026-03-19T12:00:00Z")
        );
    }

    #[test]
    fn parse_query_preserves_invalid_utf8_sequences() {
        let query = parse_query(Some("subject=svc%FFapi&limit=10"));
        assert_eq!(query.get("subject").map(String::as_str), Some("svc%FFapi"));
        assert_eq!(query.get("limit").map(String::as_str), Some("10"));
    }

    #[test]
    fn text_response_sets_plain_text_content_type() {
        let response = text_response(StatusCode::OK, "hello").expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn with_etag_rejects_invalid_values() {
        let response = text_response(StatusCode::OK, "hello").expect("response");
        assert!(with_etag(response, "bad\netag").is_err());
    }

    #[test]
    fn with_etag_sets_header() {
        let response = text_response(StatusCode::OK, "hello").expect("response");
        let response = with_etag(response, "\"abc123\"").expect("response");
        assert_eq!(
            response
                .headers()
                .get(ETAG)
                .and_then(|value| value.to_str().ok()),
            Some("\"abc123\"")
        );
    }

    async fn make_incoming_with_body(bytes: &[u8]) -> Incoming {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let payload = bytes.to_vec();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let response_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            stream
                .write_all(response_head.as_bytes())
                .await
                .expect("write head");
            stream.write_all(&payload).await.expect("write body");
            stream.shutdown().await.expect("shutdown");
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method("GET")
            .uri("/payload")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .expect("request");
        let response = sender.send_request(request).await.expect("request");
        server.await.expect("server task");
        response.into_body()
    }

    #[tokio::test]
    async fn collect_body_with_limit_accepts_payload_under_limit() {
        let body = make_incoming_with_body(b"{\"ok\":true}").await;
        let bytes = collect_body_with_limit(body, DEFAULT_MAX_JSON_BODY_BYTES)
            .await
            .expect("collect body");
        assert_eq!(bytes, BytesMut::from(&b"{\"ok\":true}"[..]).freeze());
    }

    #[tokio::test]
    async fn collect_body_with_limit_rejects_payload_over_limit() {
        let oversized = vec![b'a'; 128];
        let body = make_incoming_with_body(&oversized).await;
        let error = collect_body_with_limit(body, 64)
            .await
            .expect_err("body should exceed limit");
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert!(
            error.message.contains("maximum allowed size"),
            "error should clearly describe body size rejection"
        );
    }

    #[tokio::test]
    #[allow(clippy::assertions_on_constants)]
    async fn default_body_limit_constant_is_larger_than_json_limit() {
        assert!(DEFAULT_MAX_BODY_BYTES > DEFAULT_MAX_JSON_BODY_BYTES);
    }
}
