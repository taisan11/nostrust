use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, OriginalUri, Path, State};
use axum::http::Uri;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use nojson::{DisplayJson, JsonFormatter, RawJson};
use sha2::{Digest, Sha256};

use crate::{AppState, EventRecord, HttpRequest, RelayConfig};

const MIME_OCTET_STREAM: &str = "application/octet-stream";

#[derive(Debug, Clone)]
struct BlobDescriptor {
    url: String,
    sha256: String,
    size: u64,
    r#type: String,
    uploaded: i64,
}

impl DisplayJson for BlobDescriptor {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            f.member("url", &self.url)?;
            f.member("sha256", &self.sha256)?;
            f.member("size", self.size)?;
            f.member("type", &self.r#type)?;
            f.member("uploaded", self.uploaded)
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum BlossomAction {
    Get,
    Upload,
    List,
    Delete,
    Media,
}

impl BlossomAction {
    fn as_tag(self) -> &'static str {
        match self {
            BlossomAction::Get => "get",
            BlossomAction::Upload => "upload",
            BlossomAction::List => "list",
            BlossomAction::Delete => "delete",
            BlossomAction::Media => "media",
        }
    }
}

pub(super) async fn maybe_route_blossom_get(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
) -> Option<Response> {
    let (sha256, _) = parse_blob_reference(uri.path())?;
    let request = build_http_request("GET", uri, headers);
    if let Err(reason) = validate_blossom_authorization(
        &state.relay_config,
        &request,
        BlossomAction::Get,
        Some(sha256.as_str()),
        false,
        false,
    ) {
        return Some(blossom_error_response(StatusCode::UNAUTHORIZED, &reason));
    }

    Some(get_blob_response(state, &sha256, true).await)
}

pub(super) async fn route_blossom_blob_head(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = super::blocked_ip_response_if_needed(&state.relay, peer.ip()) {
        return response;
    }

    let Some((sha256, _)) = parse_blob_reference(uri.path()) else {
        return blossom_error_response(StatusCode::NOT_FOUND, "blob not found");
    };
    let request = build_http_request("HEAD", &uri, &headers);
    if let Err(reason) = validate_blossom_authorization(
        &state.relay_config,
        &request,
        BlossomAction::Get,
        Some(sha256.as_str()),
        false,
        false,
    ) {
        return blossom_error_response(StatusCode::UNAUTHORIZED, &reason);
    }

    get_blob_response(&state, &sha256, false).await
}

pub(super) async fn route_blossom_blob_delete(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = super::blocked_ip_response_if_needed(&state.relay, peer.ip()) {
        return response;
    }

    let Some((sha256, _)) = parse_blob_reference(uri.path()) else {
        return blossom_error_response(StatusCode::NOT_FOUND, "blob not found");
    };
    let request = build_http_request("DELETE", &uri, &headers);
    let owner_pubkey = match validate_blossom_authorization(
        &state.relay_config,
        &request,
        BlossomAction::Delete,
        Some(sha256.as_str()),
        true,
        true,
    ) {
        Ok(Some(pubkey)) => pubkey,
        Ok(None) => {
            return blossom_error_response(
                StatusCode::UNAUTHORIZED,
                "missing Authorization header",
            );
        }
        Err(reason) => return blossom_error_response(StatusCode::UNAUTHORIZED, &reason),
    };

    let meta = match state.event_store.get_blob(&sha256).await {
        Ok(Some(meta)) => meta,
        Ok(None) => return blossom_error_response(StatusCode::NOT_FOUND, "blob not found"),
        Err(err) => {
            return blossom_error_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_message());
        }
    };
    if let Some(owner) = meta.owner_pubkey.as_ref()
        && owner != &owner_pubkey
    {
        return blossom_error_response(
            StatusCode::FORBIDDEN,
            "delete token pubkey does not own this blob",
        );
    }

    match state.event_store.delete_blob(&sha256).await {
        Ok(true) => super::typed_response(
            StatusCode::NO_CONTENT,
            "text/plain; charset=utf-8",
            String::new(),
        ),
        Ok(false) => blossom_error_response(StatusCode::NOT_FOUND, "blob not found"),
        Err(err) => blossom_error_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_message()),
    }
}

pub(super) async fn route_blossom_upload(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_put_blob(state, peer, uri, headers, body, BlossomAction::Upload).await
}

pub(super) async fn route_blossom_upload_head(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    handle_head_upload_requirements(state, peer, uri, headers, BlossomAction::Upload).await
}

pub(super) async fn route_blossom_media(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_put_blob(state, peer, uri, headers, body, BlossomAction::Media).await
}

pub(super) async fn route_blossom_media_head(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    handle_head_upload_requirements(state, peer, uri, headers, BlossomAction::Media).await
}

pub(super) async fn route_blossom_list(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = super::blocked_ip_response_if_needed(&state.relay, peer.ip()) {
        return response;
    }
    if !super::is_lower_hex_of_len(&pubkey, 64) {
        return blossom_error_response(
            StatusCode::BAD_REQUEST,
            "pubkey must be 64-char lowercase hex",
        );
    }

    let request = build_http_request("GET", &uri, &headers);
    let auth_pubkey = match validate_blossom_authorization(
        &state.relay_config,
        &request,
        BlossomAction::List,
        None,
        false,
        true,
    ) {
        Ok(Some(pubkey)) => pubkey,
        Ok(None) => {
            return blossom_error_response(
                StatusCode::UNAUTHORIZED,
                "missing Authorization header",
            );
        }
        Err(reason) => return blossom_error_response(StatusCode::UNAUTHORIZED, &reason),
    };
    if auth_pubkey != pubkey {
        return blossom_error_response(
            StatusCode::FORBIDDEN,
            "Authorization pubkey does not match list target pubkey",
        );
    }

    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(uri.path());
    let request_line = format!("GET {target} HTTP/1.1");
    let cursor = match super::parse_query_param(&request_line, "cursor") {
        Ok(value) => value,
        Err(err) => return blossom_error_response(StatusCode::BAD_REQUEST, &err),
    };
    if let Some(cursor) = cursor.as_ref()
        && !super::is_lower_hex_of_len(cursor, 64)
    {
        return blossom_error_response(
            StatusCode::BAD_REQUEST,
            "cursor must be 64-char lowercase hex",
        );
    }
    let limit = match parse_query_u64(&request_line, "limit") {
        Ok(Some(limit)) => usize::try_from(limit).unwrap_or(usize::MAX).min(1000),
        Ok(None) => 100,
        Err(reason) => return blossom_error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let since = match parse_query_i64(&request_line, "since") {
        Ok(value) => value,
        Err(reason) => return blossom_error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let until = match parse_query_i64(&request_line, "until") {
        Ok(value) => value,
        Err(reason) => return blossom_error_response(StatusCode::BAD_REQUEST, &reason),
    };
    if since.zip(until).is_some_and(|(s, u)| s > u) {
        return blossom_error_response(StatusCode::BAD_REQUEST, "since must be <= until");
    }

    let mut records = match state.event_store.list_blobs_by_owner(&pubkey).await {
        Ok(records) => records,
        Err(err) => {
            return blossom_error_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_message());
        }
    };
    if let Some(since) = since {
        records.retain(|record| record.uploaded >= since);
    }
    if let Some(until) = until {
        records.retain(|record| record.uploaded <= until);
    }
    if let Some(cursor) = cursor {
        let Some(index) = records.iter().position(|record| record.sha256 == cursor) else {
            return blossom_error_response(StatusCode::BAD_REQUEST, "cursor not found");
        };
        records = records.into_iter().skip(index + 1).collect();
    }
    records.truncate(limit);

    let base_url = blossom_http_base_url(&state.relay_config, &request.headers);
    let descriptors = records
        .into_iter()
        .map(|record| record_to_descriptor(record, &base_url))
        .collect::<Vec<_>>();
    let body = nojson::Json(&descriptors).to_string();
    super::typed_response(StatusCode::OK, "application/json; charset=utf-8", body)
}

pub(super) async fn route_blossom_report(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if let Some(response) = super::blocked_ip_response_if_needed(&state.relay, peer.ip()) {
        return response;
    }

    let report_text = match std::str::from_utf8(&body) {
        Ok(text) => text,
        Err(_) => {
            return blossom_error_response(
                StatusCode::BAD_REQUEST,
                "report body must be UTF-8 JSON",
            );
        }
    };
    let raw = match RawJson::parse(report_text) {
        Ok(raw) => raw,
        Err(_) => {
            return blossom_error_response(
                StatusCode::BAD_REQUEST,
                "report body must be valid JSON",
            );
        }
    };
    let event = match super::parse_event(raw.value()) {
        Ok(event) => event,
        Err(err) => return blossom_error_response(StatusCode::BAD_REQUEST, &err),
    };
    if event.kind != 1984 {
        return blossom_error_response(StatusCode::BAD_REQUEST, "report event kind must be 1984");
    }
    if !event.tags.iter().any(|tag| {
        tag.first().map(String::as_str) == Some("x")
            && tag
                .get(1)
                .is_some_and(|value| super::is_lower_hex_of_len(value, 64))
    }) {
        return blossom_error_response(
            StatusCode::BAD_REQUEST,
            "report event must include at least one x tag with blob hash",
        );
    }

    super::typed_response(
        StatusCode::ACCEPTED,
        "text/plain; charset=utf-8",
        String::new(),
    )
}

fn parse_blob_reference(path: &str) -> Option<(String, Option<String>)> {
    let path = path.trim_start_matches('/');
    if path.is_empty() || path.contains('/') {
        return None;
    }
    if path.len() < 64 {
        return None;
    }

    let sha256 = &path[..64];
    if !super::is_lower_hex_of_len(sha256, 64) {
        return None;
    }
    if path.len() == 64 {
        return Some((sha256.to_string(), None));
    }

    let extension = path.strip_prefix(&format!("{sha256}."))?;
    if extension.is_empty()
        || !extension
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return None;
    }
    Some((sha256.to_string(), Some(extension.to_string())))
}

fn normalize_content_type(raw: Option<&str>) -> String {
    let cleaned = raw
        .unwrap_or(MIME_OCTET_STREAM)
        .split(';')
        .next()
        .unwrap_or(MIME_OCTET_STREAM)
        .trim()
        .to_ascii_lowercase();
    if cleaned.is_empty() {
        MIME_OCTET_STREAM.to_string()
    } else {
        cleaned
    }
}

async fn get_blob_response(state: &AppState, sha256: &str, with_body: bool) -> Response {
    let Some(meta) = (match state.event_store.get_blob(sha256).await {
        Ok(meta) => meta,
        Err(err) => {
            return blossom_error_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_message());
        }
    }) else {
        return blossom_error_response(StatusCode::NOT_FOUND, "blob not found");
    };
    let bytes = if with_body {
        match state.event_store.read_blob_bytes(sha256) {
            Ok(Some(bytes)) => Some(bytes),
            Ok(None) => return blossom_error_response(StatusCode::NOT_FOUND, "blob not found"),
            Err(err) => {
                return blossom_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &err.to_message(),
                );
            }
        }
    } else {
        None
    };

    let mut response = if let Some(bytes) = bytes {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(bytes))
            .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
    };
    attach_blob_headers(&mut response, &meta.mime_type, meta.size);
    super::with_cors_headers(response)
}

fn attach_blob_headers(response: &mut Response, mime_type: &str, size: u64) {
    let headers = response.headers_mut();
    let mime = HeaderValue::from_str(mime_type)
        .unwrap_or_else(|_| HeaderValue::from_static(MIME_OCTET_STREAM));
    headers.insert(axum::http::header::CONTENT_TYPE, mime);
    headers.insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&size.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        axum::http::header::ACCEPT_RANGES,
        HeaderValue::from_static("bytes"),
    );
}

async fn handle_put_blob(
    state: AppState,
    peer: SocketAddr,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    action: BlossomAction,
) -> Response {
    if let Some(response) = super::blocked_ip_response_if_needed(&state.relay, peer.ip()) {
        return response;
    }

    let request = build_http_request("PUT", &uri, &headers);
    let declared_sha256 = match headers
        .get("x-sha-256")
        .and_then(|value| value.to_str().ok())
    {
        Some(value) if value.trim().is_empty() => {
            return blossom_error_response(
                StatusCode::BAD_REQUEST,
                "X-SHA-256 header must not be empty",
            );
        }
        Some(value) => {
            let value = value.trim().to_ascii_lowercase();
            if !super::is_lower_hex_of_len(&value, 64) {
                return blossom_error_response(
                    StatusCode::BAD_REQUEST,
                    "X-SHA-256 must be 64-char lowercase hex",
                );
            }
            Some(value)
        }
        None => None,
    };
    if request.headers.contains_key("authorization") && declared_sha256.is_none() {
        return blossom_error_response(
            StatusCode::BAD_REQUEST,
            "X-SHA-256 header is required when Authorization is present",
        );
    }

    let actual_sha256 = hex_sha256(&body);
    if let Some(declared) = declared_sha256.as_ref()
        && declared != &actual_sha256
    {
        return blossom_error_response(
            StatusCode::BAD_REQUEST,
            "X-SHA-256 does not match uploaded bytes",
        );
    }

    let owner_pubkey = match validate_blossom_authorization(
        &state.relay_config,
        &request,
        action,
        declared_sha256.as_deref(),
        true,
        false,
    ) {
        Ok(pubkey) => pubkey,
        Err(reason) => return blossom_error_response(StatusCode::UNAUTHORIZED, &reason),
    };
    let sha256 = declared_sha256.unwrap_or(actual_sha256);
    let mime_type = normalize_content_type(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
    );
    let uploaded = super::current_unix_timestamp();
    let record = match state
        .event_store
        .put_blob(
            &sha256,
            &body,
            &mime_type,
            uploaded,
            owner_pubkey.as_deref(),
        )
        .await
    {
        Ok(record) => record,
        Err(err) => {
            return blossom_error_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_message());
        }
    };
    let base_url = blossom_http_base_url(&state.relay_config, &request.headers);
    let descriptor = record_to_descriptor(record, &base_url);
    let body = nojson::Json(&descriptor).to_string();
    super::typed_response(StatusCode::OK, "application/json; charset=utf-8", body)
}

async fn handle_head_upload_requirements(
    state: AppState,
    peer: SocketAddr,
    uri: Uri,
    headers: HeaderMap,
    action: BlossomAction,
) -> Response {
    if let Some(response) = super::blocked_ip_response_if_needed(&state.relay, peer.ip()) {
        return response;
    }

    let request = build_http_request("HEAD", &uri, &headers);
    let Some(sha256) = headers
        .get("x-sha-256")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return blossom_error_response(StatusCode::BAD_REQUEST, "missing X-SHA-256 header");
    };
    if !super::is_lower_hex_of_len(sha256, 64) {
        return blossom_error_response(
            StatusCode::BAD_REQUEST,
            "X-SHA-256 must be 64-char lowercase hex",
        );
    }
    let Some(content_length) = headers
        .get("x-content-length")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return blossom_error_response(
            StatusCode::LENGTH_REQUIRED,
            "missing X-Content-Length header",
        );
    };
    if content_length.parse::<u64>().is_err() {
        return blossom_error_response(
            StatusCode::BAD_REQUEST,
            "X-Content-Length must be an integer",
        );
    }
    let Some(content_type) = headers
        .get("x-content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return blossom_error_response(StatusCode::BAD_REQUEST, "missing X-Content-Type header");
    };
    if content_type.is_empty() {
        return blossom_error_response(StatusCode::BAD_REQUEST, "X-Content-Type must not be empty");
    }
    if let Err(reason) = validate_blossom_authorization(
        &state.relay_config,
        &request,
        action,
        Some(sha256),
        true,
        false,
    ) {
        return blossom_error_response(StatusCode::UNAUTHORIZED, &reason);
    }

    super::typed_response(StatusCode::OK, "text/plain; charset=utf-8", String::new())
}

fn validate_blossom_authorization(
    relay_config: &RelayConfig,
    request: &HttpRequest,
    action: BlossomAction,
    implied_blob_hash: Option<&str>,
    require_x_match: bool,
    require_header: bool,
) -> Result<Option<String>, String> {
    let auth_header = request.headers.get("authorization");
    let Some(auth_header) = auth_header else {
        return if require_header {
            Err("missing Authorization header".to_string())
        } else {
            Ok(None)
        };
    };

    let encoded = auth_header
        .strip_prefix("Nostr ")
        .ok_or_else(|| "Authorization header must use Nostr scheme".to_string())?
        .trim();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .map_err(|_| "Authorization event is not valid base64".to_string())?;
    let event_text = String::from_utf8(decoded)
        .map_err(|_| "Authorization event must be UTF-8 JSON".to_string())?;
    let raw = RawJson::parse(&event_text)
        .map_err(|_| "Authorization event is not valid JSON".to_string())?;
    let event = super::parse_event(raw.value())
        .map_err(|_| "Authorization event is invalid".to_string())?;

    if event.kind != 24242 {
        return Err("Authorization event kind must be 24242".to_string());
    }

    let now = super::current_unix_timestamp();
    if event.created_at > now {
        return Err("Authorization event created_at must be in the past".to_string());
    }
    let expiration = tag_values(&event, "expiration")
        .first()
        .ok_or_else(|| "Authorization event missing expiration tag".to_string())?
        .parse::<i64>()
        .map_err(|_| "Authorization event expiration tag must be a unix timestamp".to_string())?;
    if expiration <= now {
        return Err("Authorization event has expired".to_string());
    }

    let t_tag = tag_values(&event, "t")
        .first()
        .copied()
        .ok_or_else(|| "Authorization event missing t tag".to_string())?;
    if t_tag != action.as_tag() {
        return Err("Authorization event t tag mismatch".to_string());
    }

    let request_domain = request_server_domain(relay_config, request)?;
    let server_tags = tag_values(&event, "server");
    if !server_tags.is_empty() {
        let mut matched = false;
        for server in server_tags {
            if server != server.to_ascii_lowercase() {
                return Err("Authorization event server tag must be lowercase domain".to_string());
            }
            if server.contains("://") {
                return Err("Authorization event server tag must be a domain only".to_string());
            }
            let normalized = super::normalize_domain(server)
                .map_err(|_| "Authorization event server tag has invalid domain".to_string())?;
            if normalized == request_domain {
                matched = true;
            }
        }
        if !matched {
            return Err("Authorization event server tag does not match this server".to_string());
        }
    }

    let x_tags = tag_values(&event, "x");
    if x_tags
        .iter()
        .any(|value| !super::is_lower_hex_of_len(value, 64))
    {
        return Err("Authorization event x tags must be 64-char lowercase hex".to_string());
    }
    if let Some(blob_hash) = implied_blob_hash {
        if x_tags.is_empty() {
            if require_x_match {
                return Err("Authorization event missing x tag".to_string());
            }
        } else if !x_tags.iter().any(|value| *value == blob_hash) {
            return Err("Authorization event x tag mismatch".to_string());
        }
    }

    Ok(Some(event.pubkey))
}

fn request_server_domain(
    relay_config: &RelayConfig,
    request: &HttpRequest,
) -> Result<String, String> {
    if let Some(host) = request.headers.get("host") {
        return super::normalize_domain(host);
    }

    let relay_url = relay_config.relay_url.as_str();
    let without_scheme = relay_url.split("://").nth(1).unwrap_or(relay_url);
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    super::normalize_domain(host)
}

fn tag_values<'a>(event: &'a EventRecord, name: &str) -> Vec<&'a str> {
    event
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some(name))
        .filter_map(|tag| tag.get(1).map(String::as_str))
        .collect()
}

fn build_http_request(method: &str, uri: &Uri, headers: &HeaderMap) -> HttpRequest {
    HttpRequest {
        method: method.to_string(),
        target: uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string()),
        headers: super::headers_to_btreemap(headers),
    }
}

fn blossom_http_base_url(relay_config: &RelayConfig, headers: &BTreeMap<String, String>) -> String {
    if let Some(host) = headers.get("host") {
        let host = host.trim().trim_end_matches('/');
        if host.starts_with("http://") || host.starts_with("https://") {
            return host.to_string();
        }
        return format!("http://{host}");
    }

    relay_config
        .relay_url
        .replace("ws://", "http://")
        .replace("wss://", "https://")
        .trim_end_matches('/')
        .to_string()
}

fn record_to_descriptor(record: crate::persistence::BlobRecord, base_url: &str) -> BlobDescriptor {
    let extension = mime_file_extension(&record.mime_type);
    BlobDescriptor {
        url: format!(
            "{}/{}.{}",
            base_url.trim_end_matches('/'),
            record.sha256,
            extension
        ),
        sha256: record.sha256,
        size: record.size,
        r#type: record.mime_type,
        uploaded: record.uploaded,
    }
}

fn mime_file_extension(mime_type: &str) -> &'static str {
    match mime_type {
        "application/pdf" => "pdf",
        "application/json" => "json",
        "text/plain" => "txt",
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "audio/mpeg" => "mp3",
        "audio/ogg" => "ogg",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "application/vnd.apple.mpegurl" | "application/x-mpegurl" => "m3u8",
        _ => "bin",
    }
}

fn blossom_error_response(status: StatusCode, reason: &str) -> Response {
    let mut response = super::text_response(status, &format!("{reason}\n"));
    if let Ok(value) = HeaderValue::from_str(reason) {
        response.headers_mut().insert("X-Reason", value);
    }
    response
}

fn parse_query_u64(request_line: &str, key: &str) -> Result<Option<u64>, String> {
    let Some(value) = super::parse_query_param(request_line, key)? else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| format!("{key} must be an integer"))
}

fn parse_query_i64(request_line: &str, key: &str) -> Result<Option<i64>, String> {
    let Some(value) = super::parse_query_param(request_line, key)? else {
        return Ok(None);
    };
    value
        .parse::<i64>()
        .map(Some)
        .map_err(|_| format!("{key} must be an integer"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{compute_event_id, hex_to_fixed};
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    fn signed_blossom_auth(
        action: BlossomAction,
        x: Option<&str>,
        server: Option<&str>,
        expires_in_seconds: i64,
    ) -> EventRecord {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([2u8; 32]).expect("valid test secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_pubkey, _) = keypair.x_only_public_key();
        let now = crate::current_unix_timestamp();

        let mut tags = vec![
            vec!["t".to_string(), action.as_tag().to_string()],
            vec![
                "expiration".to_string(),
                (now + expires_in_seconds).to_string(),
            ],
        ];
        if let Some(server) = server {
            tags.push(vec!["server".to_string(), server.to_string()]);
        }
        if let Some(x) = x {
            tags.push(vec!["x".to_string(), x.to_string()]);
        }

        let mut event = EventRecord {
            id: String::new(),
            pubkey: xonly_pubkey.to_string(),
            created_at: now - 1,
            kind: 24242,
            tags,
            content: "authorize blossom".to_string(),
            sig: String::new(),
        };
        event.id = compute_event_id(&event);
        let id_bytes = hex_to_fixed::<32>(&event.id).expect("id must decode");
        event.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();
        event
    }

    fn relay_config() -> RelayConfig {
        RelayConfig {
            relay_url: "ws://example.com".to_string(),
            allow_protected_events: false,
            min_pow_difficulty: 0,
            nip05_domain: None,
        }
    }

    fn request_with_auth(method: &str, target: &str, event: &EventRecord) -> HttpRequest {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(nojson::Json(event).to_string().as_bytes());
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "example.com".to_string());
        headers.insert("authorization".to_string(), format!("Nostr {encoded}"));
        HttpRequest {
            method: method.to_string(),
            target: target.to_string(),
            headers,
        }
    }

    #[test]
    fn parse_blob_reference_accepts_with_and_without_extension() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_blob_reference(&format!("/{hash}")),
            Some((hash.to_string(), None))
        );
        assert_eq!(
            parse_blob_reference(&format!("/{hash}.png")),
            Some((hash.to_string(), Some("png".to_string())))
        );
    }

    #[test]
    fn validate_blossom_authorization_accepts_valid_upload_token() {
        let hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let event = signed_blossom_auth(BlossomAction::Upload, Some(hash), Some("example.com"), 60);
        let request = request_with_auth("PUT", "/upload", &event);
        let pubkey = validate_blossom_authorization(
            &relay_config(),
            &request,
            BlossomAction::Upload,
            Some(hash),
            true,
            true,
        )
        .expect("token should validate")
        .expect("pubkey should exist");
        assert_eq!(pubkey, event.pubkey);
    }

    #[test]
    fn validate_blossom_authorization_rejects_mismatched_x_tag() {
        let event = signed_blossom_auth(
            BlossomAction::Delete,
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            Some("example.com"),
            60,
        );
        let request = request_with_auth(
            "DELETE",
            "/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &event,
        );
        let err = validate_blossom_authorization(
            &relay_config(),
            &request,
            BlossomAction::Delete,
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            true,
            true,
        )
        .expect_err("must reject mismatched x tag");
        assert_eq!(err, "Authorization event x tag mismatch");
    }
}
