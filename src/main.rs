use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nojson::{DisplayJson, JsonFormatter, RawJson, RawJsonValue};
use tokio_tungstenite::tungstenite::{Error as WsError, Message, accept};

mod crypto;
mod commands;
mod persistence;

use crate::commands::{
    count_matching_events, event_has_protected_tag, event_matches_filter, forward_live_events,
    handle_text_frame, parse_filter, query_initial_events, search_score, send_auth_challenge,
    subscription_is_complete, validate_auth_event, validate_subscription_id,
};
use crate::crypto::{
    compute_event_id_from_serialized, verify_delegation_signature, verify_event_signature,
};
use crate::persistence::EventStore;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
struct EventRecord {
    id: String,
    pubkey: String,
    created_at: i64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

impl DisplayJson for EventRecord {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            f.member("id", &self.id)?;
            f.member("pubkey", &self.pubkey)?;
            f.member("created_at", self.created_at)?;
            f.member("kind", self.kind)?;
            f.member("tags", &self.tags)?;
            f.member("content", &self.content)?;
            f.member("sig", &self.sig)
        })
    }
}

impl EventRecord {
    fn d_tag_value(&self) -> String {
        self.tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some("d"))
            .and_then(|tag| tag.get(1).cloned())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy)]
struct CountPayload {
    count: usize,
}

impl DisplayJson for CountPayload {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| f.member("count", self.count))
    }
}

#[derive(Debug, Clone, Default)]
struct Filter {
    ids: Option<Vec<String>>,
    authors: Option<Vec<String>>,
    kinds: Option<Vec<u64>>,
    tag_values: HashMap<char, Vec<String>>,
    search: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<usize>,
}

#[derive(Debug, Default)]
struct RelayState {
    events_by_id: HashMap<String, Arc<EventRecord>>,
    archived_events_by_id: HashMap<String, Arc<EventRecord>>,
    deleted_event_ids: HashSet<String>,
    deleted_addresses: HashMap<(u64, String, String), i64>,
    replaceable_index: HashMap<(String, u64), String>,
    addressable_index: HashMap<(u64, String, String), String>,
    subscribers: Vec<Sender<Arc<EventRecord>>>,
}

#[derive(Debug, Clone)]
struct RelayConfig {
    relay_url: String,
    allow_protected_events: bool,
}

#[derive(Debug)]
struct ConnectionAuth {
    challenge: String,
    relay_url: String,
    authenticated_pubkeys: HashSet<String>,
}

impl ConnectionAuth {
    fn new(relay_url: String, challenge: String) -> Self {
        Self {
            challenge,
            relay_url,
            authenticated_pubkeys: HashSet::new(),
        }
    }

    fn is_authenticated(&self, pubkey: &str) -> bool {
        self.authenticated_pubkeys.contains(pubkey)
    }
}

#[derive(Debug)]
enum PublishOutcome {
    Accepted {
        event: Arc<EventRecord>,
        message: String,
    },
    DuplicateAccepted {
        event_id: String,
        message: String,
    },
}

fn main() -> Result<(), DynError> {
    let bind_addr = std::env::var("NOSTR_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let store_path = std::env::var("NOSTR_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("nostrust-events.db"));
    let relay_url =
        std::env::var("NOSTR_RELAY_URL").unwrap_or_else(|_| format!("ws://{bind_addr}"));
    let relay_config = RelayConfig {
        relay_url,
        allow_protected_events: parse_env_bool("NOSTR_ALLOW_PROTECTED", false),
    };
    let listener = TcpListener::bind(&bind_addr)?;
    let relay = Arc::new(Mutex::new(RelayState::default()));
    let event_store = Arc::new(EventStore::open(store_path.clone())?);
    let loaded_count = load_persisted_events(&event_store, &relay)?;

    eprintln!("nostr relay listening on ws://{bind_addr}");
    eprintln!(
        "event store: {} (loaded {loaded_count} event(s))",
        event_store.path_display().display()
    );
    eprintln!(
        "relay url: {} (protected events: {})",
        relay_config.relay_url,
        if relay_config.allow_protected_events {
            "auth-required"
        } else {
            "disabled"
        }
    );

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let relay = Arc::clone(&relay);
                let event_store = Arc::clone(&event_store);
                let relay_config = relay_config.clone();
                std::thread::spawn(move || {
                    let peer = stream
                        .peer_addr()
                        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

                    if let Err(err) =
                        handle_connection(stream, peer, relay, event_store, relay_config)
                    {
                        eprintln!("connection {peer} error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    relay: Arc<Mutex<RelayState>>,
    event_store: Arc<EventStore>,
    relay_config: RelayConfig,
) -> Result<(), DynError> {
    if maybe_serve_http_request(&mut stream, &relay_config)? {
        return Ok(());
    }

    let mut ws = accept(stream)?;
    ws.get_mut()
        .set_read_timeout(Some(Duration::from_millis(200)))?;
    let challenge = format!("{}-{}", current_unix_timestamp(), std::process::id());
    let mut auth = ConnectionAuth::new(relay_config.relay_url.clone(), challenge);

    let (tx, rx) = mpsc::channel::<Arc<EventRecord>>();
    {
        let mut state = relay
            .lock()
            .map_err(|_| "error: relay state lock poisoned during subscriber registration")?;
        state.subscribers.push(tx);
    }

    let mut subscriptions: HashMap<String, Vec<Filter>> = HashMap::new();
    eprintln!("client connected: {peer}");
    send_auth_challenge(&mut ws, &auth.challenge)?;

    loop {
        forward_live_events(&mut ws, &rx, &subscriptions)?;

        match ws.read() {
            Ok(Message::Text(text)) => {
                let payload = text.to_string();
                handle_text_frame(
                    &mut ws,
                    &mut subscriptions,
                    &relay,
                    &event_store,
                    &relay_config,
                    &mut auth,
                    &payload,
                )?;
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
            Err(WsError::ConnectionClosed) => break,
            Err(WsError::Io(err))
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(err.into()),
        }
    }

    eprintln!("client disconnected: {peer}");
    Ok(())
}

fn maybe_serve_http_request(
    stream: &mut TcpStream,
    relay_config: &RelayConfig,
) -> Result<bool, DynError> {
    let mut peek_buf = [0u8; 4096];
    let read_len = stream.peek(&mut peek_buf)?;
    if read_len == 0 {
        return Ok(false);
    }

    let request = String::from_utf8_lossy(&peek_buf[..read_len]);
    let request_lower = request.to_ascii_lowercase();
    if !request.starts_with("GET ") && !request.starts_with("OPTIONS ") {
        return Ok(false);
    }

    let is_websocket_upgrade = request_lower.contains("upgrade: websocket")
        || request_lower.contains("connection: upgrade");
    if is_websocket_upgrade {
        return Ok(false);
    }

    if request.starts_with("OPTIONS ") {
        let response = "HTTP/1.1 204 No Content\r\n\
                        Access-Control-Allow-Origin: *\r\n\
                        Access-Control-Allow-Headers: *\r\n\
                        Access-Control-Allow-Methods: GET, OPTIONS\r\n\
                        Content-Length: 0\r\n\
                        Connection: close\r\n\r\n";
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        return Ok(true);
    }

    if !request_accepts_nip11(&request_lower) {
        let body = "NIP-11 requires Accept: application/nostr+json header\n";
        let response = format!(
            "HTTP/1.1 406 Not Acceptable\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Headers: *\r\n\
             Access-Control-Allow-Methods: GET, OPTIONS\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        return Ok(true);
    }

    let body = relay_info_document(relay_config);
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/nostr+json; charset=utf-8\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Headers: *\r\n\
         Access-Control-Allow-Methods: GET, OPTIONS\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    Ok(true)
}

fn request_accepts_nip11(request_lower: &str) -> bool {
    request_lower.lines().any(|line| {
        line.trim_start().starts_with("accept:") && line.contains("application/nostr+json")
    })
}

fn relay_info_document(relay_config: &RelayConfig) -> String {
    format!(
        concat!(
            "{{",
            "\"name\":\"nostrust\",",
            "\"description\":\"Simple Rust Nostr relay\",",
            "\"supported_nips\":[1,4,9,11,26,29,40,42,45,50,59,65,70,94,96],",
            "\"software\":\"https://github.com/taisan11/nostrust\",",
            "\"version\":\"{}\",",
            "\"limitation\":{{",
            "\"auth_required\":false,",
            "\"restricted_writes\":{},",
            "\"max_subid_length\":64",
            "}}",
            "}}"
        ),
        env!("CARGO_PKG_VERSION"),
        relay_config.allow_protected_events
    )
}

fn escape_control_chars_in_json_strings(input: &str, preserve_invalid_escapes: bool) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    let mut in_string = false;
    let mut escaped = false;

    for ch in input.chars() {
        if !in_string {
            if ch == '"' {
                in_string = true;
            }
            out.push(ch);
            continue;
        }

        if escaped {
            if matches!(ch, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u') {
                out.push(ch);
            } else {
                if preserve_invalid_escapes {
                    out.push('\\');
                    out.push(ch);
                } else {
                    let code = ch as u32;
                    out.push_str("\\u");
                    out.push(hex_digit((code >> 12) as u8 & 0x0f));
                    out.push(hex_digit((code >> 8) as u8 & 0x0f));
                    out.push(hex_digit((code >> 4) as u8 & 0x0f));
                    out.push(hex_digit(code as u8 & 0x0f));
                }
            }
            escaped = false;
            continue;
        }

        match ch {
            '\\' => {
                out.push('\\');
                escaped = true;
            }
            '"' => {
                out.push('"');
                in_string = false;
            }
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            _ => out.push(ch),
        }
    }

    out
}

fn hex_digit(v: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[v as usize] as char
}

fn load_persisted_events(
    event_store: &EventStore,
    relay: &Arc<Mutex<RelayState>>,
) -> Result<usize, DynError> {
    let payloads = event_store.load_event_payloads()?;
    let mut loaded = 0usize;

    for (line_idx, payload) in payloads.iter().enumerate() {
        let trimmed = payload.trim();
        if trimmed.is_empty() {
            continue;
        }

        let raw = match RawJson::parse(trimmed) {
            Ok(raw) => raw,
            Err(err) => {
                eprintln!(
                    "skipping persisted line {} in {}: invalid json ({err})",
                    line_idx + 1,
                    event_store.path_display().display()
                );
                continue;
            }
        };

        let event = match parse_event(raw.value()) {
            Ok(event) => event,
            Err(err) => {
                eprintln!(
                    "skipping persisted line {} in {}: invalid event ({err})",
                    line_idx + 1,
                    event_store.path_display().display()
                );
                continue;
            }
        };

        if !should_persist_event(&event) {
            continue;
        }

        if event.kind == 5
            && let Err(err) = apply_deletion_request(relay, &event)
        {
            eprintln!(
                "skipping persisted line {} in {}: failed to apply deletion ({err})",
                line_idx + 1,
                event_store.path_display().display()
            );
            continue;
        }

        match publish_event(relay, event) {
            Ok(PublishOutcome::Accepted { .. }) => loaded += 1,
            Ok(PublishOutcome::DuplicateAccepted { .. }) => {}
            Err(err) => {
                eprintln!(
                    "skipping persisted line {} in {}: failed to apply event ({err})",
                    line_idx + 1,
                    event_store.path_display().display()
                );
            }
        }
    }

    Ok(loaded)
}

fn publish_event(
    relay: &Arc<Mutex<RelayState>>,
    event: EventRecord,
) -> Result<PublishOutcome, String> {
    let event_id = event.id.clone();
    let event_arc = Arc::new(event);

    let mut state = relay
        .lock()
        .map_err(|_| "relay state lock poisoned during EVENT processing".to_string())?;

    if state.events_by_id.contains_key(&event_id) {
        return Ok(PublishOutcome::DuplicateAccepted {
            event_id,
            message: "duplicate: already have this event".to_string(),
        });
    }

    if state.deleted_event_ids.contains(&event_arc.id) {
        return Err("blocked: event id was deleted".to_string());
    }

    let now = current_unix_timestamp();
    if is_event_expired(&event_arc, now) {
        return Err("invalid: event has expired".to_string());
    }

    let kind_class = classify_kind(event_arc.kind);
    if matches!(kind_class, KindClass::Replaceable | KindClass::Addressable) {
        let address_key = (
            event_arc.kind,
            event_arc.pubkey.clone(),
            event_arc.d_tag_value(),
        );
        if let Some(delete_ts) = state.deleted_addresses.get(&address_key)
            && event_arc.created_at <= *delete_ts
        {
            return Err("blocked: address was deleted for this timestamp".to_string());
        }
    }

    let should_broadcast = true;
    let mut message = String::new();

    match kind_class {
        KindClass::Replaceable => {
            let key = (event_arc.pubkey.clone(), event_arc.kind);
            if let Some(existing_id) = state.replaceable_index.get(&key).cloned() {
                if let Some(existing_event) = state.events_by_id.get(&existing_id) {
                    if !is_better_replace_candidate(&event_arc, existing_event) {
                        if event_arc.kind == 3 {
                            state
                                .archived_events_by_id
                                .insert(event_arc.id.clone(), Arc::clone(&event_arc));
                            return Ok(PublishOutcome::Accepted {
                                event: event_arc,
                                message: String::new(),
                            });
                        }
                        return Err("blocked: have newer replaceable event".to_string());
                    }
                }
                if should_broadcast {
                    remove_active_event_by_id(&mut state, &existing_id);
                }
            }

            if should_broadcast {
                state.replaceable_index.insert(key, event_arc.id.clone());
                state
                    .events_by_id
                    .insert(event_arc.id.clone(), Arc::clone(&event_arc));
            }
        }
        KindClass::Addressable => {
            let key = (
                event_arc.kind,
                event_arc.pubkey.clone(),
                event_arc.d_tag_value(),
            );

            if let Some(existing_id) = state.addressable_index.get(&key).cloned() {
                if let Some(existing_event) = state.events_by_id.get(&existing_id) {
                    if !is_better_replace_candidate(&event_arc, existing_event) {
                        return Err("blocked: have newer addressable event".to_string());
                    }
                }
                if should_broadcast {
                    remove_active_event_by_id(&mut state, &existing_id);
                }
            }

            if should_broadcast {
                state.addressable_index.insert(key, event_arc.id.clone());
                state
                    .events_by_id
                    .insert(event_arc.id.clone(), Arc::clone(&event_arc));
            }
        }
        KindClass::Ephemeral => {
            state
                .events_by_id
                .insert(event_arc.id.clone(), Arc::clone(&event_arc));
            message = "".to_string();
        }
        KindClass::RegularOrOther => {
            state
                .events_by_id
                .insert(event_arc.id.clone(), Arc::clone(&event_arc));
        }
    }

    if !should_broadcast {
        return Ok(PublishOutcome::DuplicateAccepted { event_id, message });
    }

    state
        .subscribers
        .retain(|tx| tx.send(Arc::clone(&event_arc)).is_ok());

    Ok(PublishOutcome::Accepted {
        event: event_arc,
        message,
    })
}

fn parse_event(value: RawJsonValue<'_, '_>) -> Result<EventRecord, String> {
    parse_event_with_options(value, false, None)
}

fn parse_event_with_options(
    value: RawJsonValue<'_, '_>,
    skip_id_hash_check: bool,
    raw_serialized: Option<&str>,
) -> Result<EventRecord, String> {
    let id: String = value
        .to_member("id")
        .map_err(|e| format!("invalid: {e}"))?
        .required()
        .map_err(|e| format!("invalid: {e}"))?
        .try_into()
        .map_err(|e| format!("invalid: {e}"))?;

    if !is_lower_hex_of_len(&id, 64) {
        return Err("invalid: id must be 64-char lowercase hex".to_string());
    }

    let pubkey: String = value
        .to_member("pubkey")
        .map_err(|e| format!("invalid: {e}"))?
        .required()
        .map_err(|e| format!("invalid: {e}"))?
        .try_into()
        .map_err(|e| format!("invalid: {e}"))?;

    if !is_lower_hex_of_len(&pubkey, 64) {
        return Err("invalid: pubkey must be 64-char lowercase hex".to_string());
    }

    let created_at = parse_event_created_at(
        value
        .to_member("created_at")
        .map_err(|e| format!("invalid: {e}"))?
        .required()
        .map_err(|e| format!("invalid: {e}"))?,
    )?;

    let kind: u64 = value
        .to_member("kind")
        .map_err(|e| format!("invalid: {e}"))?
        .required()
        .map_err(|e| format!("invalid: {e}"))?
        .try_into()
        .map_err(|e| format!("invalid: {e}"))?;

    if kind > 65535 {
        return Err("invalid: kind must be between 0 and 65535".to_string());
    }

    let tags_value = value
        .to_member("tags")
        .map_err(|e| format!("invalid: {e}"))?
        .required()
        .map_err(|e| format!("invalid: {e}"))?;

    let mut tags = Vec::new();
    let mut has_addressable_d_tag = false;
    for tag in tags_value.to_array().map_err(|e| format!("invalid: {e}"))? {
        let tag_values = parse_tag_values(tag)?;
        if tag_values.is_empty() {
            tags.push(tag_values);
            continue;
        }

        if tag_values[0] == "e" || tag_values[0] == "p" {
            if tag_values.len() < 2 {
                return Err(format!(
                    "invalid: {} tag must include a value",
                    tag_values[0]
                ));
            }
            if !is_lower_hex_of_len(&tag_values[1], 64) {
                return Err(format!(
                    "invalid: {} tag value must be 64-char lowercase hex",
                    tag_values[0]
                ));
            }
        }

        if tag_values[0] == "d" && tag_values.len() >= 2 {
            has_addressable_d_tag = true;
        }

        if tag_values[0] == "expiration" {
            if tag_values.len() < 2 {
                return Err("invalid: expiration tag must include a unix timestamp".to_string());
            }
            let expiration = tag_values[1]
                .parse::<i64>()
                .map_err(|_| "invalid: expiration tag must be a unix timestamp".to_string())?;
            if expiration < 0 {
                return Err("invalid: expiration tag must be >= 0".to_string());
            }
        }

        tags.push(tag_values);
    }

    if matches!(classify_kind(kind), KindClass::Addressable) && !has_addressable_d_tag {
        return Err("invalid: addressable events must include a d tag value".to_string());
    }

    let content: String = value
        .to_member("content")
        .map_err(|e| format!("invalid: {e}"))?
        .required()
        .map_err(|e| format!("invalid: {e}"))?
        .try_into()
        .map_err(|e| format!("invalid: {e}"))?;

    let sig: String = value
        .to_member("sig")
        .map_err(|e| format!("invalid: {e}"))?
        .required()
        .map_err(|e| format!("invalid: {e}"))?
        .try_into()
        .map_err(|e| format!("invalid: {e}"))?;

    if !is_lower_hex_of_len(&sig, 128) {
        return Err("invalid: sig must be 128-char lowercase hex".to_string());
    }

    let event = EventRecord {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig,
    };

    if !skip_id_hash_check {
        if let Some(raw_serialized) = raw_serialized {
            let raw_id = compute_event_id_from_serialized(raw_serialized);
            if event.id != raw_id {
                return Err("invalid: event id does not match serialized event hash".to_string());
            }
        } else if event.id != crate::crypto::compute_event_id(&event) {
            return Err("invalid: event id does not match serialized event hash".to_string());
        }
    }
    verify_event_signature(&event)?;
    validate_delegation(&event)?;
    validate_group_event_tags(&event)?;
    validate_nip65_relay_list_event(&event)?;
    Ok(event)
}

fn is_lower_hex_of_len(value: &str, len: usize) -> bool {
    if value.len() != len {
        return false;
    }

    value
        .as_bytes()
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_tag_filter_key(key: &str) -> bool {
    let mut chars = key.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some('#'), Some(letter), None) => letter.is_ascii_alphabetic(),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy)]
enum KindClass {
    RegularOrOther,
    Replaceable,
    Ephemeral,
    Addressable,
}

fn classify_kind(kind: u64) -> KindClass {
    if (20000..30000).contains(&kind) {
        KindClass::Ephemeral
    } else if (30000..40000).contains(&kind) {
        KindClass::Addressable
    } else if (10000..20000).contains(&kind) || kind == 0 || kind == 3 {
        KindClass::Replaceable
    } else {
        KindClass::RegularOrOther
    }
}

fn should_persist_event(event: &EventRecord) -> bool {
    !matches!(classify_kind(event.kind), KindClass::Ephemeral)
}

fn is_auth_event_kind(kind: u64) -> bool {
    kind == 22242
}

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn parse_env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn parse_event_created_at(value: RawJsonValue<'_, '_>) -> Result<i64, String> {
    if let Ok(created_at) = value.try_into() {
        return Ok(created_at);
    }

    let raw = value.as_raw_str().to_string();
    parse_scientific_notation_i64(&raw)
        .ok_or_else(|| "invalid: created_at must be an integer".to_string())
}

fn parse_scientific_notation_i64(raw: &str) -> Option<i64> {
    let value: f64 = raw.parse().ok()?;
    if !value.is_finite() {
        return None;
    }
    if value.fract() != 0.0 {
        return None;
    }
    if value < i64::MIN as f64 || value > i64::MAX as f64 {
        return None;
    }
    Some(value as i64)
}

fn parse_tag_values(tag: RawJsonValue<'_, '_>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut values = tag.to_array().map_err(|e| format!("invalid: {e}"))?;

    for v in &mut values {
        let s: String = v.try_into().map_err(|e| format!("invalid: {e}"))?;
        out.push(s);
    }

    Ok(out)
}

fn parse_event_field_raw(
    event_json: &str,
    field: &str,
    start_pos: usize,
) -> Result<String, String> {
    let needle = format!("\"{field}\":");
    let rel = event_json[start_pos..]
        .find(&needle)
        .ok_or_else(|| format!("invalid: missing field {field} in raw event"))?;
    let mut i = start_pos + rel + needle.len();
    let bytes = event_json.as_bytes();

    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return Err(format!("invalid: missing field value for {field}"));
    }

    let start = i;
    match bytes[i] as char {
        '"' => {
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let ch = bytes[i] as char;
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    return Ok(event_json[start..=i].to_string());
                }
                i += 1;
            }
            Err(format!("invalid: unterminated string for field {field}"))
        }
        '[' => {
            let mut depth = 0usize;
            let mut in_string = false;
            let mut escaped = false;
            while i < bytes.len() {
                let ch = bytes[i] as char;
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        in_string = false;
                    }
                } else {
                    match ch {
                        '"' => in_string = true,
                        '[' => depth += 1,
                        ']' => {
                            depth -= 1;
                            if depth == 0 {
                                return Ok(event_json[start..=i].to_string());
                            }
                        }
                        _ => {}
                    }
                }
                i += 1;
            }
            Err(format!("invalid: unterminated array for field {field}"))
        }
        _ => {
            while i < bytes.len() {
                let ch = bytes[i] as char;
                if ch == ',' || ch == '}' || ch.is_ascii_whitespace() {
                    break;
                }
                i += 1;
            }
            Ok(event_json[start..i].to_string())
        }
    }
}

fn build_raw_serialized_event_data(event_json: &str) -> Result<String, String> {
    let id_pos = event_json.find("\"id\":").unwrap_or(0);
    let pubkey_raw = parse_event_field_raw(event_json, "pubkey", id_pos)?;
    let created_at_raw = parse_event_field_raw(event_json, "created_at", id_pos)?;
    let kind_raw = parse_event_field_raw(event_json, "kind", id_pos)?;
    let tags_raw = parse_event_field_raw(event_json, "tags", id_pos)?;
    let content_raw = parse_event_field_raw(event_json, "content", id_pos)?;
    Ok(format!(
        "[0,{pubkey_raw},{created_at_raw},{kind_raw},{tags_raw},{content_raw}]"
    ))
}

fn event_expiration_timestamp(event: &EventRecord) -> Option<i64> {
    event.tags.iter().find_map(|tag| {
        if tag.first().map(String::as_str) != Some("expiration") {
            return None;
        }
        tag.get(1).and_then(|raw| raw.parse::<i64>().ok())
    })
}

fn is_event_expired(event: &EventRecord, now: i64) -> bool {
    event_expiration_timestamp(event).is_some_and(|expiration| expiration <= now)
}

fn validate_group_event_tags(event: &EventRecord) -> Result<(), String> {
    let requires_h_tag =
        event.kind == 9021 || event.kind == 9022 || (9000..=9020).contains(&event.kind);
    if requires_h_tag
        && !event
            .tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("h"))
    {
        return Err("invalid: group events must include an h tag".to_string());
    }
    Ok(())
}

fn validate_nip65_relay_list_event(event: &EventRecord) -> Result<(), String> {
    if event.kind != 10002 {
        return Ok(());
    }

    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("r") {
            continue;
        }
        if tag.len() < 2 {
            return Err("invalid: kind 10002 r tags must include relay URL".to_string());
        }
        if let Some(marker) = tag.get(2)
            && marker != "read"
            && marker != "write"
        {
            return Err("invalid: kind 10002 r tag marker must be read or write".to_string());
        }
    }

    Ok(())
}

fn validate_delegation(event: &EventRecord) -> Result<(), String> {
    let delegation_tag = event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("delegation"));

    let Some(tag) = delegation_tag else {
        return Ok(());
    };

    if tag.len() < 4 {
        return Err(
            "invalid: delegation tag must contain pubkey, conditions and token".to_string(),
        );
    }

    let delegator_pubkey = tag
        .get(1)
        .ok_or_else(|| "invalid: delegation tag missing delegator pubkey".to_string())?;
    if !is_lower_hex_of_len(delegator_pubkey, 64) {
        return Err("invalid: delegation pubkey must be 64-char lowercase hex".to_string());
    }

    let conditions = tag
        .get(2)
        .ok_or_else(|| "invalid: delegation tag missing conditions".to_string())?;
    validate_delegation_conditions(conditions, event)?;

    let token = tag
        .get(3)
        .ok_or_else(|| "invalid: delegation tag missing token".to_string())?;
    if !is_lower_hex_of_len(token, 128) {
        return Err("invalid: delegation token must be 128-char lowercase hex".to_string());
    }

    verify_delegation_signature(delegator_pubkey, &event.pubkey, conditions, token)?;
    Ok(())
}

fn event_delegator_pubkey(event: &EventRecord) -> Option<&str> {
    event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("delegation"))
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}

fn validate_delegation_conditions(conditions: &str, event: &EventRecord) -> Result<(), String> {
    for clause in conditions.split('&') {
        if clause.is_empty() {
            return Err("invalid: delegation conditions contain an empty clause".to_string());
        }

        if let Some(value) = clause.strip_prefix("kind=") {
            let kind = value
                .parse::<u64>()
                .map_err(|_| "invalid: delegation kind condition must be numeric".to_string())?;
            if event.kind != kind {
                return Err("invalid: delegation conditions not satisfied".to_string());
            }
            continue;
        }

        if let Some(value) = clause.strip_prefix("created_at<") {
            let ts = value.parse::<i64>().map_err(|_| {
                "invalid: delegation created_at upper condition must be numeric".to_string()
            })?;
            if event.created_at >= ts {
                return Err("invalid: delegation conditions not satisfied".to_string());
            }
            continue;
        }

        if let Some(value) = clause.strip_prefix("created_at>") {
            let ts = value.parse::<i64>().map_err(|_| {
                "invalid: delegation created_at lower condition must be numeric".to_string()
            })?;
            if event.created_at <= ts {
                return Err("invalid: delegation conditions not satisfied".to_string());
            }
            continue;
        }

        return Err("invalid: unsupported delegation condition".to_string());
    }

    Ok(())
}

fn remove_active_event_by_id(state: &mut RelayState, event_id: &str) {
    let Some(old) = state.events_by_id.remove(event_id) else {
        return;
    };

    match classify_kind(old.kind) {
        KindClass::Replaceable => {
            let key = (old.pubkey.clone(), old.kind);
            if state
                .replaceable_index
                .get(&key)
                .is_some_and(|mapped| mapped == event_id)
            {
                state.replaceable_index.remove(&key);
            }
        }
        KindClass::Addressable => {
            let key = (old.kind, old.pubkey.clone(), old.d_tag_value());
            if state
                .addressable_index
                .get(&key)
                .is_some_and(|mapped| mapped == event_id)
            {
                state.addressable_index.remove(&key);
            }
        }
        KindClass::RegularOrOther | KindClass::Ephemeral => {}
    }

    state
        .archived_events_by_id
        .insert(event_id.to_string(), old);
}

fn apply_deletion_request(
    relay: &Arc<Mutex<RelayState>>,
    deletion: &EventRecord,
) -> Result<(), String> {
    if deletion.kind != 5 {
        return Ok(());
    }

    let mut state = relay
        .lock()
        .map_err(|_| "relay state lock poisoned during deletion".to_string())?;

    for tag in &deletion.tags {
        if tag.first().map(String::as_str) == Some("e") {
            if let Some(target_id) = tag.get(1) {
                let target = state
                    .events_by_id
                    .get(target_id)
                    .or_else(|| state.archived_events_by_id.get(target_id))
                    .cloned();
                let Some(target) = target else {
                    continue;
                };
                if target.kind == 5 {
                    continue;
                }
                if target.pubkey != deletion.pubkey
                    && event_delegator_pubkey(&target) != Some(deletion.pubkey.as_str())
                {
                    continue;
                }

                state.deleted_event_ids.insert(target_id.clone());
                remove_active_event_by_id(&mut state, target_id);
            }
        }

        if tag.first().map(String::as_str) == Some("a")
            && let Some(address) = tag.get(1)
            && let Some((kind, pubkey, d_tag)) = parse_a_tag_address(address)
        {
            if pubkey != deletion.pubkey
                || !matches!(
                    classify_kind(kind),
                    KindClass::Replaceable | KindClass::Addressable
                )
            {
                continue;
            }

            let addr_key = (kind, pubkey.clone(), d_tag.clone());
            state
                .deleted_addresses
                .entry(addr_key.clone())
                .and_modify(|ts| *ts = (*ts).max(deletion.created_at))
                .or_insert(deletion.created_at);

            let matching_ids = state
                .events_by_id
                .values()
                .chain(state.archived_events_by_id.values())
                .filter(|event| {
                    event.kind == kind
                        && event.pubkey == pubkey
                        && event.d_tag_value() == d_tag
                        && event.created_at <= deletion.created_at
                        && event.kind != 5
                })
                .map(|event| event.id.clone())
                .collect::<Vec<_>>();

            for event_id in matching_ids {
                state.deleted_event_ids.insert(event_id.clone());
                remove_active_event_by_id(&mut state, &event_id);
            }
        }
    }

    Ok(())
}

fn parse_a_tag_address(address: &str) -> Option<(u64, String, String)> {
    let mut parts = address.splitn(3, ':');
    let kind = parts.next()?.parse::<u64>().ok()?;
    let pubkey = parts.next()?.to_string();
    let d_tag = parts.next()?.to_string();
    if !is_lower_hex_of_len(&pubkey, 64) {
        return None;
    }
    Some((kind, pubkey, d_tag))
}

fn is_better_replace_candidate(newer: &EventRecord, existing: &EventRecord) -> bool {
    if newer.created_at > existing.created_at {
        return true;
    }

    if newer.created_at < existing.created_at {
        return false;
    }

    newer.id < existing.id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{compute_event_id, hex_to_fixed, serialize_event_data};
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    fn sample_event(
        id: &str,
        created_at: i64,
        kind: u64,
        tag_key: &str,
        tag_value: &str,
    ) -> Arc<EventRecord> {
        Arc::new(EventRecord {
            id: id.to_string(),
            pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            created_at,
            kind,
            tags: vec![vec![tag_key.to_string(), tag_value.to_string()]],
            content: "hello".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        })
    }

    #[test]
    fn validates_subscription_id_rules() {
        assert!(validate_subscription_id("sub").is_ok());
        assert!(validate_subscription_id("").is_err());
        assert!(validate_subscription_id(&"x".repeat(65)).is_err());
    }

    #[test]
    fn matches_filter_with_kind_and_tag() {
        let event = sample_event(
            "1111111111111111111111111111111111111111111111111111111111111111",
            10,
            1,
            "e",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );

        let mut tag_values = HashMap::new();
        tag_values.insert(
            'e',
            vec!["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string()],
        );

        let filter = Filter {
            kinds: Some(vec![1]),
            tag_values,
            ..Filter::default()
        };

        assert!(event_matches_filter(&event, &filter));
    }

    #[test]
    fn applies_limit_per_filter_and_global_sorting() {
        let e1 = sample_event(
            "0000000000000000000000000000000000000000000000000000000000000002",
            100,
            1,
            "p",
            "v1",
        );
        let e2 = sample_event(
            "0000000000000000000000000000000000000000000000000000000000000001",
            100,
            1,
            "p",
            "v1",
        );
        let e3 = sample_event(
            "0000000000000000000000000000000000000000000000000000000000000003",
            90,
            1,
            "p",
            "v1",
        );

        let mut state = RelayState::default();
        state.events_by_id.insert(e1.id.clone(), e1.clone());
        state.events_by_id.insert(e2.id.clone(), e2.clone());
        state.events_by_id.insert(e3.id.clone(), e3.clone());
        let filter = Filter {
            kinds: Some(vec![1]),
            limit: Some(2),
            ..Filter::default()
        };

        let result = query_initial_events(&state, &[filter]);
        let ids = result.iter().map(|e| e.id.as_str()).collect::<Vec<_>>();

        assert_eq!(ids, vec![e2.id.as_str(), e1.id.as_str()]);
    }

    #[test]
    fn replaceable_tie_keeps_lowest_id() {
        let old = EventRecord {
            id: "1111111111111111111111111111111111111111111111111111111111111112".to_string(),
            pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            created_at: 10,
            kind: 0,
            tags: vec![],
            content: "x".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        };
        let new = EventRecord {
            id: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            pubkey: old.pubkey.clone(),
            created_at: 10,
            kind: 0,
            tags: vec![],
            content: "y".to_string(),
            sig: old.sig.clone(),
        };

        assert!(is_better_replace_candidate(&new, &old));
    }

    fn signed_event(content: &str) -> EventRecord {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([1u8; 32]).expect("valid test secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_pubkey, _) = keypair.x_only_public_key();

        let mut event = EventRecord {
            id: String::new(),
            pubkey: xonly_pubkey.to_string(),
            created_at: 1_710_000_000,
            kind: 1,
            tags: vec![vec![
                "e".to_string(),
                "6f4c7eb5f9a4f14d99db3f6df2b0f9300ddc01e3bb73ef27c9cc10a7f0478d9f".to_string(),
            ]],
            content: content.to_string(),
            sig: String::new(),
        };

        event.id = compute_event_id(&event);
        let id_bytes = hex_to_fixed::<32>(&event.id).expect("id must decode");
        event.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();
        event
    }

    #[test]
    fn parse_event_accepts_valid_schnorr_event() {
        let event = signed_event("hello nostr");
        let json = nojson::Json(&event).to_string();
        let raw = RawJson::parse(&json).expect("json parses");
        let parsed = parse_event(raw.value()).expect("event should verify");

        assert_eq!(parsed.id, event.id);
        assert_eq!(parsed.pubkey, event.pubkey);
    }

    #[test]
    fn parse_event_rejects_mismatched_event_id() {
        let mut event = signed_event("hello nostr");
        event.id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        let json = nojson::Json(&event).to_string();
        let raw = RawJson::parse(&json).expect("json parses");
        let err = parse_event(raw.value()).expect_err("id mismatch should fail");

        assert!(err.starts_with("invalid: event id"));
    }

    #[test]
    fn serialized_event_data_escapes_content() {
        let event = signed_event("line1\nline2\\\"x\"");
        let serialized = serialize_event_data(&event);

        assert!(serialized.contains("\\n"));
        assert!(serialized.contains("\\\\"));
        assert!(serialized.contains("\\\""));
        assert!(!serialized.contains('\n'));
    }

    #[test]
    fn parse_filter_rejects_invalid_since_until_range() {
        let raw = RawJson::parse(r#"{"since": 20, "until": 10}"#).expect("valid filter json");
        let err = parse_filter(raw.value()).expect_err("invalid range should fail");
        assert_eq!(err, "invalid: since must be <= until");
    }

    #[test]
    fn parse_filter_rejects_negative_since() {
        let raw = RawJson::parse(r#"{"since": -1}"#).expect("valid filter json");
        let err = parse_filter(raw.value()).expect_err("negative since should fail");
        assert_eq!(err, "invalid: since must be >= 0");
    }

    #[test]
    fn parse_filter_accepts_zero_limit() {
        let raw = RawJson::parse(r#"{"limit": 0}"#).expect("valid filter json");
        let filter = parse_filter(raw.value()).expect("zero limit should be valid");
        assert_eq!(filter.limit, Some(0));
    }

    #[test]
    fn parse_event_rejects_invalid_e_tag_value() {
        let mut event = signed_event("hello nostr");
        event.tags = vec![vec!["e".to_string(), "nothex".to_string()]];
        event.id = compute_event_id(&event);

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([1u8; 32]).expect("valid test secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let id_bytes = hex_to_fixed::<32>(&event.id).expect("id must decode");
        event.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();

        let json = nojson::Json(&event).to_string();
        let raw = RawJson::parse(&json).expect("json parses");
        let err = parse_event(raw.value()).expect_err("invalid e tag should fail");

        assert_eq!(err, "invalid: e tag value must be 64-char lowercase hex");
    }

    #[test]
    fn parse_event_rejects_addressable_without_d_tag() {
        let mut event = signed_event("hello nostr");
        event.kind = 30001;
        event.tags = vec![vec![
            "e".to_string(),
            "6f4c7eb5f9a4f14d99db3f6df2b0f9300ddc01e3bb73ef27c9cc10a7f0478d9f".to_string(),
        ]];
        event.id = compute_event_id(&event);

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([1u8; 32]).expect("valid test secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let id_bytes = hex_to_fixed::<32>(&event.id).expect("id must decode");
        event.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();

        let json = nojson::Json(&event).to_string();
        let raw = RawJson::parse(&json).expect("json parses");
        let err = parse_event(raw.value()).expect_err("missing d tag should fail");

        assert_eq!(
            err,
            "invalid: addressable events must include a d tag value"
        );
    }

    #[test]
    fn protected_tag_is_detected_only_for_single_dash_tag() {
        let mut protected = signed_event("protected");
        protected.tags = vec![vec!["-".to_string()]];
        assert!(event_has_protected_tag(&protected));

        let mut not_protected = signed_event("not protected");
        not_protected.tags = vec![vec!["-".to_string(), "x".to_string()]];
        assert!(!event_has_protected_tag(&not_protected));
    }

    #[test]
    fn relay_info_document_includes_nip11_and_nip42() {
        let cfg = RelayConfig {
            relay_url: "ws://127.0.0.1:8080".to_string(),
            allow_protected_events: true,
        };
        let doc = relay_info_document(&cfg);
        assert!(doc.contains("\"supported_nips\":[1,4,9,11,26,29,40,42,45,50,59,65,70,94,96]"));
        assert!(doc.contains("\"restricted_writes\":true"));
    }

    #[test]
    fn request_accepts_nip11_checks_accept_header() {
        let req_ok = "get / http/1.1\r\nhost: localhost\r\naccept: application/nostr+json\r\n\r\n";
        let req_ng = "get / http/1.1\r\nhost: localhost\r\naccept: application/json\r\n\r\n";

        assert!(request_accepts_nip11(req_ok));
        assert!(!request_accepts_nip11(req_ng));
    }

    #[test]
    fn auth_event_validation_requires_kind_challenge_and_relay() {
        let mut auth_event = signed_event("auth");
        auth_event.kind = 22242;
        auth_event.created_at = current_unix_timestamp();
        auth_event.tags = vec![
            vec!["relay".to_string(), "ws://127.0.0.1:8080".to_string()],
            vec!["challenge".to_string(), "abc123".to_string()],
        ];
        auth_event.id = compute_event_id(&auth_event);
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([1u8; 32]).expect("valid test secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let id_bytes = hex_to_fixed::<32>(&auth_event.id).expect("id must decode");
        auth_event.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();

        let auth = ConnectionAuth {
            challenge: "abc123".to_string(),
            relay_url: "ws://127.0.0.1:8080".to_string(),
            authenticated_pubkeys: HashSet::new(),
        };
        assert!(validate_auth_event(&auth_event, &auth).is_ok());

        let mut wrong_challenge = auth_event.clone();
        wrong_challenge.tags = vec![
            vec!["relay".to_string(), "ws://127.0.0.1:8080".to_string()],
            vec!["challenge".to_string(), "zzz".to_string()],
        ];
        wrong_challenge.id = compute_event_id(&wrong_challenge);
        let id_bytes = hex_to_fixed::<32>(&wrong_challenge.id).expect("id must decode");
        wrong_challenge.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();

        assert_eq!(
            validate_auth_event(&wrong_challenge, &auth).expect_err("must fail"),
            "invalid: AUTH event challenge tag mismatch"
        );
    }

    #[test]
    fn parse_a_tag_address_parses_valid_input() {
        let parsed = parse_a_tag_address(
            "30023:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:dval",
        )
        .expect("valid a tag");
        assert_eq!(parsed.0, 30023);
        assert_eq!(
            parsed.1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(parsed.2, "dval");
    }

    #[test]
    fn parse_a_tag_address_rejects_invalid_pubkey() {
        assert!(parse_a_tag_address("30023:nothex:d").is_none());
    }

    #[test]
    fn query_initial_events_skips_deleted_replaced_and_tombstoned() {
        let mut state = RelayState::default();
        let pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let deleted_regular = Arc::new(EventRecord {
            id: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            pubkey: pubkey.clone(),
            created_at: 100,
            kind: 1,
            tags: vec![],
            content: "deleted".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        });
        state
            .archived_events_by_id
            .insert(deleted_regular.id.clone(), Arc::clone(&deleted_regular));
        state.deleted_event_ids.insert(deleted_regular.id.clone());

        let old_replaceable = Arc::new(EventRecord {
            id: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            pubkey: pubkey.clone(),
            created_at: 100,
            kind: 0,
            tags: vec![],
            content: "old metadata".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        });
        state
            .archived_events_by_id
            .insert(old_replaceable.id.clone(), Arc::clone(&old_replaceable));

        let new_replaceable = Arc::new(EventRecord {
            id: "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            pubkey: pubkey.clone(),
            created_at: 101,
            kind: 0,
            tags: vec![],
            content: "new metadata".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        });
        state
            .events_by_id
            .insert(new_replaceable.id.clone(), Arc::clone(&new_replaceable));
        state.replaceable_index.insert(
            (pubkey.clone(), new_replaceable.kind),
            new_replaceable.id.clone(),
        );

        let tombstoned_addressable = Arc::new(EventRecord {
            id: "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
            pubkey: pubkey.clone(),
            created_at: 50,
            kind: 30023,
            tags: vec![vec!["d".to_string(), "x".to_string()]],
            content: "old address".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        });
        state.archived_events_by_id.insert(
            tombstoned_addressable.id.clone(),
            Arc::clone(&tombstoned_addressable),
        );
        state.deleted_addresses.insert(
            (30023, pubkey.clone(), "x".to_string()),
            tombstoned_addressable.created_at,
        );

        let ids_filter = Filter {
            ids: Some(vec![
                deleted_regular.id.clone(),
                old_replaceable.id.clone(),
                new_replaceable.id.clone(),
                tombstoned_addressable.id.clone(),
            ]),
            ..Filter::default()
        };

        let result = query_initial_events(&state, &[ids_filter]);
        let ids = result.iter().map(|e| e.id.as_str()).collect::<Vec<_>>();

        assert_eq!(
            ids,
            vec![new_replaceable.id.as_str(), old_replaceable.id.as_str()]
        );
    }

    #[test]
    fn apply_deletion_request_deletes_replaceable_and_rejects_old_republish() {
        let relay = Arc::new(Mutex::new(RelayState::default()));
        let pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let initial = EventRecord {
            id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            pubkey: pubkey.clone(),
            created_at: 100,
            kind: 0,
            tags: vec![],
            content: "v1".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        };
        let delete = EventRecord {
            id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            pubkey: pubkey.clone(),
            created_at: 110,
            kind: 5,
            tags: vec![vec!["a".to_string(), format!("0:{pubkey}:")]],
            content: "".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        };
        let older_retry = EventRecord {
            id: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            pubkey: pubkey.clone(),
            created_at: 109,
            kind: 0,
            tags: vec![],
            content: "old".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        };
        let newer_retry = EventRecord {
            id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            pubkey,
            created_at: 111,
            kind: 0,
            tags: vec![],
            content: "new".to_string(),
            sig: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        };

        assert!(publish_event(&relay, initial).is_ok());
        assert!(apply_deletion_request(&relay, &delete).is_ok());
        assert!(publish_event(&relay, delete).is_ok());
        assert!(publish_event(&relay, older_retry).is_err());
        assert!(publish_event(&relay, newer_retry).is_ok());
    }

    #[test]
    fn subscription_completeness_matches_expected_cases() {
        assert!(subscription_is_complete(&[Filter {
            ids: Some(vec!["x".repeat(64)]),
            ..Filter::default()
        }]));
        assert!(!subscription_is_complete(&[Filter {
            kinds: Some(vec![1]),
            ..Filter::default()
        }]));
    }

    #[test]
    fn parse_filter_accepts_search_field() {
        let raw = RawJson::parse(r#"{"kinds":[1],"search":"nostr rust"}"#).expect("valid json");
        let filter = parse_filter(raw.value()).expect("search should parse");
        assert_eq!(filter.search.as_deref(), Some("nostr rust"));
    }

    #[test]
    fn search_score_counts_term_matches_and_ignores_extensions() {
        let event = sample_event(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            10,
            1,
            "t",
            "x",
        );
        let score = search_score(&event, "hello include:spam");
        assert_eq!(score, Some(1));
        assert_eq!(search_score(&event, "domain:example.com"), Some(0));
        assert_eq!(search_score(&event, "missing"), None);
    }

    #[test]
    fn query_initial_events_sorts_search_results_by_score() {
        let mut state = RelayState::default();
        let low = Arc::new(EventRecord {
            id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            created_at: 10,
            kind: 1,
            tags: vec![],
            content: "rust".to_string(),
            sig: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        });
        let high = Arc::new(EventRecord {
            id: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            created_at: 9,
            kind: 1,
            tags: vec![],
            content: "rust rust rust".to_string(),
            sig: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        });
        state.events_by_id.insert(low.id.clone(), Arc::clone(&low));
        state
            .events_by_id
            .insert(high.id.clone(), Arc::clone(&high));

        let filter = Filter {
            search: Some("rust".to_string()),
            ..Filter::default()
        };
        let result = query_initial_events(&state, &[filter]);
        let ids = result.iter().map(|e| e.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids, vec![high.id.as_str(), low.id.as_str()]);
    }

    #[test]
    fn count_matching_events_respects_or_filters_and_deduplicates() {
        let mut state = RelayState::default();
        let e1 = sample_event(
            "1010101010101010101010101010101010101010101010101010101010101010",
            10,
            1,
            "p",
            "v1",
        );
        let e2 = sample_event(
            "2020202020202020202020202020202020202020202020202020202020202020",
            9,
            1,
            "p",
            "v2",
        );
        state.events_by_id.insert(e1.id.clone(), e1.clone());
        state.events_by_id.insert(e2.id.clone(), e2.clone());

        let f1 = Filter {
            ids: Some(vec![e1.id.clone()]),
            ..Filter::default()
        };
        let f2 = Filter {
            kinds: Some(vec![1]),
            ..Filter::default()
        };
        assert_eq!(count_matching_events(&state, &[f1, f2]), 2);
    }

    #[test]
    fn event_with_expiration_tag_expires_and_is_rejected() {
        let mut event = signed_event("temp");
        event.tags = vec![vec!["expiration".to_string(), "1".to_string()]];
        event.id = compute_event_id(&event);
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([1u8; 32]).expect("valid test secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let id_bytes = hex_to_fixed::<32>(&event.id).expect("id must decode");
        event.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();

        assert!(
            parse_event(
                RawJson::parse(&nojson::Json(&event).to_string())
                    .expect("json")
                    .value()
            )
            .is_ok()
        );
        assert!(is_event_expired(&event, current_unix_timestamp()));
    }

    #[test]
    fn kind_10002_accepts_non_r_tags_and_validates_markers_when_present() {
        let mut event = signed_event("relay list");
        event.kind = 10002;
        event.tags = vec![vec!["test".to_string()]];
        event.id = compute_event_id(&event);
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([1u8; 32]).expect("valid test secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let id_bytes = hex_to_fixed::<32>(&event.id).expect("id must decode");
        event.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();
        assert!(
            parse_event(
                RawJson::parse(&nojson::Json(&event).to_string())
                    .expect("json")
                    .value()
            )
            .is_ok()
        );
    }

    #[test]
    fn group_moderation_events_require_h_tag() {
        let mut event = signed_event("group");
        event.kind = 9000;
        event.tags = vec![vec![
            "p".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ]];
        event.id = compute_event_id(&event);
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array([1u8; 32]).expect("valid test secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let id_bytes = hex_to_fixed::<32>(&event.id).expect("id must decode");
        event.sig = secp
            .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
            .to_string();
        let err = parse_event(
            RawJson::parse(&nojson::Json(&event).to_string())
                .expect("json")
                .value(),
        )
        .expect_err("must reject without h tag");
        assert_eq!(err, "invalid: group events must include an h tag");
    }

    #[test]
    fn delegation_conditions_are_verified() {
        let delegator_pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut event = signed_event("delegated");
        event.tags = vec![vec![
            "delegation".to_string(),
            delegator_pubkey.to_string(),
            "kind=1&created_at>1&created_at<9999999999".to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ]];

        let err = validate_delegation(&event).expect_err("fake signature should fail");
        assert!(
            err == "invalid: bad delegation signature"
                || err == "invalid: delegation token must be 128-char lowercase hex"
        );
    }
}
