use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nojson::{DisplayJson, JsonFormatter, RawJson, RawJsonValue};
use tokio_tungstenite::tungstenite::protocol::WebSocket;
use tokio_tungstenite::tungstenite::{Error as WsError, Message, accept};

mod crypto;
mod persistence;

use crate::crypto::{verify_delegation_signature, verify_event_id_and_signature};
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
            "\"supported_nips\":[1,9,11,26,29,40,42,45,50,65,70],",
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

fn forward_live_events(
    ws: &mut WebSocket<TcpStream>,
    rx: &Receiver<Arc<EventRecord>>,
    subscriptions: &HashMap<String, Vec<Filter>>,
) -> Result<(), DynError> {
    loop {
        match rx.try_recv() {
            Ok(event) => {
                for (sub_id, filters) in subscriptions {
                    if matches_any_filter(&event, filters) {
                        send_event(ws, sub_id, &event)?;
                    }
                }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
        }
    }

    Ok(())
}

fn handle_text_frame(
    ws: &mut WebSocket<TcpStream>,
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    relay: &Arc<Mutex<RelayState>>,
    event_store: &Arc<EventStore>,
    relay_config: &RelayConfig,
    auth: &mut ConnectionAuth,
    text: &str,
) -> Result<(), DynError> {
    let raw = match RawJson::parse(text) {
        Ok(value) => value,
        Err(err) => {
            send_notice(ws, &format!("invalid: {err}"))?;
            return Ok(());
        }
    };

    let root = raw.value();
    let values: Vec<RawJsonValue<'_, '_>> = match root.try_into() {
        Ok(values) => values,
        Err(_) => {
            send_notice(ws, "invalid: message must be a JSON array")?;
            return Ok(());
        }
    };

    if values.is_empty() {
        send_notice(ws, "invalid: message must be a non-empty array")?;
        return Ok(());
    }

    let command: String = match values[0].try_into() {
        Ok(command) => command,
        Err(_) => {
            send_notice(ws, "invalid: first element must be a command string")?;
            return Ok(());
        }
    };

    match command.as_str() {
        "REQ" => handle_req(ws, subscriptions, relay, &values),
        "COUNT" => handle_count(ws, relay, &values),
        "CLOSE" => handle_close(subscriptions, &values),
        "EVENT" => handle_event(ws, relay, event_store, relay_config, auth, &values),
        "AUTH" => handle_auth(ws, auth, &values),
        _ => {
            send_notice(ws, &format!("unsupported: command {command}"))?;
            Ok(())
        }
    }
}

fn handle_req(
    ws: &mut WebSocket<TcpStream>,
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    relay: &Arc<Mutex<RelayState>>,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() < 2 {
        send_notice(ws, "invalid: REQ must include a subscription id")?;
        return Ok(());
    }

    let sub_id: String = match values[1].try_into() {
        Ok(sub_id) => sub_id,
        Err(_) => {
            send_notice(ws, "invalid: subscription id must be a string")?;
            return Ok(());
        }
    };

    if let Err(err) = validate_subscription_id(&sub_id) {
        send_closed(ws, &sub_id, &err)?;
        return Ok(());
    }

    if values.len() < 3 {
        send_closed(ws, &sub_id, "invalid: REQ must include at least one filter")?;
        return Ok(());
    }

    let mut filters = Vec::new();
    for raw_filter in values.iter().skip(2) {
        match parse_filter(*raw_filter) {
            Ok(filter) => filters.push(filter),
            Err(err) => {
                send_closed(ws, &sub_id, &err)?;
                return Ok(());
            }
        }
    }

    subscriptions.insert(sub_id.clone(), filters.clone());

    let initial_events = {
        let state = relay
            .lock()
            .map_err(|_| "error: relay state lock poisoned during REQ")?;
        query_initial_events(&state, &filters)
    };

    for event in initial_events {
        send_event(ws, &sub_id, &event)?;
    }

    send_eose(ws, &sub_id)?;
    if subscription_is_complete(&filters) {
        subscriptions.remove(&sub_id);
        send_closed(ws, &sub_id, "closed: complete")?;
    }
    Ok(())
}

fn handle_count(
    ws: &mut WebSocket<TcpStream>,
    relay: &Arc<Mutex<RelayState>>,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() < 2 {
        send_notice(ws, "invalid: COUNT must include a query id")?;
        return Ok(());
    }

    let query_id: String = match values[1].try_into() {
        Ok(query_id) => query_id,
        Err(_) => {
            send_notice(ws, "invalid: query id must be a string")?;
            return Ok(());
        }
    };

    if let Err(err) = validate_subscription_id(&query_id) {
        send_closed(ws, &query_id, &err)?;
        return Ok(());
    }

    if values.len() < 3 {
        send_closed(
            ws,
            &query_id,
            "invalid: COUNT must include at least one filter",
        )?;
        return Ok(());
    }

    let mut filters = Vec::new();
    for raw_filter in values.iter().skip(2) {
        match parse_filter(*raw_filter) {
            Ok(filter) => filters.push(filter),
            Err(err) => {
                send_closed(ws, &query_id, &err)?;
                return Ok(());
            }
        }
    }

    let count = {
        let state = relay
            .lock()
            .map_err(|_| "error: relay state lock poisoned during COUNT")?;
        count_matching_events(&state, &filters)
    };

    send_count(ws, &query_id, count)?;
    Ok(())
}

fn handle_close(
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() < 2 {
        return Ok(());
    }

    let sub_id: String = match values[1].try_into() {
        Ok(sub_id) => sub_id,
        Err(_) => return Ok(()),
    };

    subscriptions.remove(&sub_id);
    Ok(())
}

fn handle_event(
    ws: &mut WebSocket<TcpStream>,
    relay: &Arc<Mutex<RelayState>>,
    event_store: &Arc<EventStore>,
    relay_config: &RelayConfig,
    auth: &ConnectionAuth,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() != 2 {
        send_ok(
            ws,
            "",
            false,
            "invalid: EVENT must contain exactly one event object",
        )?;
        return Ok(());
    }

    let event_id_hint = extract_event_id(values[1]);
    let event = match parse_event(values[1]) {
        Ok(event) => event,
        Err(err) => {
            send_ok(ws, &event_id_hint, false, &err)?;
            return Ok(());
        }
    };

    if is_auth_event_kind(event.kind) {
        send_ok(
            ws,
            &event.id,
            false,
            "invalid: AUTH command must be used for kind 22242 events",
        )?;
        return Ok(());
    }

    if event_has_protected_tag(&event) {
        if !relay_config.allow_protected_events {
            send_ok(
                ws,
                &event.id,
                false,
                "restricted: protected events are disabled on this relay",
            )?;
            return Ok(());
        }

        if !auth.is_authenticated(&event.pubkey) {
            send_ok(
                ws,
                &event.id,
                false,
                "auth-required: this event may only be published by its author",
            )?;
            return Ok(());
        }
    }

    if event.kind == 5 {
        apply_deletion_request(relay, &event)?;
    }

    match publish_event(relay, event) {
        Ok(PublishOutcome::Accepted { event, message }) => {
            if should_persist_event(&event)
                && let Err(err) = event_store.append_event(&event)
            {
                eprintln!("persistence error: {err}");
                send_notice(ws, &format!("warning: persistence failed: {err}"))?;
            }
            send_ok(ws, &event.id, true, &message)?;
        }
        Ok(PublishOutcome::DuplicateAccepted { event_id, message }) => {
            send_ok(ws, &event_id, true, &message)?;
        }
        Err(err) => {
            let fallback_id = if event_id_hint.is_empty() {
                ""
            } else {
                &event_id_hint
            };
            send_ok(ws, fallback_id, false, &format!("error: {err}"))?;
        }
    }

    Ok(())
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

fn send_event(
    ws: &mut WebSocket<TcpStream>,
    sub_id: &str,
    event: &EventRecord,
) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("EVENT")?;
        f.element(sub_id)?;
        f.element(event)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

fn send_ok(
    ws: &mut WebSocket<TcpStream>,
    event_id: &str,
    accepted: bool,
    message: &str,
) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("OK")?;
        f.element(event_id)?;
        f.element(accepted)?;
        f.element(message)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

fn send_eose(ws: &mut WebSocket<TcpStream>, sub_id: &str) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("EOSE")?;
        f.element(sub_id)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

fn send_closed(ws: &mut WebSocket<TcpStream>, sub_id: &str, message: &str) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("CLOSED")?;
        f.element(sub_id)?;
        f.element(message)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

fn send_count(ws: &mut WebSocket<TcpStream>, query_id: &str, count: usize) -> Result<(), DynError> {
    let payload = CountPayload { count };
    let frame = nojson::array(|f| {
        f.element("COUNT")?;
        f.element(query_id)?;
        f.element(&payload)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

fn send_notice(ws: &mut WebSocket<TcpStream>, message: &str) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("NOTICE")?;
        f.element(message)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

fn send_auth_challenge(ws: &mut WebSocket<TcpStream>, challenge: &str) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("AUTH")?;
        f.element(challenge)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

fn handle_auth(
    ws: &mut WebSocket<TcpStream>,
    auth: &mut ConnectionAuth,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() != 2 {
        send_ok(
            ws,
            "",
            false,
            "invalid: AUTH must contain exactly one event object",
        )?;
        return Ok(());
    }

    let event_id_hint = extract_event_id(values[1]);
    let event = match parse_event(values[1]) {
        Ok(event) => event,
        Err(err) => {
            send_ok(ws, &event_id_hint, false, &err)?;
            return Ok(());
        }
    };

    match validate_auth_event(&event, auth) {
        Ok(()) => {
            auth.authenticated_pubkeys.insert(event.pubkey.clone());
            send_ok(ws, &event.id, true, "")?;
        }
        Err(err) => {
            send_ok(ws, &event.id, false, &err)?;
        }
    }

    Ok(())
}

fn parse_event(value: RawJsonValue<'_, '_>) -> Result<EventRecord, String> {
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

    let created_at: i64 = value
        .to_member("created_at")
        .map_err(|e| format!("invalid: {e}"))?
        .required()
        .map_err(|e| format!("invalid: {e}"))?
        .try_into()
        .map_err(|e| format!("invalid: {e}"))?;

    if created_at < 0 {
        return Err("invalid: created_at must be >= 0".to_string());
    }

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
        let tag_values: Vec<String> = tag.try_into().map_err(|e| format!("invalid: {e}"))?;
        if tag_values.is_empty() {
            return Err("invalid: each tag must be a non-empty string array".to_string());
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

    verify_event_id_and_signature(&event)?;
    validate_delegation(&event)?;
    validate_group_event_tags(&event)?;
    validate_nip65_relay_list_event(&event)?;
    Ok(event)
}

fn parse_filter(value: RawJsonValue<'_, '_>) -> Result<Filter, String> {
    let mut filter = Filter::default();

    for (key_raw, val) in value.to_object().map_err(|e| format!("invalid: {e}"))? {
        let key: String = key_raw.try_into().map_err(|e| format!("invalid: {e}"))?;

        match key.as_str() {
            "ids" => {
                filter.ids = Some(parse_string_array(val, true)?);
                validate_hex_list(filter.ids.as_ref().expect("set by line above"), 64, "ids")?;
            }
            "authors" => {
                filter.authors = Some(parse_string_array(val, true)?);
                validate_hex_list(
                    filter.authors.as_ref().expect("set by line above"),
                    64,
                    "authors",
                )?;
            }
            "kinds" => {
                let mut kinds = Vec::new();
                let mut iter = val.to_array().map_err(|e| format!("invalid: {e}"))?;
                let mut saw_any = false;

                for raw_kind in &mut iter {
                    saw_any = true;
                    let kind: u64 = raw_kind.try_into().map_err(|e| format!("invalid: {e}"))?;
                    if kind > 65535 {
                        return Err("invalid: filter kinds must be 0..65535".to_string());
                    }
                    kinds.push(kind);
                }

                if !saw_any {
                    return Err("invalid: filter arrays must not be empty".to_string());
                }

                filter.kinds = Some(kinds);
            }
            "search" => {
                let search: String = val.try_into().map_err(|e| format!("invalid: {e}"))?;
                filter.search = Some(search);
            }
            "since" => {
                let since: i64 = val.try_into().map_err(|e| format!("invalid: {e}"))?;
                if since < 0 {
                    return Err("invalid: since must be >= 0".to_string());
                }
                filter.since = Some(since);
            }
            "until" => {
                let until: i64 = val.try_into().map_err(|e| format!("invalid: {e}"))?;
                if until < 0 {
                    return Err("invalid: until must be >= 0".to_string());
                }
                filter.until = Some(until);
            }
            "limit" => {
                let limit_raw: u64 = val.try_into().map_err(|e| format!("invalid: {e}"))?;
                let limit = usize::try_from(limit_raw)
                    .map_err(|_| "invalid: limit is too large for this relay".to_string())?;
                filter.limit = Some(limit);
            }
            _ if is_tag_filter_key(&key) => {
                let letter = key.chars().nth(1).expect("#x has second char");
                let values = parse_string_array(val, true)?;

                if letter == 'e' || letter == 'p' {
                    validate_hex_list(&values, 64, "tag values")?;
                }

                filter.tag_values.insert(letter, values);
            }
            _ => return Err("unsupported: filter contains unknown elements".to_string()),
        }
    }

    if let (Some(since), Some(until)) = (filter.since, filter.until)
        && since > until
    {
        return Err("invalid: since must be <= until".to_string());
    }

    Ok(filter)
}

fn parse_string_array(value: RawJsonValue<'_, '_>, non_empty: bool) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut iter = value.to_array().map_err(|e| format!("invalid: {e}"))?;

    let mut saw_any = false;
    for entry in &mut iter {
        saw_any = true;
        let s: String = entry.try_into().map_err(|e| format!("invalid: {e}"))?;
        out.push(s);
    }

    if non_empty && !saw_any {
        return Err("invalid: filter arrays must not be empty".to_string());
    }

    Ok(out)
}

fn validate_hex_list(values: &[String], len: usize, field_name: &str) -> Result<(), String> {
    if values.iter().all(|v| is_lower_hex_of_len(v, len)) {
        Ok(())
    } else {
        Err(format!(
            "invalid: {field_name} must contain exact {len}-char lowercase hex values"
        ))
    }
}

fn validate_subscription_id(sub_id: &str) -> Result<(), String> {
    if sub_id.is_empty() {
        return Err("invalid: subscription id must not be empty".to_string());
    }

    if sub_id.len() > 64 {
        return Err("invalid: subscription id max length is 64".to_string());
    }

    Ok(())
}

fn extract_event_id(value: RawJsonValue<'_, '_>) -> String {
    value
        .to_member("id")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.try_into().ok())
        .unwrap_or_default()
}

fn query_initial_events(state: &RelayState, filters: &[Filter]) -> Vec<Arc<EventRecord>> {
    let mut selected: HashMap<String, Arc<EventRecord>> = HashMap::new();

    for filter in filters {
        let mut matching = if let Some(ids) = &filter.ids {
            ids.iter()
                .filter_map(|id| {
                    state
                        .events_by_id
                        .get(id)
                        .or_else(|| state.archived_events_by_id.get(id))
                        .cloned()
                })
                .collect::<Vec<_>>()
        } else {
            state.events_by_id.values().cloned().collect::<Vec<_>>()
        };

        matching.retain(|event| {
            !state.deleted_event_ids.contains(&event.id)
                && !event_blocked_by_address_tombstone(event, &state.deleted_addresses)
                && (filter.ids.is_some() || !event_is_superseded(event, state))
                && !is_event_expired(event, current_unix_timestamp())
                && event_matches_filter(event, filter)
        });

        matching.sort_by(|a, b| compare_events_for_filter(filter, a, b));

        if let Some(limit) = filter.limit {
            matching.truncate(limit);
        }

        for event in matching {
            selected.entry(event.id.clone()).or_insert(event);
        }
    }

    let mut out = selected.into_values().collect::<Vec<_>>();
    if filters.iter().any(|filter| filter.search.is_some()) {
        out.sort_by(|a, b| compare_events_for_filters(filters, a, b));
    } else {
        out.sort_by(compare_events_desc);
    }
    out
}

fn compare_events_desc(a: &Arc<EventRecord>, b: &Arc<EventRecord>) -> Ordering {
    b.created_at
        .cmp(&a.created_at)
        .then_with(|| a.id.cmp(&b.id))
}

fn compare_events_for_filter(
    filter: &Filter,
    a: &Arc<EventRecord>,
    b: &Arc<EventRecord>,
) -> Ordering {
    if let Some(search) = &filter.search {
        let a_score = search_score(a, search).unwrap_or(0);
        let b_score = search_score(b, search).unwrap_or(0);
        b_score
            .cmp(&a_score)
            .then_with(|| compare_events_desc(a, b))
    } else {
        compare_events_desc(a, b)
    }
}

fn compare_events_for_filters(
    filters: &[Filter],
    a: &Arc<EventRecord>,
    b: &Arc<EventRecord>,
) -> Ordering {
    let a_score = combined_search_score(a, filters);
    let b_score = combined_search_score(b, filters);
    b_score
        .cmp(&a_score)
        .then_with(|| compare_events_desc(a, b))
}

fn combined_search_score(event: &EventRecord, filters: &[Filter]) -> usize {
    filters
        .iter()
        .filter_map(|filter| filter.search.as_ref().and_then(|q| search_score(event, q)))
        .max()
        .unwrap_or(0)
}

fn count_matching_events(state: &RelayState, filters: &[Filter]) -> usize {
    let mut selected = HashSet::new();

    for filter in filters {
        let matching = if let Some(ids) = &filter.ids {
            ids.iter()
                .filter_map(|id| {
                    state
                        .events_by_id
                        .get(id)
                        .or_else(|| state.archived_events_by_id.get(id))
                        .cloned()
                })
                .collect::<Vec<_>>()
        } else {
            state.events_by_id.values().cloned().collect::<Vec<_>>()
        };

        for event in matching {
            if !state.deleted_event_ids.contains(&event.id)
                && !event_blocked_by_address_tombstone(&event, &state.deleted_addresses)
                && (filter.ids.is_some() || !event_is_superseded(&event, state))
                && !is_event_expired(&event, current_unix_timestamp())
                && event_matches_filter(&event, filter)
            {
                selected.insert(event.id.clone());
            }
        }
    }

    selected.len()
}

fn event_blocked_by_address_tombstone(
    event: &EventRecord,
    deleted_addresses: &HashMap<(u64, String, String), i64>,
) -> bool {
    if !matches!(
        classify_kind(event.kind),
        KindClass::Replaceable | KindClass::Addressable
    ) {
        return false;
    }

    let key = (event.kind, event.pubkey.clone(), event.d_tag_value());
    deleted_addresses
        .get(&key)
        .is_some_and(|delete_ts| event.created_at <= *delete_ts)
}

fn event_is_superseded(event: &EventRecord, state: &RelayState) -> bool {
    match classify_kind(event.kind) {
        KindClass::Replaceable => {
            let key = (event.pubkey.clone(), event.kind);
            state
                .replaceable_index
                .get(&key)
                .is_some_and(|active_id| active_id != &event.id)
        }
        KindClass::Addressable => {
            let key = (event.kind, event.pubkey.clone(), event.d_tag_value());
            state
                .addressable_index
                .get(&key)
                .is_some_and(|active_id| active_id != &event.id)
        }
        KindClass::RegularOrOther | KindClass::Ephemeral => false,
    }
}

fn subscription_is_complete(filters: &[Filter]) -> bool {
    filters.iter().all(|filter| filter.ids.is_some())
}

fn matches_any_filter(event: &EventRecord, filters: &[Filter]) -> bool {
    filters
        .iter()
        .any(|filter| event_matches_filter(event, filter))
}

fn event_matches_filter(event: &EventRecord, filter: &Filter) -> bool {
    if let Some(ids) = &filter.ids
        && !ids.iter().any(|id| id == &event.id)
    {
        return false;
    }

    if let Some(authors) = &filter.authors
        && !authors.iter().any(|author| author == &event.pubkey)
    {
        return false;
    }

    if let Some(kinds) = &filter.kinds
        && !kinds.iter().any(|kind| kind == &event.kind)
    {
        return false;
    }

    if let Some(since) = filter.since
        && event.created_at < since
    {
        return false;
    }

    if let Some(until) = filter.until
        && event.created_at > until
    {
        return false;
    }

    for (tag_name, wanted_values) in &filter.tag_values {
        let mut matched = false;
        let tag_name_str = tag_name.to_string();

        for tag in &event.tags {
            if tag.first().map(String::as_str) != Some(tag_name_str.as_str()) {
                continue;
            }

            if let Some(value) = tag.get(1)
                && wanted_values.iter().any(|wanted| wanted == value)
            {
                matched = true;
                break;
            }
        }

        if !matched {
            return false;
        }
    }

    if let Some(search) = &filter.search
        && search_score(event, search).is_none()
    {
        return false;
    }

    true
}

fn search_score(event: &EventRecord, query: &str) -> Option<usize> {
    let terms = query
        .split_whitespace()
        .filter(|term| !term.contains(':'))
        .map(|term| term.to_lowercase())
        .filter(|term| !term.is_empty())
        .collect::<Vec<_>>();

    if terms.is_empty() {
        return Some(0);
    }

    let content = event.content.to_lowercase();
    let score = terms
        .iter()
        .map(|term| content.match_indices(term).count())
        .sum::<usize>();

    if score == 0 { None } else { Some(score) }
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

fn event_has_protected_tag(event: &EventRecord) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.len() == 1 && tag.first().map(String::as_str) == Some("-"))
}

fn validate_auth_event(event: &EventRecord, auth: &ConnectionAuth) -> Result<(), String> {
    if !is_auth_event_kind(event.kind) {
        return Err("invalid: AUTH event kind must be 22242".to_string());
    }

    let now = current_unix_timestamp();
    if (event.created_at - now).abs() > 600 {
        return Err("invalid: AUTH event created_at is too far from current time".to_string());
    }

    let relay_tag = event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("relay"))
        .and_then(|tag| tag.get(1))
        .ok_or_else(|| "invalid: AUTH event missing relay tag".to_string())?;
    if relay_tag != &auth.relay_url {
        return Err("invalid: AUTH event relay tag mismatch".to_string());
    }

    let challenge_tag = event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("challenge"))
        .and_then(|tag| tag.get(1))
        .ok_or_else(|| "invalid: AUTH event missing challenge tag".to_string())?;
    if challenge_tag != &auth.challenge {
        return Err("invalid: AUTH event challenge tag mismatch".to_string());
    }

    Ok(())
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

    let mut has_r = false;
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("r") {
            continue;
        }
        has_r = true;
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

    if !has_r {
        return Err("invalid: kind 10002 must include at least one r tag".to_string());
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
        assert!(doc.contains("\"supported_nips\":[1,9,11,26,29,40,42,45,50,65,70]"));
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
    fn kind_10002_requires_r_tags_with_valid_markers() {
        let mut event = signed_event("relay list");
        event.kind = 10002;
        event.tags = vec![vec![
            "r".to_string(),
            "wss://relay.example".to_string(),
            "read".to_string(),
        ]];
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
