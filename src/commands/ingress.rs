use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};

use nojson::{RawJson, RawJsonValue};
use negentropy::{Id, Negentropy, NegentropyStorageVector};
use tokio_tungstenite::tungstenite::protocol::WebSocket;

use crate::crypto::compute_event_id_from_serialized;
use crate::{
    ConnectionAuth, DynError, EventRecord, EventStore, Filter, RelayConfig, RelayState,
    build_raw_serialized_event_data, escape_control_chars_in_json_strings, parse_event_with_options,
};

use super::{
    extract_event_id, handle_auth, handle_count, handle_event, handle_parsed_event_submission,
    handle_req, parse_filter, query_initial_events_for_auth, send_event, send_notice, send_ok,
    validate_subscription_id,
};

#[derive(Debug, Clone)]
pub(crate) struct NegentropySession {
    storage: NegentropyStorageVector,
}

pub(crate) type NegentropySessions = HashMap<String, NegentropySession>;

pub(crate) fn forward_live_events(
    ws: &mut WebSocket<TcpStream>,
    rx: &Receiver<Arc<EventRecord>>,
    subscriptions: &HashMap<String, Vec<Filter>>,
    auth: &ConnectionAuth,
) -> Result<(), DynError> {
    loop {
        match rx.try_recv() {
            Ok(event) => {
                for (sub_id, filters) in subscriptions {
                    if super::matches_any_filter_for_auth(&event, filters, auth) {
                        send_event(ws, sub_id, &event)?;
                    }
                }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
        }
    }

    Ok(())
}

pub(crate) fn handle_text_frame(
    ws: &mut WebSocket<TcpStream>,
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    negentropy_sessions: &mut NegentropySessions,
    relay: &Arc<Mutex<RelayState>>,
    event_store: &Arc<EventStore>,
    relay_config: &RelayConfig,
    auth: &mut ConnectionAuth,
    text: &str,
) -> Result<(), DynError> {
    let raw = match RawJson::parse(text) {
        Ok(value) => value,
        Err(err) => {
            if try_handle_relaxed_event_frame(ws, relay, event_store, relay_config, auth, text)? {
                return Ok(());
            }
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
        "REQ" => handle_req(ws, subscriptions, relay, auth, &values),
        "COUNT" => handle_count(ws, relay, auth, &values),
        "CLOSE" => super::handle_close(subscriptions, &values),
        "NEG-OPEN" => handle_neg_open(ws, negentropy_sessions, relay, auth, &values),
        "NEG-MSG" => handle_neg_msg(ws, negentropy_sessions, &values),
        "NEG-CLOSE" => handle_neg_close(negentropy_sessions, &values),
        "EVENT" => handle_event(ws, relay, event_store, relay_config, auth, &values),
        "AUTH" => handle_auth(ws, auth, &values),
        _ => {
            send_notice(ws, &format!("unsupported: command {command}"))?;
            Ok(())
        }
    }
}

fn try_handle_relaxed_event_frame(
    ws: &mut WebSocket<TcpStream>,
    relay: &Arc<Mutex<RelayState>>,
    event_store: &Arc<EventStore>,
    relay_config: &RelayConfig,
    auth: &ConnectionAuth,
    text: &str,
) -> Result<bool, DynError> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with("[\"EVENT\",") {
        return Ok(false);
    }

    let Some(start) = text.find('{') else {
        return Ok(false);
    };
    let Some(end) = text.rfind('}') else {
        return Ok(false);
    };
    if start >= end {
        return Ok(false);
    }

    let event_json = &text[start..=end];
    let escaped = escape_control_chars_in_json_strings(event_json, true);
    let escaped_relaxed = escape_control_chars_in_json_strings(event_json, false);
    let (raw, used_relaxed) = match RawJson::parse(&escaped) {
        Ok(raw) => (raw, false),
        Err(_) => match RawJson::parse(&escaped_relaxed) {
            Ok(raw) => (raw, true),
            Err(_) => return Ok(false),
        },
    };

    let event_id_hint = extract_event_id(raw.value());
    let raw_serialized = if used_relaxed {
        build_raw_serialized_event_data(&escaped_relaxed)?
    } else {
        build_raw_serialized_event_data(event_json)?
    };
    let event = match parse_event_with_options(raw.value(), false, Some(&raw_serialized)) {
        Ok(event) => event,
        Err(err) => {
            send_ok(ws, &event_id_hint, false, &err)?;
            return Ok(true);
        }
    };
    let raw_id = compute_event_id_from_serialized(&raw_serialized);
    if event.id != raw_id {
        send_ok(
            ws,
            &event_id_hint,
            false,
            "invalid: event id does not match serialized event hash",
        )?;
        return Ok(true);
    }

    handle_parsed_event_submission(
        ws,
        relay,
        event_store,
        relay_config,
        auth,
        event,
        &event_id_hint,
    )?;

    Ok(true)
}

fn handle_neg_open(
    ws: &mut WebSocket<TcpStream>,
    sessions: &mut NegentropySessions,
    relay: &Arc<Mutex<RelayState>>,
    auth: &ConnectionAuth,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() != 4 {
        send_neg_err(
            ws,
            "",
            "invalid: NEG-OPEN must include subscription id, filter and initial message",
        )?;
        return Ok(());
    }

    let sub_id: String = match values[1].try_into() {
        Ok(sub_id) => sub_id,
        Err(_) => {
            send_neg_err(ws, "", "invalid: NEG-OPEN subscription id must be a string")?;
            return Ok(());
        }
    };
    if let Err(err) = validate_subscription_id(&sub_id) {
        send_neg_err(ws, &sub_id, &err)?;
        return Ok(());
    }

    let filter = match parse_filter(values[2]) {
        Ok(filter) => filter,
        Err(err) => {
            send_neg_err(ws, &sub_id, &err)?;
            return Ok(());
        }
    };
    let message_hex: String = match values[3].try_into() {
        Ok(value) => value,
        Err(_) => {
            send_neg_err(
                ws,
                &sub_id,
                "invalid: NEG-OPEN initial message must be hex string",
            )?;
            return Ok(());
        }
    };
    let message = match hex_to_bytes(&message_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            send_neg_err(ws, &sub_id, &err)?;
            return Ok(());
        }
    };

    let storage = {
        let state = relay
            .lock()
            .map_err(|_| "error: relay state lock poisoned during NEG-OPEN")?;
        build_negentropy_storage(&state, &filter, auth)?
    };

    let mut engine = match Negentropy::owned(storage.clone(), 0) {
        Ok(engine) => engine,
        Err(err) => {
            send_neg_err(ws, &sub_id, &format!("error: NEG-OPEN init failed ({err})"))?;
            return Ok(());
        }
    };
    let response = match engine.reconcile(&message) {
        Ok(response) => response,
        Err(err) => {
            send_neg_err(
                ws,
                &sub_id,
                &format!("invalid: NEG-OPEN reconciliation failed ({err})"),
            )?;
            return Ok(());
        }
    };

    sessions.insert(sub_id.clone(), NegentropySession { storage });
    send_neg_msg(ws, &sub_id, &bytes_to_hex(&response))?;
    Ok(())
}

fn handle_neg_msg(
    ws: &mut WebSocket<TcpStream>,
    sessions: &mut NegentropySessions,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() != 3 {
        send_neg_err(
            ws,
            "",
            "invalid: NEG-MSG must include subscription id and message",
        )?;
        return Ok(());
    }

    let sub_id: String = match values[1].try_into() {
        Ok(sub_id) => sub_id,
        Err(_) => {
            send_neg_err(ws, "", "invalid: NEG-MSG subscription id must be a string")?;
            return Ok(());
        }
    };
    let Some(session) = sessions.get(&sub_id) else {
        send_neg_err(ws, &sub_id, "closed: unknown NEG subscription id")?;
        return Ok(());
    };

    let message_hex: String = match values[2].try_into() {
        Ok(value) => value,
        Err(_) => {
            send_neg_err(ws, &sub_id, "invalid: NEG-MSG payload must be hex string")?;
            return Ok(());
        }
    };
    let message = match hex_to_bytes(&message_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            send_neg_err(ws, &sub_id, &err)?;
            return Ok(());
        }
    };

    let mut engine = match Negentropy::owned(session.storage.clone(), 0) {
        Ok(engine) => engine,
        Err(err) => {
            send_neg_err(ws, &sub_id, &format!("error: NEG-MSG init failed ({err})"))?;
            return Ok(());
        }
    };
    let response = match engine.reconcile(&message) {
        Ok(response) => response,
        Err(err) => {
            sessions.remove(&sub_id);
            send_neg_err(
                ws,
                &sub_id,
                &format!("invalid: NEG-MSG reconciliation failed ({err})"),
            )?;
            return Ok(());
        }
    };

    send_neg_msg(ws, &sub_id, &bytes_to_hex(&response))?;
    Ok(())
}

fn handle_neg_close(
    sessions: &mut NegentropySessions,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() < 2 {
        return Ok(());
    }

    let sub_id: String = match values[1].try_into() {
        Ok(sub_id) => sub_id,
        Err(_) => return Ok(()),
    };
    sessions.remove(&sub_id);
    Ok(())
}

fn build_negentropy_storage(
    state: &RelayState,
    filter: &Filter,
    auth: &ConnectionAuth,
) -> Result<NegentropyStorageVector, DynError> {
    let events = query_initial_events_for_auth(state, &[filter.clone()], auth);
    let mut storage = NegentropyStorageVector::with_capacity(events.len());

    for event in events {
        let timestamp = u64::try_from(event.created_at).unwrap_or(0);
        let id_bytes = crate::crypto::hex_to_fixed::<32>(&event.id)
            .map_err(|e| format!("invalid: failed to decode event id for NEG-OPEN ({e})"))?;
        storage.insert(timestamp, Id::from_byte_array(id_bytes))?;
    }
    storage.seal()?;
    Ok(storage)
}

fn hex_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Err("invalid: NEG payload must be non-empty even-length hex".to_string());
    }
    if !value
        .as_bytes()
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("invalid: NEG payload must be lowercase hex".to_string());
    }

    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = from_hex_nibble(bytes[i])?;
        let lo = from_hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }

    Ok(out)
}

fn from_hex_nibble(ch: u8) -> Result<u8, String> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        _ => Err("invalid: NEG payload must be lowercase hex".to_string()),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[nibble as usize] as char
}

fn send_neg_msg(
    ws: &mut WebSocket<TcpStream>,
    sub_id: &str,
    payload_hex: &str,
) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("NEG-MSG")?;
        f.element(sub_id)?;
        f.element(payload_hex)
    })
    .to_string();
    ws.send(tokio_tungstenite::tungstenite::Message::text(frame))?;
    Ok(())
}

fn send_neg_err(
    ws: &mut WebSocket<TcpStream>,
    sub_id: &str,
    reason: &str,
) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("NEG-ERR")?;
        f.element(sub_id)?;
        f.element(reason)
    })
    .to_string();
    ws.send(tokio_tungstenite::tungstenite::Message::text(frame))?;
    Ok(())
}
