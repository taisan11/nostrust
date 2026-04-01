use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};

use nojson::{RawJson, RawJsonValue};
use tokio_tungstenite::tungstenite::protocol::WebSocket;

use crate::crypto::compute_event_id_from_serialized;
use crate::{
    ConnectionAuth, DynError, EventRecord, EventStore, Filter, RelayConfig, RelayState,
    build_raw_serialized_event_data, escape_control_chars_in_json_strings, parse_event_with_options,
};

use super::{
    extract_event_id, handle_auth, handle_count, handle_event, handle_parsed_event_submission,
    handle_req, matches_any_filter, send_event, send_notice, send_ok,
};

pub(crate) fn forward_live_events(
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

pub(crate) fn handle_text_frame(
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
        "REQ" => handle_req(ws, subscriptions, relay, &values),
        "COUNT" => handle_count(ws, relay, &values),
        "CLOSE" => super::handle_close(subscriptions, &values),
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
