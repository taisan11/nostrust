use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use tokio_tungstenite::tungstenite::protocol::WebSocket;

use crate::{
    ConnectionAuth, DynError, EventRecord, EventStore, PublishOutcome, RelayConfig, RelayState,
    apply_deletion_request, current_unix_timestamp, is_auth_event_kind, publish_event,
    should_persist_event,
};

use super::{send_notice, send_ok};

pub(crate) fn handle_parsed_event_submission(
    ws: &mut WebSocket<TcpStream>,
    relay: &Arc<Mutex<RelayState>>,
    event_store: &Arc<EventStore>,
    relay_config: &RelayConfig,
    auth: &ConnectionAuth,
    event: EventRecord,
    event_id_hint: &str,
) -> Result<(), DynError> {
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
                event_id_hint
            };
            send_ok(ws, fallback_id, false, &format!("error: {err}"))?;
        }
    }

    Ok(())
}

pub(crate) fn event_has_protected_tag(event: &EventRecord) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.len() == 1 && tag.first().map(String::as_str) == Some("-"))
}

pub(crate) fn validate_auth_event(event: &EventRecord, auth: &ConnectionAuth) -> Result<(), String> {
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
