use axum::extract::ws::WebSocket;
use nojson::RawJsonValue;

use crate::{ConnectionAuth, DynError, parse_event};

use super::{extract_event_id, send_ok, validate_auth_event};

pub(crate) async fn handle_auth(
    ws: &mut WebSocket,
    auth: &mut ConnectionAuth,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() != 2 {
        send_ok(
            ws,
            "",
            false,
            "invalid: AUTH must contain exactly one event object",
        )
        .await?;
        return Ok(());
    }

    let event_id_hint = extract_event_id(values[1]);
    let event = match parse_event(values[1]) {
        Ok(event) => event,
        Err(err) => {
            send_ok(ws, &event_id_hint, false, &err).await?;
            return Ok(());
        }
    };

    match validate_auth_event(&event, auth) {
        Ok(()) => {
            auth.authenticated_pubkeys.insert(event.pubkey.clone());
            send_ok(ws, &event.id, true, "").await?;
        }
        Err(err) => {
            send_ok(ws, &event.id, false, &err).await?;
        }
    }

    Ok(())
}
