use std::net::TcpStream;

use nojson::RawJsonValue;
use tokio_tungstenite::tungstenite::protocol::WebSocket;

use crate::{ConnectionAuth, DynError, parse_event};

use super::{extract_event_id, send_ok, validate_auth_event};

pub(crate) fn handle_auth(
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
