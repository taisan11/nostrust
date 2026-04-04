use std::sync::{Arc, Mutex};

use axum::extract::ws::WebSocket;
use nojson::RawJsonValue;

use crate::{
    ConnectionAuth, DynError, EventStore, RelayConfig, RelayState, build_raw_serialized_event_data,
    parse_event_with_options,
};

use super::{extract_event_id, handle_parsed_event_submission, send_ok};

pub(crate) async fn handle_event(
    ws: &mut WebSocket,
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
        )
        .await?;
        return Ok(());
    }

    let event_id_hint = extract_event_id(values[1]);
    let raw_serialized = match build_raw_serialized_event_data(values[1].as_raw_str()) {
        Ok(v) => v,
        Err(err) => {
            send_ok(ws, &event_id_hint, false, &err).await?;
            return Ok(());
        }
    };
    let event = match parse_event_with_options(values[1], false, Some(&raw_serialized)) {
        Ok(event) => event,
        Err(err) => {
            send_ok(ws, &event_id_hint, false, &err).await?;
            return Ok(());
        }
    };

    handle_parsed_event_submission(
        ws,
        relay,
        event_store,
        relay_config,
        auth,
        event,
        &event_id_hint,
    )
    .await
}
