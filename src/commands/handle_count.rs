use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use nojson::RawJsonValue;
use tokio_tungstenite::tungstenite::protocol::WebSocket;

use crate::{DynError, RelayState};

use super::{
    count_matching_events, parse_filter, send_closed, send_count, send_notice,
    validate_subscription_id,
};

pub(crate) fn handle_count(
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
