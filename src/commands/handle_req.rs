use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use nojson::RawJsonValue;
use tokio_tungstenite::tungstenite::protocol::WebSocket;

use crate::{DynError, Filter, RelayState};

use super::{
    parse_filter, query_initial_events, send_closed, send_eose, send_event, send_notice,
    subscription_is_complete, validate_subscription_id,
};

pub(crate) fn handle_req(
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
