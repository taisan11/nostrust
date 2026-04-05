use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::ws::WebSocket;
use nojson::RawJsonValue;

use crate::{ConnectionAuth, DynError, Filter, RelayState};

use super::{
    parse_filter, query_initial_events_for_auth, send_closed, send_eose, send_event, send_notice,
    subscription_is_complete, validate_subscription_id,
};

pub(crate) async fn handle_req(
    ws: &mut WebSocket,
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    relay: &Arc<Mutex<RelayState>>,
    auth: &ConnectionAuth,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() < 2 {
        send_notice(ws, "invalid: REQ must include a subscription id").await?;
        return Ok(());
    }

    let sub_id: String = match values[1].try_into() {
        Ok(sub_id) => sub_id,
        Err(_) => {
            send_notice(ws, "invalid: subscription id must be a string").await?;
            return Ok(());
        }
    };

    if let Err(err) = validate_subscription_id(&sub_id) {
        send_closed(ws, &sub_id, &err).await?;
        return Ok(());
    }

    if values.len() < 3 {
        send_closed(ws, &sub_id, "invalid: REQ must include at least one filter").await?;
        return Ok(());
    }

    let mut filters = Vec::new();
    for raw_filter in values.iter().skip(2) {
        match parse_filter(*raw_filter) {
            Ok(filter) => filters.push(filter),
            Err(err) => {
                send_closed(ws, &sub_id, &err).await?;
                return Ok(());
            }
        }
    }

    subscriptions.insert(sub_id.clone(), filters.clone());

    let initial_events = {
        let state = relay
            .lock()
            .map_err(|_| "error: relay state lock poisoned during REQ")?;
        query_initial_events_for_auth(&state, &filters, auth)
    };

    for event in initial_events {
        send_event(ws, &sub_id, &event).await?;
    }

    send_eose(ws, &sub_id).await?;
    if subscription_is_complete(&filters) {
        subscriptions.remove(&sub_id);
        send_closed(ws, &sub_id, "closed: complete").await?;
    }
    Ok(())
}
