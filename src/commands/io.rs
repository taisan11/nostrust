use std::net::TcpStream;

use tokio_tungstenite::tungstenite::protocol::WebSocket;
use tokio_tungstenite::tungstenite::Message;

use crate::{CountPayload, DynError, EventRecord};

pub(crate) fn send_event(
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

pub(crate) fn send_ok(
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

pub(crate) fn send_eose(ws: &mut WebSocket<TcpStream>, sub_id: &str) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("EOSE")?;
        f.element(sub_id)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

pub(crate) fn send_closed(
    ws: &mut WebSocket<TcpStream>,
    sub_id: &str,
    message: &str,
) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("CLOSED")?;
        f.element(sub_id)?;
        f.element(message)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

pub(crate) fn send_count(
    ws: &mut WebSocket<TcpStream>,
    query_id: &str,
    count: usize,
) -> Result<(), DynError> {
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

pub(crate) fn send_notice(ws: &mut WebSocket<TcpStream>, message: &str) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("NOTICE")?;
        f.element(message)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}

pub(crate) fn send_auth_challenge(
    ws: &mut WebSocket<TcpStream>,
    challenge: &str,
) -> Result<(), DynError> {
    let frame = nojson::array(|f| {
        f.element("AUTH")?;
        f.element(challenge)
    })
    .to_string();

    ws.send(Message::text(frame))?;
    Ok(())
}
