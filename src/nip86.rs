use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use nojson::{DisplayJson, JsonFormatter, RawJson, RawJsonValue};
use sha2::{Digest, Sha256};

use crate::{EventRecord, RelayConfig, RelayState, current_unix_timestamp, parse_event};

#[derive(Debug, Clone)]
pub(crate) struct HttpRequest {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: std::collections::BTreeMap<String, String>,
}

#[derive(Debug)]
pub(crate) enum Nip86HttpError {
    Unauthorized(String),
    BadRequest(String),
    Internal(String),
}

#[derive(Debug)]
enum Nip86Result {
    Bool(bool),
    Methods(Vec<String>),
    Pubkeys(Vec<PubkeyReasonEntry>),
    Events(Vec<EventReasonEntry>),
    Ips(Vec<IpReasonEntry>),
    Kinds(Vec<u64>),
}

impl DisplayJson for Nip86Result {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        match self {
            Nip86Result::Bool(v) => f.value(*v),
            Nip86Result::Methods(values) => f.value(values),
            Nip86Result::Pubkeys(values) => f.value(values),
            Nip86Result::Events(values) => f.value(values),
            Nip86Result::Ips(values) => f.value(values),
            Nip86Result::Kinds(values) => f.value(values),
        }
    }
}

#[derive(Debug, Clone)]
struct PubkeyReasonEntry {
    pubkey: String,
    reason: String,
}

impl DisplayJson for PubkeyReasonEntry {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            f.member("pubkey", &self.pubkey)?;
            if !self.reason.is_empty() {
                f.member("reason", &self.reason)?;
            }
            Ok(())
        })
    }
}

#[derive(Debug, Clone)]
struct EventReasonEntry {
    id: String,
    reason: String,
}

impl DisplayJson for EventReasonEntry {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            f.member("id", &self.id)?;
            if !self.reason.is_empty() {
                f.member("reason", &self.reason)?;
            }
            Ok(())
        })
    }
}

#[derive(Debug, Clone)]
struct IpReasonEntry {
    ip: String,
    reason: String,
}

impl DisplayJson for IpReasonEntry {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            f.member("ip", &self.ip)?;
            if !self.reason.is_empty() {
                f.member("reason", &self.reason)?;
            }
            Ok(())
        })
    }
}

pub(crate) fn nip86_response_json(result: bool, error: Option<String>) -> String {
    nojson::json(|f| {
        f.object(|f| {
            f.member("result", result)?;
            if let Some(error) = error.as_ref() {
                f.member("error", error)?;
            }
            Ok(())
        })
    })
    .to_string()
}

fn supported_nip86_methods() -> Vec<String> {
    [
        "supportedmethods",
        "banpubkey",
        "unbanpubkey",
        "listbannedpubkeys",
        "allowpubkey",
        "unallowpubkey",
        "listallowedpubkeys",
        "listeventsneedingmoderation",
        "allowevent",
        "banevent",
        "listbannedevents",
        "changerelayname",
        "changerelaydescription",
        "changerelayicon",
        "allowkind",
        "disallowkind",
        "listallowedkinds",
        "blockip",
        "unblockip",
        "listblockedips",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

pub(crate) fn handle_nip86_http_request(
    relay: &Arc<Mutex<RelayState>>,
    relay_config: &RelayConfig,
    request: &HttpRequest,
    body: &str,
) -> Result<String, Nip86HttpError> {
    validate_nip98_authorization(relay_config, request, body)?;

    let raw = RawJson::parse(body).map_err(|e| Nip86HttpError::BadRequest(format!("{e}")))?;
    let method: String = raw
        .value()
        .to_member("method")
        .map_err(|_| Nip86HttpError::BadRequest("method is required".to_string()))?
        .required()
        .map_err(|_| Nip86HttpError::BadRequest("method is required".to_string()))?
        .try_into()
        .map_err(|_| Nip86HttpError::BadRequest("method must be a string".to_string()))?;
    let params_raw = raw
        .value()
        .to_member("params")
        .map_err(|_| Nip86HttpError::BadRequest("params is required".to_string()))?
        .required()
        .map_err(|_| Nip86HttpError::BadRequest("params is required".to_string()))?;
    let params = params_raw
        .to_array()
        .map_err(|_| Nip86HttpError::BadRequest("params must be an array".to_string()))?
        .collect::<Vec<_>>();

    let result = apply_nip86_method(relay, &method, &params)?;
    Ok(nip86_result_json(result, None))
}

fn validate_nip98_authorization(
    relay_config: &RelayConfig,
    request: &HttpRequest,
    body: &str,
) -> Result<(), Nip86HttpError> {
    let auth_header = request
        .headers
        .get("authorization")
        .ok_or_else(|| Nip86HttpError::Unauthorized("missing Authorization header".to_string()))?;
    let Some(encoded) = auth_header.strip_prefix("Nostr ") else {
        return Err(Nip86HttpError::Unauthorized(
            "Authorization header must use Nostr scheme".to_string(),
        ));
    };

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded.trim()))
        .map_err(|_| {
            Nip86HttpError::Unauthorized("Authorization event is not valid base64".to_string())
        })?;
    let event_text = String::from_utf8(decoded).map_err(|_| {
        Nip86HttpError::Unauthorized("Authorization event must be UTF-8 JSON".to_string())
    })?;
    let raw = RawJson::parse(&event_text).map_err(|_| {
        Nip86HttpError::Unauthorized("Authorization event is not valid JSON".to_string())
    })?;
    let event = parse_event(raw.value())
        .map_err(|_| Nip86HttpError::Unauthorized("Authorization event is invalid".to_string()))?;

    if event.kind != 27235 {
        return Err(Nip86HttpError::Unauthorized(
            "Authorization event kind must be 27235".to_string(),
        ));
    }

    let now = current_unix_timestamp();
    if (event.created_at - now).abs() > 60 {
        return Err(Nip86HttpError::Unauthorized(
            "Authorization event created_at is outside allowed window".to_string(),
        ));
    }

    let method_tag = first_tag_value(&event, "method").ok_or_else(|| {
        Nip86HttpError::Unauthorized("Authorization event missing method tag".to_string())
    })?;
    if method_tag != request.method {
        return Err(Nip86HttpError::Unauthorized(
            "Authorization event method tag mismatch".to_string(),
        ));
    }

    let expected_request_url = request
        .headers
        .get("host")
        .map(|host| format!("http://{}{}", host.trim(), request.target))
        .unwrap_or_else(|| relay_config.relay_url.replace("ws://", "http://"));
    let u_tag = first_tag_value(&event, "u").ok_or_else(|| {
        Nip86HttpError::Unauthorized("Authorization event missing u tag".to_string())
    })?;
    if u_tag != relay_config.relay_url && u_tag != expected_request_url {
        return Err(Nip86HttpError::Unauthorized(
            "Authorization event u tag mismatch".to_string(),
        ));
    }

    let payload_tag = first_tag_value(&event, "payload").ok_or_else(|| {
        Nip86HttpError::Unauthorized("Authorization event missing payload tag".to_string())
    })?;
    let payload_hash = hex_sha256(body.as_bytes());
    if payload_tag != payload_hash {
        return Err(Nip86HttpError::Unauthorized(
            "Authorization event payload tag mismatch".to_string(),
        ));
    }

    Ok(())
}

fn apply_nip86_method(
    relay: &Arc<Mutex<RelayState>>,
    method: &str,
    params: &[RawJsonValue<'_, '_>],
) -> Result<Nip86Result, Nip86HttpError> {
    match method {
        "supportedmethods" => {
            if !params.is_empty() {
                return Err(Nip86HttpError::BadRequest(
                    "supportedmethods expects [] params".to_string(),
                ));
            }
            Ok(Nip86Result::Methods(supported_nip86_methods()))
        }
        "banpubkey" => {
            let (pubkey, reason) = parse_pubkey_with_reason(params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.banned_pubkeys.insert(pubkey, reason);
            Ok(Nip86Result::Bool(true))
        }
        "unbanpubkey" => {
            let (pubkey, _) = parse_pubkey_with_reason(params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.banned_pubkeys.remove(&pubkey);
            Ok(Nip86Result::Bool(true))
        }
        "listbannedpubkeys" => {
            ensure_empty_params(method, params)?;
            let state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            let out = state
                .banned_pubkeys
                .iter()
                .map(|(pubkey, reason)| PubkeyReasonEntry {
                    pubkey: pubkey.clone(),
                    reason: reason.clone(),
                })
                .collect();
            Ok(Nip86Result::Pubkeys(out))
        }
        "allowpubkey" => {
            let (pubkey, reason) = parse_pubkey_with_reason(params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.allowed_pubkeys.insert(pubkey, reason);
            Ok(Nip86Result::Bool(true))
        }
        "unallowpubkey" => {
            let (pubkey, _) = parse_pubkey_with_reason(params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.allowed_pubkeys.remove(&pubkey);
            Ok(Nip86Result::Bool(true))
        }
        "listallowedpubkeys" => {
            ensure_empty_params(method, params)?;
            let state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            let out = state
                .allowed_pubkeys
                .iter()
                .map(|(pubkey, reason)| PubkeyReasonEntry {
                    pubkey: pubkey.clone(),
                    reason: reason.clone(),
                })
                .collect();
            Ok(Nip86Result::Pubkeys(out))
        }
        "listeventsneedingmoderation" => {
            ensure_empty_params(method, params)?;
            Ok(Nip86Result::Events(Vec::new()))
        }
        "allowevent" => {
            let (event_id, _) = parse_event_id_with_reason(params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.banned_events.remove(&event_id);
            Ok(Nip86Result::Bool(true))
        }
        "banevent" => {
            let (event_id, reason) = parse_event_id_with_reason(params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.banned_events.insert(event_id, reason);
            Ok(Nip86Result::Bool(true))
        }
        "listbannedevents" => {
            ensure_empty_params(method, params)?;
            let state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            let out = state
                .banned_events
                .iter()
                .map(|(id, reason)| EventReasonEntry {
                    id: id.clone(),
                    reason: reason.clone(),
                })
                .collect();
            Ok(Nip86Result::Events(out))
        }
        "changerelayname" => {
            let value = parse_single_string_param(method, params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.relay_name = value;
            Ok(Nip86Result::Bool(true))
        }
        "changerelaydescription" => {
            let value = parse_single_string_param(method, params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.relay_description = value;
            Ok(Nip86Result::Bool(true))
        }
        "changerelayicon" => {
            let value = parse_single_string_param(method, params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.relay_icon = value;
            Ok(Nip86Result::Bool(true))
        }
        "allowkind" => {
            let kind = parse_single_kind_param(method, params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.allowed_kinds.insert(kind);
            Ok(Nip86Result::Bool(true))
        }
        "disallowkind" => {
            let kind = parse_single_kind_param(method, params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.allowed_kinds.remove(&kind);
            Ok(Nip86Result::Bool(true))
        }
        "listallowedkinds" => {
            ensure_empty_params(method, params)?;
            let state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            Ok(Nip86Result::Kinds(
                state.allowed_kinds.iter().copied().collect(),
            ))
        }
        "blockip" => {
            let (ip, reason) = parse_ip_with_reason(params)?;
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.blocked_ips.insert(ip, reason);
            Ok(Nip86Result::Bool(true))
        }
        "unblockip" => {
            let ip = parse_single_string_param(method, params)?;
            if ip.parse::<IpAddr>().is_err() {
                return Err(Nip86HttpError::BadRequest(
                    "unblockip first param must be an IP address".to_string(),
                ));
            }
            let mut state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            state.blocked_ips.remove(&ip);
            Ok(Nip86Result::Bool(true))
        }
        "listblockedips" => {
            ensure_empty_params(method, params)?;
            let state = relay
                .lock()
                .map_err(|_| Nip86HttpError::Internal("relay state lock poisoned".to_string()))?;
            let out = state
                .blocked_ips
                .iter()
                .map(|(ip, reason)| IpReasonEntry {
                    ip: ip.clone(),
                    reason: reason.clone(),
                })
                .collect();
            Ok(Nip86Result::Ips(out))
        }
        _ => Err(Nip86HttpError::BadRequest(format!(
            "unsupported method: {method}"
        ))),
    }
}

fn nip86_result_json(result: Nip86Result, error: Option<String>) -> String {
    nojson::json(|f| {
        f.object(|f| {
            f.member("result", &result)?;
            if let Some(error) = error.as_ref() {
                f.member("error", error)?;
            }
            Ok(())
        })
    })
    .to_string()
}

fn ensure_empty_params(
    method: &str,
    params: &[RawJsonValue<'_, '_>],
) -> Result<(), Nip86HttpError> {
    if params.is_empty() {
        Ok(())
    } else {
        Err(Nip86HttpError::BadRequest(format!(
            "{method} expects [] params"
        )))
    }
}

fn parse_single_string_param(
    method: &str,
    params: &[RawJsonValue<'_, '_>],
) -> Result<String, Nip86HttpError> {
    if params.len() != 1 {
        return Err(Nip86HttpError::BadRequest(format!(
            "{method} expects exactly one string param"
        )));
    }
    params[0]
        .try_into()
        .map_err(|_| Nip86HttpError::BadRequest(format!("{method} param must be a string")))
}

fn parse_single_kind_param(
    method: &str,
    params: &[RawJsonValue<'_, '_>],
) -> Result<u64, Nip86HttpError> {
    if params.len() != 1 {
        return Err(Nip86HttpError::BadRequest(format!(
            "{method} expects exactly one numeric kind param"
        )));
    }
    let kind: u64 = params[0]
        .try_into()
        .map_err(|_| Nip86HttpError::BadRequest(format!("{method} param must be a number")))?;
    if kind > 65535 {
        return Err(Nip86HttpError::BadRequest(
            "kind must be between 0 and 65535".to_string(),
        ));
    }
    Ok(kind)
}

fn parse_pubkey_with_reason(
    params: &[RawJsonValue<'_, '_>],
) -> Result<(String, String), Nip86HttpError> {
    if params.is_empty() || params.len() > 2 {
        return Err(Nip86HttpError::BadRequest(
            "method expects [\"<pubkey>\", \"<optional-reason>\"]".to_string(),
        ));
    }
    let pubkey: String = params[0]
        .try_into()
        .map_err(|_| Nip86HttpError::BadRequest("pubkey must be a string".to_string()))?;
    if !crate::is_lower_hex_of_len(&pubkey, 64) {
        return Err(Nip86HttpError::BadRequest(
            "pubkey must be 64-char lowercase hex".to_string(),
        ));
    }
    let reason = if params.len() == 2 {
        params[1]
            .try_into()
            .map_err(|_| Nip86HttpError::BadRequest("reason must be a string".to_string()))?
    } else {
        String::new()
    };
    Ok((pubkey, reason))
}

fn parse_event_id_with_reason(
    params: &[RawJsonValue<'_, '_>],
) -> Result<(String, String), Nip86HttpError> {
    if params.is_empty() || params.len() > 2 {
        return Err(Nip86HttpError::BadRequest(
            "method expects [\"<event-id>\", \"<optional-reason>\"]".to_string(),
        ));
    }
    let event_id: String = params[0]
        .try_into()
        .map_err(|_| Nip86HttpError::BadRequest("event id must be a string".to_string()))?;
    if !crate::is_lower_hex_of_len(&event_id, 64) {
        return Err(Nip86HttpError::BadRequest(
            "event id must be 64-char lowercase hex".to_string(),
        ));
    }
    let reason = if params.len() == 2 {
        params[1]
            .try_into()
            .map_err(|_| Nip86HttpError::BadRequest("reason must be a string".to_string()))?
    } else {
        String::new()
    };
    Ok((event_id, reason))
}

fn parse_ip_with_reason(
    params: &[RawJsonValue<'_, '_>],
) -> Result<(String, String), Nip86HttpError> {
    if params.is_empty() || params.len() > 2 {
        return Err(Nip86HttpError::BadRequest(
            "blockip expects [\"<ip-address>\", \"<optional-reason>\"]".to_string(),
        ));
    }
    let ip: String = params[0]
        .try_into()
        .map_err(|_| Nip86HttpError::BadRequest("ip must be a string".to_string()))?;
    if ip.parse::<IpAddr>().is_err() {
        return Err(Nip86HttpError::BadRequest(
            "ip must be a valid IPv4 or IPv6 address".to_string(),
        ));
    }
    let reason = if params.len() == 2 {
        params[1]
            .try_into()
            .map_err(|_| Nip86HttpError::BadRequest("reason must be a string".to_string()))?
    } else {
        String::new()
    };
    Ok((ip, reason))
}

fn first_tag_value<'a>(event: &'a EventRecord, tag_name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some(tag_name))
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}
