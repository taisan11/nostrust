use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use nojson::{DisplayJson, JsonFormatter, RawJson};

use crate::{EventRecord, RelayConfig, RelayState, is_better_replace_candidate};

pub(crate) fn nip05_document(
    relay: &Arc<Mutex<RelayState>>,
    relay_config: &RelayConfig,
    requested_name: &str,
    host_header: Option<&str>,
) -> Result<String, String> {
    validate_nip05_name(requested_name)?;
    let domain = if let Some(domain) = relay_config.nip05_domain.as_ref() {
        domain.clone()
    } else {
        request_host_domain(host_header)?
    };

    let state = relay
        .lock()
        .map_err(|_| "relay state lock poisoned during NIP-05 request".to_string())?;

    let mut winners: BTreeMap<String, Arc<EventRecord>> = BTreeMap::new();
    for event in state.events_by_id.values() {
        if event.kind != 0 {
            continue;
        }
        let Some((name, identifier_domain)) = event_nip05_identifier(event) else {
            continue;
        };
        if name != requested_name || identifier_domain != domain {
            continue;
        }

        match winners.get(&name) {
            Some(existing) if !is_better_replace_candidate(event, existing) => {}
            _ => {
                winners.insert(name, Arc::clone(event));
            }
        }
    }

    let names = winners
        .iter()
        .map(|(name, event)| (name.clone(), event.pubkey.clone()))
        .collect::<BTreeMap<_, _>>();
    let selected_pubkeys = names.values().cloned().collect::<BTreeSet<_>>();
    let relays = nip05_relays_for_pubkeys(&state, &selected_pubkeys);

    let doc = Nip05Document { names, relays };
    Ok(nojson::Json(&doc).to_string())
}

pub(crate) fn parse_nip05_identifier(value: &str) -> Result<(String, String), String> {
    let trimmed = value.trim();
    let (name, domain) = trimmed
        .split_once('@')
        .ok_or_else(|| "nip05 identifier must contain '@'".to_string())?;
    if name.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err("nip05 identifier must be in local-part@domain form".to_string());
    }
    validate_nip05_name(name)?;
    let domain = normalize_domain(domain)?;
    Ok((name.to_string(), domain))
}

pub(crate) fn normalize_domain(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("domain must not be empty".to_string());
    }

    let host = if let Some(stripped) = trimmed.strip_prefix('[') {
        let Some((ipv6, _)) = stripped.split_once(']') else {
            return Err("invalid Host header".to_string());
        };
        ipv6
    } else {
        trimmed.split(':').next().unwrap_or(trimmed)
    };

    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("domain must not be empty".to_string());
    }
    if normalized
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || ch == '/' || ch == '?' || ch == '@')
    {
        return Err("domain contains invalid characters".to_string());
    }
    Ok(normalized)
}

fn nip05_relays_for_pubkeys(
    state: &RelayState,
    pubkeys: &BTreeSet<String>,
) -> BTreeMap<String, Vec<String>> {
    let mut relays_by_pubkey = BTreeMap::<String, BTreeSet<String>>::new();
    for event in state.events_by_id.values() {
        if event.kind != 10002 || !pubkeys.contains(&event.pubkey) {
            continue;
        }

        for tag in &event.tags {
            if tag.first().map(String::as_str) != Some("r") {
                continue;
            }
            let Some(url) = tag.get(1) else {
                continue;
            };
            if url.is_empty() {
                continue;
            }
            relays_by_pubkey
                .entry(event.pubkey.clone())
                .or_default()
                .insert(url.clone());
        }
    }

    relays_by_pubkey
        .into_iter()
        .map(|(pubkey, urls)| (pubkey, urls.into_iter().collect()))
        .collect()
}

fn event_nip05_identifier(event: &EventRecord) -> Option<(String, String)> {
    if event.kind != 0 {
        return None;
    }

    let raw = RawJson::parse(&event.content).ok()?;
    let nip05: String = raw
        .value()
        .to_member("nip05")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.try_into().ok())?;
    parse_nip05_identifier(&nip05).ok()
}

fn validate_nip05_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if name
        .chars()
        .all(|ch| matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_' | '.'))
    {
        Ok(())
    } else {
        Err("name must contain only a-z, 0-9, '-', '_' or '.'".to_string())
    }
}

fn request_host_domain(host_header: Option<&str>) -> Result<String, String> {
    let host = host_header.ok_or_else(|| {
        "Host header is required for NIP-05 when NOSTR_NIP05_DOMAIN is unset".to_string()
    })?;
    normalize_domain(host)
}

#[derive(Debug)]
struct Nip05Document {
    names: BTreeMap<String, String>,
    relays: BTreeMap<String, Vec<String>>,
}

impl DisplayJson for Nip05Document {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            f.member("names", Nip05Names(&self.names))?;
            if !self.relays.is_empty() {
                f.member("relays", Nip05Relays(&self.relays))?;
            }
            Ok(())
        })
    }
}

struct Nip05Names<'a>(&'a BTreeMap<String, String>);

impl DisplayJson for Nip05Names<'_> {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            for (name, pubkey) in self.0 {
                f.member(name.as_str(), pubkey.as_str())?;
            }
            Ok(())
        })
    }
}

struct Nip05Relays<'a>(&'a BTreeMap<String, Vec<String>>);

impl DisplayJson for Nip05Relays<'_> {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            for (pubkey, relays) in self.0 {
                f.member(pubkey.as_str(), relays)?;
            }
            Ok(())
        })
    }
}
