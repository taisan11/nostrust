use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nojson::RawJsonValue;

use crate::{
    ConnectionAuth, EventRecord, Filter, KindClass, RelayState, classify_kind,
    current_unix_timestamp, is_event_expired, is_lower_hex_of_len, is_tag_filter_key,
};

pub(crate) fn parse_filter(value: RawJsonValue<'_, '_>) -> Result<Filter, String> {
    let mut filter = Filter::default();

    for (key_raw, val) in value.to_object().map_err(|e| format!("invalid: {e}"))? {
        let key: String = key_raw.try_into().map_err(|e| format!("invalid: {e}"))?;

        match key.as_str() {
            "ids" => {
                filter.ids = Some(parse_string_array(val, true)?);
                validate_hex_list(filter.ids.as_ref().expect("set by line above"), 64, "ids")?;
            }
            "authors" => {
                filter.authors = Some(parse_string_array(val, true)?);
                validate_hex_list(
                    filter.authors.as_ref().expect("set by line above"),
                    64,
                    "authors",
                )?;
            }
            "kinds" => {
                let mut kinds = Vec::new();
                let mut iter = val.to_array().map_err(|e| format!("invalid: {e}"))?;
                let mut saw_any = false;

                for raw_kind in &mut iter {
                    saw_any = true;
                    let kind: u64 = raw_kind.try_into().map_err(|e| format!("invalid: {e}"))?;
                    if kind > 65535 {
                        return Err("invalid: filter kinds must be 0..65535".to_string());
                    }
                    kinds.push(kind);
                }

                if !saw_any {
                    return Err("invalid: filter arrays must not be empty".to_string());
                }

                filter.kinds = Some(kinds);
            }
            "search" => {
                let search: String = val.try_into().map_err(|e| format!("invalid: {e}"))?;
                filter.search = Some(search);
            }
            "since" => {
                let since: i64 = val.try_into().map_err(|e| format!("invalid: {e}"))?;
                if since < 0 {
                    return Err("invalid: since must be >= 0".to_string());
                }
                filter.since = Some(since);
            }
            "until" => {
                let until: i64 = val.try_into().map_err(|e| format!("invalid: {e}"))?;
                if until < 0 {
                    return Err("invalid: until must be >= 0".to_string());
                }
                filter.until = Some(until);
            }
            "limit" => {
                let limit_raw: u64 = val.try_into().map_err(|e| format!("invalid: {e}"))?;
                let limit = usize::try_from(limit_raw)
                    .map_err(|_| "invalid: limit is too large for this relay".to_string())?;
                filter.limit = Some(limit);
            }
            _ if is_tag_filter_key(&key) => {
                let letter = key.chars().nth(1).expect("#x has second char");
                let values = parse_string_array(val, true)?;

                if letter == 'e' || letter == 'p' {
                    validate_hex_list(&values, 64, "tag values")?;
                }

                filter.tag_values.insert(letter, values);
            }
            _ => return Err("unsupported: filter contains unknown elements".to_string()),
        }
    }

    if let (Some(since), Some(until)) = (filter.since, filter.until)
        && since > until
    {
        return Err("invalid: since must be <= until".to_string());
    }

    Ok(filter)
}

fn parse_string_array(value: RawJsonValue<'_, '_>, non_empty: bool) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut iter = value.to_array().map_err(|e| format!("invalid: {e}"))?;

    let mut saw_any = false;
    for entry in &mut iter {
        saw_any = true;
        let s: String = entry.try_into().map_err(|e| format!("invalid: {e}"))?;
        out.push(s);
    }

    if non_empty && !saw_any {
        return Err("invalid: filter arrays must not be empty".to_string());
    }

    Ok(out)
}

fn validate_hex_list(values: &[String], len: usize, field_name: &str) -> Result<(), String> {
    if values.iter().all(|v| is_lower_hex_of_len(v, len)) {
        Ok(())
    } else {
        Err(format!(
            "invalid: {field_name} must contain exact {len}-char lowercase hex values"
        ))
    }
}

pub(crate) fn validate_subscription_id(sub_id: &str) -> Result<(), String> {
    if sub_id.is_empty() {
        return Err("invalid: subscription id must not be empty".to_string());
    }

    if sub_id.len() > 64 {
        return Err("invalid: subscription id max length is 64".to_string());
    }

    Ok(())
}

pub(crate) fn extract_event_id(value: RawJsonValue<'_, '_>) -> String {
    value
        .to_member("id")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.try_into().ok())
        .unwrap_or_default()
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn query_initial_events(
    state: &RelayState,
    filters: &[Filter],
) -> Vec<Arc<EventRecord>> {
    query_initial_events_inner(state, filters, None)
}

fn query_initial_events_inner(
    state: &RelayState,
    filters: &[Filter],
    auth: Option<&ConnectionAuth>,
) -> Vec<Arc<EventRecord>> {
    let now = current_unix_timestamp();
    let parsed_search_terms = parsed_search_terms_for_filters(filters);
    let mut selected: HashMap<String, Arc<EventRecord>> = HashMap::new();

    for (filter, search_terms) in filters.iter().zip(parsed_search_terms.iter()) {
        let mut matching = Vec::new();
        for_each_filter_candidate(state, filter, |event| {
            if event_matches_initial_query(event, state, filter, search_terms.as_deref(), auth, now)
            {
                matching.push(Arc::clone(event));
            }
        });

        matching.sort_by(|a, b| compare_events_for_filter(search_terms.as_deref(), a, b));

        if let Some(limit) = filter.limit {
            matching.truncate(limit);
        }

        for event in matching {
            selected.entry(event.id.clone()).or_insert(event);
        }
    }

    let mut out = selected.into_values().collect::<Vec<_>>();
    if parsed_search_terms.iter().any(Option::is_some) {
        out.sort_by(|a, b| compare_events_for_filters(&parsed_search_terms, a, b));
    } else {
        out.sort_by(compare_events_desc);
    }
    out
}

pub(crate) fn query_initial_events_for_auth(
    state: &RelayState,
    filters: &[Filter],
    auth: &ConnectionAuth,
) -> Vec<Arc<EventRecord>> {
    query_initial_events_inner(state, filters, Some(auth))
}

fn compare_events_desc(a: &Arc<EventRecord>, b: &Arc<EventRecord>) -> Ordering {
    b.created_at
        .cmp(&a.created_at)
        .then_with(|| a.id.cmp(&b.id))
}

fn compare_events_for_filter(
    search_terms: Option<&[String]>,
    a: &Arc<EventRecord>,
    b: &Arc<EventRecord>,
) -> Ordering {
    if let Some(search_terms) = search_terms {
        let a_score = search_score_for_terms(a, search_terms).unwrap_or(0);
        let b_score = search_score_for_terms(b, search_terms).unwrap_or(0);
        b_score
            .cmp(&a_score)
            .then_with(|| compare_events_desc(a, b))
    } else {
        compare_events_desc(a, b)
    }
}

fn compare_events_for_filters(
    parsed_search_terms: &[Option<Vec<String>>],
    a: &Arc<EventRecord>,
    b: &Arc<EventRecord>,
) -> Ordering {
    let a_score = combined_search_score(a, parsed_search_terms);
    let b_score = combined_search_score(b, parsed_search_terms);
    b_score
        .cmp(&a_score)
        .then_with(|| compare_events_desc(a, b))
}

fn combined_search_score(
    event: &EventRecord,
    parsed_search_terms: &[Option<Vec<String>>],
) -> usize {
    parsed_search_terms
        .iter()
        .filter_map(|search_terms| {
            search_terms
                .as_deref()
                .and_then(|terms| search_score_for_terms(event, terms))
        })
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn count_matching_events(state: &RelayState, filters: &[Filter]) -> usize {
    count_matching_events_inner(state, filters, None)
}

fn count_matching_events_inner(
    state: &RelayState,
    filters: &[Filter],
    auth: Option<&ConnectionAuth>,
) -> usize {
    let now = current_unix_timestamp();
    let parsed_search_terms = parsed_search_terms_for_filters(filters);
    let mut selected = HashSet::new();

    for (filter, search_terms) in filters.iter().zip(parsed_search_terms.iter()) {
        for_each_filter_candidate(state, filter, |event| {
            if event_matches_initial_query(event, state, filter, search_terms.as_deref(), auth, now)
            {
                selected.insert(event.id.clone());
            }
        });
    }

    selected.len()
}

pub(crate) fn count_matching_events_for_auth(
    state: &RelayState,
    filters: &[Filter],
    auth: &ConnectionAuth,
) -> usize {
    count_matching_events_inner(state, filters, Some(auth))
}

fn for_each_filter_candidate(
    state: &RelayState,
    filter: &Filter,
    mut visit: impl FnMut(&Arc<EventRecord>),
) {
    if let Some(ids) = &filter.ids {
        for id in ids {
            if let Some(event) = state
                .events_by_id
                .get(id)
                .or_else(|| state.archived_events_by_id.get(id))
            {
                visit(event);
            }
        }
        return;
    }

    for event in state.events_by_id.values() {
        visit(event);
    }
}

fn event_matches_initial_query(
    event: &EventRecord,
    state: &RelayState,
    filter: &Filter,
    search_terms: Option<&[String]>,
    auth: Option<&ConnectionAuth>,
    now: i64,
) -> bool {
    !state.deleted_event_ids.contains(&event.id)
        && !state.banned_events.contains_key(&event.id)
        && !state.banned_pubkeys.contains_key(&event.pubkey)
        && (state.allowed_pubkeys.is_empty() || state.allowed_pubkeys.contains_key(&event.pubkey))
        && (state.allowed_kinds.is_empty() || state.allowed_kinds.contains(&event.kind))
        && !event_blocked_by_address_tombstone(event, &state.deleted_addresses)
        && (filter.ids.is_some() || !event_is_superseded(event, state))
        && !is_event_expired(event, now)
        && event_matches_filter_with_search_terms(event, filter, search_terms)
        && auth.is_none_or(|auth| event_visible_to_auth(event, auth))
}

fn event_blocked_by_address_tombstone(
    event: &EventRecord,
    deleted_addresses: &HashMap<(u64, String, String), i64>,
) -> bool {
    if !matches!(
        classify_kind(event.kind),
        KindClass::Replaceable | KindClass::Addressable
    ) {
        return false;
    }

    let key = (event.kind, event.pubkey.clone(), event.d_tag_value());
    deleted_addresses
        .get(&key)
        .is_some_and(|delete_ts| event.created_at <= *delete_ts)
}

fn event_is_superseded(event: &EventRecord, state: &RelayState) -> bool {
    match classify_kind(event.kind) {
        KindClass::Replaceable => {
            let key = (event.pubkey.clone(), event.kind);
            state
                .replaceable_index
                .get(&key)
                .is_some_and(|active_id| active_id != &event.id)
        }
        KindClass::Addressable => {
            let key = (event.kind, event.pubkey.clone(), event.d_tag_value());
            state
                .addressable_index
                .get(&key)
                .is_some_and(|active_id| active_id != &event.id)
        }
        KindClass::RegularOrOther | KindClass::Ephemeral => false,
    }
}

pub(crate) fn subscription_is_complete(filters: &[Filter]) -> bool {
    filters.iter().all(|filter| filter.ids.is_some())
}

pub(crate) fn matches_any_filter(event: &EventRecord, filters: &[Filter]) -> bool {
    filters
        .iter()
        .any(|filter| event_matches_filter(event, filter))
}

pub(crate) fn matches_any_filter_for_auth(
    event: &EventRecord,
    filters: &[Filter],
    auth: &ConnectionAuth,
) -> bool {
    event_visible_to_auth(event, auth) && matches_any_filter(event, filters)
}

pub(crate) fn event_visible_to_auth(event: &EventRecord, auth: &ConnectionAuth) -> bool {
    if event.kind != 1059 {
        return true;
    }

    event.tags.iter().any(|tag| {
        tag.first().map(String::as_str) == Some("p")
            && tag
                .get(1)
                .is_some_and(|pubkey| auth.is_authenticated(pubkey))
    })
}

pub(crate) fn event_matches_filter(event: &EventRecord, filter: &Filter) -> bool {
    let search_terms = filter.search.as_deref().map(parsed_search_terms_from_query);
    event_matches_filter_with_search_terms(event, filter, search_terms.as_deref())
}

fn event_matches_filter_with_search_terms(
    event: &EventRecord,
    filter: &Filter,
    search_terms: Option<&[String]>,
) -> bool {
    if let Some(ids) = &filter.ids
        && !ids.iter().any(|id| id == &event.id)
    {
        return false;
    }

    if let Some(authors) = &filter.authors
        && !authors.iter().any(|author| author == &event.pubkey)
    {
        return false;
    }

    if let Some(kinds) = &filter.kinds
        && !kinds.iter().any(|kind| kind == &event.kind)
    {
        return false;
    }

    if let Some(since) = filter.since
        && event.created_at < since
    {
        return false;
    }

    if let Some(until) = filter.until
        && event.created_at > until
    {
        return false;
    }

    for (tag_name, wanted_values) in &filter.tag_values {
        let mut matched = false;
        let tag_name_str = tag_name.to_string();

        for tag in &event.tags {
            if tag.first().map(String::as_str) != Some(tag_name_str.as_str()) {
                continue;
            }

            if let Some(value) = tag.get(1)
                && wanted_values.iter().any(|wanted| wanted == value)
            {
                matched = true;
                break;
            }
        }

        if !matched {
            return false;
        }
    }

    if filter.search.is_some() {
        if let Some(search_terms) = search_terms {
            if search_score_for_terms(event, search_terms).is_none() {
                return false;
            }
        } else {
            return false;
        }
    }

    true
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn search_score(event: &EventRecord, query: &str) -> Option<usize> {
    let terms = parsed_search_terms_from_query(query);
    search_score_for_terms(event, &terms)
}

fn search_score_for_terms(event: &EventRecord, terms: &[String]) -> Option<usize> {
    if terms.is_empty() {
        return Some(0);
    }

    let content = event.content.to_lowercase();
    let score = terms
        .iter()
        .map(|term| content.match_indices(term).count())
        .sum::<usize>();

    if score == 0 { None } else { Some(score) }
}

fn parsed_search_terms_for_filters(filters: &[Filter]) -> Vec<Option<Vec<String>>> {
    filters
        .iter()
        .map(|filter| filter.search.as_deref().map(parsed_search_terms_from_query))
        .collect()
}

fn parsed_search_terms_from_query(query: &str) -> Vec<String> {
    query
        .split_whitespace()
        .filter(|term| !term.contains(':'))
        .map(|term| term.to_lowercase())
        .filter(|term| !term.is_empty())
        .collect()
}
