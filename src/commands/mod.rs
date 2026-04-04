mod handle_auth;
mod handle_close;
mod handle_count;
mod handle_event;
mod handle_req;
mod ingress;
mod io;
mod query;
mod submission;

pub(crate) use handle_auth::handle_auth;
pub(crate) use handle_close::handle_close;
pub(crate) use handle_count::handle_count;
pub(crate) use handle_event::handle_event;
pub(crate) use handle_req::handle_req;
pub(crate) use ingress::NegentropySessions;
pub(crate) use ingress::{FrameContext, forward_live_events, handle_text_frame};
pub(crate) use io::{
    send_auth_challenge, send_closed, send_count, send_eose, send_event, send_notice, send_ok,
};
#[cfg(test)]
pub(crate) use query::{
    count_matching_events, event_matches_filter, query_initial_events, search_score,
};
pub(crate) use query::{
    count_matching_events_for_auth, extract_event_id, matches_any_filter_for_auth, parse_filter,
    query_initial_events_for_auth, subscription_is_complete, validate_subscription_id,
};
pub(crate) use submission::{
    event_has_protected_tag, handle_parsed_event_submission, validate_auth_event,
};
