use std::collections::HashMap;

use nojson::RawJsonValue;

use crate::{DynError, Filter};

pub(crate) fn handle_close(
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    values: &[RawJsonValue<'_, '_>],
) -> Result<(), DynError> {
    if values.len() < 2 {
        return Ok(());
    }

    let sub_id: String = match values[1].try_into() {
        Ok(sub_id) => sub_id,
        Err(_) => return Ok(()),
    };

    subscriptions.remove(&sub_id);
    Ok(())
}
