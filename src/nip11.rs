use std::sync::{Arc, Mutex};

use nojson::{DisplayJson, JsonFormatter};

use crate::{RelayConfig, RelayState};

pub(crate) fn relay_info_document(
    relay: &Arc<Mutex<RelayState>>,
    relay_config: &RelayConfig,
) -> Result<String, String> {
    let state = relay
        .lock()
        .map_err(|_| "relay state lock poisoned during relay info request".to_string())?;
    let supported_nips = vec![
        1u64, 4, 5, 9, 11, 13, 17, 26, 29, 40, 42, 43, 45, 50, 57, 59, 62, 65, 66, 70, 77, 86, 94,
        96,
    ];
    let limitations = RelayLimitations {
        auth_required: false,
        min_pow_difficulty: relay_config.min_pow_difficulty,
        restricted_writes: relay_config.allow_protected_events,
        max_subid_length: 64,
    };

    let doc = nojson::json(|f| {
        f.object(|f| {
            f.member("name", &state.relay_name)?;
            f.member("description", &state.relay_description)?;
            f.member("supported_nips", &supported_nips)?;
            f.member("software", "https://github.com/taisan11/nostrust")?;
            f.member("version", env!("CARGO_PKG_VERSION"))?;
            if !state.relay_icon.is_empty() {
                f.member("icon", &state.relay_icon)?;
            }
            f.member("limitation", limitations)
        })
    })
    .to_string();

    Ok(doc)
}

#[derive(Debug, Clone, Copy)]
struct RelayLimitations {
    auth_required: bool,
    min_pow_difficulty: u8,
    restricted_writes: bool,
    max_subid_length: u64,
}

impl DisplayJson for RelayLimitations {
    fn fmt(&self, f: &mut JsonFormatter<'_, '_>) -> std::fmt::Result {
        f.object(|f| {
            f.member("auth_required", self.auth_required)?;
            f.member("min_pow_difficulty", self.min_pow_difficulty)?;
            f.member("restricted_writes", self.restricted_writes)?;
            f.member("max_subid_length", self.max_subid_length)
        })
    }
}
