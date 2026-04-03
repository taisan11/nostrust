# nostrust

Minimal Rust Nostr relay implementation.

## Configuration (`nostrust.json`)

`nostrust` reads runtime settings from `./nostrust.json` if present.  
If the file is missing, built-in defaults are used.

Example:

```json
{
  "bind": "127.0.0.1:8080",
  "store": "nostrust-events.db",
  "relay_url": "ws://127.0.0.1:8080",
  "allow_protected_events": false,
  "min_pow_difficulty": 0,
  "nip05_domain": null
}
```

Schema: `nostrust.schema.json`

## NIP support and `relay`-tagged document audit

NIPs whose documents in `../nips/` include the `` `relay` `` tag:

`01, 04, 09, 11, 13, 17, 26, 29, 40, 42, 43, 45, 50, 59, 62, 66, 70, 77`

Current `supported_nips` advertised by this relay:

`1, 4, 5, 9, 11, 13, 17, 26, 29, 40, 42, 43, 45, 50, 57, 59, 62, 65, 66, 70, 77, 86, 94, 96`

Alignment summary:

- Relay-tagged and currently advertised: `01, 04, 09, 11, 13, 17, 26, 29, 40, 42, 43, 45, 50, 59, 62, 66, 70, 77`
- Relay-tagged but not currently advertised: `(none)`
- Advertised but not relay-tagged in header metadata: `5, 57, 65, 86, 94, 96`

Notes:

- `1` and `4` in `supported_nips` correspond to NIP-01 and NIP-04.
- This project currently keeps the existing advertised list and does not auto-sync it from documents.

## Newly added support

- **NIP-57 (Lightning Zaps):** kind `9734` and `9735` validation rules are enforced.
- **NIP-86 (Relay Management API):** HTTP JSON-RPC endpoint over the relay URI with NIP-98 authorization (`Authorization: Nostr ...`) and moderation/state management methods.
- **NIP-B7 (Blossom media):** kind `10063` user server-list validation is enforced (`server` tags with `http(s)` URLs).
