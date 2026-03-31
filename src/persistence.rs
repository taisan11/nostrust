use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::runtime::Runtime;
use turso::{Builder, Connection};

use crate::{DynError, EventRecord};

#[derive(Debug)]
pub struct EventStore {
    path: PathBuf,
    runtime: Runtime,
    conn: Arc<Connection>,
}

impl EventStore {
    pub fn open(path: PathBuf) -> Result<Self, DynError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let runtime = Runtime::new()?;
        let conn = runtime.block_on(async {
            let path_str = path_to_str(&path)?;
            let db = Builder::new_local(path_str).build().await?;
            let conn = db.connect()?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )",
                (),
            )
            .await?;
            Ok::<Connection, Box<dyn std::error::Error + Send + Sync>>(conn)
        })?;

        Ok(Self {
            path,
            runtime,
            conn: Arc::new(conn),
        })
    }

    pub fn append_event(&self, event: &EventRecord) -> Result<(), String> {
        let id = event.id.clone();
        let payload = nojson::Json(event).to_string();
        let conn = Arc::clone(&self.conn);
        self.runtime
            .block_on(async move {
                conn.execute(
                    "INSERT OR IGNORE INTO events (id, payload) VALUES (?1, ?2)",
                    [id, payload],
                )
                .await
            })
            .map(|_| ())
            .map_err(|e| format!("failed to persist event in {}: {e}", self.path.display()))
    }

    pub fn load_event_payloads(&self) -> Result<Vec<String>, DynError> {
        let conn = Arc::clone(&self.conn);
        self.runtime.block_on(async move {
            let mut rows = conn
                .query("SELECT payload FROM events ORDER BY rowid ASC", ())
                .await?;
            let mut out = Vec::new();

            while let Some(row) = rows.next().await? {
                let value = row.get_value(0)?;
                let payload = value
                    .as_text()
                    .ok_or("event payload should be text")?
                    .to_string();
                out.push(payload);
            }

            Ok::<Vec<String>, Box<dyn std::error::Error + Send + Sync>>(out)
        })
    }

    pub fn path_display(&self) -> &Path {
        &self.path
    }
}

fn path_to_str(path: &Path) -> Result<&str, DynError> {
    path.to_str()
        .ok_or_else(|| "NOSTR_STORE must be valid UTF-8".into())
}
