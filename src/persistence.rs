use std::path::{Path, PathBuf};
use std::sync::Arc;

use turso::{Builder, Connection};

use crate::{DynError, EventRecord, RelayError};

#[derive(Debug, Clone)]
pub struct BlobRecord {
    pub sha256: String,
    pub mime_type: String,
    pub size: u64,
    pub uploaded: i64,
    pub owner_pubkey: Option<String>,
}

#[derive(Debug)]
pub struct EventStore {
    path: PathBuf,
    blob_dir: PathBuf,
    conn: Arc<Connection>,
}

impl EventStore {
    pub async fn open(path: PathBuf) -> Result<Self, DynError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let path_str = path_to_str(&path)?;
        let db = Builder::new_local(path_str).build().await?;
        let conn = db.connect()?;
        let blob_dir = path.with_extension("blobs");
        std::fs::create_dir_all(&blob_dir)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            )",
            (),
        )
        .await?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blobs (
                sha256 TEXT PRIMARY KEY,
                mime_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploaded INTEGER NOT NULL,
                owner_pubkey TEXT
            )",
            (),
        )
        .await?;

        Ok(Self {
            path,
            blob_dir,
            conn: Arc::new(conn),
        })
    }

    pub async fn append_event(&self, event: &EventRecord) -> Result<(), RelayError> {
        let id = event.id.clone();
        let payload = nojson::Json(event).to_string();
        let conn = Arc::clone(&self.conn);
        conn.execute(
            "INSERT OR IGNORE INTO events (id, payload) VALUES (?1, ?2)",
            [id, payload],
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            RelayError::internal(format!(
                "failed to persist event in {}: {e}",
                self.path.display()
            ))
        })
    }

    pub async fn load_event_payloads(&self) -> Result<Vec<String>, DynError> {
        let conn = Arc::clone(&self.conn);
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

        Ok(out)
    }

    pub fn path_display(&self) -> &Path {
        &self.path
    }

    pub async fn put_blob(
        &self,
        sha256: &str,
        bytes: &[u8],
        mime_type: &str,
        uploaded: i64,
        owner_pubkey: Option<&str>,
    ) -> Result<BlobRecord, RelayError> {
        let blob_path = self.blob_dir.join(sha256);
        std::fs::write(&blob_path, bytes).map_err(|e| {
            RelayError::internal(format!(
                "failed to write blob file {}: {e}",
                blob_path.display()
            ))
        })?;

        let size = i64::try_from(bytes.len())
            .map_err(|_| RelayError::internal("blob size exceeds i64".to_string()))?;
        let owner = owner_pubkey.unwrap_or("").to_string();
        let conn = Arc::clone(&self.conn);
        conn.execute(
            "INSERT OR IGNORE INTO blobs (sha256, mime_type, size, uploaded, owner_pubkey)
             VALUES (?1, ?2, ?3, ?4, NULLIF(?5, ''))",
            (
                sha256.to_string(),
                mime_type.to_string(),
                size,
                uploaded,
                owner,
            ),
        )
        .await
        .map_err(|e| {
            RelayError::internal(format!(
                "failed to persist blob metadata in {}: {e}",
                self.path.display()
            ))
        })?;

        self.get_blob(sha256).await?.ok_or_else(|| {
            RelayError::internal("blob metadata missing immediately after insert".to_string())
        })
    }

    pub async fn get_blob(&self, sha256: &str) -> Result<Option<BlobRecord>, RelayError> {
        let conn = Arc::clone(&self.conn);
        let mut rows = conn
            .query(
                "SELECT sha256, mime_type, size, uploaded, owner_pubkey
                 FROM blobs
                 WHERE sha256 = ?1",
                (sha256.to_string(),),
            )
            .await
            .map_err(|e| {
                RelayError::internal(format!(
                    "failed to query blob metadata in {}: {e}",
                    self.path.display()
                ))
            })?;

        let Some(row) = rows.next().await.map_err(|e| {
            RelayError::internal(format!(
                "failed to read blob metadata in {}: {e}",
                self.path.display()
            ))
        })?
        else {
            return Ok(None);
        };

        Ok(Some(blob_record_from_row(&row)?))
    }

    pub fn read_blob_bytes(&self, sha256: &str) -> Result<Option<Vec<u8>>, RelayError> {
        let blob_path = self.blob_dir.join(sha256);
        if !blob_path.exists() {
            return Ok(None);
        }
        std::fs::read(&blob_path).map(Some).map_err(|e| {
            RelayError::internal(format!(
                "failed to read blob file {}: {e}",
                blob_path.display()
            ))
        })
    }

    pub async fn list_blobs_by_owner(
        &self,
        owner_pubkey: &str,
    ) -> Result<Vec<BlobRecord>, RelayError> {
        let conn = Arc::clone(&self.conn);
        let mut rows = conn
            .query(
                "SELECT sha256, mime_type, size, uploaded, owner_pubkey
                 FROM blobs
                 WHERE owner_pubkey = ?1
                 ORDER BY uploaded DESC, sha256 ASC",
                (owner_pubkey.to_string(),),
            )
            .await
            .map_err(|e| {
                RelayError::internal(format!(
                    "failed to query owner blob metadata in {}: {e}",
                    self.path.display()
                ))
            })?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| {
            RelayError::internal(format!(
                "failed to read owner blob metadata in {}: {e}",
                self.path.display()
            ))
        })? {
            out.push(blob_record_from_row(&row)?);
        }

        Ok(out)
    }

    pub async fn delete_blob(&self, sha256: &str) -> Result<bool, RelayError> {
        let existing = self.get_blob(sha256).await?;
        if existing.is_none() {
            return Ok(false);
        }

        let conn = Arc::clone(&self.conn);
        conn.execute("DELETE FROM blobs WHERE sha256 = ?1", (sha256.to_string(),))
            .await
            .map_err(|e| {
                RelayError::internal(format!(
                    "failed to delete blob metadata in {}: {e}",
                    self.path.display()
                ))
            })?;

        let blob_path = self.blob_dir.join(sha256);
        if blob_path.exists() {
            std::fs::remove_file(&blob_path).map_err(|e| {
                RelayError::internal(format!(
                    "failed to remove blob file {}: {e}",
                    blob_path.display()
                ))
            })?;
        }

        Ok(true)
    }
}

fn path_to_str(path: &Path) -> Result<&str, DynError> {
    path.to_str()
        .ok_or_else(|| "NOSTR_STORE must be valid UTF-8".into())
}

fn blob_record_from_row(row: &turso::Row) -> Result<BlobRecord, RelayError> {
    let sha256 = row
        .get_value(0)
        .map_err(|e| RelayError::internal(format!("failed to decode blob sha256: {e}")))?
        .as_text()
        .ok_or_else(|| RelayError::internal("blob sha256 must be text".to_string()))?
        .to_string();
    let mime_type = row
        .get_value(1)
        .map_err(|e| RelayError::internal(format!("failed to decode blob mime type: {e}")))?
        .as_text()
        .ok_or_else(|| RelayError::internal("blob mime type must be text".to_string()))?
        .to_string();
    let size = *row
        .get_value(2)
        .map_err(|e| RelayError::internal(format!("failed to decode blob size: {e}")))?
        .as_integer()
        .ok_or_else(|| RelayError::internal("blob size must be integer".to_string()))?;
    let uploaded = *row
        .get_value(3)
        .map_err(|e| {
            RelayError::internal(format!("failed to decode blob uploaded timestamp: {e}"))
        })?
        .as_integer()
        .ok_or_else(|| {
            RelayError::internal("blob uploaded timestamp must be integer".to_string())
        })?;
    let owner_pubkey = row
        .get_value(4)
        .map_err(|e| RelayError::internal(format!("failed to decode blob owner pubkey: {e}")))?
        .as_text()
        .map(ToString::to_string);

    let size = u64::try_from(size)
        .map_err(|_| RelayError::internal("blob size must be non-negative".to_string()))?;
    Ok(BlobRecord {
        sha256,
        mime_type,
        size,
        uploaded,
        owner_pubkey,
    })
}
