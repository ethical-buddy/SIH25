use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct WipeEvidence {
    pub version: String,
    pub certificate_id: String,
    pub device_id: String,
    pub device_path: String,
    pub method: String,
    pub nist_level: String,
    pub timestamp_start: DateTime<Utc>,
    pub timestamp_end: Option<DateTime<Utc>>,
    pub pre_hash: Option<String>,
    pub post_hash: Option<String>,
    pub logs: Vec<String>,
}

impl WipeEvidence {
    pub fn new(device_id: &str, device_path: &str, method: &str, nist_level: &str) -> Self {
        WipeEvidence {
            version: "1.0".to_string(),
            certificate_id: Uuid::new_v4().to_string(),
            device_id: device_id.to_string(),
            device_path: device_path.to_string(),
            method: method.to_string(),
            nist_level: nist_level.to_string(),
            timestamp_start: Utc::now(),
            timestamp_end: None,
            pre_hash: None,
            post_hash: None,
            logs: Vec::new(),
        }
    }

    pub fn finish(&mut self) {
        self.timestamp_end = Some(Utc::now());
    }
}

