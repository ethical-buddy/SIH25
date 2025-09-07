use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use anyhow::Result;
use std::path::Path;
use hex;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Device {
    pub id:         String,        // hash id
    pub dev_path:   String,  // /dev/sdX ya fir  /dev/nvme0n1
    pub model:      Option<String>,
    pub serial:     Option<String>,
    pub vendor:     Option<String>,
}

impl Device {
    /// Create a device from basic info and  hashes serial for privacy.
    pub fn new(dev_path: &str, model: Option<&str>, serial: Option<&str>, vendor: Option<&str>, run_salt: &str) -> Self {
        let mut hasher = Sha256::new();
        if let Some(s) = serial {
            hasher.update(s.as_bytes());
        }
        hasher.update(run_salt.as_bytes());
        let id = hex::encode(hasher.finalize());
        Device {
            id,
            dev_path: dev_path.to_string(),
            model: model.map(|s| s.to_string()),
            serial: serial.map(|s| s.to_string()),
            vendor: vendor.map(|s| s.to_string()),
        }
    }

    pub fn exists(&self) -> bool {
        Path::new(&self.dev_path).exists()
    }
}

// This parse only linux block devices. Windows and MacOS later
pub fn enumerate_block_devices_linux(run_salt: &str) -> Result<Vec<Device>> {
    let mut devices = Vec::new();
    let sys_block = std::fs::read_dir("/sys/block")?;
    for entry in sys_block {
        let entry = entry?;
        
        let name = entry.file_name().into_string().unwrap_or_default();
        if name.starts_with("loop") || name.starts_with("ram") { continue; }
        
        let dev_path = format!("/dev/{}", name);
        
        let dev_dir = format!("/sys/block/{}/device", name);
        
        let model = std::fs::read_to_string(format!("{}/model", dev_dir)).ok().map(|s| s.trim().to_string());
        
        let vendor = std::fs::read_to_string(format!("{}/vendor", dev_dir)).ok().map(|s| s.trim().to_string());
        
        let serial = std::fs::read_to_string(format!("{}/serial", dev_dir)).ok().map(|s| s.trim().to_string());
        let d = Device::new(&dev_path, model.as_deref(), serial.as_deref(), vendor.as_deref(), run_salt);
        devices.push(d);
    }
    Ok(devices)
}

