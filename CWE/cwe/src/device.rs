use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use anyhow::Result;
use std::path::Path;
use std::process::Command;
use hex;

/// Representation of a block device (Phase 0)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Device {
    pub id: String,              // hashed identifier (serial + run_salt)
    pub dev_path: String,        // /dev/sdX or /dev/nvme0n1
    pub name: String,            // block device name (sda, nvme0n1)
    pub model: Option<String>,
    pub serial: Option<String>,
    pub vendor: Option<String>,
    pub bus: Option<String>,        // "sata", "nvme", "usb", ...
    pub rotational: Option<bool>,   // true = HDD, false = SSD/flash
    pub size_bytes: Option<u64>,
    pub extra: Option<serde_json::Value>, // optional raw probe snippets
}

impl Device {
    pub fn new(
        dev_path: &str,
        name: &str,
        model: Option<&str>,
        serial: Option<&str>,
        vendor: Option<&str>,
        bus: Option<&str>,
        rotational: Option<bool>,
        size_bytes: Option<u64>,
        run_salt: &str,
    ) -> Self {
        let mut hasher = Sha256::new();
        if let Some(s) = serial {
            hasher.update(s.as_bytes());
        }
        hasher.update(run_salt.as_bytes());
        let id = hex::encode(hasher.finalize());

        Device {
            id,
            dev_path: dev_path.to_string(),
            name: name.to_string(),
            model: model.map(|s| s.to_string()),
            serial: serial.map(|s| s.to_string()),
            vendor: vendor.map(|s| s.to_string()),
            bus: bus.map(|s| s.to_string()),
            rotational,
            size_bytes,
            extra: None,
        }
    }

    pub fn exists(&self) -> bool {
        Path::new(&self.dev_path).exists()
    }
}

/// Try to enumerate devices via `lsblk --json --output-all`.
/// If lsblk is unavailable or returns nothing, fall back to sysfs `/sys/block`.
pub fn enumerate_block_devices(run_salt: &str) -> Result<Vec<Device>> {
    if let Ok(list) = enumerate_lsblk(run_salt) {
        if !list.is_empty() {
            return Ok(list);
        }
    }
    // fallback
    enumerate_sysfs(run_salt)
}

fn enumerate_lsblk(run_salt: &str) -> Result<Vec<Device>> {
    let out = Command::new("lsblk")
        .args(&["--json", "--output-all"])
        .output();

    let mut devices: Vec<Device> = Vec::new();

    if let Ok(out) = out {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(arr) = v.get("blockdevices").and_then(|b| b.as_array()) {
                    for dev in arr {
                        if let Some(name) = dev.get("name").and_then(|n| n.as_str()) {
                            if name.starts_with("loop") || name.starts_with("ram") {
                                continue;
                            }
                            let dev_path = format!("/dev/{}", name);
                            let model = dev.get("model").and_then(|m| m.as_str());
                            let serial = dev.get("serial").and_then(|s| s.as_str());
                            let vendor = dev.get("vendor").and_then(|s| s.as_str());
                            let bus = dev.get("tran").and_then(|t| t.as_str());
                            // rota may be number or boolean in different lsblk versions
                            let rotational = dev.get("rota")
                                .and_then(|r| {
                                    if r.is_boolean() { r.as_bool().map(|b| b) }
                                    else if r.is_number() { r.as_u64().map(|v| v == 1) }
                                    else { None }
                                });
                            // size: lsblk sometimes gives size human-readable as string; also may have "size" numeric
                            let size_bytes = dev.get("size").and_then(|s| {
                                if s.is_number() { s.as_u64() }
                                else if let Some(s) = s.as_str() {
                                    // try parse human readable like "931.5G"
                                    parse_human_size(s)
                                } else { None }
                            });

                            let mut d = Device::new(
                                &dev_path,
                                name,
                                model,
                                serial,
                                vendor,
                                bus,
                                rotational,
                                size_bytes,
                                run_salt,
                            );
                            d.extra = Some(dev.clone());
                            devices.push(d);
                        }
                    }
                }
            }
        }
    }

    Ok(devices)
}

fn enumerate_sysfs(run_salt: &str) -> Result<Vec<Device>> {
    let mut devices = Vec::new();
    let sys_block = std::fs::read_dir("/sys/block")?;
    for entry in sys_block {
        let entry = entry?;
        let name = entry.file_name().into_string().unwrap_or_default();
        if name.starts_with("loop") || name.starts_with("ram") {
            continue;
        }
        let dev_path = format!("/dev/{}", name);
        let dev_dir = format!("/sys/block/{}/device", name);

        let model = std::fs::read_to_string(format!("{}/model", dev_dir)).ok().map(|s| s.trim().to_string());
        let vendor = std::fs::read_to_string(format!("{}/vendor", dev_dir)).ok().map(|s| s.trim().to_string());
        let serial = std::fs::read_to_string(format!("{}/serial", dev_dir)).ok().map(|s| s.trim().to_string());
        let rotational = std::fs::read_to_string(format!("/sys/block/{}/queue/rotational", name))
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .map(|v| v == 1);
        let size_bytes = std::fs::read_to_string(format!("/sys/block/{}/size", name))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|sectors| sectors * 512);

        let d = Device::new(
            &dev_path,
            &name,
            model.as_deref(),
            serial.as_deref(),
            vendor.as_deref(),
            None,
            rotational,
            size_bytes,
            run_salt,
        );
        devices.push(d);
    }
    Ok(devices)
}

/// parse human-readable sizes like "931.5G" => bytes
fn parse_human_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() { return None; }

    // If it's plain numeric without unit, attempt parsing as bytes
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }

    // last char may be unit
    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: f64 = num_str.trim().parse().ok()?;
    let bytes = match unit.to_ascii_uppercase().as_str() {
        "K" => num * 1024.0,
        "M" => num * 1024.0 * 1024.0,
        "G" => num * 1024.0 * 1024.0 * 1024.0,
        "T" => num * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "P" => num * 1024.0_f64.powi(5),
        _ => num,
    };
    Some(bytes as u64)
}

