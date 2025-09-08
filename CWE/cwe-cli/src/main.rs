use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
struct Args {
    /// optional run salt (if omitted, timestamp is used)
    #[clap(long)]
    salt: Option<String>,

    /// output machine-friendly JSON
    #[clap(long, default_value_t = false)]
    json: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let salt = args.salt.unwrap_or_else(|| format!("{}", chrono::Utc::now().timestamp()));
    let devices = cwe::enumerate_block_devices(&salt)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&devices)?);
        return Ok(());
    }

    println!("CWE Phase 0 — Device enumeration (non-destructive)");
    println!("Run salt: {}", salt);
    println!();

    if devices.is_empty() {
        println!("No block devices detected.");
        return Ok(());
    }

    for d in &devices {
        println!("Device: {}", d.dev_path);
        println!("  name: {}", d.name);
        println!("  model: {}", d.model.as_deref().unwrap_or("N/A"));
        println!("  vendor: {}", d.vendor.as_deref().unwrap_or("N/A"));
        println!("  serial (hashed id prefix): {}", &d.id[..12]);
        println!("  exists: {}", d.exists());
        println!("  bus: {}", d.bus.as_deref().unwrap_or("unknown"));
        match d.rotational {
            Some(true) => println!("  media: HDD (rotational)"),
            Some(false) => println!("  media: SSD/Flash (non-rotational)"),
            None => println!("  media: unknown"),
        }
        if let Some(sz) = d.size_bytes {
            println!("  size (bytes): {}", sz);
        }
        println!();
    }

    println!("Summary suggestions:");
    println!(" - No destructive actions are performed by this command.");
    println!(" - Use these capability hints to select appropriate wipe strategy in subsequent phases.");
    Ok(())
}

