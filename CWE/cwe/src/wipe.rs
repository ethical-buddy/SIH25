use std::io;
use std::io::{Seek,Write};
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use libc::{c_void, ioctl};
use rand::Rng;
use std::time::Instant;
use std::time::Duration;
use std::thread;
use crate::device;


pub fn wipe_device(dev: &mut device::Device) -> io::Result<()> { // the main wipe routine
    if dev.firmsan {
        match firmware_erase(dev) {
            Ok(_) => {
                println!("Firmware sanitize completed on {}", dev.dev_path);
                return Ok(());
            }
            Err(e) => println!("Firmware erase failed: {}. Falling back.", e),
        }
    }

    if try_crypto_purge(dev)? {
        println!("Crypto purge completed on {}", dev.dev_path);
        return Ok(());
    }

    println!("Falling back to software overwrite on {}", dev.dev_path);
    disk_clean(&dev.dev_path)?;

    Ok(())
}

fn firmware_erase(dev: &device::Device) -> io::Result<()> {
    let file = File::open(&dev.dev_path)?;
    let fd = file.as_raw_fd();

    match dev.devtype {
        device::DeviceType::Sata => ata_secure_erase(fd, "ERASEPWD"),
        device::DeviceType::Nvme => nvme_sanitize(fd, 3), // use crypto erase
        _ => Err(io::Error::new(io::ErrorKind::Other, "Unsupported device type")),
    }
}


fn try_crypto_purge(dev: &device::Device) -> io::Result<bool> {
    match dev.devtype {
        device::DeviceType::Nvme => {
            println!("Attempting NVMe crypto erase on {}", dev.dev_path);

            match nvme_crypto_purge("/dev/nvme0n1", 3600) {
                Ok(_) => println!("NVMe crypto purge complete"),
                Err(e) => eprintln!("NVMe purge failed: {}", e),
            }

            Ok(true)
        }
        device::DeviceType::Sata => {
            println!("Attempting ATA crypto purge on {}", dev.dev_path);

            match ata_crypto_purge("/dev/sda", "ERASEPWD") {
                Ok(_) => println!("ATA secure erase triggered"),
                Err(e) => eprintln!("ATA purge failed: {}", e),
            }

            // for many SATA SEDs, normal secure erase == crypto purge
            Ok(false) // only return true if known supported
        }
        _ => Ok(false),
    }
}

fn disk_clean(dev_path: &str) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .open(dev_path)?;

    let size = f.metadata()?.len();

    let mut buf = vec![0u8; 1024 * 1024]; // 1 MB buffer
    let mut rng = rand::thread_rng();

    for offset in (0..size).step_by(buf.len()) {
        rng.fill(&mut buf[..]);
        f.seek(io::SeekFrom::Start(offset))?;
        f.write_all(&buf)?;
    }

    f.flush()?;
    Ok(())
}

fn nvme_sanitize(fd: i32, action: u32) -> io::Result<()> {
    let mut cmd = device::nvme_admin_cmd {
        opcode: 0x84, // SANITIZE
        flags: 0,
        rsvd1: 0,
        nsid: 0,
        cdw2: 0,
        cdw3: 0,
        metadata: 0,
        addr: 0,
        metadata_len: 0,
        data_len: 0,
        cdw10: action, // 1=overwrite, 2=block, 3=crypto
        cdw11: 0,
        cdw12: 0,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
        timeout_ms: 0,
        result: 0,
    };

    let ret = unsafe { ioctl(fd, device::NVME_IOCTL_ADMIN_CMD, &mut cmd) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn ata_secure_erase(fd: i32, password: &str) -> io::Result<()> {
    let mut args: [u8; 4 + 512] = [0; 4 + 512];

    // SECURITY_SET_PASSWORD
    args[0] = 0xF1;
    args[1] = 0; // sector count
    let pwd_bytes = password.as_bytes();
    args[4..4+pwd_bytes.len()].copy_from_slice(pwd_bytes);

    let ret = unsafe { ioctl(fd, device::HDIO_DRIVE_CMD as _, args.as_mut_ptr() as *mut c_void) };
    if ret < 0 { return Err(io::Error::last_os_error()); }

    // SECURITY_ERASE_UNIT
    let mut args: [u8; 4 + 512] = [0; 4 + 512];
    args[0] = 0xF4; // erase
    let ret = unsafe { ioctl(fd, device::HDIO_DRIVE_CMD as _, args.as_mut_ptr() as *mut c_void) };
    if ret < 0 { return Err(io::Error::last_os_error()); }

    Ok(())
}

/// ---------- ATA (SATA) crypto purge via SECURITY_SET_PASSWORD + SECURITY_ERASE_UNIT ----------
pub fn ata_crypto_purge(dev_path: &str, password: &str) -> io::Result<()> {
    // open block device
    let file = File::open(dev_path)?;
    let fd = file.as_raw_fd();

    // Build 4 + 512 buffer as used by HDIO_DRIVE_CMD (first 4 bytes are header)
    // SECURITY_SET_PASSWORD (0xF1)
    {
        let mut args: [u8; 4 + 512] = [0; 4 + 512];
        args[0] = 0xF1u8; // SECURITY_SET_PASSWORD

        // password length — ATA password area varies; we copy at offset 4, smallest common subset
        let pwd_bytes = password.as_bytes();
        let max_pwd = 32.min(pwd_bytes.len()); // don't overflow; typical ATA password field is 32 bytes
        args[4..4 + max_pwd].copy_from_slice(&pwd_bytes[..max_pwd]);

        let ret = unsafe {
            ioctl(fd, device::HDIO_DRIVE_CMD as _, args.as_mut_ptr() as *mut c_void)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // SECURITY_ERASE_UNIT (0xF4) - this will start the secure erase (may be async)
    {
        let mut args: [u8; 4 + 512] = [0; 4 + 512];
        args[0] = 0xF4u8; // SECURITY_ERASE_UNIT
        // Optionally set feature bits in args[1..], vendor-specific - keeping defaults (0).
        let ret = unsafe {
            ioctl(fd, device::HDIO_DRIVE_CMD as _, args.as_mut_ptr() as *mut c_void)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // At this point the drive should begin the erase (may be time-consuming).
    // Many drives do this synchronously at firmware level (or in background). There's
    // no portable way here to poll ATA sanitize progress conveniently — userspace tools
    // like hdparm often rely on subsequent IDENTIFY to check status or use vendor-specific logs.
    Ok(())
}

/// ---------- NVMe crypto purge (SANITIZE action=3) + polling of Sanitize Status log page ----------
pub fn nvme_crypto_purge(dev_path: &str, timeout_secs: u64) -> io::Result<()> {
    // NVMe admin ioctl usually expects controller character device (e.g., /dev/nvme0).
    let ctrl_path = nvme_ctrl_path(dev_path);
    let file = File::open(&ctrl_path)?;
    let fd = file.as_raw_fd();

    // Issue SANITIZE with action = 3 (Crypto Erase)
    {
        let mut cmd = device::nvme_admin_cmd {
            opcode: 0x84, // SANITIZE
            flags: 0,
            rsvd1: 0,
            nsid: 0, // controller-level sanitize
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            addr: 0,
            metadata_len: 0,
            data_len: 0,
            cdw10: 3, // action = 3 (crypto erase)
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
            timeout_ms: 0,
            result: 0,
        };

        let ret = unsafe { ioctl(fd, device::NVME_IOCTL_ADMIN_CMD, &mut cmd) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // Poll Sanitize Status log page (0x81). We'll read 512 bytes and parse sprog (u16 at 0)
    // and sstat (u16 at offset 2). SPROG==0xFFFF (65535) usually means finished (see spec).
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    loop {
        // read log page 0x81 into buffer
        let mut buf = vec![0u8; 512];
        get_nvme_log_page(fd, 0x81, &mut buf)?;

        // parse SPROG and SSTAT (both little-endian)
        if buf.len() >= 4 {
            let sprog = u16::from_le_bytes([buf[0], buf[1]]);
            let sstat = u16::from_le_bytes([buf[2], buf[3]]);

            // Debug print (optional)
            println!("nvme sanitize log: SPROG={} SSTAT=0x{:x}", sprog, sstat);

            // SPROG is 16-bit numerator over 65536; spec says set to 0xFFFF if not IN_PROGRESS.
            // In practice: sprog == 0xFFFF or sprog == 65535 indicates completion (100%).
            if sprog == 0xFFFF || sprog == 65535 {
                // Completed. Now check SSTAT for success/failure.
                // The SSTAT contains flags & status; highest-level detection varies by implementation.
                // We'll treat 0x0 or low bit success codes as success; otherwise return error.
                // (For robust handling you may mask with NVME_SANITIZE_SSTAT_STATUS_MASK from headers)
                // Many tools print SSTAT like 0x101 on success. We'll treat any non-zero as success
                // if lower 3 bits indicate COMPLETE_SUCCESS — but to keep portable we'll accept common cases:
                let status_masked = sstat; // real implementation: mask with NVME_SANITIZE_SSTAT_STATUS_MASK
                // heuristics: if masked == 0 (never sanitized) or indicates fail -> compute accordingly.
                // We'll assume completion is OK unless SSTAT explicitly indicates failure code. Some controllers
                // use values > 0 to indicate success (e.g., 0x101). So treat SSTAT == 0x2xx (failed) as failure.
                // Simple heuristic:
                if (status_masked & 0x0FF) == 0x2 {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("NVMe sanitize reported failure sstat=0x{:x}", sstat)));
                } else {
                    println!("NVMe sanitize/crypto-erase complete: sstat=0x{:x}", sstat);
                    return Ok(());
                }
            }

            // If still in progress, continue to poll until timeout
        }

        if start.elapsed() > timeout {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out waiting for NVMe sanitize"));
        }

        // Sleep a short while before polling again
        thread::sleep(Duration::from_secs(3));
    }
}

/// Helper: perform NVMe Get Log Page (opcode=0x02)
fn get_nvme_log_page(fd: i32, log_id: u32, buf: &mut [u8]) -> io::Result<()> {
    // cdw10 format: (numd-1) << 16 | (log_id)
    // numd is number of dwords (32-bit) to transfer. numd = (buf.len() / 4)
    let numd = (buf.len() / 4) as u32;
    let numd_field = if numd == 0 { 0 } else { (numd - 1) << 16 };
    let cdw10 = (log_id & 0xff) | numd_field;

    let mut cmd = device::nvme_admin_cmd {
        opcode: 0x02, // Get Log Page
        flags: 0,
        rsvd1: 0,
        nsid: 0xffffffff, // controller-global
        cdw2: 0,
        cdw3: 0,
        metadata: 0,
        addr: buf.as_mut_ptr() as u64,
        metadata_len: 0,
        data_len: buf.len() as u32,
        cdw10,
        cdw11: 0,
        cdw12: 0,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
        timeout_ms: 0,
        result: 0,
    };

    let ret = unsafe { ioctl(fd, device::NVME_IOCTL_ADMIN_CMD, &mut cmd) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Convert a namespace device path like /dev/nvme0n1 -> controller device /dev/nvme0
fn nvme_ctrl_path(dev_path: &str) -> String {
    // If device looks like /dev/nvme0n1 or /dev/nvme1n2, strip trailing 'n<digits>'
    if dev_path.starts_with("/dev/nvme") {
        // find last 'n' followed by digits
        if let Some(pos) = dev_path.rfind('n') {
            let tail = &dev_path[pos+1..];
            if tail.chars().all(|c| c.is_ascii_digit()) {
                return dev_path[..pos].to_string(); // strip the n#
            }
        }
    }
    // otherwise return input (may already be controller or char device)
    dev_path.to_string()
}



pub fn dummy_erase(){
    println!("OHMYGOD ERASED!!!");
}


