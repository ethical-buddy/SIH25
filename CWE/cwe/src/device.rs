use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use anyhow::Result;
use std::path::Path;
use hex;
use std::fs::File;
use std::io;
use std::io::Write;
use libc::{c_void, ioctl};
use std::os::unix::io::AsRawFd;

pub const HDIO_DRIVE_CMD: u64 = 0x031f;
pub const NVME_IOCTL_ADMIN_CMD: u64 = 0xC0484E41; // _IOWR('N', 0x41, struct nvme_admin_cmd)

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DeviceType{
    Nvme,
    Sata,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Device {
    pub id:         String,        // hash id
    pub dev_path:   String,  // /dev/sdX ya fir  /dev/nvme0n1
    pub model:      Option<String>,
    pub serial:     Option<String>,
    pub vendor:     Option<String>,
    pub devtype:    DeviceType,
    pub firmsan:    bool,   
}



#[repr(C)]
#[derive(Debug)]
pub struct nvme_admin_cmd {
    pub opcode: u8,
    pub flags: u8,
    pub rsvd1: u16,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub metadata: u64,
    pub addr: u64,
    pub metadata_len: u32,
    pub data_len: u32,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
    pub timeout_ms: u32,
    pub result: u32,
}


impl Device {
    /// Create a device from basic info and  hashes serial for privacy.
    pub fn new(dev_path: &str, model: Option<&str>, serial: Option<&str>, vendor: Option<&str>, devtype: DeviceType, run_salt: &str) -> Self {
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
            devtype: devtype,
            firmsan: false,
        }
    }

    pub fn exists(&self) -> bool {
        Path::new(&self.dev_path).exists()
    }
}

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

        let device_type = device_type(&dev_path);
        let d = Device::new(&dev_path, model.as_deref(), serial.as_deref(), vendor.as_deref(), device_type, run_salt);
        devices.push(d);
    }
    Ok(devices)
}

pub fn find_device_by_path(dev_path: &str, run_salt: &str) -> std::io::Result<Device> {
    let devices = enumerate_block_devices_linux(run_salt)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    for device in devices {
        if device.dev_path == dev_path {
            return Ok(device);
        }
    }
    
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound, 
        format!("Device not found: {}", dev_path)
    ))
}
pub fn list_devices() -> Device {
    
    let enum_res = enumerate_block_devices_linux("run");

    match enum_res{
        Ok(devices) => {
            let mut i : u32 = 0;
            println!("------------Devices------------");
            for device in &devices {
                println!("#{} {} {}",i,device.id,device.dev_path);
                i+=1;
            }

            print!("Device to wipe: ");
            io::stdout().flush().unwrap();
            
            let mut input = String::new();
            io::stdin().read_line(&mut input).expect("error: unable to read user input");
            let choice : usize = input.trim().parse().expect("Please type a valid number");

            devices[choice].clone()

        }
        Err(e) => panic!("Error trying to enumerate devices : {}",e),
    }
}

fn device_type(dev_path: &str) -> DeviceType {
    
    if dev_path.contains("nvme"){
        DeviceType::Nvme
    }else if dev_path.contains("sd"){
        DeviceType::Sata
    }else{
        DeviceType::Unknown
    }
}

fn check_ata_secure_erase(dev_path: &str) -> io::Result<bool> {   
    let file = File::open(dev_path)?;
    let fd = file.as_raw_fd();

    // buffer: first byte = command, second = sector count, rest = data
    let mut args: [u8; 4 + 512] = [0; 4 + 512];
    args[0] = 0xEC; // IDENTIFY DEVICE command

    let ret = unsafe {
        ioctl(fd, HDIO_DRIVE_CMD as _, args.as_mut_ptr() as *mut c_void)
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // IDENTIFY DEVICE result is at offset 4
    let data = &args[4..];

    // Word 82-83 = supported features
    let word82 = u16::from_le_bytes([data[82*2], data[82*2+1]]);
    let word89 = u16::from_le_bytes([data[89*2], data[89*2+1]]);

    let security_supported = (word82 & (1 << 1)) != 0; // "Security feature set"
    let sanitize_supported = (word89 & (1 << 13)) != 0; // Sanitize Device feature

    Ok(security_supported || sanitize_supported)
}


fn check_nvme_sanitize(dev_path: &str) -> io::Result<bool> {
    let file = File::open(dev_path)?;
    let fd = file.as_raw_fd();

    let mut ctrl_data = vec![0u8; 4096]; // Identify Controller returns 4096 bytes

    let mut cmd = nvme_admin_cmd {
        opcode: 0x06, // Identify
        flags: 0,
        rsvd1: 0,
        nsid: 0, // CNS=1 => Identify Controller
        cdw2: 0,
        cdw3: 0,
        metadata: 0,
        addr: ctrl_data.as_mut_ptr() as u64,
        metadata_len: 0,
        data_len: ctrl_data.len() as u32,
        cdw10: 1, // CNS=1 -> controller
        cdw11: 0,
        cdw12: 0,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
        timeout_ms: 0,
        result: 0,
    };

    let ret = unsafe { ioctl(fd, NVME_IOCTL_ADMIN_CMD, &mut cmd) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Sanitize Capabilities at byte offset 536 (dword 267)
    let sanicap_offset = 536;
    let sanicap = u16::from_le_bytes([
        ctrl_data[sanicap_offset],
        ctrl_data[sanicap_offset + 1],
    ]);

    Ok(sanicap != 0)
}

pub fn check_firmware_sanitize(dev: &mut Device) {
    if dev.devtype == DeviceType::Nvme{
        match check_nvme_sanitize(&dev.dev_path) {
            Ok(true) =>{
                println!("{} supports NVMe sanitize",dev.dev_path);
                dev.firmsan = true;
            }
            Ok(false) => println!("{} doesn't support NVMe sanitize", dev.dev_path),
            Err(e) => println!("Error checking firmware sanitize support {}",e),
        }
    }else if dev.devtype == DeviceType::Sata{
        match check_ata_secure_erase(&dev.dev_path){
            Ok(true) =>{
                println!("{} supports ATA secure erase",dev.dev_path);
                dev.firmsan = true;
            }
            Ok(false) => println!("{} doesn't support ATA secure erase",dev.dev_path),
            Err(e) => println!("Error checking firmware sanitize support {}",e),
        }
    }
}

