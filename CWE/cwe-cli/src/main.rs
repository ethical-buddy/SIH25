use cwe::device::list_devices;
use cwe::device::check_firmware_sanitize;

// Main entry point for the utility
// Working steps
// 1. List Devices
// 2. Check wiping options for selected device
//    -- Firmware supported sanitize
//    -- Purge 
//    -- Clear


fn main(){
    println!("Enumerating block devices");

    // Get the device to wipe
    let mut dev = list_devices();
    

    // Check what kind of wiping device supports

    check_firmware_sanitize(&mut dev);
}
