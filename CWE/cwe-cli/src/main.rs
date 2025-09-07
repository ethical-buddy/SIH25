use cwe::device::list_devices;
use cwe::device::Device;

// Main entry point for the utility
// Working steps
// 1. List Devices
// 2. Check wiping options for selected device


fn main(){
    println!("Enumerating block devices");

    // Get the device to wipe
    let dev = list_devices();

    // Check what kind of wiping device supports

}
