use std::path::Path;

/// Check if interface is virtual by examining sysfs
pub fn check_iface_virtual(iface_name: &str) -> bool {
    // Physical interfaces have /sys/class/net/<interface>/device symlink
    // Virtual interfaces don't have this symlink
    let device_path = format!("/sys/class/net/{}/device", iface_name);
    !Path::new(&device_path).exists()
}
