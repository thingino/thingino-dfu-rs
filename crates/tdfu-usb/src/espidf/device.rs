//! What the library already knows about an enumerated device, read without a transfer.

use core::ptr;

use esp_idf_sys as sys;

use super::{DevHandle, check};
use crate::{DeviceDescriptors, Pipe, UsbError};

pub(super) struct Described {
    pub(super) descriptors: DeviceDescriptors,
    pub(super) mps0: usize,
    pub(super) configuration: u8,
}

pub(super) fn describe(dev: DevHandle, address: u8) -> Result<Described, UsbError> {
    // SAFETY: an all-zero `usb_device_info_t` is a valid value for the library to fill.
    let mut info: sys::usb_device_info_t = unsafe { core::mem::zeroed() };
    // SAFETY: `dev` is an open handle and `info` outlives the call.
    check(
        unsafe { sys::usb_host_device_info(dev, &raw mut info) },
        Pipe::Device,
        "usb_host_device_info",
    )?;
    let mut device: *const sys::usb_device_desc_t = ptr::null();
    // SAFETY: as above; the library points `device` at its own copy of the descriptor.
    let got = unsafe { sys::usb_host_get_device_descriptor(dev, &raw mut device) };
    check(got, Pipe::Device, "usb_host_get_device_descriptor")?;
    // SAFETY: a successful call left `device` pointing at the library's 18-byte descriptor,
    // which lives as long as the device is open.
    let device = unsafe { (*device).val };
    let mut config: *const sys::usb_config_desc_t = ptr::null();
    // SAFETY: as for the device descriptor.
    let got = unsafe { sys::usb_host_get_active_config_descriptor(dev, &raw mut config) };
    check(got, Pipe::Device, "usb_host_get_active_config_descriptor")?;
    // SAFETY: a successful call left `config` pointing at the whole configuration, of
    // `wTotalLength` bytes, owned by the library while the device is open.
    let head = unsafe { (*config).val };
    let total = usize::from(u16::from_le_bytes([head[2], head[3]]));
    // SAFETY: as above: `total` bytes are readable at `config`.
    let config = unsafe { core::slice::from_raw_parts(config.cast::<u8>(), total) }.to_vec();

    let mut descriptors = DeviceDescriptors::new(
        u16::from_le_bytes([device[8], device[9]]),
        u16::from_le_bytes([device[10], device[11]]),
    )
    .with_bus_address(1, address)
    // One root port and no hub support: every device is on port 1, before and after it
    // re-enumerates, which is the identity thingino-dfu tracks across a bootstrap.
    .with_port_path(vec![1])
    .with_config_descriptor(config);
    if let Some(product) = string_descriptor(info.str_desc_product) {
        descriptors = descriptors.with_product_string(product);
    }
    Ok(Described {
        descriptors,
        mps0: usize::from(info.bMaxPacketSize0),
        configuration: info.bConfigurationValue,
    })
}

fn string_descriptor(desc: *const sys::usb_str_desc_t) -> Option<String> {
    if desc.is_null() {
        return None;
    }
    let bytes = desc.cast::<u8>();
    // SAFETY: a non-null string descriptor from the library starts with its own length.
    let len = usize::from(unsafe { *bytes });
    // SAFETY: that length covers the two header bytes and the UTF-16 body after them.
    let body = unsafe { core::slice::from_raw_parts(bytes.add(2), len.checked_sub(2)?) };
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}
