// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw BPF batch syscall wrappers.
//!
//! aya 0.13 does not expose batch operations. We call the bpf() syscall directly
//! using the BPF_MAP_LOOKUP_BATCH and BPF_MAP_LOOKUP_AND_DELETE_BATCH commands
//! (available since Linux 5.6; we require 5.8+).

use aya::maps::{HashMap as SharedHashMap, IterableMap, MapData};
use aya::Pod;
use aya_obj::generated::bpf_cmd;
use std::os::fd::AsFd;

/// Attr struct matching the batch fields of the kernel's `struct bpf_attr`.
/// Layout must match `linux/bpf.h` for the batch commands.
#[repr(C)]
#[derive(Default)]
struct BatchAttr {
    in_batch: u64,  // pointer to opaque batch cursor (input)
    out_batch: u64, // pointer to opaque batch cursor (output)
    keys: u64,      // pointer to keys buffer
    values: u64,    // pointer to values buffer
    count: u32,     // in: max entries to read, out: entries actually read
    map_fd: u32,    // fd of bpf hashmap
    elem_flags: u64,
    flags: u64,
}

/// Reads all entries from a BPF HashMap using `BPF_MAP_LOOKUP_BATCH`.
///
/// Iterates through the map in batches of up to `max_entries` per syscall,
/// collecting all key-value pairs. Stops when the kernel returns `ENOENT`
/// (indicating the end of the map) or when a batch returns zero entries.
///
/// # Arguments
/// * `map` - Reference to the aya `HashMap` to read from.
/// * `max_entries` - Maximum number of entries to fetch per batch syscall. Kernel will return less if there are less entries.
///
/// # Returns
/// A `Vec` of all `(key, value)` pairs currently in the map.
pub fn lookup_batch<K: Pod + Default, V: Pod + Default>(
    map: &SharedHashMap<MapData, K, V>,
    max_entries: usize,
) -> Vec<(K, V)> {
    let fd = map.map().fd().as_fd();
    let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&fd);

    let mut keys: Vec<K> = Vec::with_capacity(max_entries);
    let mut values: Vec<V> = Vec::with_capacity(max_entries);
    unsafe {
        keys.set_len(max_entries);
        values.set_len(max_entries);
    }
    let mut results = Vec::new();

    let mut in_batch: u64 = 0;
    let mut out_batch: u64 = 0;
    let mut first_call = true;

    loop {
        let mut attr = BatchAttr {
            in_batch: if first_call {
                0
            } else {
                &in_batch as *const u64 as u64
            },
            out_batch: &mut out_batch as *mut u64 as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count: max_entries as u32,
            map_fd: raw_fd as u32,
            elem_flags: 0,
            flags: 0,
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                bpf_cmd::BPF_MAP_LOOKUP_BATCH as u64,
                &mut attr as *mut BatchAttr,
                std::mem::size_of::<BatchAttr>(),
            )
        };

        let count = attr.count as usize;
        for i in 0..count {
            results.push((keys[i], values[i]));
        }

        if ret != 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::ENOENT {
                log::error!("BPF Batch lookup error: {errno}");
            }
            break;
        }
        if count == 0 {
            break;
        }
        in_batch = out_batch;
        first_call = false;
    }

    results
}

/// Deletes multiple entries from a BPF HashMap in a single syscall using
/// `BPF_MAP_DELETE_BATCH`.
///
/// # Arguments
/// * `map` - Mutable reference to the aya `HashMap` to delete from.
/// * `keys` - Slice of keys to delete.
///
/// # Returns
/// The number of entries successfully deleted by the kernel.
pub fn delete_batch<K: Pod + Default, V: Pod + Default>(
    map: &mut SharedHashMap<MapData, K, V>,
    keys: &[K],
) -> u32 {
    if keys.is_empty() {
        return 0;
    }
    let fd = map.map().fd().as_fd();
    let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&fd);

    let mut attr = BatchAttr {
        in_batch: 0,
        out_batch: 0,
        keys: keys.as_ptr() as u64,
        values: 0,
        count: keys.len() as u32,
        map_fd: raw_fd as u32,
        elem_flags: 0,
        flags: 0,
    };

    unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_MAP_DELETE_BATCH as u64,
            &mut attr as *mut BatchAttr,
            std::mem::size_of::<BatchAttr>(),
        );
    }

    attr.count
}
