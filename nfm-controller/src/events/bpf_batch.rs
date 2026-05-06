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
use log::debug;
use std::os::fd::AsFd;

/// Attr struct matching kernel's `struct bpf_attr` batch fields.
/// Must match the layout in linux/bpf.h.
#[repr(C)]
#[derive(Default)]
struct BatchAttr {
    in_batch: u64,  // pointer to opaque batch cursor (input)
    out_batch: u64, // pointer to opaque batch cursor (output)
    keys: u64,      // pointer to keys buffer
    values: u64,    // pointer to values buffer
    count: u32,     // in: max entries to read, out: entries actually read
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

/// Reads all entries from a BPF HashMap using BPF_MAP_LOOKUP_BATCH.
/// Returns a Vec of (key, value) pairs. Much faster than iterating with
/// BPF_MAP_GET_NEXT_KEY + BPF_MAP_LOOKUP_ELEM per entry (2 syscalls/entry → ~1 syscall total).
pub fn lookup_batch<K: Pod + Default, V: Pod + Default>(
    map: &SharedHashMap<MapData, K, V>,
    max_entries: usize,
) -> Vec<(K, V)> {
    let fd = map.map().fd().as_fd();
    let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&fd);

    let mut keys: Vec<K> = vec![K::default(); max_entries];
    let mut values: Vec<V> = vec![V::default(); max_entries];
    let mut results = Vec::new();

    // The batch cursor is opaque to userspace; kernel writes to out_batch,
    // we pass it back as in_batch on the next call.
    let mut in_batch: u64 = 0;
    let mut out_batch: u64 = 0;
    let mut first_call = true;

    loop {
        let batch_size = max_entries.min(keys.len()) as u32;
        let mut attr = BatchAttr {
            in_batch: if first_call {
                0
            } else {
                &in_batch as *const u64 as u64
            },
            out_batch: &mut out_batch as *mut u64 as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count: batch_size,
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

        // ret == 0 means more entries; ret == -1 with ENOENT means we've read all entries
        if ret != 0 || count == 0 {
            break;
        }
        in_batch = out_batch;
        first_call = false;
    }

    debug!("lookup_batch: read {} entries", results.len());
    results
}

/// Deletes multiple entries from a BPF HashMap in one syscall using BPF_MAP_DELETE_BATCH.
/// Returns the number of entries successfully deleted.
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
