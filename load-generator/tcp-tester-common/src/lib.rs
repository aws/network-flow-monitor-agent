#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, PartialEq)]
pub enum Direction {
    INGRESS,
    EGRESS,
}
#[cfg(feature = "user")]
unsafe impl Pod for Direction {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SocketKey {
    pub cookie: u64,
    pub direction: Direction,
    // need to verify this, but it looks like since the struct is not aligned
    // rust adds implicit padding, but doesn't initialize it.
    // when used as a key in bpf world, the rust verifier complains that the value
    // is not initialized. Add the padding explicitly to work around this.
    pub _pad: [u8; 7],
}

impl SocketKey {
    pub fn new(cookie: u64, direction: Direction) -> Self {
        SocketKey {
            cookie,
            direction,
            _pad: [0; 7],
        }
    }

    pub fn reverse(&self) -> SocketKey {
        SocketKey {
            cookie: self.cookie,
            direction: if self.direction == Direction::INGRESS {
                Direction::EGRESS
            } else {
                Direction::INGRESS
            },
            _pad: [0; 7],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for SocketKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FlowKey {
    pub sip: u32,
    pub dip: u32,
    pub sport: u32,
    pub dport: u32,
}
#[cfg(feature = "user")]
unsafe impl Pod for FlowKey {}

impl FlowKey {
    pub fn reverse(&self) -> FlowKey {
        FlowKey {
            sip: self.dip,
            dip: self.sip,
            sport: self.dport,
            dport: self.sport,
        }
    }
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug)]
pub struct DelayConditioner {
    pub count: u32,
    pub offset: u64,
    pub jitter: u64,
}
#[cfg(feature = "user")]
unsafe impl Pod for DelayConditioner {}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug)]
pub struct ClassifyConditioner {
    pub classid: u32,
}
#[cfg(feature = "user")]
unsafe impl Pod for ClassifyConditioner {}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug)]
pub struct DropPacketConditioner {
    pub count: u32,
    pub range: u32,
}
#[cfg(feature = "user")]
unsafe impl Pod for DropPacketConditioner {}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug)]
pub struct Selector {
    pub data_offset_min: u32,
    pub data_offset_max: u32,
    pub flags: u32,
}
#[cfg(feature = "user")]
unsafe impl Pod for Selector {}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug)]
pub enum Conditioner {
    Delay(DelayConditioner),
    DropPacket(DropPacketConditioner),
    Classify(ClassifyConditioner),
}
#[cfg(feature = "user")]
unsafe impl Pod for Conditioner {}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug)]
pub struct FlowConfig {
    pub selector: Selector,
    pub conditioner: Conditioner,
}
#[cfg(feature = "user")]
unsafe impl Pod for FlowConfig {}
