use anyhow::{Context, Result};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::path::Path;

/// Trait for checking if a network interface is virtual
pub trait InterfaceVirtualChecker {
    /// Check if the given interface is virtual
    /// Returns Ok(true) if virtual, Ok(false) if physical, Err for filesystem errors
    fn is_virtual(&mut self, iface_name: &str) -> Result<bool>;
}

/// Cached implementation of InterfaceVirtualChecker using LRU cache
pub struct CachedInterfaceVirtualChecker {
    cache: LruCache<String, bool>,
}

impl CachedInterfaceVirtualChecker {
    /// Create a new cached interface virtual checker with default capacity (100)
    pub fn new() -> Self {
        Self::with_capacity(100)
    }

    /// Create a new cached interface virtual checker with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(100).unwrap());
        Self {
            cache: LruCache::new(capacity),
        }
    }

    /// Check the filesystem directly for interface virtual status
    fn check_virtual_iface(&self, iface_name: &str) -> Result<bool> {
        // Physical interfaces have /sys/class/net/<interface>/device symlink
        // Virtual interfaces don't have this symlink
        let device_path = format!("/sys/class/net/{}/device", iface_name);
        Ok(!Path::new(&device_path).exists())
    }
}

impl Default for CachedInterfaceVirtualChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceVirtualChecker for CachedInterfaceVirtualChecker {
    fn is_virtual(&mut self, iface_name: &str) -> Result<bool> {
        // Check cache first
        if let Some(&is_virtual) = self.cache.get(iface_name) {
            return Ok(is_virtual);
        }

        // Not in cache, check filesystem
        let is_virtual = self
            .check_virtual_iface(iface_name)
            .with_context(|| format!("Failed to check if interface '{}' is virtual", iface_name))?;

        // Store result in cache
        self.cache.put(iface_name.to_string(), is_virtual);

        Ok(is_virtual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_interface_virtual_checker_basic() {
        let mut checker = CachedInterfaceVirtualChecker::new();

        // Test that known interface names return consistent results
        // Note: These tests work by checking filesystem, so results depend on the system
        let interface_name = "lo";

        let result1 = checker.is_virtual(interface_name);
        let result2 = checker.is_virtual(interface_name);

        // Both calls should return same result
        match (result1, result2) {
            (Ok(val1), Ok(val2)) => assert_eq!(val1, val2),
            _ => panic!("Interface checker should not fail for loopback interface"),
        }
    }

    #[test]
    fn test_trait_object() {
        let mut checker: Box<dyn InterfaceVirtualChecker> =
            Box::new(CachedInterfaceVirtualChecker::new());

        // Should work through trait object
        let result = checker.is_virtual("lo");
        assert!(result.is_ok());
    }
}
