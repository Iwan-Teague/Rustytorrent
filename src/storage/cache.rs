//! In-memory LRU cache of whole pieces, used to avoid hitting disk for every
//! upload-side Request from a peer.
//!
//! Each cached entry holds the full piece bytes. A typical 256 KiB piece
//! contributes 16 blocks of 16 KiB each to peers; without this cache every
//! block triggers an independent disk seek+read.
//!
//! Sync-safe: wrapped in `Arc<Mutex<…>>` at the call site so the engine and
//! upload-helper tasks share a single cache.

use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use tokio::sync::Mutex;

/// Default capacity. 32 pieces × 256 KiB = 8 MiB upper-bound footprint for
/// typical torrents; small enough to never matter, large enough to absorb
/// a few simultaneous leechers grabbing the same piece block-by-block.
pub const DEFAULT_CAPACITY: usize = 32;

#[derive(Clone)]
pub struct PieceCache {
    inner: Arc<Mutex<LruCache<u32, Arc<Vec<u8>>>>>,
}

impl PieceCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity > 0");
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(cap))),
        }
    }

    /// Fetch a previously-cached piece. Touches the LRU recency for it.
    pub async fn get(&self, index: u32) -> Option<Arc<Vec<u8>>> {
        let mut cache = self.inner.lock().await;
        cache.get(&index).cloned()
    }

    /// Insert a piece. Evicts the least-recently-used entry if at capacity.
    pub async fn insert(&self, index: u32, data: Arc<Vec<u8>>) {
        let mut cache = self.inner.lock().await;
        cache.put(index, data);
    }

    /// Drop a single entry — used when a piece is re-verified as bad.
    pub async fn invalidate(&self, index: u32) {
        let mut cache = self.inner.lock().await;
        cache.pop(&index);
    }
}

impl Default for PieceCache {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_after_insert() {
        let cache = PieceCache::new(4);
        let data = Arc::new(vec![1u8, 2, 3]);
        cache.insert(7, data.clone()).await;
        let got = cache.get(7).await.unwrap();
        assert_eq!(*got, vec![1u8, 2, 3]);
    }

    #[tokio::test]
    async fn evicts_lru_when_full() {
        let cache = PieceCache::new(2);
        cache.insert(1, Arc::new(vec![1])).await;
        cache.insert(2, Arc::new(vec![2])).await;
        // Touch 1 to mark it more recent than 2.
        let _ = cache.get(1).await;
        cache.insert(3, Arc::new(vec![3])).await;
        // 2 should have been evicted.
        assert!(cache.get(2).await.is_none());
        assert!(cache.get(1).await.is_some());
        assert!(cache.get(3).await.is_some());
    }

    #[tokio::test]
    async fn invalidate_removes() {
        let cache = PieceCache::new(4);
        cache.insert(1, Arc::new(vec![1, 2])).await;
        cache.invalidate(1).await;
        assert!(cache.get(1).await.is_none());
    }
}
