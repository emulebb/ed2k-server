//! SmartSources cache (SPEC.md §6.2.6).
//!
//! GETSOURCES is the hot path on a busy eD2k server — for popular files,
//! hundreds of clients ask for the same hash within seconds. Rebuilding the
//! source list and re-encoding the FOUNDSOURCES payload for every one of
//! those identical requests is wasted work.
//!
//! This cache stores the *already-encoded* FOUNDSOURCES payload bytes for a
//! canonical file id, for a short TTL (a few seconds). Within that window every
//! GETSOURCES for the same `(hash, size)` is answered from the cache with a single
//! HashMap lookup and a clone — no source-list iteration, no re-encoding.
//!
//! The TTL is deliberately short: source lists change as clients come and
//! go, and a few seconds of staleness is harmless (clients re-query often).
//! Short TTL also bounds memory — entries for files nobody is asking about
//! expire and get swept.
//!
//! Design notes for the small-VPS target:
//!   * Pure in-memory, no disk.
//!   * Bounded size — when the map exceeds MAX_ENTRIES we sweep expired
//!     entries; if still over, we clear it (cheap, correctness-preserving).
//!   * One Mutex around a HashMap. GETSOURCES handlers are short; contention
//!     is not a concern at the hundreds-of-clients scale.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::file_id::FileId;

/// How long a cached FOUNDSOURCES payload stays fresh.
const CACHE_TTL: Duration = Duration::from_secs(5);

/// Soft cap on the number of cached file entries. Beyond this we sweep /
/// clear. At ~22 bytes-per-source * 200 sources that's a few MB worst case.
const MAX_ENTRIES: usize = 4096;

struct CacheEntry {
    /// Fully-encoded FOUNDSOURCES payload (everything after proto+opcode).
    payload: Vec<u8>,
    /// Who each record in `payload` belongs to, in record order: the first 8
    /// bytes of the source's user hash. The payload is shared by every
    /// requester of the file, so it is built with ALL sources and the asker's
    /// own record is dropped when it is served (see `get_with`).
    owners: Vec<u64>,
    /// When this entry was inserted.
    inserted: Instant,
}

/// Thread-safe SmartSources cache, keyed by canonical file id.
pub struct SmartSourcesCache {
    map: Mutex<HashMap<FileId, CacheEntry>>,
    /// Served-from-cache count (fresh entry found).
    hits: AtomicU64,
    /// Cache-miss count (no entry, or entry expired). Equivalent to a rebuild.
    misses: AtomicU64,
}

impl SmartSourcesCache {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached FOUNDSOURCES payload for `file_id`.
    /// Returns the payload bytes if a fresh entry exists, else None.
    pub fn get(&self, file_id: FileId) -> Option<Vec<u8>> {
        let map = self.map.lock().unwrap();
        let entry = match map.get(&file_id) {
            Some(e) => e,
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if entry.inserted.elapsed() < CACHE_TTL {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.payload.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Like `get`, but hands the fresh payload and its owner list to `f` under
    /// the lock and returns what `f` builds — so a requester-specific answer is
    /// cut from the shared payload without cloning it first.
    pub fn get_with<R>(&self, file_id: FileId, f: impl FnOnce(&[u8], &[u64]) -> R) -> Option<R> {
        let map = self.map.lock().unwrap();
        let entry = match map.get(&file_id) {
            Some(e) => e,
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if entry.inserted.elapsed() < CACHE_TTL {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(f(&entry.payload, &entry.owners))
        } else {
            // Expired — counts as a miss (the caller will rebuild). We leave it
            // for the next insert() to sweep; keeping the lock simple avoids
            // upgrade churn.
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Cache statistics: (hits, misses). Used by the admin Status page to show
    /// the real GETSOURCES cache hit rate.
    /// Heap bytes held by the cache (for /api/memsize): map slots plus each
    /// entry's encoded payload buffer (by capacity).
    pub fn size_bytes(&self) -> u64 {
        let m = self.map.lock().unwrap();
        let slots = (m.capacity()
            * (std::mem::size_of::<FileId>() + std::mem::size_of::<CacheEntry>() + 1))
            as u64;
        let payloads: u64 = m
            .values()
            .map(|e| (e.payload.capacity() + e.owners.capacity() * 8) as u64)
            .sum();
        slots + payloads
    }

    /// Number of cached entries (diagnostics).
    pub fn entry_count(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Store a freshly-built FOUNDSOURCES payload for `file_id`, with the owner
    /// of each record (see `CacheEntry::owners`).
    pub fn put(&self, file_id: FileId, payload: Vec<u8>, owners: Vec<u64>) {
        let mut map = self.map.lock().unwrap();

        // Bound memory: if the map is getting large, sweep expired entries
        // first; if that's not enough, clear it entirely. Clearing is safe —
        // it just means the next requests rebuild and re-cache.
        if map.len() >= MAX_ENTRIES {
            let now = Instant::now();
            map.retain(|_, e| now.duration_since(e.inserted) < CACHE_TTL);
            if map.len() >= MAX_ENTRIES {
                map.clear();
            }
        }

        map.insert(
            file_id,
            CacheEntry {
                payload,
                owners,
                inserted: Instant::now(),
            },
        );
    }

    /// Invalidate the cached entry for a file — call when its source list
    /// changes in a way that matters (e.g. a new source was added). This is
    /// optional: the short TTL means stale entries self-heal anyway, so
    /// callers may skip invalidation on the hot path and just let TTL handle it.
    pub fn invalidate(&self, file_id: FileId) {
        let mut map = self.map.lock().unwrap();
        map.remove(&file_id);
    }

    /// Number of currently-cached entries (including not-yet-swept expired
    /// ones). Intended for stats/metrics, not correctness.
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

impl Default for SmartSourcesCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_then_miss_after_ttl() {
        let cache = SmartSourcesCache::new();
        let file_id = FileId(7);
        let payload = vec![1, 2, 3, 4, 5];

        cache.put(file_id, payload.clone(), Vec::new());

        // Immediate get is a hit with identical bytes.
        assert_eq!(cache.get(file_id), Some(payload));

        // A different hash is a miss.
        assert_eq!(cache.get(FileId(9)), None);
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = SmartSourcesCache::new();
        let file_id = FileId(3);
        cache.put(file_id, vec![0xAA, 0xBB], Vec::new());
        assert!(cache.get(file_id).is_some());

        cache.invalidate(file_id);
        assert!(cache.get(file_id).is_none());
    }

    #[test]
    fn expired_entry_is_a_miss() {
        // We can't easily fast-forward Instant, so this test validates the
        // logic path by constructing an entry with an old timestamp directly.
        let cache = SmartSourcesCache::new();
        let file_id = FileId(5);
        {
            let mut map = cache.map.lock().unwrap();
            map.insert(
                file_id,
                CacheEntry {
                    payload: vec![1, 2, 3],
                    owners: Vec::new(),
                    inserted: Instant::now() - Duration::from_secs(60),
                },
            );
        }
        // Entry exists but is well past TTL → get() returns None.
        assert_eq!(cache.get(file_id), None);
    }

    #[test]
    fn put_overwrites_with_fresh_timestamp() {
        let cache = SmartSourcesCache::new();
        let file_id = FileId(1);
        cache.put(file_id, vec![0x01], Vec::new());
        cache.put(file_id, vec![0x02, 0x03], Vec::new());
        // Latest put wins.
        assert_eq!(cache.get(file_id), Some(vec![0x02, 0x03]));
    }

    #[test]
    fn stats_count_hits_and_misses() {
        let cache = SmartSourcesCache::new();
        let file_id = FileId(4);
        assert_eq!(cache.get(file_id), None); // miss (no entry)
        cache.put(file_id, vec![1, 2, 3], Vec::new());
        assert!(cache.get(file_id).is_some()); // hit
        let (hits, misses) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }
}
