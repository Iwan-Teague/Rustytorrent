//! Kademlia k-bucket routing table.
//!
//! Standard layout: 160 buckets indexed by the position of the highest
//! differing bit between our `local_id` and the contact's id. Each bucket
//! holds at most K=8 contacts, ordered most-recently-seen last.
//!
//! We use the "single-bucket-per-index" variant instead of the
//! split-on-overflow tree. It's simpler and serves a few-hundred-node
//! routing table just fine for opportunistic peer discovery; libtorrent's
//! splittable-tree gives marginally better locality but adds significant
//! complexity that this client doesn't need.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::node_id::NodeId;

pub const K: usize = 8;

/// Considered "good" if seen this recently. Per BEP 5.
pub const GOOD_NODE_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub last_seen: Instant,
}

impl Contact {
    pub fn new(id: NodeId, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            last_seen: Instant::now(),
        }
    }

    pub fn is_good(&self) -> bool {
        self.last_seen.elapsed() < GOOD_NODE_TTL
    }
}

#[derive(Debug, Default, Clone)]
pub struct KBucket {
    contacts: Vec<Contact>,
}

impl KBucket {
    /// Insert a contact. Returns `true` if it was added or refreshed.
    ///
    /// Policy:
    /// - If the contact's id is already present, refresh its `last_seen`
    ///   and move it to the end of the bucket (most-recently-seen).
    /// - If the bucket has room, append.
    /// - If the bucket is full but contains a stale ("not good") contact,
    ///   evict the oldest stale one and append.
    /// - Otherwise reject (return `false`).
    pub fn insert(&mut self, contact: Contact) -> bool {
        if let Some(pos) = self.contacts.iter().position(|c| c.id == contact.id) {
            let mut existing = self.contacts.remove(pos);
            existing.last_seen = contact.last_seen;
            existing.addr = contact.addr;
            self.contacts.push(existing);
            return true;
        }
        if self.contacts.len() < K {
            self.contacts.push(contact);
            return true;
        }
        // Bucket full — evict the oldest stale contact, if any.
        if let Some(stale_pos) = self.contacts.iter().position(|c| !c.is_good()) {
            self.contacts.remove(stale_pos);
            self.contacts.push(contact);
            return true;
        }
        false
    }

    pub fn contacts(&self) -> &[Contact] {
        &self.contacts
    }

    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_id: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        Self {
            local_id,
            buckets: vec![KBucket::default(); 160],
        }
    }

    pub fn local_id(&self) -> NodeId {
        self.local_id
    }

    /// Insert a contact under the bucket corresponding to its distance from us.
    /// Returns `true` if the contact landed in a bucket (or refreshed an entry).
    pub fn insert(&mut self, contact: Contact) -> bool {
        if contact.id == self.local_id {
            return false;
        }
        let bucket = match self.local_id.bucket_index(&contact.id) {
            Some(i) => i,
            None => return false,
        };
        self.buckets[bucket].insert(contact)
    }

    /// Return up to `count` contacts closest (XOR) to `target`, sorted nearest-first.
    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<Contact> {
        let mut all: Vec<Contact> = self
            .buckets
            .iter()
            .flat_map(|b| b.contacts().iter().cloned())
            .collect();
        all.sort_by_key(|c| c.id.distance(target));
        all.truncate(count);
        all
    }

    /// Total number of contacts across all buckets.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(seed: u8, port: u16) -> Contact {
        let mut id = [0u8; 20];
        id[0] = seed;
        Contact::new(
            NodeId(id),
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
        )
    }

    #[test]
    fn bucket_fills_to_k() {
        let mut b = KBucket::default();
        for i in 0..K {
            assert!(b.insert(contact(i as u8, 1000 + i as u16)));
        }
        assert_eq!(b.len(), K);
        // Bucket full, all entries fresh — new contact rejected.
        let new = contact(99, 9999);
        assert!(!b.insert(new));
    }

    #[test]
    fn bucket_refreshes_existing() {
        let mut b = KBucket::default();
        let c = contact(1, 1000);
        let id = c.id;
        assert!(b.insert(c));
        let c2 = Contact::new(id, "127.0.0.1:2000".parse().unwrap());
        assert!(b.insert(c2));
        assert_eq!(b.len(), 1);
        assert_eq!(b.contacts()[0].addr.port(), 2000);
    }

    #[test]
    fn routing_table_inserts_into_correct_bucket() {
        // local = all zeros.
        let mut rt = RoutingTable::new(NodeId([0u8; 20]));
        // Contact with first byte = 0x80 → bucket 159.
        let mut id = [0u8; 20];
        id[0] = 0x80;
        rt.insert(Contact::new(NodeId(id), "127.0.0.1:1234".parse().unwrap()));
        // Contact with last byte = 0x01 → bucket 0.
        let mut id2 = [0u8; 20];
        id2[19] = 0x01;
        rt.insert(Contact::new(NodeId(id2), "127.0.0.1:5678".parse().unwrap()));
        assert_eq!(rt.len(), 2);
        assert_eq!(rt.buckets[159].len(), 1);
        assert_eq!(rt.buckets[0].len(), 1);
    }

    #[test]
    fn closest_returns_nearest_first() {
        let mut rt = RoutingTable::new(NodeId([0u8; 20]));
        // Three contacts at varying distances from target 0x42.
        let mut target = [0u8; 20];
        target[0] = 0x42;
        let target = NodeId(target);

        let mut a = [0u8; 20];
        a[0] = 0x40;
        let mut b = [0u8; 20];
        b[0] = 0x80;
        let mut c = [0u8; 20];
        c[0] = 0x43;
        for id in [a, b, c] {
            rt.insert(Contact::new(NodeId(id), "127.0.0.1:1".parse().unwrap()));
        }
        let nearest = rt.closest(&target, 3);
        // distances from 0x42: 0x40→0x02, 0x80→0xC2, 0x43→0x01
        // sorted ascending: 0x43, 0x40, 0x80
        assert_eq!(nearest[0].id.0[0], 0x43);
        assert_eq!(nearest[1].id.0[0], 0x40);
        assert_eq!(nearest[2].id.0[0], 0x80);
    }

    #[test]
    fn routing_table_ignores_self() {
        let id = NodeId([5u8; 20]);
        let mut rt = RoutingTable::new(id);
        assert!(!rt.insert(Contact::new(id, "127.0.0.1:1".parse().unwrap())));
        assert_eq!(rt.len(), 0);
    }
}
