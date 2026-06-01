//! KRPC: the four DHT message types (ping / find_node / get_peers /
//! announce_peer) and their bencoded wire format.
//!
//! Every message is a bencoded dict with at minimum a transaction id `t`
//! and a type discriminator `y` ∈ {`"q"`, `"r"`, `"e"`}. Queries also carry
//! `q` (the method name) and `a` (args dict); responses carry `r` (response
//! dict); errors carry `e` (a [code, message] list).
//!
//! Compact contact info (BEP 5):
//! - "nodes" string: concatenated 26-byte chunks (20 ID + 4 IP + 2 port BE).
//! - "values" list: each element is a 6-byte string (4 IP + 2 port BE).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::error::{Error, Result};
use crate::metainfo::BencodeValue;

use super::node_id::NodeId;
use super::routing::Contact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Ping {
        id: NodeId,
    },
    FindNode {
        id: NodeId,
        target: NodeId,
    },
    GetPeers {
        id: NodeId,
        info_hash: [u8; 20],
    },
    AnnouncePeer {
        id: NodeId,
        info_hash: [u8; 20],
        port: u16,
        token: Vec<u8>,
        implied_port: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Ping reply, or any reply where we know only `id`.
    Id { id: NodeId },
    /// Find-node reply.
    Nodes { id: NodeId, nodes: Vec<Contact> },
    /// Get-peers reply with peers directly.
    Peers {
        id: NodeId,
        token: Vec<u8>,
        values: Vec<SocketAddr>,
    },
    /// Get-peers reply with closer nodes to try.
    PeersNodes {
        id: NodeId,
        token: Vec<u8>,
        nodes: Vec<Contact>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Query {
        transaction_id: Vec<u8>,
        query: Query,
    },
    Response {
        transaction_id: Vec<u8>,
        response: Response,
    },
    Error {
        transaction_id: Vec<u8>,
        code: i64,
        message: String,
    },
}

fn b_bytes(v: &[u8]) -> BencodeValue {
    BencodeValue::Bytes(v.to_vec())
}

fn b_int(n: i64) -> BencodeValue {
    BencodeValue::Int(n)
}

fn b_list(v: Vec<BencodeValue>) -> BencodeValue {
    BencodeValue::List(v)
}

fn build_dict(entries: &[(&[u8], BencodeValue)]) -> BencodeValue {
    let mut d = BTreeMap::new();
    for (k, v) in entries {
        d.insert(k.to_vec(), v.clone());
    }
    BencodeValue::Dict(d)
}

/// Bencode encoder for any `BencodeValue` we construct. Implemented in this
/// module to avoid coupling the metainfo bencode parser to the DHT module;
/// it's a thin 50-line inverse of the parser.
pub fn encode(v: &BencodeValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &BencodeValue, out: &mut Vec<u8>) {
    match v {
        BencodeValue::Int(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        BencodeValue::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        BencodeValue::List(items) => {
            out.push(b'l');
            for item in items {
                encode_into(item, out);
            }
            out.push(b'e');
        }
        BencodeValue::Dict(d) => {
            out.push(b'd');
            for (k, v) in d {
                encode_into(&BencodeValue::Bytes(k.clone()), out);
                encode_into(v, out);
            }
            out.push(b'e');
        }
    }
}

pub fn nodes_to_bytes(nodes: &[Contact]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 26);
    for c in nodes {
        if let SocketAddr::V4(v4) = c.addr {
            out.extend_from_slice(c.id.as_bytes());
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        // Skip IPv6 contacts — compact form is v4-only per BEP 5.
    }
    out
}

pub fn parse_nodes_bytes(buf: &[u8]) -> Result<Vec<Contact>> {
    if !buf.len().is_multiple_of(26) {
        return Err(Error::Network(format!(
            "nodes length {} not multiple of 26",
            buf.len()
        )));
    }
    let mut out = Vec::with_capacity(buf.len() / 26);
    for chunk in buf.chunks_exact(26) {
        let mut id = [0u8; 20];
        id.copy_from_slice(&chunk[..20]);
        let ip = Ipv4Addr::new(chunk[20], chunk[21], chunk[22], chunk[23]);
        let port = u16::from_be_bytes([chunk[24], chunk[25]]);
        if port == 0 {
            continue;
        }
        out.push(Contact::new(
            NodeId(id),
            SocketAddr::new(IpAddr::V4(ip), port),
        ));
    }
    Ok(out)
}

fn values_to_list(values: &[SocketAddr]) -> BencodeValue {
    let mut out = Vec::new();
    for addr in values {
        if let SocketAddr::V4(v4) = addr {
            let mut bytes = [0u8; 6];
            bytes[..4].copy_from_slice(&v4.ip().octets());
            bytes[4..].copy_from_slice(&v4.port().to_be_bytes());
            out.push(b_bytes(&bytes));
        }
    }
    b_list(out)
}

pub fn parse_values_list(v: &BencodeValue) -> Result<Vec<SocketAddr>> {
    let list = v.as_list()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let b = item.as_bytes()?;
        if b.len() != 6 {
            // Some peers send IPv6 compact peers as 18-byte strings; ignore.
            continue;
        }
        let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        let port = u16::from_be_bytes([b[4], b[5]]);
        if port == 0 {
            continue;
        }
        out.push(SocketAddr::new(IpAddr::V4(ip), port));
    }
    Ok(out)
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::Query {
                transaction_id,
                query,
            } => match query {
                Query::Ping { id } => {
                    let args = build_dict(&[(b"id", b_bytes(id.as_bytes()))]);
                    encode(&build_dict(&[
                        (b"a", args),
                        (b"q", b_bytes(b"ping")),
                        (b"t", b_bytes(transaction_id)),
                        (b"y", b_bytes(b"q")),
                    ]))
                }
                Query::FindNode { id, target } => {
                    let args = build_dict(&[
                        (b"id", b_bytes(id.as_bytes())),
                        (b"target", b_bytes(target.as_bytes())),
                    ]);
                    encode(&build_dict(&[
                        (b"a", args),
                        (b"q", b_bytes(b"find_node")),
                        (b"t", b_bytes(transaction_id)),
                        (b"y", b_bytes(b"q")),
                    ]))
                }
                Query::GetPeers { id, info_hash } => {
                    let args = build_dict(&[
                        (b"id", b_bytes(id.as_bytes())),
                        (b"info_hash", b_bytes(info_hash)),
                    ]);
                    encode(&build_dict(&[
                        (b"a", args),
                        (b"q", b_bytes(b"get_peers")),
                        (b"t", b_bytes(transaction_id)),
                        (b"y", b_bytes(b"q")),
                    ]))
                }
                Query::AnnouncePeer {
                    id,
                    info_hash,
                    port,
                    token,
                    implied_port,
                } => {
                    let args = build_dict(&[
                        (b"id", b_bytes(id.as_bytes())),
                        (b"implied_port", b_int(if *implied_port { 1 } else { 0 })),
                        (b"info_hash", b_bytes(info_hash)),
                        (b"port", b_int(*port as i64)),
                        (b"token", b_bytes(token)),
                    ]);
                    encode(&build_dict(&[
                        (b"a", args),
                        (b"q", b_bytes(b"announce_peer")),
                        (b"t", b_bytes(transaction_id)),
                        (b"y", b_bytes(b"q")),
                    ]))
                }
            },
            Message::Response {
                transaction_id,
                response,
            } => {
                let r = match response {
                    Response::Id { id } => build_dict(&[(b"id", b_bytes(id.as_bytes()))]),
                    Response::Nodes { id, nodes } => build_dict(&[
                        (b"id", b_bytes(id.as_bytes())),
                        (b"nodes", b_bytes(&nodes_to_bytes(nodes))),
                    ]),
                    Response::Peers { id, token, values } => build_dict(&[
                        (b"id", b_bytes(id.as_bytes())),
                        (b"token", b_bytes(token)),
                        (b"values", values_to_list(values)),
                    ]),
                    Response::PeersNodes { id, token, nodes } => build_dict(&[
                        (b"id", b_bytes(id.as_bytes())),
                        (b"nodes", b_bytes(&nodes_to_bytes(nodes))),
                        (b"token", b_bytes(token)),
                    ]),
                };
                encode(&build_dict(&[
                    (b"r", r),
                    (b"t", b_bytes(transaction_id)),
                    (b"y", b_bytes(b"r")),
                ]))
            }
            Message::Error {
                transaction_id,
                code,
                message,
            } => {
                let e = b_list(vec![b_int(*code), b_bytes(message.as_bytes())]);
                encode(&build_dict(&[
                    (b"e", e),
                    (b"t", b_bytes(transaction_id)),
                    (b"y", b_bytes(b"e")),
                ]))
            }
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let v = BencodeValue::parse_all(buf).map_err(|e| Error::Network(format!("krpc: {e}")))?;
        let dict = v.as_dict()?;
        let txid = dict
            .get(&b"t".to_vec())
            .ok_or_else(|| Error::Network("krpc: missing t".into()))?
            .as_bytes()?
            .to_vec();
        let ty = dict
            .get(&b"y".to_vec())
            .ok_or_else(|| Error::Network("krpc: missing y".into()))?
            .as_bytes()?;
        match ty {
            b"q" => {
                let qname = dict
                    .get(&b"q".to_vec())
                    .ok_or_else(|| Error::Network("krpc: missing q".into()))?
                    .as_bytes()?;
                let args = dict
                    .get(&b"a".to_vec())
                    .ok_or_else(|| Error::Network("krpc: missing a".into()))?
                    .as_dict()?;
                let id = node_id_from(args, b"id")?;
                let query = match qname {
                    b"ping" => Query::Ping { id },
                    b"find_node" => {
                        let target = node_id_from(args, b"target")?;
                        Query::FindNode { id, target }
                    }
                    b"get_peers" => {
                        let info_hash = bytes20_from(args, b"info_hash")?;
                        Query::GetPeers { id, info_hash }
                    }
                    b"announce_peer" => {
                        let info_hash = bytes20_from(args, b"info_hash")?;
                        let port = args
                            .get(&b"port".to_vec())
                            .and_then(|v| v.as_int().ok())
                            .unwrap_or(0);
                        let token = args
                            .get(&b"token".to_vec())
                            .ok_or_else(|| Error::Network("ap: missing token".into()))?
                            .as_bytes()?
                            .to_vec();
                        let implied_port = args
                            .get(&b"implied_port".to_vec())
                            .and_then(|v| v.as_int().ok())
                            .unwrap_or(0)
                            != 0;
                        Query::AnnouncePeer {
                            id,
                            info_hash,
                            port: u16::try_from(port).unwrap_or(0),
                            token,
                            implied_port,
                        }
                    }
                    other => {
                        return Err(Error::Network(format!(
                            "krpc: unknown query {}",
                            String::from_utf8_lossy(other)
                        )))
                    }
                };
                Ok(Message::Query {
                    transaction_id: txid,
                    query,
                })
            }
            b"r" => {
                let r = dict
                    .get(&b"r".to_vec())
                    .ok_or_else(|| Error::Network("krpc: missing r".into()))?
                    .as_dict()?;
                let id = node_id_from(r, b"id")?;
                let nodes = r
                    .get(&b"nodes".to_vec())
                    .and_then(|v| v.as_bytes().ok())
                    .map(parse_nodes_bytes)
                    .transpose()?;
                let values = r
                    .get(&b"values".to_vec())
                    .map(parse_values_list)
                    .transpose()?;
                let token = r
                    .get(&b"token".to_vec())
                    .and_then(|v| v.as_bytes().ok())
                    .map(|b| b.to_vec());
                let response = match (nodes, values, token) {
                    (None, None, None) => Response::Id { id },
                    (Some(nodes), None, None) => Response::Nodes { id, nodes },
                    (None, Some(values), Some(token)) => Response::Peers { id, token, values },
                    (Some(nodes), None, Some(token)) => Response::PeersNodes { id, token, nodes },
                    (Some(nodes), Some(values), Some(token)) => {
                        // Some clients send both — prefer values when present.
                        let _ = nodes;
                        Response::Peers { id, token, values }
                    }
                    _ => Response::Id { id },
                };
                Ok(Message::Response {
                    transaction_id: txid,
                    response,
                })
            }
            b"e" => {
                let err_list = dict
                    .get(&b"e".to_vec())
                    .ok_or_else(|| Error::Network("krpc: missing e".into()))?
                    .as_list()?;
                if err_list.len() < 2 {
                    return Err(Error::Network("krpc: malformed error".into()));
                }
                let code = err_list[0].as_int()?;
                let message = err_list[1].as_str().unwrap_or("").to_string();
                Ok(Message::Error {
                    transaction_id: txid,
                    code,
                    message,
                })
            }
            other => Err(Error::Network(format!(
                "krpc: unknown y {}",
                String::from_utf8_lossy(other)
            ))),
        }
    }
}

fn node_id_from(dict: &BTreeMap<Vec<u8>, BencodeValue>, key: &[u8]) -> Result<NodeId> {
    Ok(NodeId(bytes20_from(dict, key)?))
}

fn bytes20_from(dict: &BTreeMap<Vec<u8>, BencodeValue>, key: &[u8]) -> Result<[u8; 20]> {
    let bytes = dict
        .get(&key.to_vec())
        .ok_or_else(|| Error::Network(format!("krpc: missing {}", String::from_utf8_lossy(key))))?
        .as_bytes()?;
    if bytes.len() != 20 {
        return Err(Error::Network(format!(
            "krpc: {} must be 20 bytes, got {}",
            String::from_utf8_lossy(key),
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(m: Message) {
        let bytes = m.encode();
        let decoded = Message::decode(&bytes).expect("decode");
        assert_eq!(decoded, m);
    }

    #[test]
    fn ping_query_roundtrip() {
        roundtrip(Message::Query {
            transaction_id: b"aa".to_vec(),
            query: Query::Ping {
                id: NodeId([0xAB; 20]),
            },
        });
    }

    #[test]
    fn find_node_query_roundtrip() {
        roundtrip(Message::Query {
            transaction_id: b"bb".to_vec(),
            query: Query::FindNode {
                id: NodeId([0x11; 20]),
                target: NodeId([0x22; 20]),
            },
        });
    }

    #[test]
    fn get_peers_query_roundtrip() {
        roundtrip(Message::Query {
            transaction_id: b"cc".to_vec(),
            query: Query::GetPeers {
                id: NodeId([0x33; 20]),
                info_hash: [0x44; 20],
            },
        });
    }

    #[test]
    fn announce_query_roundtrip() {
        roundtrip(Message::Query {
            transaction_id: b"dd".to_vec(),
            query: Query::AnnouncePeer {
                id: NodeId([0x55; 20]),
                info_hash: [0x66; 20],
                port: 6881,
                token: b"opaque-token".to_vec(),
                implied_port: false,
            },
        });
    }

    #[test]
    fn ping_response_roundtrip() {
        roundtrip(Message::Response {
            transaction_id: b"aa".to_vec(),
            response: Response::Id {
                id: NodeId([0xAB; 20]),
            },
        });
    }

    #[test]
    fn nodes_response_roundtrip() {
        let nodes = vec![
            Contact::new(NodeId([0x01; 20]), "1.2.3.4:5678".parse().unwrap()),
            Contact::new(NodeId([0x02; 20]), "10.20.30.40:6881".parse().unwrap()),
        ];
        let m = Message::Response {
            transaction_id: b"xx".to_vec(),
            response: Response::Nodes {
                id: NodeId([0x77; 20]),
                nodes,
            },
        };
        let bytes = m.encode();
        let dec = Message::decode(&bytes).unwrap();
        match dec {
            Message::Response {
                response: Response::Nodes { id, nodes },
                ..
            } => {
                assert_eq!(id, NodeId([0x77; 20]));
                assert_eq!(nodes.len(), 2);
                assert_eq!(nodes[0].addr.port(), 5678);
                assert_eq!(nodes[1].addr.port(), 6881);
            }
            _ => panic!("expected Nodes response"),
        }
    }

    #[test]
    fn peers_response_roundtrip() {
        let values: Vec<SocketAddr> = vec![
            "1.2.3.4:5678".parse().unwrap(),
            "10.20.30.40:6881".parse().unwrap(),
        ];
        let m = Message::Response {
            transaction_id: b"yy".to_vec(),
            response: Response::Peers {
                id: NodeId([0x88; 20]),
                token: b"tk".to_vec(),
                values: values.clone(),
            },
        };
        let bytes = m.encode();
        let dec = Message::decode(&bytes).unwrap();
        match dec {
            Message::Response {
                response:
                    Response::Peers {
                        id,
                        token,
                        values: vs,
                    },
                ..
            } => {
                assert_eq!(id, NodeId([0x88; 20]));
                assert_eq!(token, b"tk");
                assert_eq!(vs, values);
            }
            _ => panic!("expected Peers response"),
        }
    }

    #[test]
    fn error_roundtrip() {
        roundtrip(Message::Error {
            transaction_id: b"ee".to_vec(),
            code: 201,
            message: "Generic".into(),
        });
    }

    /// Known KRPC ping query from BEP 5:
    /// d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe
    #[test]
    fn bep5_ping_example_decodes() {
        let raw = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        let m = Message::decode(raw).unwrap();
        match m {
            Message::Query {
                transaction_id,
                query: Query::Ping { id },
            } => {
                assert_eq!(transaction_id, b"aa");
                assert_eq!(id.as_bytes(), b"abcdefghij0123456789");
            }
            other => panic!("expected ping query, got {other:?}"),
        }
    }
}
