//! GETSOURCES → FOUNDSOURCES handler (SPEC.md §3.5).
//!
//! Single-hash lookup. Returns up to N source endpoints for a file.
//! In production this is the hot path (~80% of total server load) and
//! would be backed by SmartSources cache; MVP does direct lookup.

use crate::proto::{opcodes::*, Frame};
use crate::state::{ClientHandle, ServerState};
use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use tracing::debug;

/// Maximum sources returned per response (SPEC.md §6.2.6 SmartSources tiers).
const MAX_SOURCES_PER_REPLY: usize = 200;

/// ClientID marking an inline IPv6 source. `255.255.255.255` is never a real
/// client, so the value is unambiguous. Agreed with eMuleQt and eNode-go.
pub const IPV6_SOURCE_SENTINEL: u32 = 0xFFFF_FFFF;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceReplyFormat {
    Classic,
    Obfuscated,
}

impl SourceReplyFormat {
    fn opcode(self) -> u8 {
        match self {
            Self::Classic => OP_FOUNDSOURCES,
            Self::Obfuscated => OP_FOUNDSOURCES_OBFU,
        }
    }
}

#[derive(Debug)]
pub struct GetSourcesRequest {
    pub file_hash: [u8; 16],
    /// File size, encoded as v2 (4 bytes) or v2-large (4 + 4 bytes) extension.
    pub size: Option<u64>,
}

impl GetSourcesRequest {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 16 {
            return Err(anyhow!("GETSOURCES too short ({} bytes)", payload.len()));
        }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&payload[0..16]);

        // v2:       payload[16..20] = size as u32
        // v2-large: payload[16..20] = 0 (sentinel), payload[20..28] = size as u64 LE
        //
        // The layout comes straight from eMule, DownloadQueue.cpp:1352-1357:
        //
        //     if (!cur_file->IsLargeFile())
        //         smPacket.WriteUInt32((uint32)(uint64)cur_file->GetFileSize());
        //     else {
        //         smPacket.WriteUInt32(0);   // large-file marker, a u64 follows
        //         smPacket.WriteUInt64(cur_file->GetFileSize());
        //     }
        //
        // and `WriteUInt64` is `Write(&nVal, sizeof nVal)` (SafeFile.cpp:155), a
        // raw little-endian u64 — LOW dword first.
        //
        // This used to read [20..24] as the HIGH half and [24..28] as the low
        // one, i.e. the two words swapped, so a 6 GiB file decoded as
        // 9223372036854775809 instead of 6442450944.
        let size = if payload.len() >= 20 {
            let lo = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
            if lo == 0 && payload.len() >= 28 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&payload[20..28]);
                Some(u64::from_le_bytes(b))
            } else {
                Some(lo as u64)
            }
        } else {
            None
        };

        Ok(Self {
            file_hash: hash,
            size,
        })
    }
}

/// Build the matching FOUNDSOURCES frame for the given request. Returns Frame
/// even when there are no sources (count=0) — clients expect a reply for every
/// request.
///
/// Hot-path optimization: results are cached in the SmartSources cache for a
/// few seconds. For popular files this turns a source-list iteration + encode
/// into a single map lookup. The cache key is the file hash; the requester is
/// not part of the key, so we must still filter "self" out of a cache hit —
/// but that's a cheap scan over an already-built payload, done below.
/// A well-formed FOUNDSOURCES payload carrying zero sources.
///
/// Clients expect a reply to every request, so a listed file answers "nobody
/// has it" rather than staying silent — silence just makes the client re-ask.
fn encode_empty_sources(file_hash: &[u8; 16]) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(17);
    payload.put_slice(file_hash);
    payload.put_u8(0);
    payload.to_vec()
}

pub(crate) fn handle_get_sources(
    state: &ServerState,
    requester: &ClientHandle,
    req: GetSourcesRequest,
    reply_format: SourceReplyFormat,
) -> Frame {
    // Hash lists first, BEFORE the cache. Handing out sources is how a download
    // actually starts, so a listed file must stop being served here too, not
    // just stop appearing in search — otherwise a client that already has the
    // ed2k link still gets peers for it.
    //
    // Ahead of the cache on purpose: a cached payload built before the hash was
    // listed would otherwise keep being served for the life of its TTL.
    let indexed_file = state
        .file_slab
        .with_record_by_hash(&req.file_hash, |_id, r| (r.name().to_string(), r.size));
    if state
        .filter
        .is_withheld_opt(
            &req.file_hash,
            indexed_file.as_ref().map(|(name, _size)| name.as_str()),
        )
    {
        debug!(
            file_hash = hex::encode(req.file_hash),
            "getsources refused: file is withheld by the content filter"
        );
        return Frame::new(reply_format.opcode(), encode_empty_sources(&req.file_hash));
    }

    if let (Some(requested_size), Some((_name, indexed_size))) = (req.size, indexed_file) {
        if requested_size != indexed_size {
            debug!(
                file_hash = hex::encode(req.file_hash),
                requested_size,
                indexed_size,
                "getsources refused: requested size does not match indexed file"
            );
            return Frame::new(reply_format.opcode(), encode_empty_sources(&req.file_hash));
        }
    }

    // Whether this requester gets inline IPv6 records. Decided once, and it
    // also decides whether the cache may be used at all.
    //
    // ⚠ ONLY A LowID REQUESTER (issue #33). A HighID requester reaches a LowID
    //   source by OP_CALLBACKREQUEST, which works whenever the requester is
    //   HighID. Handing it the sentinel instead took that away and left only a
    //   dial to the source's IPv6, an address taken from the login tag and
    //   never checked: many home routers drop inbound IPv6, so the dial often
    //   failed with nothing to fall back on. A LowID requester cannot use a
    //   callback, so for it the IPv6 path is the only one and it keeps it. A
    //   session that arrived over IPv6 is always LowID (an eD2k id is an IPv4
    //   address), so it keeps the sentinel too.
    let live = state.live_cfg.load();
    let v6_capable = live.network.ipv6_publish_sources
        && requester.ipv6_capable
        && !requester.is_high_id;
    let private_highid_routes = live.network.private_highid_probe
        && matches!(requester.ip, std::net::IpAddr::V4(ip) if ip.is_private());
    let requester_specific = reply_format == SourceReplyFormat::Obfuscated
        || !requester.is_high_id
        || private_highid_routes;

    // Fast path: a freshly-cached payload for this hash.
    //
    // ⚠ NOT FOR A REQUESTER-SPECIFIC REPLY. The cache is keyed on the file hash
    //   alone. LowID source eligibility depends on the requester's NAT-T
    //   capability, IPv6-capable requesters receive longer sentinel records,
    //   and verified private HighID routes must never reach public requesters.
    //
    //   Bypassing rather than adding the capability to the key, because the
    //   cache exists to absorb bursts of identical public HighID requests. The
    //   requester-specific classes are uncommon and correctness matters more
    //   than splitting this hot cache into several key spaces.
    let me = owner_key(&requester.user_hash);
    if !requester_specific {
        if let Some(payload) = state
            .smart_sources
            .get_with(&req.file_hash, |p, owners| without_owner(p, owners, me))
        {
            debug!(
                file_hash = hex::encode(req.file_hash),
                "getsources answered from SmartSources cache"
            );
            return Frame::new(OP_FOUNDSOURCES, payload);
        }
    }

    // Slow path: build the source list from the index.
    // Only the sources are copied out, not the whole record and its name.
    let sources = state
        .file_slab
        .with_record_by_hash(&req.file_hash, |_id, entry| {
            entry
                .sources
                .iter()
                // The requester is NOT filtered out here: the payload built
                // from this list is cached and served to everyone who asks for
                // the file, so it must contain every source. Each requester's
                // own record is removed when the payload is served (below, and
                // on a cache hit above). One extra is taken so that removing
                // it still leaves a full reply.
                //
                // Requester-specific filtering happens after this lock is
                // released because it consults the live-client map. Walk the
                // whole source set in that rare path so ineligible LowID peers
                // at the front cannot hide usable HighID peers behind them.
                .take(if requester_specific {
                    usize::MAX
                } else {
                    MAX_SOURCES_PER_REPLY + 1
                })
                .copied()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    debug!(
        file_hash = hex::encode(req.file_hash),
        source_count = sources.len(),
        "getsources answered (rebuilt)"
    );

    // The count byte has to match what actually gets written, and the loop below
    // can skip a source, so the entries are built first and the real count is
    // prefixed afterwards. Writing sources.len() and then emitting fewer would
    // leave the client parsing past the end of the payload.
    let mut entries = BytesMut::new();
    let mut emitted: u8 = 0;
    let mut owners: Vec<u64> = Vec::with_capacity(if requester_specific {
        0
    } else {
        sources.len()
    });
    for s in &sources {
        // A requester-specific reply is never cached, so it is built for this
        // requester alone: skip their own record and stop at the cap here. A
        // shared HighID payload keeps everyone; it is cut per requester later.
        if requester_specific {
            if s.user_hash == requester.user_hash {
                continue;
            }
            if emitted as usize == MAX_SOURCES_PER_REPLY {
                break;
            }
        }
        // Encode the source ID the way eD2k clients expect:
        //   * HighID source  -> its real IPv4 (client connects directly)
        //   * LowID source   -> its server-assigned low ID (< 0x01000000), so the
        //     downloader recognizes it as LowID (::IsLowID) and uses a callback /
        //     (with our mod) a NAT-traversal hole punch instead of a doomed direct
        //     connect to the firewalled peer's real IP.
        // We discover LowID-ness by looking the source up in the live client map
        // by user_hash; if it's currently connected and firewalled, use its low id.
        // If the client isn't found (stale source) we fall back to the real IP —
        // same behavior as before this change.
        // ── IPv6 sentinel ────────────────────────────────────────────────
        //
        // Only when ALL of these hold, and each guards a different failure:
        //
        //   * the requester can parse it. A classic record is 6 bytes; this one
        //     is 22 (or more, with the obfuscation fields). Sending it to a
        //     client that does not know the sentinel makes it read the next
        //     record from the middle of this one and mis-parse everything after.
        //   * the source has no usable IPv4 HighID. A HighID peer is directly
        //     reachable over IPv4 already, so its record stays classic and no
        //     requester loses anything. Only a firewalled-on-v4 peer gains from
        //     publishing the v6 path — matching what the other server doing
        //     this decided, so both produce the same answer for the same source.
        //   * the address survives the same publishability rules as IPv4.
        //
        // A requester that cannot parse the sentinel still gets the LowID for
        // that same source and reaches it by callback, exactly as before. That
        // is why gating per requester loses nothing rather than forcing a choice
        // between the two addresses.
        let source_handle = state.clients.get(&s.user_hash);
        let source_is_live_lowid = source_handle
            .as_ref()
            .map(|handle| !handle.is_high_id)
            .unwrap_or(false);
        let v6 = if v6_capable && source_is_live_lowid {
            state
                .client_ipv6
                .get(&s.user_hash)
                .map(|e| *e.value())
                .filter(|a| crate::server::login::is_publishable_ipv6(*a))
        } else {
            None
        };

        // Classic eD2k has no usable LowID-to-LowID route. Preserve that source
        // only when both live clients advertised this server's NAT-T extension.
        // A HighID requester can still reach a LowID source through callback,
        // and a publishable IPv6 sentinel is already a direct route.
        if v6.is_none() && source_is_live_lowid && !requester.is_high_id {
            let source_is_natt = source_handle
                .as_ref()
                .map(|handle| handle.natt_capable)
                .unwrap_or(false);
            if !(requester.natt_capable && source_is_natt) {
                continue;
            }
        }

        let id = match (v6, source_handle.as_deref()) {
            (Some(_), _) => IPV6_SOURCE_SENTINEL,
            (None, Some(handle)) if !handle.is_high_id => handle.assigned_id,
            (None, Some(_)) => {
                if ServerState::is_publishable_source_ip(s.ip())
                    || (private_highid_routes
                        && matches!(s.ip(), std::net::IpAddr::V4(ip) if ip.is_private()))
                {
                    s.ipv4
                } else {
                    continue;
                }
            }
            (None, None) => {
                // STALE SOURCE. The client is gone, so there is no low id to
                // substitute and the stored address goes out verbatim. If that
                // address is private it means nothing outside one LAN: every
                // peer that receives it burns a connect attempt on it and then
                // passes it on when it exchanges sources. Drop it instead.
                //
                // Only reachable for a departed client — a connected firewalled
                // one takes the branch above and is reached by callback.
                if !ServerState::is_publishable_source_ip(s.ip()) {
                    continue;
                }
                s.ipv4
            }
        };
        entries.put_u32_le(id);
        entries.put_u16_le(s.port());
        if reply_format == SourceReplyFormat::Obfuscated {
            let source_flags = source_handle
                .as_ref()
                .map(|handle| handle.server_flags)
                .unwrap_or(0);
            let supports_crypt = source_flags & CAPABLE_SUPPORTCRYPT != 0;
            let mut crypt_options = 0u8;
            if supports_crypt {
                crypt_options |= 0x01 | 0x80;
            }
            if source_flags & CAPABLE_REQUESTCRYPT != 0 {
                crypt_options |= 0x02;
            }
            if source_flags & CAPABLE_REQUIRECRYPT != 0 {
                crypt_options |= 0x04;
            }
            entries.put_u8(crypt_options);
            if supports_crypt {
                entries.put_slice(&s.user_hash);
            }
        }
        if let Some(a) = v6 {
            // ALWAYS LAST, after any obfuscation fields — both existing
            // implementations read it there, and the position is the only thing
            // making the record self-delimiting.
            entries.put_slice(&a.octets());
        }
        emitted += 1;
        if !requester_specific {
            owners.push(owner_key(&s.user_hash));
        }
    }

    let mut payload = BytesMut::new();
    payload.put_slice(&req.file_hash);
    payload.put_u8(emitted);
    payload.put_slice(&entries);
    let payload_vec = payload.to_vec();

    if requester_specific {
        // Already this requester's own reply (see the loop). Not cached, for
        // the reason at the read side.
        return Frame::new(reply_format.opcode(), payload_vec);
    }

    // Cache the payload with EVERY source, and serve this requester the same
    // cut every later requester gets. It used to be cached with the first
    // requester already removed: for the TTL that source was hidden from
    // everyone else, and every later requester was handed its own address.
    let reply = without_owner(&payload_vec, &owners, me);
    state.smart_sources.put(req.file_hash, payload_vec, owners);
    Frame::new(reply_format.opcode(), reply)
}

/// The key a cached record's owner is stored under: the first 8 bytes of the
/// user hash. A collision would only hide one source from one requester.
fn owner_key(user_hash: &[u8; 16]) -> u64 {
    u64::from_le_bytes(user_hash[..8].try_into().unwrap())
}

/// Cut a requester-specific reply from a shared classic payload: drop the
/// records owned by `me` and keep at most `MAX_SOURCES_PER_REPLY`, fixing the
/// count byte to match.
///
/// Classic records only (6 bytes: id + port) — the only kind ever cached. A
/// payload whose length does not match its owner list is returned unchanged
/// apart from the cap, rather than being cut at the wrong offsets.
fn without_owner(payload: &[u8], owners: &[u64], me: u64) -> Vec<u8> {
    const HDR: usize = 17;
    const REC: usize = 6;
    if payload.len() < HDR || payload.len() != HDR + owners.len() * REC {
        return payload.to_vec();
    }
    let mut out = Vec::with_capacity(payload.len());
    out.extend_from_slice(&payload[..HDR]);
    let mut n: usize = 0;
    for (i, &owner) in owners.iter().enumerate() {
        if owner == me {
            continue;
        }
        if n == MAX_SOURCES_PER_REPLY {
            break;
        }
        out.extend_from_slice(&payload[HDR + i * REC..HDR + (i + 1) * REC]);
        n += 1;
    }
    out[16] = n as u8;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v1() {
        // Just hash, no size (legacy)
        let payload = [0x42u8; 16];
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.file_hash, [0x42; 16]);
        assert_eq!(r.size, None);
    }

    #[test]
    fn parse_v2() {
        // hash + 4-byte size
        let mut payload = vec![0x42u8; 16];
        payload.extend_from_slice(&1234u32.to_le_bytes());
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.size, Some(1234));
    }

    #[test]
    fn parse_v2_large() {
        // The tail after the sentinel is a plain little-endian u64, exactly as
        // eMule's WriteUInt64 emits it — NOT two dwords in high/low order.
        //
        // This test previously encoded the bug: it wrote the high dword first
        // and asserted the swapped reading back, so it passed while real clients
        // were being misparsed. Build the payload the way the wire does.
        let size: u64 = (5u64 << 32) | 123;
        let mut payload = vec![0x42u8; 16];
        payload.extend_from_slice(&0u32.to_le_bytes()); // large-file sentinel
        payload.extend_from_slice(&size.to_le_bytes()); // u64 LE, low dword first
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.size, Some(size));
    }

    #[test]
    fn parse_v2_large_six_gib_from_the_report() {
        // The exact frame from the interop report: 6 GiB, which used to decode
        // as 9223372036854775809 because the two dwords were swapped.
        let mut payload = vec![0x33u8; 16];
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // sentinel
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00]);
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.size, Some(6_442_450_944));
    }

    #[test]
    fn parse_v2_large_straddling_the_4gib_boundary() {
        for size in [(1u64 << 32) - 1, 1u64 << 32, (1u64 << 32) + 1] {
            let mut payload = vec![0x11u8; 16];
            payload.extend_from_slice(&0u32.to_le_bytes());
            payload.extend_from_slice(&size.to_le_bytes());
            assert_eq!(
                GetSourcesRequest::parse(&payload).unwrap().size,
                Some(size),
                "size {size} must round-trip"
            );
        }
    }

    #[test]
    fn v2_large_sentinel_without_the_u64_is_not_misread() {
        // Sentinel present but the u64 truncated: must fall back to "size 0"
        // rather than reading past the end or inventing a value.
        let mut payload = vec![0x77u8; 16];
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&[0xFF; 4]); // only half of the u64
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.size, Some(0));
    }

    // A LowID source must be encoded as its server-assigned low id (so the
    // downloader treats it as LowID and uses callback / NAT-T), while a HighID
    // source is encoded as its real IPv4. Regression test for the bug where
    // every source (LowID included) was encoded as its real IP, making LowID
    // peers look like HighID and breaking LowID<->LowID NAT traversal.
    #[test]
    fn the_sentinel_value_is_the_agreed_one() {
        // 255.255.255.255 is never a real client, which is what makes it
        // unambiguous. Both implementations already speaking this use the same
        // value; changing it would silently break both.
        assert_eq!(IPV6_SOURCE_SENTINEL, 0xFFFF_FFFF);
    }

    #[test]
    fn a_link_local_ipv6_is_not_publishable() {
        // The case that would actually happen: a client behind a router with no
        // global prefix advertises fe80::… , which is useless to every peer that
        // receives it and spreads through source exchange like any other junk
        // address.
        use crate::server::login::is_publishable_ipv6;
        use std::net::Ipv6Addr;
        for bad in [
            "fe80::1",            // link-local
            "fd00::1",            // unique local
            "::1",                // loopback
            "::",                 // unspecified
            "ff02::1",            // multicast
            "::ffff:203.0.113.7", // IPv4 in disguise
        ] {
            let a: Ipv6Addr = bad.parse().unwrap();
            assert!(!is_publishable_ipv6(a), "{bad} must not be published");
        }
        for good in ["2001:db8::1", "2a01:4f8::1"] {
            let a: Ipv6Addr = good.parse().unwrap();
            assert!(is_publishable_ipv6(a), "{good}");
        }
    }

    #[test]
    fn a_stale_private_source_is_not_emitted() {
        // The address of a client that has gone. There is no low id left to
        // substitute, so it would go out verbatim — and outside its own LAN it
        // means nothing except a wasted connect attempt for every peer that
        // receives it, and for every peer they hand it on to.
        use std::net::{IpAddr, Ipv4Addr};
        for ip in [
            Ipv4Addr::new(192, 168, 30, 254),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 20, 1, 1),
            Ipv4Addr::new(100, 90, 0, 1),
        ] {
            assert!(
                !ServerState::is_publishable_source_ip(IpAddr::V4(ip)),
                "{ip}"
            );
        }
        assert!(ServerState::is_publishable_source_ip(IpAddr::V4(
            Ipv4Addr::new(85, 17, 116, 222)
        )));
    }

    fn classic_records(frame: &Frame) -> Vec<(u32, u16)> {
        let payload = &frame.payload;
        let count = payload[16] as usize;
        assert_eq!(payload.len(), 17 + count * 6);
        (0..count)
            .map(|i| {
                let offset = 17 + i * 6;
                (
                    u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()),
                    u16::from_le_bytes(payload[offset + 4..offset + 6].try_into().unwrap()),
                )
            })
            .collect()
    }

    fn one_source_state(source_highid: bool, source_udp: u16) -> (ServerState, [u8; 16]) {
        use std::net::{IpAddr, Ipv4Addr};
        let state = ServerState::for_test();
        let file_hash = [0x77u8; 16];
        let source = [0xAAu8; 16];
        state.add_file_with_source(
            file_hash,
            1000,
            "f".into(),
            (
                source,
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                4001,
                true,
            ),
        );
        state.register_test_client(
            source,
            if source_highid { 0x0102_0304 } else { 42 },
            source_highid,
            source_udp,
        );
        (state, file_hash)
    }

    fn ask_as(
        state: &ServerState,
        file_hash: [u8; 16],
        user_hash: [u8; 16],
        highid: bool,
        udp: u16,
    ) -> Frame {
        state.register_test_client(
            user_hash,
            if highid { 0x0506_0708 } else { 77 },
            highid,
            udp,
        );
        let requester = state.clients.get(&user_hash).unwrap().clone();
        handle_get_sources(
            state,
            &requester,
            GetSourcesRequest {
                file_hash,
                size: None,
            },
            SourceReplyFormat::Classic,
        )
    }

    #[test]
    fn highid_requester_gets_lowid_callback_record() {
        let (state, file_hash) = one_source_state(false, 0);
        let records = classic_records(&ask_as(&state, file_hash, [0xC1; 16], true, 0));
        assert_eq!(records, vec![(42, 4001)]);
    }

    #[test]
    fn obfuscated_reply_maps_source_crypt_options_and_user_hash() {
        let (state, file_hash) = one_source_state(true, 0);
        let source_hash = [0xAA; 16];
        let requester_hash = [0xC1; 16];
        state.register_test_client(requester_hash, 0x0506_0708, true, 0);
        let requester = state.clients.get(&requester_hash).unwrap().clone();

        for (server_flags, expected_options, has_hash) in [
            (CAPABLE_SUPPORTCRYPT, 0x81, true),
            (
                CAPABLE_SUPPORTCRYPT | CAPABLE_REQUESTCRYPT | CAPABLE_REQUIRECRYPT,
                0x87,
                true,
            ),
            (0, 0x00, false),
        ] {
            state.clients.get_mut(&source_hash).unwrap().server_flags = server_flags;
            let reply = handle_get_sources(
                &state,
                &requester,
                GetSourcesRequest {
                    file_hash,
                    size: None,
                },
                SourceReplyFormat::Obfuscated,
            );

            assert_eq!(reply.opcode, OP_FOUNDSOURCES_OBFU);
            assert_eq!(reply.payload[16], 1);
            assert_eq!(
                reply.payload.len(),
                17 + 4 + 2 + 1 + usize::from(has_hash) * 16
            );
            assert_eq!(
                u32::from_le_bytes(reply.payload[17..21].try_into().unwrap()),
                u32::from_le_bytes([198, 51, 100, 7])
            );
            assert_eq!(
                u16::from_le_bytes(reply.payload[21..23].try_into().unwrap()),
                4001
            );
            assert_eq!(reply.payload[23], expected_options);
            if has_hash {
                assert_eq!(&reply.payload[24..40], &source_hash);
            }
        }
    }

    #[test]
    fn wrong_size_does_not_reuse_cached_sources() {
        let (state, file_hash) = one_source_state(true, 0);
        let requester_hash = [0xC1; 16];
        state.register_test_client(requester_hash, 0x0506_0708, true, 0);
        let requester = state.clients.get(&requester_hash).unwrap().clone();

        let correct = handle_get_sources(
            &state,
            &requester,
            GetSourcesRequest {
                file_hash,
                size: Some(1000),
            },
            SourceReplyFormat::Classic,
        );
        let indexed_ip = u32::from_le_bytes([198, 51, 100, 7]);
        assert_eq!(classic_records(&correct), vec![(indexed_ip, 4001)]);

        let wrong = handle_get_sources(
            &state,
            &requester,
            GetSourcesRequest {
                file_hash,
                size: Some(1001),
            },
            SourceReplyFormat::Classic,
        );
        assert!(classic_records(&wrong).is_empty());

        let legacy = handle_get_sources(
            &state,
            &requester,
            GetSourcesRequest {
                file_hash,
                size: None,
            },
            SourceReplyFormat::Classic,
        );
        assert_eq!(classic_records(&legacy), vec![(indexed_ip, 4001)]);
    }

    #[test]
    fn classic_lowid_requester_does_not_get_classic_lowid_source() {
        let (state, file_hash) = one_source_state(false, 0);
        let records = classic_records(&ask_as(&state, file_hash, [0xC2; 16], false, 0));
        assert!(records.is_empty());
    }

    #[test]
    fn natt_lowid_pair_gets_lowid_source() {
        let (state, file_hash) = one_source_state(false, 5001);
        let records = classic_records(&ask_as(&state, file_hash, [0xC3; 16], false, 5002));
        assert_eq!(records, vec![(42, 4001)]);
    }

    #[test]
    fn natt_lowid_requester_does_not_get_non_natt_lowid_source() {
        let (state, file_hash) = one_source_state(false, 0);
        let records = classic_records(&ask_as(&state, file_hash, [0xC4; 16], false, 5002));
        assert!(records.is_empty());
    }

    #[test]
    fn classic_lowid_requester_still_gets_highid_source() {
        use std::net::Ipv4Addr;
        let (state, file_hash) = one_source_state(true, 0);
        let records = classic_records(&ask_as(&state, file_hash, [0xC5; 16], false, 0));
        assert_eq!(
            records,
            vec![(u32::from_le_bytes(Ipv4Addr::new(198, 51, 100, 7).octets()), 4001)]
        );
    }

    #[test]
    fn lowid_requester_never_reuses_a_highid_cached_reply() {
        let (state, file_hash) = one_source_state(false, 0);
        assert_eq!(
            classic_records(&ask_as(&state, file_hash, [0xD1; 16], true, 0)),
            vec![(42, 4001)]
        );
        assert!(classic_records(&ask_as(&state, file_hash, [0xD2; 16], false, 0)).is_empty());
        assert_eq!(
            classic_records(&ask_as(&state, file_hash, [0xD3; 16], true, 0)),
            vec![(42, 4001)]
        );
        let (hits, _) = state.smart_sources.stats();
        assert_eq!(hits, 1, "only the second HighID request may hit the cache");
    }

    #[test]
    fn verified_private_highid_routes_never_leak_to_public_requesters() {
        use std::net::{IpAddr, Ipv4Addr};
        let state = ServerState::for_test();
        let mut cfg = (**state.live_cfg.load()).clone();
        cfg.network.private_highid_probe = true;
        state.live_cfg.store(std::sync::Arc::new(cfg));

        let file_hash = [0x76u8; 16];
        let source = [0xAAu8; 16];
        let source_ip = Ipv4Addr::new(10, 0, 0, 43);
        state.add_file_with_source(
            file_hash,
            1000,
            "f".into(),
            (source, IpAddr::V4(source_ip), 4001, true),
        );
        state.register_test_client(source, u32::from_le_bytes(source_ip.octets()), true, 0);

        let private_user = [0xCCu8; 16];
        state.register_test_client(private_user, 0x0506_0708, true, 0);
        let private_requester = state.clients.get(&private_user).unwrap().clone();
        let private_reply = handle_get_sources(
            &state,
            &private_requester,
            GetSourcesRequest { file_hash, size: None },
            SourceReplyFormat::Classic,
        );
        assert_eq!(private_reply.payload[16], 1);
        assert_eq!(
            u32::from_le_bytes(private_reply.payload[17..21].try_into().unwrap()),
            u32::from_le_bytes(source_ip.octets())
        );

        let public_user = [0xDDu8; 16];
        state.register_test_client(public_user, 0x090A_0B0C, true, 0);
        let mut public_requester = state.clients.get(&public_user).unwrap().clone();
        public_requester.ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90));
        let public_reply = handle_get_sources(
            &state,
            &public_requester,
            GetSourcesRequest { file_hash, size: None },
            SourceReplyFormat::Classic,
        );
        assert_eq!(public_reply.payload[16], 0);
    }

    /// Issue #33: the sentinel goes to a LowID requester only.
    #[test]
    fn a_highid_requester_keeps_the_lowid_and_its_callback() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let state = ServerState::for_test();
        let mut cfg = (**state.live_cfg.load()).clone();
        cfg.network.ipv6_publish_sources = true;
        state.live_cfg.store(std::sync::Arc::new(cfg));

        let file_hash = [0x66u8; 16];
        let src = [0xA0u8; 16];
        state.add_file_with_source(
            file_hash,
            1000,
            "f".into(),
            (src, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 4001, true),
        );
        state.register_test_client(src, 42, false, 0);
        state.client_ipv6.insert(src, "2001:db8:5::1".parse::<Ipv6Addr>().unwrap());

        let ask = |uh: [u8; 16], high: bool| {
            state.register_test_client(uh, if high { 0x0102_0304 } else { 77 }, high, 0);
            let mut requester = state.clients.get(&uh).unwrap().clone();
            requester.ipv6_capable = true;
            handle_get_sources(
                &state,
                &requester,
                GetSourcesRequest { file_hash, size: None },
                SourceReplyFormat::Classic,
            )
        };
        // HighID, sentinel-capable: the classic record with the low id.
        let p = ask([0xC1; 16], true).payload;
        assert_eq!(p[16], 1);
        assert_eq!(p.len(), 17 + 6, "classic record");
        assert_eq!(u32::from_le_bytes([p[17], p[18], p[19], p[20]]), 42);
        // LowID, sentinel-capable: no callback possible, so the IPv6 route.
        let p = ask([0xC2; 16], false).payload;
        assert_eq!(p[16], 1);
        assert_eq!(u32::from_le_bytes([p[17], p[18], p[19], p[20]]), IPV6_SOURCE_SENTINEL);
    }

    fn ports_of(frame: &Frame) -> Vec<u16> {
        let p = &frame.payload;
        let count = p[16] as usize;
        assert_eq!(p.len(), 17 + count * 6, "count byte must match the records");
        let mut v: Vec<u16> = (0..count)
            .map(|i| u16::from_le_bytes([p[17 + i * 6 + 4], p[17 + i * 6 + 5]]))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_cached_reply_hides_each_requester_from_itself_only() {
        // The cache is shared by every requester of the file. It used to be
        // filled with the FIRST requester already removed: that source was then
        // hidden from everyone else for the TTL, and every later requester got
        // its own address back.
        use std::net::{IpAddr, Ipv4Addr};
        let state = ServerState::for_test();
        let file_hash = [0x55u8; 16];
        let users = [[0xA1u8; 16], [0xA2u8; 16], [0xA3u8; 16]];
        for (i, uh) in users.iter().enumerate() {
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10 + i as u8));
            state.add_file_with_source(file_hash, 1000, "f".into(), (*uh, ip, 4001 + i as u16, true));
            state.register_test_client(*uh, 0x0A00_0001 + i as u32, true, 0);
        }
        let ask = |uh: &[u8; 16]| {
            let requester = state.clients.get(uh).unwrap().clone();
            handle_get_sources(
                &state,
                &requester,
                GetSourcesRequest { file_hash, size: None },
                SourceReplyFormat::Classic,
            )
        };
        // First requester builds the cache entry.
        assert_eq!(ports_of(&ask(&users[0])), vec![4002, 4003]);
        // The next two are answered from the cache.
        assert_eq!(ports_of(&ask(&users[1])), vec![4001, 4003]);
        assert_eq!(ports_of(&ask(&users[2])), vec![4001, 4002]);
        let (hits, _) = state.smart_sources.stats();
        assert_eq!(hits, 2, "the later requests must come from the cache");

        // A client that is not a source gets everyone.
        let outsider = [0xEEu8; 16];
        state.register_test_client(outsider, 7, false, 0);
        assert_eq!(ports_of(&ask(&outsider)), vec![4001, 4002, 4003]);
    }

    #[test]
    fn the_reply_cap_holds_after_removing_the_requester() {
        let mut payload = vec![0u8; 16];
        payload.push(0);
        let mut owners = Vec::new();
        for i in 0..=MAX_SOURCES_PER_REPLY as u64 {
            payload.extend_from_slice(&[1, 2, 3, 4, (i & 0xFF) as u8, (i >> 8) as u8]);
            owners.push(i);
        }
        payload[16] = owners.len() as u8;
        // The requester is in the list: the rest exactly fills the cap.
        let out = without_owner(&payload, &owners, 5);
        assert_eq!(out[16] as usize, MAX_SOURCES_PER_REPLY);
        assert_eq!(out.len(), 17 + MAX_SOURCES_PER_REPLY * 6);
        // Not in the list: still capped.
        let out = without_owner(&payload, &owners, 99_999);
        assert_eq!(out[16] as usize, MAX_SOURCES_PER_REPLY);
    }
}
