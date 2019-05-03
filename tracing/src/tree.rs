use super::*;
use log::info;
use redis::Commands;

pub struct TraceMetadata {
    bptr: [u8; 16],
    gk: [u8; 16],
}

pub struct SenderTraceTag {
    addr: [u8; 16],
    ct_ptr: [u8; 16],
    ct_bptr: [u8; 16],
    ct_gk: [u8; 16],
    ct_fgk: [u8; 16],
}

pub struct RecTraceTag {
    addr: [u8; 16],
    ct_ptr: [u8; 16],
    ct_fgk: [u8; 16],
    ks_fgk: [u8; 16],
}

pub struct Tree {
    uid: u32,
    children: Vec<Tree>,
}

pub fn new_message(_m: &[u8]) -> TraceMetadata {
    TraceMetadata {
        bptr: [0; 16],
        gk: rand::random::<[u8; 16]>(),
    }
}

pub fn generate_tag(k: &[u8; 16], m: &[u8], md: &TraceMetadata, ctr: u32) -> SenderTraceTag {
    let ptr = prf(&md.gk, &ctr.to_be_bytes());
    let addr = prf(&ptr, m);
    SenderTraceTag {
        addr: addr,
        ct_ptr: encipher(k, &ptr),
        ct_bptr: encipher(&ptr, &md.bptr),
        ct_gk: encipher(&ptr, &md.gk),
        ct_fgk: encipher(&ptr, &rand::random::<[u8; 16]>()),
    }
}

pub fn verify_tag(k: &[u8; 16], m: &[u8], ttr: &RecTraceTag) -> Option<TraceMetadata> {
    let ptr = decipher(k, &ttr.ct_ptr);
    let addr = prf(&ptr, m);
    if addr != ttr.addr {
        None
    } else {
        Some(TraceMetadata {
            bptr: ptr,
            gk: hash(&[&decipher(&ptr, &ttr.ct_fgk)[..], &ttr.ks_fgk[..]].concat()),
        })
    }
}

pub fn svr_process(
    conn: &redis::Connection,
    tts: &SenderTraceTag,
    sid: u32,
    rid: u32,
) -> Option<RecTraceTag> {
    let addr_filled: bool = conn.exists(&tts.addr).unwrap();

    if addr_filled {
        None
    } else {
        let ks_fgk = rand::random::<[u8; 16]>();
        let _: () = conn
            .hset_multiple(
                &tts.addr,
                &[
                    ("ct_bptr", &tts.ct_bptr),
                    ("ct_gk", &tts.ct_gk),
                    ("ct_fgk", &tts.ct_fgk),
                    ("ks_fgk", &ks_fgk),
                ],
            )
            .unwrap();
        let _: () = conn
            .hset_multiple(&tts.addr, &[("sid", sid), ("rid", rid)])
            .unwrap();
        Some(RecTraceTag {
            addr: tts.addr.clone(),
            ct_ptr: tts.ct_ptr.clone(),
            ct_fgk: tts.ct_fgk.clone(),
            ks_fgk: ks_fgk,
        })
    }
}

pub fn svr_trace(conn: &redis::Connection, m: &[u8], md: &TraceMetadata, uid: u32) -> Tree {
    let mut root = uid;
    let mut root_gk = md.gk;
    let mut gk = md.gk;
    let mut bptr = md.bptr;
    let mut addr = prf(&bptr, m);
    let mut prev_sid = uid;

    while conn.exists(&addr).unwrap() {
        let (ct_bptr, ct_gk, ct_fgk, ks_platform, sid, rid) = svr_read_state(conn, &addr);

        // Identity matching
        if prev_sid != rid {
            info!(target: "root_traceback", "Identity mismatch: {}, {}", prev_sid, rid);
            break;
        }

        // Wellformedness check of forward generator key
        let ks_sender = decipher(&bptr, &ct_fgk);
        if gk != hash(&[&ks_sender[..], &ks_platform[..]].concat()) {
            info!(target: "root_traceback", "Malformed forward generator key");
            break;
        }

        // Move current root to sender
        gk = decipher(&bptr, &ct_gk);
        root = sid;
        root_gk = gk;
        prev_sid = sid;

        // Wellformedness check of pointer from generator key
        let mut ctr: u32 = 0;
        let ptr_valid = loop {
            let ptr = prf(&gk, &ctr.to_be_bytes());
            if ptr == bptr {
                break true;
            };
            let addr_filled: bool = conn.exists(&prf(&ptr, m)).unwrap();
            if !addr_filled {
                break false;
            };
            ctr = ctr + 1;
        };
        if ptr_valid {
            info!(target: "root_traceback", "Malformed generator key usage");
            break;
        }

        // Next address
        bptr = decipher(&bptr, &ct_bptr);
        addr = prf(&bptr, m);
    }
    svr_build_tree(conn, m, &root_gk, root)
}

fn svr_build_tree(conn: &redis::Connection, m: &[u8], gk: &[u8; 16], uid: u32) -> Tree {
    let mut tree = Tree {
        uid: uid,
        children: Vec::new(),
    };
    let mut ctr: u32 = 0;
    loop {
        let ptr = prf(gk, &ctr.to_be_bytes());
        let addr = prf(&ptr, m);
        let addr_filled: bool = conn.exists(&addr).unwrap();
        if !addr_filled {
            break;
        };

        let (_, _, ct_fgk, ks_platform, sid, rid) = svr_read_state(conn, &addr);
        if sid != uid {
            break;
        }

        let ks_sender = decipher(&ptr, &ct_fgk);
        let fgk = hash(&[&ks_sender[..], &ks_platform[..]].concat());
        tree.children.push(svr_build_tree(conn, m, &fgk, rid));
        ctr = ctr + 1;
    }
    tree
}

fn svr_read_state(
    conn: &redis::Connection,
    addr: &[u8; 16],
) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16], u32, u32) {
    let mut ct_bptr: [u8; 16] = Default::default();
    let mut ct_gk: [u8; 16] = Default::default();
    let mut ct_fgk: [u8; 16] = Default::default();
    let mut ks_platform: [u8; 16] = Default::default();
    let mut ctvec: Vec<u8>;

    ctvec = conn.hget(addr, "ct_bptr").unwrap();
    ct_bptr.copy_from_slice(&ctvec);
    ctvec = conn.hget(addr, "ct_gk").unwrap();
    ct_gk.copy_from_slice(&ctvec);
    ctvec = conn.hget(addr, "ct_fgk").unwrap();
    ct_fgk.copy_from_slice(&ctvec);
    ctvec = conn.hget(addr, "ks_fgk").unwrap();
    ks_platform.copy_from_slice(&ctvec);
    let sid: u32 = conn.hget(addr, "sid").unwrap();
    let rid: u32 = conn.hget(addr, "rid").unwrap();
    (ct_bptr, ct_gk, ct_fgk, ks_platform, sid, rid)
}
