use super::*;
use log::info;
use redis::Commands;

#[derive(Clone)]
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

#[derive(Debug, PartialEq)]
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
        let fgk = hash(&[&ks_sender[..], &ks_platform[..]].concat());
        if gk != fgk {
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
        if !ptr_valid {
            info!(target: "root_traceback", "Malformed generator key usage");
            return Tree {
                uid: sid,
                children: vec![svr_build_tree(conn, m, &fgk, rid)],
            };
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

#[cfg(test)]
mod tests {
    use super::*;

    extern crate test;
    use test::Bencher;

    fn init_logger() {
        //env_logger::init();
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn mock_send(
        conn: &redis::Connection,
        m: &[u8],
        tmd: &TraceMetadata,
        ctr: u32,
        sid: u32,
        rid: u32,
    ) -> TraceMetadata {
        let k = rand::random::<[u8; 16]>();
        let tts = generate_tag(&k, m, &tmd, ctr);
        let ttr = svr_process(conn, &tts, sid, rid).unwrap();
        verify_tag(&k, m, &ttr).unwrap()
    }

    fn mock_tree(
        conn: &redis::Connection,
        m: &[u8],
        tmd: &TraceMetadata,
        depth: u32,
        span: u32,
        uid: u32,
    ) {
        match depth {
            0 => (),
            _ => {
                for i in 0..span {
                    let rid = rand::random::<u32>();
                    let tmd_out = mock_send(conn, m, tmd, i, uid, rid);
                    let _ = mock_tree(conn, m, &tmd_out, depth - 1, span, rid);
                }
            }
        }
    }

    #[test]
    fn process_tag_verifies() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let k = rand::random::<[u8; 16]>();
        let tmd0 = new_message(m.as_bytes());
        let tts = generate_tag(&k, m.as_bytes(), &tmd0, 0);
        let ttr = svr_process(&conn, &tts, 0, 1).unwrap();
        let tmd1 = verify_tag(&k, m.as_bytes(), &ttr).unwrap();
        assert_eq!(prf(&tmd0.gk, &0u32.to_be_bytes()), tmd1.bptr);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[test]
    fn trace_simple_tree() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let tmd0 = new_message(m.as_bytes());
        let tmd01 = mock_send(&conn, m.as_bytes(), &tmd0, 0, 0, 1);
        let tmd02 = mock_send(&conn, m.as_bytes(), &tmd0, 1, 0, 2);

        let tree0 = svr_trace(&conn, m.as_bytes(), &tmd0, 0);
        let tree1 = svr_trace(&conn, m.as_bytes(), &tmd01, 1);
        let tree2 = svr_trace(&conn, m.as_bytes(), &tmd02, 2);

        let tree = Tree {
            uid: 0,
            children: vec![
                Tree {
                    uid: 1,
                    children: vec![],
                },
                Tree {
                    uid: 2,
                    children: vec![],
                },
            ],
        };

        assert_eq!(tree, tree0);
        assert_eq!(tree, tree1);
        assert_eq!(tree, tree2);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[test]
    fn trace_message_switch() {
        init_logger();
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let m2 = "Different Plaintext";
        let tmd0 = new_message(m.as_bytes());
        let tmd01 = mock_send(&conn, m.as_bytes(), &tmd0, 0, 0, 1);
        let tmd12 = mock_send(&conn, m.as_bytes(), &tmd01, 0, 1, 2);
        let tmd13 = mock_send(&conn, m2.as_bytes(), &tmd01, 0, 1, 3);

        let tree2 = svr_trace(&conn, m.as_bytes(), &tmd12, 2);
        let tree3 = svr_trace(&conn, m2.as_bytes(), &tmd13, 3);

        let real_tree2 = Tree {
            uid: 0,
            children: vec![Tree {
                uid: 1,
                children: vec![Tree {
                    uid: 2,
                    children: vec![],
                }],
            }],
        };

        let real_tree3 = Tree {
            uid: 1,
            children: vec![Tree {
                uid: 3,
                children: vec![],
            }],
        };

        assert_eq!(tree2, real_tree2);
        assert_eq!(tree3, real_tree3);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[test]
    fn trace_counter_skip() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let tmd0 = new_message(m.as_bytes());
        let tmd01 = mock_send(&conn, m.as_bytes(), &tmd0, 0, 0, 1);
        let tmd12 = mock_send(&conn, m.as_bytes(), &tmd01, 0, 1, 2);
        let tmd13 = mock_send(&conn, m.as_bytes(), &tmd01, 2, 1, 3);

        let tree2 = svr_trace(&conn, m.as_bytes(), &tmd12, 2);
        let tree3 = svr_trace(&conn, m.as_bytes(), &tmd13, 3);

        let real_tree2 = Tree {
            uid: 0,
            children: vec![Tree {
                uid: 1,
                children: vec![Tree {
                    uid: 2,
                    children: vec![],
                }],
            }],
        };

        let real_tree3 = Tree {
            uid: 1,
            children: vec![Tree {
                uid: 3,
                children: vec![],
            }],
        };

        assert_eq!(tree2, real_tree2);
        assert_eq!(tree3, real_tree3);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[test]
    fn trace_malformed_forward_generator() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let tmd0 = new_message(m.as_bytes());
        let tmd01 = mock_send(&conn, m.as_bytes(), &tmd0, 0, 0, 1);
        let mut tmd01_mal = tmd01.clone();
        tmd01_mal.gk = [0; 16];
        let tmd12 = mock_send(&conn, m.as_bytes(), &tmd01_mal, 0, 1, 2);
        let tmd13 = mock_send(&conn, m.as_bytes(), &tmd01_mal, 1, 1, 3);

        let tree0 = svr_trace(&conn, m.as_bytes(), &tmd0, 0);
        let tree2 = svr_trace(&conn, m.as_bytes(), &tmd12, 2);
        let tree3 = svr_trace(&conn, m.as_bytes(), &tmd13, 3);

        let real_tree0 = Tree {
            uid: 0,
            children: vec![Tree {
                uid: 1,
                children: vec![],
            }],
        };

        let real_tree23 = Tree {
            uid: 1,
            children: vec![
                Tree {
                    uid: 2,
                    children: vec![],
                },
                Tree {
                    uid: 3,
                    children: vec![],
                },
            ],
        };

        assert_eq!(tree0, real_tree0);
        assert_eq!(tree2, real_tree23);
        assert_eq!(tree3, real_tree23);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[bench]
    fn bench_tag_gen(b: &mut Bencher) {
        let m = [0u8; 256];
        let k = rand::random::<[u8; 16]>();
        let md = TraceMetadata {
            bptr: rand::random::<[u8; 16]>(),
            gk: rand::random::<[u8; 16]>(),
        };
        b.iter(|| generate_tag(&k, &m, &md, 0));
    }

    #[bench]
    fn bench_tag_receive(b: &mut Bencher) {
        let m = [0u8; 256];
        let k = rand::random::<[u8; 16]>();
        let ptr = rand::random::<[u8; 16]>();
        let ttr = RecTraceTag {
            addr: prf(&k, &m),
            ct_ptr: encipher(&k, &ptr),
            ct_fgk: rand::random::<[u8; 16]>(),
            ks_fgk: rand::random::<[u8; 16]>(),
        };
        b.iter(|| verify_tag(&k, &m, &ttr));
    }

    #[bench]
    fn bench_tag_process(b: &mut Bencher) {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();
        let sid = rand::random::<u32>();
        let rid = rand::random::<u32>();
        let tts = SenderTraceTag {
            addr: rand::random::<[u8; 16]>(),
            ct_ptr: rand::random::<[u8; 16]>(),
            ct_bptr: rand::random::<[u8; 16]>(),
            ct_gk: rand::random::<[u8; 16]>(),
            ct_fgk: rand::random::<[u8; 16]>(),
        };
        b.iter(|| {
            svr_process(&conn, &tts, sid, rid);
            let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
        });
    }

    #[bench]
    fn bench_trace_tree(b: &mut Bencher) {
        let depth = 4;
        let span = 3;
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();
        let m = [0u8; 256];
        let tmd = new_message(&m);
        mock_tree(&conn, &m, &tmd, depth, span, 0);
        b.iter(|| svr_trace(&conn, &m, &tmd, 0));
        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }
}
