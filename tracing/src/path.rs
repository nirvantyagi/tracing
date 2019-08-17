use super::*;
use redis::Commands;

pub struct TraceMetadata {
    ptr: [u8; 16],
}

pub struct SenderTraceTag {
    addr: [u8; 32],
    ct: [u8; 16],
}

pub struct RecTraceTag {
    addr: [u8; 32],
}

pub fn new_message(_m: &[u8]) -> TraceMetadata {
    TraceMetadata { ptr: [0; 16] }
}

pub fn generate_tag(k: &[u8; 16], m: &[u8], md: &TraceMetadata) -> SenderTraceTag {
    let addr = crprf(k, m);
    let ct = encipher(k, &md.ptr);
    SenderTraceTag { addr: addr, ct: ct }
}

pub fn verify_tag(k: &[u8; 16], m: &[u8], ttr: &RecTraceTag) -> Option<TraceMetadata> {
    let addr = crprf(k, m);
    if addr != ttr.addr {
        None
    } else {
        Some(TraceMetadata { ptr: k.clone() })
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
        let _: () = conn.hset(&tts.addr, "ct", &tts.ct).unwrap();
        let _: () = conn
            .hset_multiple(&tts.addr, &[("sid", sid), ("rid", rid)])
            .unwrap();
        Some(RecTraceTag {
            addr: tts.addr.clone(),
        })
    }
}

pub fn svr_trace(conn: &redis::Connection, m: &[u8], md: &TraceMetadata, uid: u32) -> Vec<u32> {
    let mut path = vec![uid];
    let mut ptr = md.ptr.clone();
    let mut addr = crprf(&md.ptr, m);
    let mut ct: [u8; 16] = Default::default();

    while conn.exists(&addr).unwrap() {
        let ctvec: Vec<u8> = conn.hget(&addr, "ct").unwrap();
        ct.copy_from_slice(&ctvec);
        let rid: u32 = conn.hget(&addr, "rid").unwrap();
        if *path.last().unwrap() != rid {
            break;
        }
        path.push(conn.hget(&addr, "sid").unwrap());

        ptr = decipher(&ptr, &ct);
        addr = crprf(&ptr, m);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate test;
    use test::Bencher;

    fn mock_send(
        conn: &redis::Connection,
        m: &[u8],
        tmd: &TraceMetadata,
        sid: u32,
        rid: u32,
    ) -> TraceMetadata {
        let k = rand::random::<[u8; 16]>();
        let tts = generate_tag(&k, m, &tmd);
        let ttr = svr_process(conn, &tts, sid, rid).unwrap();
        verify_tag(&k, m, &ttr).unwrap()
    }

    fn mock_path(
        conn: &redis::Connection,
        m: &[u8],
        mut tmd: TraceMetadata,
        len: u32,
    ) -> TraceMetadata {
        for i in 0..len {
            tmd = mock_send(conn, m, &tmd, i, i + 1);
        }
        tmd
    }

    #[test]
    fn tag_verifies() {
        let m = "Plaintext";
        let k = rand::random::<[u8; 16]>();
        let tmd0 = new_message(m.as_bytes());
        let tts = generate_tag(&k, m.as_bytes(), &tmd0);
        let ttr = RecTraceTag {
            addr: tts.addr.clone(),
        };
        let tmd1 = verify_tag(&k, m.as_bytes(), &ttr).unwrap();
        assert_eq!(k, tmd1.ptr);
    }

    #[test]
    fn tag_fails() {
        let m1 = "Plaintext";
        let m2 = "Different Plaintext";
        let k1 = rand::random::<[u8; 16]>();
        let k2 = rand::random::<[u8; 16]>();
        let tmd0 = new_message(m1.as_bytes());
        let tts = generate_tag(&k1, m1.as_bytes(), &tmd0);
        let ttr = RecTraceTag {
            addr: tts.addr.clone(),
        };

        assert!(verify_tag(&k1, m2.as_bytes(), &ttr).is_none());
        assert!(verify_tag(&k2, m1.as_bytes(), &ttr).is_none());
    }

    #[test]
    fn process_tag_verifies() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let k = rand::random::<[u8; 16]>();
        let tmd0 = new_message(m.as_bytes());
        let tts = generate_tag(&k, m.as_bytes(), &tmd0);
        let ttr = svr_process(&conn, &tts, 0, 1).unwrap();
        let tmd1 = verify_tag(&k, m.as_bytes(), &ttr).unwrap();
        assert_eq!(k, tmd1.ptr);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[test]
    fn process_duplicate_address() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();
        let addr = rand::random::<[u8; 32]>();

        let tts1 = SenderTraceTag {
            addr: addr.clone(),
            ct: [1; 16],
        };
        let tts2 = SenderTraceTag {
            addr: addr.clone(),
            ct: [2; 16],
        };

        let resp1 = svr_process(&conn, &tts1, 0, 1);
        let resp2 = svr_process(&conn, &tts2, 0, 1);
        assert_eq!(resp1.unwrap().addr, tts1.addr);
        assert!(resp2.is_none());

        let ct: Vec<u8> = conn.hget(&tts1.addr, "ct").unwrap();
        assert_eq!(ct, tts1.ct);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[test]
    fn trace_simple_path() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let tmd0 = new_message(m.as_bytes());
        let tmd1 = mock_send(&conn, m.as_bytes(), &tmd0, 0, 1);
        let tmd2 = mock_send(&conn, m.as_bytes(), &tmd1, 1, 2);

        let path = svr_trace(&conn, m.as_bytes(), &tmd2, 2);
        assert_eq!(vec![2, 1, 0], path);

        let subpath = svr_trace(&conn, m.as_bytes(), &tmd1, 1);
        assert_eq!(vec![1, 0], subpath);

        let m2 = "Different Plaintext";
        let wrong_msg_path = svr_trace(&conn, m2.as_bytes(), &tmd2, 2);
        assert_eq!(vec![2], wrong_msg_path);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[test]
    fn trace_message_switch() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let m2 = "Different Plaintext";
        let tmd0 = new_message(m.as_bytes());
        let tmd1 = mock_send(&conn, m.as_bytes(), &tmd0, 0, 1);
        let tmd2 = mock_send(&conn, m2.as_bytes(), &tmd1, 1, 2);

        let path = svr_trace(&conn, m2.as_bytes(), &tmd2, 2);
        assert_eq!(vec![2, 1], path);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[test]
    fn trace_identity_binding() {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();

        let m = "Plaintext";
        let tmd0 = new_message(m.as_bytes());
        let tmd1 = mock_send(&conn, m.as_bytes(), &tmd0, 0, 1);
        let tmd2 = mock_send(&conn, m.as_bytes(), &tmd1, 3, 2);

        let path = svr_trace(&conn, m.as_bytes(), &tmd2, 2);
        assert_eq!(vec![2, 3], path);

        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

    #[bench]
    fn bench_tag_gen(b: &mut Bencher) {
        let m = [0u8; 256];
        let k = rand::random::<[u8; 16]>();
        let md = TraceMetadata {
            ptr: rand::random::<[u8; 16]>(),
        };
        b.iter(|| generate_tag(&k, &m, &md));
    }

    #[bench]
    fn bench_tag_receive(b: &mut Bencher) {
        let m = [0u8; 256];
        let k = rand::random::<[u8; 16]>();
        let ttr = RecTraceTag { addr: crprf(&k, &m) };
        b.iter(|| verify_tag(&k, &m, &ttr));
    }

    #[bench]
    fn bench_tag_process(b: &mut Bencher) {
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();
        let sid = rand::random::<u32>();
        let rid = rand::random::<u32>();
        let tts = SenderTraceTag {
            addr: rand::random::<[u8; 32]>(),
            ct: rand::random::<[u8; 16]>(),
        };
        b.iter(|| {
            svr_process(&conn, &tts, sid, rid);
            let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
        });
    }

    #[bench]
    fn bench_trace_path(b: &mut Bencher) {
        let len = 10;
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap();
        let m = [0u8; 256];
        let tmd = mock_path(&conn, &m, new_message(&m), len);
        b.iter(|| svr_trace(&conn, &m, &tmd, len));
        let _: () = redis::cmd("FLUSHDB").query(&conn).unwrap();
    }

}
