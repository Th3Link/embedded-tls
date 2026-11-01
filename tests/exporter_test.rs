//! The TLS exporter (RFC 8446 7.5) against rustls' exporter on the server
//! side: both ends must derive the same keying material.
use embedded_io_adapters::std::FromStd;
use rand::rngs::OsRng;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

mod tlsserver;

/// NTS (RFC 8915 5.1): the label and the contexts of the two keys.
const LABEL: &[u8] = b"EXPORTER-network-time-security";
const C2S: [u8; 5] = [0, 0, 0, 15, 0];
const S2C: [u8; 5] = [0, 0, 0, 15, 1];

/// Accepts one connection, completes the handshake and sends what its
/// exporter derives: 32 bytes for C2S, 64 for S2C, 16 for a short label
/// without context.
fn serve(listener: TcpListener) {
    let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let certs = tlsserver::load_certs(&test_dir.join("data").join("server-cert.pem"));
    let key = tlsserver::load_private_key(&test_dir.join("data").join("server-key.pem"));
    let config = rustls::ServerConfig::builder()
        .with_cipher_suites(rustls::ALL_CIPHER_SUITES)
        .with_kx_groups(&rustls::ALL_KX_GROUPS)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let (socket, _) = listener.accept().unwrap();
    let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, socket);
    // The client's first byte: the handshake is done.
    let mut byte = [0; 1];
    tls.read_exact(&mut byte).unwrap();

    let c2s = tls
        .conn
        .export_keying_material([0u8; 32], LABEL, Some(&C2S))
        .unwrap();
    let s2c = tls
        .conn
        .export_keying_material([0u8; 64], LABEL, Some(&S2C))
        .unwrap();
    let short = tls
        .conn
        .export_keying_material([0u8; 16], b"EXPERIMENTAL-x", Some(&[]))
        .unwrap();
    tls.write_all(&c2s).unwrap();
    tls.write_all(&s2c).unwrap();
    tls.write_all(&short).unwrap();
    tls.flush().unwrap();
}

fn exporter_matches_rustls<CipherSuite>()
where
    CipherSuite: embedded_tls::TlsCipherSuite + 'static,
{
    use embedded_tls::blocking::*;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || serve(listener));

    let stream = TcpStream::connect(addr).unwrap();
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<FromStd<TcpStream>, CipherSuite> = TlsConnection::new(
        FromStd::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let mut c2s = [0u8; 32];
    assert!(matches!(
        tls.export_keying_material(LABEL, &C2S, &mut c2s),
        Err(TlsError::MissingHandshake)
    ));

    tls.open(TlsContext::new(
        &config,
        UnsecureProvider::new::<CipherSuite>(OsRng),
    ))
    .expect("error establishing TLS connection");
    tls.write(b"x").unwrap();
    tls.flush().unwrap();

    let mut s2c = [0u8; 64];
    let mut short = [0u8; 16];
    tls.export_keying_material(LABEL, &C2S, &mut c2s).unwrap();
    tls.export_keying_material(LABEL, &S2C, &mut s2c).unwrap();
    tls.export_keying_material(b"EXPERIMENTAL-x", &[], &mut short)
        .unwrap();

    let mut expected = [0u8; 32 + 64 + 16];
    let mut read = 0;
    while read < expected.len() {
        read += tls.read(&mut expected[read..]).unwrap();
    }
    assert_eq!(&expected[..32], &c2s);
    assert_eq!(&expected[32..96], &s2c);
    assert_eq!(&expected[96..], &short);
    assert_ne!(&c2s[..], &s2c[..32]);

    server.join().unwrap();
}

#[test]
fn exporter_aes128_gcm_sha256() {
    exporter_matches_rustls::<embedded_tls::Aes128GcmSha256>();
}

#[test]
fn exporter_aes256_gcm_sha384() {
    exporter_matches_rustls::<embedded_tls::Aes256GcmSha384>();
}
