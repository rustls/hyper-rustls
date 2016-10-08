use std::process::{Command, Stdio};
use std::io::Write;
use std::thread;
use std::time;

#[test]
fn client() {
  let rc = Command::new("target/debug/examples/client")
    .arg("https://google.com")
    .output()
    .expect("cannot run client example");

  assert!(rc.status.success());
}

#[test]
fn server() {
  let mut srv = Command::new("target/debug/examples/server")
    .spawn()
    .expect("cannot run server example");

  thread::sleep(time::Duration::from_secs(1));

  let mut cli = Command::new("openssl")
    .arg("s_client")
    .arg("-ign_eof")
    .arg("-connect")
    .arg("localhost:1337")
    .stdin(Stdio::piped())
    .spawn()
    .expect("cannot run openssl");

  cli.stdin
    .as_mut()
    .unwrap()
    .write(b"GET / HTTP/1.0\r\n\r\n").unwrap();

  let rc = cli.wait()
    .expect("openssl failed");

  assert!(rc.success());

  srv.kill()
    .unwrap();
}
