use std::env;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

fn examples_dir() -> PathBuf {
    let target_dir: PathBuf = env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| "target".to_string())
        .into();
    target_dir
        .join("debug")
        .join("examples")
}

fn server_command() -> Command {
    Command::new(examples_dir().join("server"))
}

fn start_server() -> (Child, SocketAddr) {
    let mut srv = server_command()
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("cannot run server example");

    let stdout = srv
        .stdout
        .take()
        .expect("failed to get stdout");

    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("failed to read line");

    let addr = line
        .trim()
        .strip_prefix("Starting to serve on https://")
        .expect("unexpected output")
        .parse()
        .expect("failed to parse socket address");

    (srv, addr)
}

fn client_command() -> Command {
    Command::new(examples_dir().join("client"))
}

#[test]
fn client() {
    let rc = client_command()
        .arg("https://google.com")
        .output()
        .expect("cannot run client example");

    assert!(rc.status.success());
}

#[test]
fn server() {
    let (mut srv, addr) = start_server();

    let output = Command::new("curl")
        .arg("--insecure")
        .arg("--http1.0")
        .arg(format!("https://localhost:{}", addr.port()))
        .output()
        .expect("cannot run curl");

    srv.kill().unwrap();
    srv.wait()
        .expect("failed to wait on server process");

    if !output.status.success() {
        let version_stdout = Command::new("curl")
            .arg("--version")
            .output()
            .expect("cannot run curl to collect --version")
            .stdout;
        println!("curl version: {}", String::from_utf8_lossy(&version_stdout));
        println!("curl stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }

    assert_eq!(String::from_utf8_lossy(&output.stdout), "Try POST /echo\n");
}

#[test]
fn custom_ca_store() {
    let (mut srv, addr) = start_server();

    let rc = client_command()
        .arg(format!("https://localhost:{}", addr.port()))
        .arg("examples/sample.pem")
        .output()
        .expect("cannot run client example");

    srv.kill().unwrap();
    srv.wait()
        .expect("failed to wait on server process");

    if !rc.status.success() {
        assert_eq!(String::from_utf8_lossy(&rc.stdout), "");
        panic!("test failed");
    }
}
