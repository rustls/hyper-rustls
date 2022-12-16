use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time;

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
    let mut srv = server_command()
        .arg("1337")
        .spawn()
        .expect("cannot run server example");

    thread::sleep(time::Duration::from_secs(1));

    let output = Command::new("curl")
        .arg("--insecure")
        .arg("--http1.0")
        .arg("--silent")
        .arg("https://localhost:1337")
        .output()
        .expect("cannot run curl");

    println!("client output: {:?}", output.stdout);
    assert_eq!(output.stdout, b"Try POST /echo\n");

    srv.kill().unwrap();
}

#[test]
fn custom_ca_store() {
    let mut srv = server_command()
        .arg("1338")
        .spawn()
        .expect("cannot run server example");

    thread::sleep(time::Duration::from_secs(1));

    let rc = client_command()
        .arg("https://localhost:1338")
        .arg("examples/sample.pem")
        .output()
        .expect("cannot run client example");

    srv.kill().unwrap();

    if !rc.status.success() {
        assert_eq!(String::from_utf8_lossy(&rc.stdout), "");
    }
}
