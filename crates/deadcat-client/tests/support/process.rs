use std::io::{self, BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bitcoincore_rpc::Auth;
use deadcat_iroh::EndpointAddr;
use deadcat_rpc::{NodeInfo, Response};
use deadcat_types::LiquidNetwork;
use elements::AssetId;
use serde_json::Value as JsonValue;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) struct NodeProcess {
    child: Option<Child>,
    endpoint: Option<EndpointAddr>,
}

impl NodeProcess {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn(
        binary: &Path,
        database: &Path,
        iroh_secret: &Path,
        network: LiquidNetwork,
        policy_asset: AssetId,
        baseline_height: Option<u32>,
        rpc_url: &str,
        auth: &Auth,
    ) -> Self {
        let mut command = Command::new(binary);
        command
            .arg("run")
            .arg("--database")
            .arg(database)
            .arg("--iroh-secret")
            .arg(iroh_secret)
            .arg("--network")
            .arg(match network {
                LiquidNetwork::Liquid => "liquid",
                LiquidNetwork::LiquidTestnet => "liquid-testnet",
                LiquidNetwork::ElementsRegtest => "elements-regtest",
            })
            .arg("--policy-asset")
            .arg(policy_asset.to_string())
            .arg("--sync-interval-seconds")
            .arg("1")
            .arg("--direct-only");
        if let Some(height) = baseline_height {
            command.arg("--baseline-height").arg(height.to_string());
        }
        append_elements_backend(&mut command, rpc_url, auth);
        command
            .env("RUST_LOG", "deadcat=warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let child = command
            .spawn()
            .unwrap_or_else(|error| panic!("failed to spawn {}: {error}", binary.display()));
        let mut process = Self {
            child: Some(child),
            endpoint: None,
        };
        let stdout = process
            .child
            .as_mut()
            .expect("spawned child")
            .stdout
            .take()
            .expect("node stdout pipe");
        let (send, receive) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let result = reader.read_line(&mut line).and_then(|read| {
                if read == 0 {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "node exited before printing its endpoint",
                    ))
                } else {
                    Ok(line)
                }
            });
            let _ = send.send(result);
            // Tracing may keep writing after the endpoint line. Drain the
            // pipe for the daemon lifetime so later diagnostics never see
            // EPIPE merely because the test already parsed its address.
            let _ = io::copy(&mut reader, &mut io::sink());
        });
        let endpoint_line = receive
            .recv_timeout(PROCESS_TIMEOUT)
            .expect("node endpoint startup timed out")
            .expect("read node endpoint");
        process.endpoint = Some(
            serde_json::from_str(endpoint_line.trim())
                .unwrap_or_else(|error| panic!("invalid node endpoint {endpoint_line:?}: {error}")),
        );
        assert!(
            process.endpoint().ip_addrs().next().is_some(),
            "direct-only node did not advertise an IP address"
        );
        process
    }

    pub(super) fn endpoint(&self) -> &EndpointAddr {
        self.endpoint
            .as_ref()
            .expect("node endpoint is initialized")
    }

    pub(super) fn stop_gracefully(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let status = stop_child(&mut child)
            .unwrap_or_else(|error| panic!("failed to stop node cleanly: {error}"));
        assert!(status.success(), "node exited unsuccessfully: {status}");
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            terminate_and_reap(&mut child);
        }
    }
}

pub(super) fn required_binary(variable: &str, name: &str) -> PathBuf {
    let path = std::env::var_os(variable).map_or_else(
        || {
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
            target
                .join("debug")
                .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
        },
        PathBuf::from,
    );
    assert!(
        path.is_file(),
        "required process-test binary {} is missing; run the dedicated just recipe",
        path.display()
    );
    path
}

pub(super) fn cli_output(binary: &Path, endpoint: &EndpointAddr, args: &[String]) -> Output {
    let mut command = configured_cli(binary, endpoint);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().unwrap_or_else(|error| {
        panic!("failed to run {} with {args:?}: {error}", binary.display())
    });
    wait_for_output(child, PROCESS_TIMEOUT)
        .unwrap_or_else(|error| panic!("{} {args:?} did not complete: {error}", binary.display()))
}

pub(super) fn cli_response(binary: &Path, endpoint: &EndpointAddr, args: &[String]) -> Response {
    try_cli_response(binary, endpoint, args).unwrap_or_else(|error| panic!("{error}"))
}

pub(super) fn wait_for_info(
    binary: &Path,
    endpoint: &EndpointAddr,
    predicate: impl Fn(&NodeInfo) -> bool,
) -> NodeInfo {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        let latest = match try_cli_response(binary, endpoint, &["get-info".to_owned()]) {
            Ok(Response::Info { info }) if predicate(&info) => return info,
            Ok(response) => format!("unexpected response: {response:?}"),
            Err(error) => error,
        };
        assert!(
            Instant::now() < deadline,
            "node did not reach the expected state within {PROCESS_TIMEOUT:?}: {latest}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

pub(super) fn subscription_until(
    binary: &Path,
    endpoint: &EndpointAddr,
    args: &[String],
    predicate: impl Fn(&JsonValue) -> bool + Send + 'static,
) -> Vec<JsonValue> {
    let mut command = configured_cli(binary, endpoint);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().expect("spawn deadcat subscription CLI");
    let stdout = child.stdout.take().expect("subscription stdout");
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut values = Vec::new();
        let mut stream =
            serde_json::Deserializer::from_reader(&mut reader).into_iter::<JsonValue>();
        let result = loop {
            match stream.next() {
                Some(Ok(value)) => {
                    let matched = predicate(&value);
                    values.push(value);
                    if matched {
                        break Ok(values);
                    }
                    if values.len() == 256 {
                        break Err(
                            "subscription predicate did not match within 256 frames".to_owned()
                        );
                    }
                }
                Some(Err(error)) => break Err(error.to_string()),
                None => break Err("subscription ended before the expected event".to_owned()),
            }
        };
        let _ = send.send(result);
        // Keep the pipe open until the parent sends SIGINT. Otherwise the CLI
        // can observe EPIPE while it races to emit a later durable event.
        let _ = io::copy(&mut reader, &mut io::sink());
    });
    let received = receive.recv_timeout(PROCESS_TIMEOUT);
    let status = stop_child(&mut child)
        .unwrap_or_else(|error| panic!("failed to stop subscription CLI: {error}"));
    assert!(status.success(), "subscription CLI failed: {status}");
    received
        .expect("subscription output timed out")
        .expect("decode subscription output")
}

pub(super) fn run_rebuild(binary: &Path, database: &Path, rpc_url: &str, auth: &Auth) -> String {
    let mut command = Command::new(binary);
    command.arg("rebuild").arg("--database").arg(database);
    append_elements_backend(&mut command, rpc_url, auth);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn().expect("spawn deadcat-node rebuild");
    let output = wait_for_output(child, PROCESS_TIMEOUT).expect("deadcat-node rebuild timed out");
    assert!(
        output.status.success(),
        "rebuild failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("rebuild stdout is UTF-8")
}

fn try_cli_response(
    binary: &Path,
    endpoint: &EndpointAddr,
    args: &[String],
) -> Result<Response, String> {
    let output = cli_output(binary, endpoint, args);
    if !output.status.success() {
        return Err(format!(
            "deadcat {args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "deadcat {args:?} returned invalid response JSON: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn configured_cli(binary: &Path, endpoint: &EndpointAddr) -> Command {
    let mut command = Command::new(binary);
    command.arg("--endpoint-id").arg(endpoint.id.to_string());
    for address in endpoint.ip_addrs() {
        command.arg("--direct-addr").arg(address.to_string());
    }
    command
}

fn append_elements_backend(command: &mut Command, rpc_url: &str, auth: &Auth) {
    command.arg("elements").arg("--url").arg(rpc_url);
    match auth {
        Auth::None => {}
        Auth::UserPass(username, password) => {
            command
                .arg("--rpc-user")
                .arg(username)
                .arg("--rpc-password")
                .arg(password);
        }
        Auth::CookieFile(path) => {
            command.arg("--cookie-file").arg(path);
        }
    }
}

fn interrupt(child: &mut Child) -> Result<(), String> {
    let status = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map_err(|error| format!("invoke kill -INT: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("kill -INT exited with {status}"))
    }
}

fn stop_child(child: &mut Child) -> Result<std::process::ExitStatus, String> {
    let initial = match child.try_wait() {
        Ok(status) => status,
        Err(error) => {
            terminate_and_reap(child);
            return Err(format!("poll child process: {error}"));
        }
    };
    if let Some(status) = initial {
        return Ok(status);
    }
    if let Err(error) = interrupt(child) {
        if let Ok(Some(status)) = child.try_wait() {
            return Ok(status);
        }
        terminate_and_reap(child);
        return Err(error);
    }
    match wait_for_exit(child, PROCESS_TIMEOUT) {
        Ok(Some(status)) => Ok(status),
        Ok(None) => {
            terminate_and_reap(child);
            Err("child process did not stop after SIGINT".to_owned())
        }
        Err(error) => {
            terminate_and_reap(child);
            Err(error)
        }
    }
}

fn wait_for_exit(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll child process: {error}"))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn terminate_and_reap(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn wait_for_output(mut child: Child, timeout: Duration) -> Result<Output, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let exited = match child.try_wait() {
            Ok(status) => status.is_some(),
            Err(error) => {
                terminate_and_reap(&mut child);
                return Err(format!("failed to poll child: {error}"));
            }
        };
        if exited {
            return child
                .wait_with_output()
                .map_err(|error| format!("failed to collect child output: {error}"));
        }
        if Instant::now() >= deadline {
            terminate_and_reap(&mut child);
            return Err("timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(50));
    }
}
