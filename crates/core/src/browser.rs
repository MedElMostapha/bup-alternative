//! Opens Chrome or Firefox already set up to use the proxy. Each browser gets
//! its own profile under Sluice's data folder; the user's own profiles and
//! the system certificate store are never touched.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::ca::CertAuthority;

const CHROME_NAMES: &[&str] = &["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"];
const FIREFOX_NAMES: &[&str] = &["firefox", "firefox-esr"];
const IMPORT_TIMEOUT: Duration = Duration::from_secs(30);
const EXIT_GRACE: Duration = Duration::from_secs(10);
const IMPORTED_MARKER: &str = "sluice-imported-ca";

const IMPORT_SCRIPT: &str = r#"
Components.classes["@mozilla.org/security/x509certdb;1"]
  .getService(Components.interfaces.nsIX509CertDB)
  .addCertFromBase64(arguments[0], "C,,");
return true;
"#;

#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("{0} is not installed")]
    NotInstalled(BrowserKind),
    #[error("{0} is already open from Sluice")]
    AlreadyRunning(BrowserKind),
    #[error("could not add the certificate to Firefox: {0}. You can still import it by hand from Settings.")]
    CertificateImport(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserKind {
    Chrome,
    Firefox,
}

impl std::fmt::Display for BrowserKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Chrome => "Chrome",
            Self::Firefox => "Firefox",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserInfo {
    pub kind: BrowserKind,
    pub path: PathBuf,
}

/// Which browsers are open is true of the whole process, not of one project.
static RUNNING: LazyLock<Mutex<HashSet<BrowserKind>>> = LazyLock::new(Default::default);

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn find_first(names: &[&str], search_path: &OsStr) -> Option<PathBuf> {
    names.iter().find_map(|name| {
        std::env::split_paths(search_path)
            .map(|dir| dir.join(name))
            .find(|path| is_executable(path))
    })
}

fn detect_in(search_path: &OsStr) -> Vec<BrowserInfo> {
    [(BrowserKind::Chrome, CHROME_NAMES), (BrowserKind::Firefox, FIREFOX_NAMES)]
        .into_iter()
        .filter_map(|(kind, names)| find_first(names, search_path).map(|path| BrowserInfo { kind, path }))
        .collect()
}

pub fn detect() -> Vec<BrowserInfo> {
    detect_in(&std::env::var_os("PATH").unwrap_or_default())
}

/// A listener on every interface is reached through loopback.
fn reachable(proxy: SocketAddr) -> SocketAddr {
    match proxy.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::new(Ipv4Addr::LOCALHOST.into(), proxy.port()),
        IpAddr::V6(ip) if ip.is_unspecified() => SocketAddr::new(Ipv6Addr::LOCALHOST.into(), proxy.port()),
        _ => proxy,
    }
}

pub fn chrome_args(profile: &Path, proxy: SocketAddr, leaf_spki: &str) -> Vec<String> {
    vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server={}", reachable(proxy)),
        // Chrome skips the proxy for loopback unless this is set.
        "--proxy-bypass-list=<-loopback>".to_string(),
        format!("--ignore-certificate-errors-spki-list={leaf_spki}"),
        // Hides the banner warning about the option above.
        "--test-type".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-sync".to_string(),
        "--disable-component-update".to_string(),
        "--no-pings".to_string(),
    ]
}

pub fn firefox_user_js(proxy: SocketAddr, marionette_port: Option<u16>) -> String {
    let proxy = reachable(proxy);
    let host = proxy.ip();
    let port = proxy.port();
    let mut prefs = vec![
        ("network.proxy.type", "1".to_string()),
        ("network.proxy.http", format!("\"{host}\"")),
        ("network.proxy.http_port", port.to_string()),
        ("network.proxy.ssl", format!("\"{host}\"")),
        ("network.proxy.ssl_port", port.to_string()),
        ("network.proxy.no_proxies_on", "\"\"".to_string()),
        ("network.proxy.allow_hijacking_localhost", "true".to_string()),
        ("network.http.http3.enable", "false".to_string()),
    ];
    // Background requests that would otherwise fill the history.
    for name in [
        "network.captive-portal-service.enabled",
        "network.connectivity-service.enabled",
        "browser.safebrowsing.malware.enabled",
        "browser.safebrowsing.phishing.enabled",
        "browser.safebrowsing.downloads.enabled",
        "toolkit.telemetry.enabled",
        "datareporting.healthreport.uploadEnabled",
        "datareporting.policy.dataSubmissionEnabled",
        "app.update.auto",
        "app.normandy.enabled",
        "extensions.update.enabled",
        "browser.search.update",
        "browser.newtabpage.enabled",
        "browser.aboutwelcome.enabled",
        "browser.shell.checkDefaultBrowser",
    ] {
        prefs.push((name, "false".to_string()));
    }
    prefs.push(("security.OCSP.enabled", "0".to_string()));
    prefs.push(("network.trr.mode", "5".to_string()));
    prefs.push(("browser.startup.homepage_override.mstone", "\"ignore\"".to_string()));
    if let Some(port) = marionette_port {
        prefs.push(("marionette.port", port.to_string()));
    }
    prefs
        .iter()
        .map(|(name, value)| format!("user_pref(\"{name}\", {value});\n"))
        .collect()
}

/// Minimal client for Firefox's built-in automation protocol.
struct Marionette {
    stream: TcpStream,
    next_id: u64,
    deadline: Instant,
}

impl Marionette {
    fn connect(port: u16, deadline: Instant) -> io::Result<Self> {
        loop {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
                Ok(stream) => {
                    let mut client = Self {
                        stream,
                        next_id: 0,
                        deadline,
                    };
                    client.read_packet()?;
                    return Ok(client);
                }
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(e),
            }
        }
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Firefox did not respond in time"))?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read_exact(buffer)
    }

    /// Packets are `<length>:<json>`.
    fn read_packet(&mut self) -> io::Result<Value> {
        let mut length = 0usize;
        loop {
            let mut byte = [0u8; 1];
            self.read_exact(&mut byte)?;
            match byte[0] {
                b':' => break,
                digit @ b'0'..=b'9' => length = length * 10 + (digit - b'0') as usize,
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected Marionette data")),
            }
        }
        let mut body = vec![0u8; length];
        self.read_exact(&mut body)?;
        serde_json::from_slice(&body).map_err(io::Error::other)
    }

    fn command(&mut self, name: &str, params: Value) -> io::Result<Value> {
        self.next_id += 1;
        let body = json!([0, self.next_id, name, params]).to_string();
        self.stream.write_all(format!("{}:{body}", body.len()).as_bytes())?;
        let reply = self.read_packet()?;
        match reply.get(2) {
            Some(Value::Null) | None => Ok(reply.get(3).cloned().unwrap_or(Value::Null)),
            Some(error) => Err(io::Error::other(format!("{name}: {error}"))),
        }
    }
}

fn import_over_marionette(port: u16, certificate: &str) -> io::Result<()> {
    let mut client = Marionette::connect(port, Instant::now() + IMPORT_TIMEOUT)?;
    client.command("WebDriver:NewSession", json!({}))?;
    client.command("Marionette:SetContext", json!({ "value": "chrome" }))?;
    client.command(
        "WebDriver:ExecuteScript",
        json!({ "script": IMPORT_SCRIPT, "args": [certificate], "sandbox": "system" }),
    )?;
    client.command("Marionette:Quit", json!({}))?;
    Ok(())
}

fn free_port() -> io::Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port())
}

fn wait_or_kill(child: &mut Child) {
    let deadline = Instant::now() + EXIT_GRACE;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn quiet(command: &mut Command) -> &mut Command {
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
}

/// Writes the profile's settings and makes sure it trusts Sluice's root.
/// The slow certificate step only runs when the root has changed.
pub fn prepare_firefox(
    executable: &Path,
    profile: &Path,
    proxy: SocketAddr,
    ca: &CertAuthority,
) -> Result<(), BrowserError> {
    fs::create_dir_all(profile)?;
    let user_js = profile.join("user.js");
    let marker = profile.join(IMPORTED_MARKER);
    let certificate = ca.cert_base64();
    if fs::read_to_string(&marker).is_ok_and(|saved| saved == certificate) {
        fs::write(&user_js, firefox_user_js(proxy, None))?;
        return Ok(());
    }

    let port = free_port()?;
    fs::write(&user_js, firefox_user_js(proxy, Some(port)))?;
    let mut child = quiet(
        Command::new(executable)
            .args(["--headless", "--marionette", "--remote-allow-system-access", "--new-instance", "--profile"])
            .arg(profile),
    )
    .spawn()?;
    let imported = import_over_marionette(port, &certificate);
    // Firefox must finish writing the database and release the profile.
    wait_or_kill(&mut child);
    fs::write(&user_js, firefox_user_js(proxy, None))?;
    imported.map_err(|e| BrowserError::CertificateImport(e.to_string()))?;
    fs::write(&marker, certificate)?;
    Ok(())
}

fn spawn_browser(kind: BrowserKind, proxy: SocketAddr, data_dir: &Path, ca: &CertAuthority) -> Result<Child, BrowserError> {
    let info = detect()
        .into_iter()
        .find(|info| info.kind == kind)
        .ok_or(BrowserError::NotInstalled(kind))?;
    let profile = data_dir.join("browsers").join(match kind {
        BrowserKind::Chrome => "chrome",
        BrowserKind::Firefox => "firefox",
    });
    let mut command = Command::new(&info.path);
    match kind {
        BrowserKind::Chrome => {
            fs::create_dir_all(&profile)?;
            command.args(chrome_args(&profile, proxy, &ca.leaf_spki_base64()));
        }
        BrowserKind::Firefox => {
            prepare_firefox(&info.path, &profile, proxy, ca)?;
            command.args(["--new-instance", "--profile"]).arg(&profile);
        }
    }
    Ok(quiet(&mut command).spawn()?)
}

/// Opens a browser and returns once it has started. This can block for
/// several seconds the first time Firefox is used.
pub fn launch(kind: BrowserKind, proxy: SocketAddr, data_dir: &Path, ca: &CertAuthority) -> Result<(), BrowserError> {
    if !RUNNING.lock().expect("browser lock").insert(kind) {
        return Err(BrowserError::AlreadyRunning(kind));
    }
    match spawn_browser(kind, proxy, data_dir, ca) {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
                RUNNING.lock().expect("browser lock").remove(&kind);
            });
            Ok(())
        }
        Err(e) => {
            RUNNING.lock().expect("browser lock").remove(&kind);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn proxy() -> SocketAddr {
        "127.0.0.1:18080".parse().unwrap()
    }

    fn fake_executable(dir: &Path, name: &str) {
        let path = dir.join(name);
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn detects_the_first_match_for_each_browser() {
        let dir = tempfile::tempdir().unwrap();
        fake_executable(dir.path(), "chromium");
        fake_executable(dir.path(), "google-chrome");
        fake_executable(dir.path(), "firefox-esr");
        let found = detect_in(dir.path().as_os_str());
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].path, dir.path().join("google-chrome"));
        assert_eq!(found[1].path, dir.path().join("firefox-esr"));
    }

    #[test]
    fn non_executable_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("firefox"), "").unwrap();
        assert!(detect_in(dir.path().as_os_str()).is_empty());
    }

    #[test]
    fn chrome_uses_its_own_profile_proxy_and_fingerprint() {
        let args = chrome_args(Path::new("/data/chrome"), proxy(), "FINGERPRINT=");
        for expected in [
            "--user-data-dir=/data/chrome",
            "--proxy-server=127.0.0.1:18080",
            "--proxy-bypass-list=<-loopback>",
            "--ignore-certificate-errors-spki-list=FINGERPRINT=",
        ] {
            assert!(args.iter().any(|a| a == expected), "{expected} in {args:?}");
        }
    }

    #[test]
    fn firefox_settings_point_at_the_proxy() {
        let js = firefox_user_js(proxy(), None);
        assert!(js.contains("user_pref(\"network.proxy.type\", 1);"));
        assert!(js.contains("user_pref(\"network.proxy.ssl\", \"127.0.0.1\");"));
        assert!(js.contains("user_pref(\"network.proxy.ssl_port\", 18080);"));
        assert!(js.contains("user_pref(\"network.captive-portal-service.enabled\", false);"));
        assert!(!js.contains("marionette"));
    }

    #[test]
    fn marionette_port_is_only_set_for_the_import() {
        assert!(firefox_user_js(proxy(), Some(4444)).contains("user_pref(\"marionette.port\", 4444);"));
    }

    #[test]
    fn a_listener_on_all_interfaces_is_reached_through_loopback() {
        let any: SocketAddr = "0.0.0.0:8081".parse().unwrap();
        assert!(firefox_user_js(any, None).contains("\"127.0.0.1\""));
    }

    #[test]
    fn a_ready_firefox_profile_is_not_imported_again() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertAuthority::load_or_create(&dir.path().join("ca")).unwrap();
        let profile = dir.path().join("profile");
        fs::create_dir_all(&profile).unwrap();
        fs::write(profile.join(IMPORTED_MARKER), ca.cert_base64()).unwrap();
        // The executable does not exist, so this only passes if it is not run.
        prepare_firefox(Path::new("/nonexistent/firefox"), &profile, proxy(), &ca).unwrap();
        assert!(fs::read_to_string(profile.join("user.js")).unwrap().contains("18080"));
    }
}
