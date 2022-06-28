use std::{
    collections::HashMap,
    convert::TryFrom,
    path::PathBuf,
    sync::Arc,
};

use crate::error::{
    WireguardRestApiError,
    WireguardRestApiResult,
};
use serde::Serialize;
use tokio::sync::RwLock;

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct PeerOutput {
    pub public_key: String,
    pub allowed_ips: String,
    pub latest_handshake: String,
    pub transfer: String,
}

impl TryFrom<&str> for PeerOutput {
    type Error = WireguardRestApiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.trim();
        let lines: HashMap<&str, &str> = value
            .split('\n')
            .map(|v| v.trim())
            .filter_map(|v| v.split_once(": "))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect();
        log::debug!(" :: PeerOutput raw ::\n{:#?}", lines);

        Ok(PeerOutput {
            public_key: lines
                .get("peer")
                .ok_or_else(|| {
                    WireguardRestApiError::ConfigParseError(
                        "key 'peer' not found in output".to_string(),
                    )
                })?
                .to_string(),
            allowed_ips: lines
                .get("allowed ips")
                .ok_or_else(|| {
                    WireguardRestApiError::ConfigParseError(
                        "key 'allowed ips' not found in output".to_string(),
                    )
                })?
                .to_string(),
            latest_handshake: lines
                .get("latest handshake")
                .ok_or_else(|| {
                    WireguardRestApiError::ConfigParseError(
                        "key 'latest handshake' not found in output".to_string(),
                    )
                })?
                .to_string(),
            transfer: lines
                .get("transfer")
                .ok_or_else(|| {
                    WireguardRestApiError::ConfigParseError(
                        "key 'transfer' not found in output".to_string(),
                    )
                })?
                .to_string(),
        })
    }
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct WireguardShowOutput {
    pub peers: Vec<PeerOutput>,
}

impl TryFrom<&str> for WireguardShowOutput {
    type Error = WireguardRestApiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            peers: value
                .split("\n\n")
                .filter_map(|v| TryFrom::try_from(v).ok())
                .collect(),
        })
    }
}

/// Wrapper around config file access and cli commands
#[derive(Clone)]
pub struct WireguardCli {
    /// this symbolises file access
    pub file_path: Arc<RwLock<PathBuf>>,
    /// this symbolises cli access
    pub interface_name: Arc<RwLock<String>>,
}
fn normalize(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}
fn handle_output(output: &std::process::Output) -> WireguardRestApiResult<String> {
    let (stdout, stderr) = (normalize(&output.stdout), normalize(&output.stderr));
    if !output.status.success() {
        Err(WireguardRestApiError::CommandError {
            code: output.status.code(),
            message: if stderr.is_empty() { stdout } else { stderr },
        })
    } else {
        Ok(stdout)
    }
}
impl WireguardCli {
    pub fn new(file_path: &std::path::Path) -> WireguardRestApiResult<Self> {
        file_path.try_exists()?;
        let filename = file_path
            .file_name()
            .ok_or(WireguardRestApiError::NotFound)?
            .to_string_lossy()
            .to_string();
        let extension = file_path
            .extension()
            .ok_or(WireguardRestApiError::NotFound)?
            .to_string_lossy()
            .to_string();
        let extension_part = format!(".{}", extension);
        let interface_name = filename.trim_end_matches(&extension_part);

        Ok(Self {
            file_path: Arc::new(RwLock::new(file_path.to_owned())),
            interface_name: Arc::new(RwLock::new(interface_name.to_string())),
        })
    }
    async fn wireguard_status_raw(&self) -> WireguardRestApiResult<String> {
        let interface_name = self.interface_name.read().await;
        let mut command = tokio::process::Command::new("wg");
        command.arg("show").arg(interface_name.as_str());
        log::debug!(" :: executing command :: {:?}", command);
        let output = command.output().await?;
        handle_output(&output)
    }

    pub async fn wireguard_status(&self) -> WireguardRestApiResult<WireguardShowOutput> {
        WireguardShowOutput::try_from(self.wireguard_status_raw().await?.as_str())
    }
    pub async fn wireguard_refresh(&self) -> WireguardRestApiResult<()> {
        use tokio::process::Command;
        let interface_name = self.interface_name.write().await;
        handle_output(
            &Command::new("wg-quick")
                .arg("down")
                .arg(interface_name.as_str())
                .output()
                .await?,
        )?;
        handle_output(
            &Command::new("wg-quick")
                .arg("up")
                .arg(interface_name.as_str())
                .output()
                .await?,
        )?;
        Ok(())
        // let mut command = txcokio::process::Command::new("wg-quick")
    }
}
// fn wireguard_status_raw(interface_name: &str) -> WireguardRestApiResult<String> {
//     let mut command = std::process::Command::new("wg");
//     command.arg("show").arg(interface_name);
//     log::debug!(" :: executing command :: {:?}", command);
//     let output = command.output()?;
//     let output = String::from_utf8_lossy(&output.stdout).to_string();
//     log::debug!(" :: output ::\n{}", output);
//     Ok(output)
// }

// pub fn wireguard_status(interface_name: &str) -> WireguardRestApiResult<WireguardShowOutput> {
//     WireguardShowOutput::try_from(wireguard_status_raw(interface_name)?.as_str())
// }

#[cfg(test)]
mod test_wireguard_cli {
    use super::*;
    const FULL_OUTPUT: &str = r#"interface: wg0
  public key: Wln+VBn+kjmNK2LVtnXEewhoBNnpnqgZqmj1+AhG1Vs=
  private key: (hidden)
  listening port: 51820

peer: KBHVKxxg0kf+yGcPX94VgDigACuY3fS3Id0UdOVGXxc=
  endpoint: 31.60.50.91:7115
  allowed ips: 192.0.2.5/32
  latest handshake: 26 seconds ago
  transfer: 43.54 MiB received, 1023.41 KiB sent

peer: 0UtJfUPpQpQrhHoJ8wknG1oIz71QOdwOuRzkY5Mzgko=
  endpoint: 80.48.164.90:59166
  allowed ips: 192.0.2.15/32
  latest handshake: 27 seconds ago
  transfer: 7.82 MiB received, 1.13 MiB sent

peer: tidfxUXZ4BJjLC98zIUB8bdEowF+5ivtUnaFKrzm/Gw=
  endpoint: 80.48.164.90:41163
  allowed ips: 192.0.2.6/32
  latest handshake: 31 seconds ago
  transfer: 49.32 MiB received, 1.29 MiB sent

peer: fL7q1wazXVq2OZLtGZtNVmQPDENnu0RX0piccZMgn34=
  endpoint: 91.208.78.242:49798
  allowed ips: 192.0.2.8/32
  latest handshake: 40 seconds ago
  transfer: 42.67 MiB received, 1003.73 KiB sent

peer: gL1ujq1Eyh+FGHIFJSbJFYzrBkT6+8VbywtR27jPoQ0=
  endpoint: 80.48.164.90:53511
  allowed ips: 192.0.2.11/32
  latest handshake: 1 minute, 4 seconds ago
  transfer: 52.18 MiB received, 1.47 MiB sent

peer: rbkuZ+3SyPtT/QLZhFhiTo555ekSCJRsHf3jJb5kdkI=
  endpoint: 217.96.243.205:50224
  allowed ips: 192.0.2.2/32
  latest handshake: 1 minute, 6 seconds ago
  transfer: 64.87 MiB received, 77.40 MiB sent

peer: 1qGZ4pzx5BKku3TLjYZwKm3H7zOEhrZ1aGJ90FlAQFw=
  endpoint: 80.48.164.90:54560
  allowed ips: 192.0.2.9/32
  latest handshake: 1 minute, 30 seconds ago
  transfer: 43.55 MiB received, 1.51 MiB sent

peer: mWVmpWIo+Nlr9MJks82r/i/ZySXjhuUYgrIVCeUaMXw=
  endpoint: 80.48.164.90:52277
  allowed ips: 192.0.2.10/32
  latest handshake: 1 minute, 40 seconds ago
  transfer: 43.49 MiB received, 1.02 MiB sent

peer: I/ig5VyXW+QP8d2l5A672TiF905ofCQSsJ+ypwJ/5Uk=
  endpoint: 195.136.207.106:62290
  allowed ips: 192.0.2.4/32
  latest handshake: 1 minute, 54 seconds ago
  transfer: 58.80 MiB received, 1.86 MiB sent

peer: lGExho0DizJAfYp1rOo/HvAc+dDb7m7e2cqKoYxbKm0=
  endpoint: 31.60.18.66:10913
  allowed ips: 192.0.2.7/32
  latest handshake: 6 days, 3 hours, 23 minutes, 30 seconds ago
  transfer: 66.54 MiB received, 22.93 MiB sent

peer: Nkq/T9eM+EbUAQ2LQ3DtKIZH9tFtJJIM9Pg+CpjK5Ec=
  endpoint: 83.23.16.77:44535
  allowed ips: 192.0.2.3/32
  latest handshake: 7 days, 17 hours, 46 minutes, 22 seconds ago
  transfer: 2.39 MiB received, 519.93 KiB sent

peer: O2M7actvTiOVapkxyB0bUYidbGwDavnyfx9O1isudiM=
  allowed ips: 192.0.2.13/32

peer: p6Fzp5BrmyQJGb63/eDmZe2ovQz/pMwf4kr8FrBqoRY=
  allowed ips: 192.0.2.12/32

peer: h4AwTZ29w+XRjAKR5nYxa0dEh0H7fjRfAPnTqlo80wM=
  allowed ips: 192.0.2.14/32"#;

    const SINGLE_ENTRY: &str = r#"peer: 1qGZ4pzx5BKku3TLjYZwKm3H7zOEhrZ1aGJ90FlAQFw=
  endpoint: 80.48.164.90:54560
  allowed ips: 192.0.2.9/32
  latest handshake: 1 minute, 30 seconds ago
  transfer: 43.55 MiB received, 1.51 MiB sent"#;

    #[test]
    fn test_wireguard_output_single_entry() {
        assert_eq!(
            PeerOutput::try_from(SINGLE_ENTRY).unwrap(),
            PeerOutput {
                public_key: "1qGZ4pzx5BKku3TLjYZwKm3H7zOEhrZ1aGJ90FlAQFw=".to_string(),
                latest_handshake: "1 minute, 30 seconds ago".to_string(),
                allowed_ips: "192.0.2.9/32".to_string(),
                transfer: "43.55 MiB received, 1.51 MiB sent".to_string(),
            }
        )
    }

    #[test]
    fn test_name() {
        let entries = WireguardShowOutput::try_from(FULL_OUTPUT).unwrap();
        assert_eq!(entries.peers.len(), 11, "wrong number of peers detected");
    }
}
