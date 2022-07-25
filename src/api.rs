use crate::{
    wireguard_cli::WireguardCli,
    wireguard_conf::WireguardEntry,
};
use std::path::PathBuf;
use warp::Filter;

pub fn json_body() -> impl Filter<Extract = (WireguardEntry,), Error = warp::Rejection> + Clone {
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

pub fn with_file_path(
    file_path: PathBuf,
) -> impl Filter<Extract = (PathBuf,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || file_path.clone())
}

pub fn with_secret(
    secret: String,
) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || secret.clone())
}

pub fn with_wireguard_cli(
    wireguard_cli: WireguardCli,
) -> impl Filter<Extract = (WireguardCli,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || wireguard_cli.clone())
}

pub fn api(
    // file_path: PathBuf,
    secret: String,
    wireguard_cli: WireguardCli,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    config_list(secret.clone(), wireguard_cli.clone())
        .or(active_config_entries_list(
            // file_path.clone(),
            secret.clone(),
            wireguard_cli.clone(),
        ))
        .or(config_get(
            // file_path.clone(),
            secret.clone(),
            wireguard_cli.clone(),
        ))
        .or(config_delete(
            // file_path.clone(),
            secret.clone(),
            wireguard_cli.clone(),
        ))
        .or(config_create(
            // file_path.clone(),
            secret,
            wireguard_cli,
        ))
}

pub fn config_list(
    // file_path: PathBuf,
    secret: String,
    wireguard_cli: WireguardCli,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::get())
        // .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and(with_wireguard_cli(wireguard_cli))
        .and_then(handlers::config_list)
}

pub fn active_config_entries_list(
    // file_path: PathBuf,
    secret: String,
    wireguard_cli: WireguardCli,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("active")
        .and(warp::get())
        // .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and(with_wireguard_cli(wireguard_cli))
        .and_then(handlers::active_config_entries_list)
}

pub fn config_get(
    // file_path: PathBuf,
    secret: String,
    wireguard_cli: WireguardCli,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!(usize)
        .and(warp::post())
        // .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and(with_wireguard_cli(wireguard_cli))
        .and_then(handlers::config_get)
}

pub fn config_create(
    // file_path: PathBuf,
    secret: String,
    wireguard_cli: WireguardCli,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::post())
        .and(json_body())
        // .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and(with_wireguard_cli(wireguard_cli))
        .and_then(handlers::config_create)
}

pub fn config_delete(
    // file_path: PathBuf,
    secret: String,
    wireguard_cli: WireguardCli,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!(usize)
        .and(warp::delete())
        // .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and(with_wireguard_cli(wireguard_cli))
        .and_then(handlers::config_delete)
}

pub mod handlers {
    use crate::{
        error::WireguardRestApiError,
        wireguard_cli::WireguardCli,
        wireguard_conf::{
            WireguardConfig,
            WireguardEntry,
        },
    };
    use itertools::Itertools;
    use serde::Serialize;
    use std::{
        collections::HashMap,
        convert::Infallible,
    };
    use warp::http::StatusCode;

    #[derive(Serialize, Debug)]
    pub struct ErrorMessage {
        pub code: u16,
        pub message: String,
    }

    #[macro_export]
    macro_rules! or_error {
        ($result:expr) => {
            match $result {
                Ok(something) => something,
                Err(e) => {
                    let code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
                    let message = ErrorMessage {
                        code: code.as_u16(),
                        message: format!("{:?}", e),
                    };
                    let json = warp::reply::json(&message);
                    log::error!(" :: {:#?} ::", message);
                    return Ok(warp::reply::with_status(json, code));
                }
            }
        };
    }

    #[macro_export]
    macro_rules! auth_required {
        ($token:expr, $secret:expr) => {
            log::debug!(" :: token :: {:?}", $token);
            log::debug!(" :: secret :: {:?}", $secret);
            let token = if let Some(token) = $token {
                token
            } else {
                let code = warp::http::StatusCode::UNAUTHORIZED;
                let message = ErrorMessage {
                    code: code.as_u16(),
                    message: "Not authorized".to_string(),
                };
                log::error!(" :: {:#?} ::", message);
                let json = warp::reply::json(&message);
                return Ok(warp::reply::with_status(json, code));
            };
            if token.replace("Bearer ", "") == $secret {
                log::debug!(" :: auth OK ::");
            } else {
                let code = warp::http::StatusCode::UNAUTHORIZED;
                let message = ErrorMessage {
                    code: code.as_u16(),
                    message: "Not authorized".to_string(),
                };
                log::error!(" :: {:#?} ::", message);
                let json = warp::reply::json(&message);
                return Ok(warp::reply::with_status(json, code));
            }
        };
    }

    async fn read_config<T: AsRef<std::path::Path>>(
        file_path: T,
    ) -> Result<WireguardConfig, WireguardRestApiError> {
        let mut text: String = tokio::fs::read_to_string(&file_path).await?;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        let parse = WireguardConfig::from_str(&text);
        match parse {
            Ok((_, config)) => Ok(config),
            Err(e) => Err(WireguardRestApiError::ConfigParseError(e.to_string())),
        }
    }

    pub async fn config_list(
        // file_path: PathBuf,
        token: Option<String>,
        secret: String,
        wireguard_cli: WireguardCli,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        let file_path = wireguard_cli.file_path.read().await;
        let config = or_error!(read_config(file_path.as_path()).await);

        Ok(warp::reply::with_status(
            warp::reply::json(&config),
            StatusCode::OK,
        ))
    }

    pub async fn active_config_entries_list(
        // file_path: PathBuf,
        token: Option<String>,
        secret: String,
        wireguard_cli: WireguardCli,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        let file_path = wireguard_cli.file_path.read().await;
        let mut config = or_error!(read_config(file_path.as_path()).await);
        let status = or_error!(wireguard_cli.wireguard_status().await);
        let entries = status
            .peers
            .into_iter()
            .map(|p| (p.public_key.clone(), p))
            .collect::<HashMap<_, _>>();
        config.0.retain(|_, v| {
            v.values
                .get("PublicKey")
                .map(|key| entries.contains_key(key))
                .unwrap_or(false)
        });
        Ok(warp::reply::with_status(
            warp::reply::json(&config),
            StatusCode::OK,
        ))
    }

    pub async fn config_get(
        id: usize,
        // file_path: PathBuf,
        token: Option<String>,
        secret: String,
        wireguard_cli: WireguardCli,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        let file_path = wireguard_cli.file_path.read().await;
        let config = or_error!(read_config(file_path.as_path()).await);
        let entry = or_error!(config.0.get(&id).ok_or(WireguardRestApiError::NotFound));

        Ok(warp::reply::with_status(
            warp::reply::json(&entry),
            StatusCode::OK,
        ))
    }

    pub async fn config_delete(
        id: usize,
        // file_path: PathBuf,
        token: Option<String>,
        secret: String,
        wireguard_cli: WireguardCli,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        let file_path = wireguard_cli.file_path.write().await;
        let mut config = or_error!(read_config(file_path.as_path()).await);
        let _entry = or_error!(config.0.remove(&id).ok_or(WireguardRestApiError::NotFound));
        or_error!(tokio::fs::write(file_path.as_path(), &config.to_string()).await);
        or_error!(wireguard_cli.wireguard_refresh().await);

        Ok(warp::reply::with_status(
            warp::reply::json(&config),
            StatusCode::OK,
        ))
    }

    async fn update_config_with_entry(
        mut config: WireguardConfig,
        create: WireguardEntry,
    ) -> Result<WireguardConfig, WireguardRestApiError> {
        if let Some((id, v)) = config
            .0
            .iter()
            .find(|(_, v)| v.values.get("PublicKey") == create.values.get("PublicKey"))
        {
            return Err(WireguardRestApiError::NonUniquePublicKey(
                *id,
                create.clone(),
                v.clone(),
            ));
        }
        let before = config.0.len();
        // let allowed_ips = "allowed_ips";

        let key = |entry: &WireguardEntry| -> Option<String> {
            entry.extra_metadata.get("StationLocation").cloned()
        };
        let new = config
            .0
            .drain(..)
            .filter(|(_, entry)| {
                let already_exists = key(entry)
                    .map(|ip| {
                        key(&create)
                            .map(|create_ip| create_ip == ip)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                !already_exists
            })
            .rev()
            .collect_vec()
            .into_iter()
            .unique_by(|(index, entry)| key(entry).unwrap_or_else(|| index.to_string()))
            .collect_vec()
            .into_iter()
            .rev()
            .collect();
        config.0 = new;
        println!("WARN: removed {} entries", before - config.0.len());
        let _entry = config.0.insert(before * 2, create);
        Ok(config)
    }

    #[cfg(test)]
    mod tests {
        use crate::wireguard_conf::WireguardEntryType::Peer;

        use super::*;
        use eyre::{
            Result,
            WrapErr,
        };
        #[tokio::test]
        async fn test_adding_entries() -> Result<()> {
            const STATION_LOCATION_KEY: &str = "StationLocation";
            const PUBLIC_KEY_KEY: &str = "PublicKey";
            let config: WireguardConfig = Default::default();
            let entry = |location_name: &str| -> WireguardEntry {
                WireguardEntry {
                    kind: Peer,
                    values: vec![(PUBLIC_KEY_KEY.to_string(), uuid::Uuid::new_v4().to_string())]
                        .into_iter()
                        .collect(),
                    extra_metadata: vec![(
                        STATION_LOCATION_KEY.to_string(),
                        location_name.to_string(),
                    )]
                    .into_iter()
                    .collect(),
                }
            };
            let station_a = "station-a";
            let station_b = "station-b";
            assert_eq!(entry_by_station_name(&config, station_a), None);
            assert_eq!(entry_by_station_name(&config, station_b), None);
            let config = update_config_with_entry(config, entry(station_a)).await?;

            assert!(entry_by_station_name(&config, station_a).is_some());
            assert_eq!(entry_by_station_name(&config, station_b), None);

            let config = update_config_with_entry(config, entry(station_b)).await?;
            assert!(entry_by_station_name(&config, station_a).is_some());
            assert!(entry_by_station_name(&config, station_b).is_some());

            let config = update_config_with_entry(config, entry(station_a)).await?;
            assert!(entry_by_station_name(&config, station_a).is_some());
            assert!(entry_by_station_name(&config, station_b).is_some());

            Ok(())
        }

        fn entry_by_station_name<'config>(
            config: &'config WireguardConfig,
            location_name: &str,
        ) -> Option<&'config WireguardEntry> {
            config.0.iter().map(|(_, v)| v).find(|v| {
                v.extra_metadata
                    .iter()
                    .map(|(_, v)| v)
                    .any(|v| v == location_name)
            })
        }
    }

    async fn config_create_task(
        create: WireguardEntry,
        wireguard_cli: WireguardCli,
    ) -> Result<(), WireguardRestApiError> {
        let file_path = wireguard_cli.file_path.write().await;
        let config = read_config(file_path.as_path()).await?;
        let config = update_config_with_entry(config, create).await?;
        tokio::fs::write(file_path.as_path(), &config.to_string()).await?;
        wireguard_cli.wireguard_refresh().await?;
        Ok(())
    }

    pub async fn config_create(
        create: WireguardEntry,
        // file_path: PathBuf,
        token: Option<String>,
        secret: String,
        wireguard_cli: WireguardCli,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        or_error!(config_create_task(create.clone(), wireguard_cli).await);
        Ok(warp::reply::with_status(
            warp::reply::json(&create),
            StatusCode::CREATED,
        ))
    }
}
