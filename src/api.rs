use crate::wireguard_conf::WireguardEntry;
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

pub fn api(
    file_path: PathBuf,
    secret: String,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    config_list(file_path.clone(), secret.clone())
        .or(config_get(file_path.clone(), secret.clone()))
        .or(config_delete(file_path.clone(), secret.clone()))
        .or(config_create(file_path.clone(), secret.clone()))
}

pub fn config_list(
    file_path: PathBuf,
    secret: String,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::get())
        .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and_then(handlers::config_list)
}

pub fn config_get(
    file_path: PathBuf,
    secret: String,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!(usize)
        .and(warp::post())
        .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and_then(handlers::config_get)
}

pub fn config_create(
    file_path: PathBuf,
    secret: String,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::post())
        .and(json_body())
        .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and_then(handlers::config_create)
}

pub fn config_delete(
    file_path: PathBuf,
    secret: String,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!(usize)
        .and(warp::delete())
        .and(with_file_path(file_path))
        .and(warp::header::optional("Authorization"))
        .and(with_secret(secret))
        .and_then(handlers::config_delete)
}

pub mod handlers {
    use crate::{
        error::WireguardRestApiError,
        wireguard_conf::{WireguardConfig, WireguardEntry},
    };
    use serde::Serialize;
    use std::{convert::Infallible, path::PathBuf};
    use warp::http::StatusCode;

    #[derive(Serialize)]
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
                    let json = warp::reply::json(&ErrorMessage {
                        code: code.as_u16(),
                        message: format!("{:?}", e),
                    });
                    return Ok(warp::reply::with_status(json, code));
                }
            }
        };
    }

    #[macro_export]
    macro_rules! auth_required {
        ($token:expr, $secret:expr) => {
            let token = if let Some(token) = $token {
                token
            } else {
                let code = warp::http::StatusCode::UNAUTHORIZED;
                let json = warp::reply::json(&ErrorMessage {
                    code: code.as_u16(),
                    message: "Not authorized".to_string(),
                });
                return Ok(warp::reply::with_status(json, code));
            };
            if token.replace("Bearer ", "") == $secret {
            } else {
                let code = warp::http::StatusCode::UNAUTHORIZED;
                let json = warp::reply::json(&ErrorMessage {
                    code: code.as_u16(),
                    message: "Not authorized".to_string(),
                });
                return Ok(warp::reply::with_status(json, code));
            }
        };
    }

    fn read_config<T: AsRef<std::path::Path>>(
        file_path: T,
    ) -> Result<WireguardConfig, WireguardRestApiError> {
        let mut text: String = std::fs::read_to_string(&file_path)?;
        if !text.ends_with("\n") {
            text.push('\n');
        }
        let parse = WireguardConfig::from_str(&text);
        match parse {
            Ok((_, config)) => Ok(config),
            Err(e) => Err(WireguardRestApiError::ConfigParseError(e.to_string())),
        }
    }

    pub async fn config_list(
        file_path: PathBuf,
        token: Option<String>,
        secret: String,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        let config = or_error!(read_config(&file_path));

        Ok(warp::reply::with_status(
            warp::reply::json(&config),
            StatusCode::OK,
        ))
    }

    pub async fn config_get(
        id: usize,
        file_path: PathBuf,
        token: Option<String>,
        secret: String,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        let config = or_error!(read_config(&file_path));
        let entry = or_error!(config.0.get(&id).ok_or(WireguardRestApiError::NotFound));

        Ok(warp::reply::with_status(
            warp::reply::json(&entry),
            StatusCode::OK,
        ))
    }

    pub async fn config_delete(
        id: usize,
        file_path: PathBuf,
        token: Option<String>,
        secret: String,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        let mut config = or_error!(read_config(&file_path));
        let _entry = or_error!(config.0.remove(&id).ok_or(WireguardRestApiError::NotFound));
        or_error!(std::fs::write(&file_path, &config.to_string()));

        Ok(warp::reply::with_status(
            warp::reply::json(&config),
            StatusCode::OK,
        ))
    }

    pub async fn config_create(
        create: WireguardEntry,
        file_path: PathBuf,
        token: Option<String>,
        secret: String,
    ) -> Result<impl warp::Reply, Infallible> {
        auth_required!(token, secret);
        let mut config = or_error!(read_config(&file_path));
        if let Some((id, v)) = config
            .0
            .iter()
            .find(|(_, v)| v.values.get("PublicKey") == create.values.get("PublicKey"))
        {
            or_error!(Err(WireguardRestApiError::NonUniquePublicKey(
                *id,
                create.clone(),
                v.clone(),
            )))
        }
        let entry = config.0.insert(config.0.len(), create);
        or_error!(std::fs::write(&file_path, &config.to_string()));

        Ok(warp::reply::with_status(
            warp::reply::json(&entry),
            StatusCode::CREATED,
        ))
    }
}
