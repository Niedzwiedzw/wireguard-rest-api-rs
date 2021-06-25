mod wireguard_conf;
mod api;
mod error;

use clap::{crate_version, App, Arg};
use warp::Filter;
use std::{net::Ipv4Addr, path::PathBuf};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let matches = App::new("wireguard-rest-api-rs")
        .version(crate_version!())
        .author("Niedźwiedź <wojciech.brozek@niedzwiedz.it>")
        .about("Wireguard config modified via REST API")
        .arg(
            Arg::new("token")
                .long("token")
                .value_name("STRING")
                .about("secret token used to authenticate actions")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("NUMBER")
                .about("port to serve the API over")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::new("file_path")
                .long("file_path")
                .value_name("FILE")
                .about("config path to modify")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::new("host")
                .long("host")
                .value_name("IP")
                .about("IP to serve the API over")
                .takes_value(true)
                .required(true)
        )
        .get_matches();

    let token = matches.value_of("token").expect("token must be set");
    let port = matches.value_of_t("port")?;
    let host: Ipv4Addr = matches.value_of_t("host")?;
    let file_path: std::path::PathBuf = matches.value_of_t("file_path")?;

    if !file_path.exists() {
        panic!(" :: file does not exist : [{:#?}] ::", file_path);
    }
    eprintln!(" :: token:      {}", token);
    eprintln!(" :: host:       {}", host);
    eprintln!(" :: port:       {}", port);
    eprintln!(" :: file_path:  {:?}", file_path);
    eprintln!(" :: igniting ::");
    warp::serve(
        api::api(
            PathBuf::from(file_path),
            token.to_string(),
        ).with(warp::log("HTTP-API")),
    ).run((host, port)).await;

    Ok(())
}
