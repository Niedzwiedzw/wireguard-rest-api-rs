#![deny(unused_must_use)]

mod api;
mod error;
mod wireguard_cli;
mod wireguard_conf;

use clap::{
    crate_version,
    App,
    Arg,
};
use std::net::Ipv4Addr;
use warp::Filter;

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
                .required(true),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("NUMBER")
                .about("port to serve the API over")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("file_path")
                .long("file_path")
                .value_name("FILE")
                .about("config path to modify")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("host")
                .long("host")
                .value_name("IP")
                .about("IP to serve the API over")
                .takes_value(true)
                .required(true),
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
    let wireguard_cli = wireguard_cli::WireguardCli::new(&file_path)?;
    warp::serve(api::api(token.to_string(), wireguard_cli).with(warp::log("HTTP-API")))
        .run((host, port))
        .await;

    Ok(())
}
