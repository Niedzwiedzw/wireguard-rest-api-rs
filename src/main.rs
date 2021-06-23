mod wireguard_conf;

use clap::{crate_version, App, Arg, SubCommand};
use warp::Filter;

#[tokio::main]
async fn main() {
    let matches = App::new("wireguard-rest-api-rs")
        .version(crate_version!())
        .author("Niedźwiedź <wojciech.brozek@niedzwiedz.it>")
        .about("Wireguard config modified via REST API")
        .arg(
            Arg::with_name("token")
                .long("token")
                .value_name("STRING")
                .help("secret token used to authenticate actions")
                .takes_value(true)
                .required(true)
        )
        .get_matches();

    let token = matches.value_of("token").expect("token must be set");
    println!("TOKEN: {}", token);
    let hello = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));

    warp::serve(hello).run(([127, 0, 0, 1], 3030)).await;
}
