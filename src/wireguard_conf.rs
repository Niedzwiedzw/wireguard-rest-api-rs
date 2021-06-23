use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub enum WireguardEntryType {
    Interface,
    Peer,
}

impl WireguardEntryType {
    pub fn to_string(&self) -> String {
        match *self {
            Self::Interface => "Interface".to_string(),
            Self::Peer => "Peer".to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct WireguardEntry {
    pub kind: WireguardEntryType,
    pub values: IndexMap<String, String>,
}

impl std::fmt::Display for WireguardEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl WireguardEntry {
    pub fn to_string(&self) -> String {
        format!(
            r#"[{header}]
{values}
"#,
            header = self.kind.to_string(),
            values = self
                .values
                .iter()
                .map(|(key, value)| format!("{} = {}", key, value))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireguardConfig(pub IndexMap<usize, WireguardEntry>);

impl WireguardConfig {
    pub fn to_string(&self) -> String {
        self.0
            .iter()
            .map(|(_idx, entry)| entry.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub mod parser {
    use super::*;
    use nom::{
        branch::alt,
        bytes::complete::{tag, take_till1, take_while, take_while1},
        combinator::value,
        multi::{separated_list0, separated_list1},
        sequence::{delimited, tuple},
        IResult,
    };

    pub fn wireguard_entry(input: &str) -> IResult<&str, WireguardEntry> {
        let is_newline = |c: char| c == '\n';
        let non_whitespaces = take_till1(|c: char| c.is_whitespace());
        let newlines = take_while1(is_newline);

        let header = alt((
            value(WireguardEntryType::Peer, tag("[Peer]")),
            value(WireguardEntryType::Interface, tag("[Interface]")),
        ));

        let keyvalue = tuple((
            &non_whitespaces,
            delimited(
                take_while(char::is_whitespace),
                tag("="),
                take_while(char::is_whitespace),
            ),
            &non_whitespaces,
        ));

        let keyvalues = separated_list0(&newlines, keyvalue);

        let (input, (header, _, keyvalues)) = tuple((header, &newlines, keyvalues))(input)?;

        Ok((
            input,
            WireguardEntry {
                kind: header,
                values: keyvalues
                    .into_iter()
                    .map(|(key, _, value)| (key.to_string(), value.to_string()))
                    .collect(),
            },
        ))
    }

    impl WireguardConfig {
        pub fn from_str(input: &str) -> IResult<&str, Self> {
            let is_newline = |c: char| c == '\n';
            let optional_newlines = take_while(is_newline);
            let (input, values) = separated_list1(optional_newlines, wireguard_entry)(input)?;
            Ok((
                input,
                WireguardConfig(values.into_iter().enumerate().collect()),
            ))
        }
    }
}

#[cfg(test)]
mod test_config_parsing {
    use super::parser::*;
    use super::*;

    #[test]
    fn test_config_entry_parsing() {
        let input = r#"[Peer]
PublicKey = eBtRjue9MBZqpQMi4UWFOY5DXYKarMGpWosKm+YU+UE=
AllowedIPs = 192.0.2.0/24
Endpoint = 162.34.62.31:51820
PersistentKeepAlive = 15"#;

        let (_input, _entry) = wireguard_entry(input).unwrap();
    }
    #[test]
    fn test_example_config_parsing() {
        let conf = include_str!("../test-client-config.conf");
        let (_input, wg) = WireguardConfig::from_str(conf).expect("bad format");
        println!(
            " :: PARSED CONFIG :: \n{}",
            serde_json::to_string_pretty(&wg).unwrap()
        );

        assert_eq!(conf, &wg.to_string())
    }
}
