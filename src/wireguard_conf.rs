use indexmap::IndexMap;
use serde::{
    Deserialize,
    Serialize,
};

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
    #[serde(default)]
    pub extra_metadata: IndexMap<String, String>,
}

impl std::fmt::Display for WireguardEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl WireguardEntry {
    pub fn to_string(&self) -> String {
        format!(
            r#"{extra_metadata}[{header}]
{values}
"#,
            header = self.kind.to_string(),
            values = self
                .values
                .iter()
                .map(|(key, value)| format!("{} = {}", key, value))
                .collect::<Vec<_>>()
                .join("\n"),
            extra_metadata = if self.extra_metadata.len() == 0 {
                "".to_string()
            } else {
                format!(
                    "{}\n",
                    self.extra_metadata
                        .iter()
                        .map(|(key, value)| format!("## {} = {}", key, value))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            },
        )
    }
}

#[derive(Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        bytes::complete::{
            tag,
            take_till,
            take_till1,
            take_while,
            take_while1,
        },
        combinator::{
            opt,
            value,
        },
        multi::{
            separated_list0,
            separated_list1,
        },
        sequence::{
            delimited,
            terminated,
            tuple,
        },
        IResult,
    };
    pub fn is_newline(c: char) -> bool {
        c == '\n'
    }

    pub fn non_whitespaces(input: &str) -> IResult<&str, &str> {
        take_till1(|c: char| c.is_whitespace())(input)
    }
    pub fn maybe_empty_non_newlines(input: &str) -> IResult<&str, &str> {
        take_while(|c: char| c != '\n')(input)
    }
    pub fn newlines(input: &str) -> IResult<&str, &str> {
        take_while1(is_newline)(input)
    }
    pub fn non_newlines(input: &str) -> IResult<&str, &str> {
        take_while1(|c| !is_newline(c))(input)
    }

    pub fn skip_whitespace(input: &str) -> IResult<&str, &str> {
        take_while(char::is_whitespace)(input)
    }

    pub fn skip_whitespace_non_newline(input: &str) -> IResult<&str, &str> {
        take_while(|c: char| c.is_whitespace() && c != '\n')(input)
    }
    pub fn double_comment(input: &str) -> IResult<&str, (&str, &str, &str)> {
        tuple((tag("#"), take_while(char::is_whitespace), tag("#")))(input)
    }

    pub fn keyvalue(input: &str) -> IResult<&str, (&str, &str)> {
        tuple((
            non_whitespaces,
            delimited(skip_whitespace, tag("="), skip_whitespace_non_newline),
            maybe_empty_non_newlines,
        ))(input)
        .map(|(input, (k, _, v))| (input, (k, v)))
    }

    pub fn double_commented_key_value(input: &str) -> IResult<&str, (&str, &str)> {
        tuple((double_comment, skip_whitespace, keyvalue))(input)
            .map(|(input, (_, _, (key, value)))| (input, (key, value)))
    }

    pub fn wireguard_entry(input: &str) -> IResult<&str, WireguardEntry> {
        let double_commented_key_values = separated_list0(newlines, double_commented_key_value);
        let header = alt((
            value(WireguardEntryType::Peer, tag("[Peer]")),
            value(WireguardEntryType::Interface, tag("[Interface]")),
        ));

        let keyvalues = separated_list0(newlines, keyvalue);

        let double_commented_key_values_segment =
            opt(tuple((double_commented_key_values, newlines)));

        let (input, (double_commented_key_values_segment, header, _, keyvalues)) =
            tuple((
                double_commented_key_values_segment,
                header,
                newlines,
                keyvalues,
            ))(input)?;
        let extra_metadata = match double_commented_key_values_segment {
            Some((metadata, _)) => metadata
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            None => Default::default(),
        };
        Ok((
            input,
            WireguardEntry {
                kind: header,
                values: keyvalues
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
                extra_metadata,
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
mod parser_unit_tests {
    use super::parser::*;

    #[test]
    fn test_double_comment() {
        assert_eq!(double_comment("##").unwrap(), ("", ("#", "", "#")));
    }

    #[test]
    fn test_double_commented_key_value() {
        assert_eq!(
            double_commented_key_value("## Nickname = My Machine 1").unwrap(),
            ("", ("Nickname", "My Machine 1"))
        )
    }

    #[test]
    fn test_single_entry() {
        assert_eq!(
            wireguard_entry(
                r#"[Interface]
PrivateKey = 8HZJm9txG0R48wz6gqqv8KP1secIj7ZRPv1nyt0lY1E=
Address = 192.0.2.3"#
            )
            .unwrap()
            .0,
            ""
        );
    }

    #[test]
    fn test_single_extended_entry() {
        assert_eq!(
            wireguard_entry(
                r#"## Nickname = My Machine 1
[Interface]
PrivateKey = 8HZJm9txG0R48wz6gqqv8KP1secIj7ZRPv1nyt0lY1E=
Address = 192.0.2.3"#
            )
            .unwrap()
            .0,
            ""
        );
    }
}
#[cfg(test)]
mod test_config_parsing {
    use super::parser::*;
    use super::*;

    #[test]
    fn test_entry_empty_value() {
        const ENTRY: &str = r#"## Nickname = 
## SomethingElse = dupa
[Interface]
PrivateKey = 8HZJm9txG0R48wz6gqqv8KP1secIj7ZRPv1nyt0lY1E=
Address = 192.0.2.3"#;
        let entry = wireguard_entry(ENTRY).unwrap().1;
        println!("{entry:#?}");
        assert_eq!(
            entry.extra_metadata.get("Nickname"),
            Some(&"".to_string()),
            "Nickname has collected all the values"
        );
        assert_eq!(
            entry.extra_metadata.get("SomethingElse"),
            Some(&"dupa".to_string()),
            "no SomethingElse found"
        );

        let back_to_string = entry.to_string();
        println!("{back_to_string}");
        assert_eq!(ENTRY.trim(), back_to_string.as_str().trim());
    }

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

    #[test]
    fn test_complex_config_parsing() {
        let conf = include_str!("../test-wg0-complex.conf");
        let (_input, wg) = WireguardConfig::from_str(conf).expect("bad format");
        println!(
            " :: PARSED CONFIG :: \n{}",
            serde_json::to_string_pretty(&wg).unwrap()
        );

        assert_eq!(conf, &wg.to_string())
    }

    #[test]
    fn test_extended_syntax_config_parsing() {
        let conf = include_str!("../test-extended-syntax.conf");
        let (_input, wg) = WireguardConfig::from_str(conf).expect("bad format");
        println!(
            " :: PARSED CONFIG :: \n{}",
            serde_json::to_string_pretty(&wg).unwrap()
        );
    }
}
