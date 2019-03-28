use serde_derive;
use toml;

#[derive(Serialize,Deserialize)]
struct Config {
    ip: String,
    port: Option<u16>,
    keys: Keys,
}

#[derive(Serialize,Deserialize)]
struct Keys {
    github: String,
    travis: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[macro_use]
    use serde_derive;
    
    #[macro_use]
    use toml;

    #[test]
    fn deserialize() {
        let config: Config = toml::from_str(r#"
        ip = '127.0.0.1'

        [keys]
        github = 'xxxxxxxxxxxxxxxxx'
        travis = 'yyyyyyyyyyyyyyyyy'
        "#).unwrap();

        assert_eq!(config.ip, "127.0.0.1");
        assert_eq!(config.port, None);
        assert_eq!(config.keys.github, "xxxxxxxxxxxxxxxxx");
        assert_eq!(config.keys.travis.as_ref().unwrap(), "yyyyyyyyyyyyyyyyy");

    }
    #[test]
    fn serialize() {
        let config = Config {
            ip: "127.0.0.1".to_string(),
            port: None,
            keys: Keys {
                github: "xxxxxxxxxxxxxxxxx".to_string(),
                travis: None("yyyyyyyyyyyyyyyyy".to_string()),
            },
        };

        let toml = toml::to_string(&config).unwrap();
        dbg!(toml);
    }
    
}