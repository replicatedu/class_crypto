
#[derive(Serialize,Deserialize, Debug)]
pub struct Class {
    pub description: String,
    pub instructor: Option<Vec<Instructors>>,
    pub student: Option<Vec<Students>>,
}

//this will be used to keep track of the instructors
#[derive(Serialize,Deserialize, Debug)]
pub struct Instructors {
    pub id: String,
    pub pk: String
}

//this will be used to keep track of the students
#[derive(Serialize,Deserialize, Debug)]
pub struct Students {
    pub id: String,
    pub pk: String
}

//this class will be used to store the key material on the instructors machine or the students
#[derive(Serialize,Deserialize, Debug)]
struct Participant {
    id: String,
    pk: String,
    sk: String,
    instructor: bool
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use std::fs::OpenOptions;
    use std::io::Write;
//     fn write_file(filepath: &str, contents: &str) {
//         match OpenOptions::new()
//             .create(true)
//             .write(true)
//             .append(true)
//             .open(filepath)
//         {
//             Ok(ref mut file) => {
//                 file.set_len(0);
//                 writeln!(file, "{}",contents).unwrap();
//             }
//             Err(err) => {
//                 panic!("Failed to open log file: {}", err);
//             }
//         }
//     }
    
    #[test]
    fn deserialize_serialize() {
        let config: Class = toml::from_str(r#"
        description = 'this is a class description'

        [[instructor]]
        id = 'test'
        pk = 'test_pk'     
            
        [[student]]
        id = 'test'
        pk = 'test_pk'
            
        [[student]]
        id = 'test'
        pk = 'test_pk'
        "#).unwrap();
        dbg!(&config);
//         assert_eq!(config.description, "this is a class description");
//         assert_eq!(config.sk, None);
//         assert_eq!(config.test.id, "test");
//         assert_eq!(config.test.pk, "test_pk");
//         assert_eq!(config.test.travis.as_ref().unwrap(), "yyyyyyyyyyyyyyyyy");
        let toml = toml::to_string(&config).unwrap();
        //write_file("test.tmp",&toml)
    }
    #[test]
    fn serialize() {
//         let config = Class {
//             ip: "127.0.0.1".to_string(),
//             port: None,
//             keys: Keys {
//                 github: "xxxxxxxxxxxxxxxxx".to_string(),
//                 travis: Some("yyyyyyyyyyyyyyyyy".to_string()),
//             },
//         };

//         let toml = toml::to_string(&config).unwrap();
//         dbg!(toml);
    }
    
}