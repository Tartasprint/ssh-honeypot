use ssh_honeypot::analysis::connection::Representation;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() {
    let path = std::env::args().nth(1).expect("Expected a file");
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let mut repr = Representation::new();
    reader
        .lines()
        .map(|json| serde_json::from_str(&json.unwrap()).unwrap())
        .fold(&mut repr, Representation::new_record);
    let output = match std::env::args()
        .nth(2)
        .expect("Expected a type of output")
        .as_str()
    {
        "password" => serde_json::to_string(&repr.passwords.list).unwrap(),
        "users" => serde_json::to_string(&repr.users.list).unwrap(),
        "fingerprints" => serde_json::to_string(&repr.fingerprints.list).unwrap(),
        "connections" => serde_json::to_string(&repr.connections).unwrap(),
        _ => panic!("Unexpected argument."),
    };
    println!("{}", output);
}
