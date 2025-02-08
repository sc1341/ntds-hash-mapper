use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} NTDS-DUMP", args[0]);
        std::process::exit(1);
    }

    let input_filename = &args[1];
    // Derive output file name
    let input_path = Path::new(input_filename);
    let mut output_filename = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output")
        .to_string();
    output_filename.push_str("-clear-text.txt");

    // Compile the NTLM regex
    let ntlm_regex = Regex::new(r"^[0-9A-Fa-f]{32}$")?;

    // Prepare a HashMap magic data structure to store ntlm_hash -> password
    let potfile_path = "/home/cloudadmin/.local/share/hashcat/hashcat.potfile";
    let potfile = File::open(potfile_path)?;
    let pot_reader = BufReader::new(potfile);

    let mut hash_to_pass = HashMap::new();

    // Read potfile lines into HashMap
    for line_res in pot_reader.lines() {
        if let Ok(line) = line_res {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let ntlm_hash = parts[0].trim();
                let clear_text = parts[1].trim();
                if ntlm_regex.is_match(ntlm_hash) {
                    hash_to_pass.insert(ntlm_hash.to_uppercase(), clear_text.to_string());
                }
            }
        }
    }

    let input_file = File::open(input_filename)?;
    let input_reader = BufReader::new(input_file);

    let mut output_file = File::create(&output_filename)?;

    // For each user line in NTDS, if the 4th field matches an NTLM hash in the map, write out user:pass
    for line_res in input_reader.lines() {
        if let Ok(line) = line_res {
            let fields: Vec<&str> = line.split(':').collect();
            // Expecting 7 fields, with the 4th (index 3) being the NTLM hash
            if fields.len() == 7 {
                let username = fields[0];
                let user_hash = fields[3].to_uppercase();
                if let Some(clear_text_pass) = hash_to_pass.get(&user_hash) {
                    let output_line = format!("{}:{}", username, clear_text_pass);
                    println!("{}", output_line);
                    writeln!(output_file, "{}", output_line)?;
                }
            }
        }
    }

    println!("Results written to {}", output_filename);

    Ok(())
}
