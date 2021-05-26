use std::env;
use std::fs::File;
use std::io::Read;

use json;
use json::JsonValue;
use proc_macro::{TokenStream, TokenTree};

#[proc_macro]
pub fn trace_init(input: TokenStream) -> TokenStream {
    let mut json = load_json();
    let mut mapping = Vec::<(String, u8)>::new();

    for obj in json.members_mut() {
        let name = obj.remove("name").as_str()
            .expect("Name property must be a string.")
            .to_string();
        let value = obj.remove("value").as_u8()
            .expect("Missing value property on JSON object.");

        mapping.push((name, value));
    }

    "".parse().unwrap()
}

#[proc_macro]
pub fn trace(input: TokenStream) -> TokenStream {
    "".parse().unwrap()
}

fn load_json() -> JsonValue {
    // Using these macros implies that a path is provided.
    let trace_spec_path = option_env!("TRACE_SPEC_PATH")
        .expect("Path to trace specification, TRACE_SPEC_PATH, not given.");
    let mut trace_spec_file = File::open(trace_spec_path)
        .expect("Could not open trace specification file.");

    let mut json_text = String::new();
    trace_spec_file.read_to_string(&mut json_text);

    json::parse(&json_text)
        .expect("Failed to parse trace specification JSON.")
}
