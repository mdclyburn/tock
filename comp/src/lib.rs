use std::env;
use std::fs::File;
use std::io::Read;

use json;
use json::JsonValue;
use proc_macro::{
    TokenStream,
    TokenTree
};

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
    let req_cardinality = mapping.len();

    let mut token_iter = input.into_iter();

    // Argument #1: available GPIO pins for tracing.
    // Literal slice needs to be kept around and we need to get pin count.
    // TODO: empty brackets case.
    let gpio_slice = token_iter.next()
        .expect("Argument #1 of invocation, slice of GPIO, is required.");
    let (slice_code, trace_pin_count) = match gpio_slice {
        TokenTree::Group(slice) => {
            let slice_code = slice.to_string();
            let count = 1 + slice.stream().into_iter()
                .filter(|token| match token {
                    TokenTree::Punct(p) => p.as_char() == ',',
                    _ => false,
                })
                .count();

            (slice_code, count)
        },
        _ => panic!("Argument #1: malformed array slice.")
    };

    // Check total state count vs. what's possible.
    let (req_states, possible_states) = (mapping.len() as u32,
                                         2u32.pow(trace_pin_count as u32) - 1);
    // Number of pins needed for state is ceiling of log_2 of number of states plus one
    // since all pins set to low is the default that I'm not counting as a state.
    let state_pins = ((req_states + 1) as f32)
        .log2()
        .ceil() as usize;
    println!("Trace pins:  {:2}", trace_pin_count);
    println!("States used: {:2} / {:2}", req_states, possible_states);
    println!("State pins:  {:2} / {:2}", state_pins, trace_pin_count);

    if possible_states < req_states {
        let e = format!(r#"compile_error!("Not enough states available. Need to represent {} but can only represent {}.")"#,
                        req_states,
                        possible_states);
        return e.parse().unwrap();
    }

    // Remaining pins can be used for transmitting additional information.
    let data_pins = trace_pin_count - state_pins;
    println!("Data pins:   {:2}", data_pins);

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
