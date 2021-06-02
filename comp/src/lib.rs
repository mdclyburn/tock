use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::iter::FromIterator;

use json;
use json::JsonValue;
use proc_macro::{
    TokenStream,
    TokenTree
};

#[proc_macro]
pub fn trace_init(input: TokenStream) -> TokenStream {
    let load_result = load_json();
    if let Err(e) = load_result {
        return format!(r#"compile_error!("Failed to parse JSON: {}")"#, e)
            .parse()
            .unwrap();
    }

    let opt_json = load_result.unwrap();
    if opt_json.is_none() {
        return "None".parse().unwrap();
    } else {
        println!("Generating tracing code.");
    }

    let mut json = opt_json.unwrap();
    let mut mapping = Vec::<(String, u8)>::new();
    for obj in json.members_mut() {
        let name = obj.remove("name").as_str()
            .expect("Name property must be a string.")
            .to_string();
        let value = obj.remove("value").as_u8()
            .expect("Missing value property on JSON object.");

        mapping.push((name, value));
    }

    let macro_args = stream_to_args(input);

    for (arg, no) in macro_args.iter().zip(1..) {
        println!("Argument #{}: {}", no, arg);
    }
    if macro_args.len() != 3 {
        return r#"compile_error!("Macro takes three arguments: pin type, pin numbers, and GPIO capsule.")"#
            .parse()
            .unwrap();
    }

    // Argument #1: chip pin type.
    let pin_type = &macro_args[0];

    // Argument #2: available GPIO pins for tracing.
    // Literal slice needs to be kept around and we need to get pin count.
    // TODO: empty brackets case.
    let gpio_slice = macro_args[1]
        .clone()
        .into_iter()
        .nth(0)
        .unwrap();
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
        let e = format!(r#"compile_error!("Not enough states available; need to represent {} but can only represent {}.")"#,
                        req_states,
                        possible_states);
        return e.parse().unwrap();
    }

    // Remaining pins can be used for transmitting additional information.
    let data_pins = trace_pin_count - state_pins;
    println!("Data pins:   {:2}", data_pins);

    // Argument #3: GPIO capsule.
    let gpio = &macro_args[2];

    println!(r#"GPIO code: {}
slice code: {}
trace pin count: {}
"#,
             gpio, slice_code, trace_pin_count);

    let generated_code = format!(r#"
{{
  let ___macro__trace_capsule = static_init!(
        capsules::trace::Trace<'static, {}>,
        capsules::trace::Trace::new({}, &{}, {}));

  hil::gpio_trace::INSTANCE.put(___macro__trace_capsule);

  Some(___macro__trace_capsule)
}}
    "#, pin_type.to_string(), gpio.to_string(), slice_code, trace_pin_count);
    println!("generated code:\n{}", generated_code);

    generated_code.parse().unwrap()
}

#[proc_macro]
pub fn trace(input: TokenStream) -> TokenStream {
    let load_result = load_json();
    if let Err(e) = load_result {
        return format!(r#"compile_error!("Failed to parse JSON: {}")"#, e)
            .parse()
            .unwrap();
    }

    let opt_json = load_result.unwrap();
    if opt_json.is_none() {
        return "None".parse().unwrap();
    }

    let macro_args = stream_to_args(input);
    if macro_args.len() == 0 || macro_args.len() > 2 {
        return
            r#"compile_error!("Macro accepts one or two arguments: name, [ extra data ]")"#
            .parse()
            .unwrap()
    }
    println!("Generating tracing code for '{}'.", macro_args[0]);

    println!("DEBUG: {:?}", macro_args[0]);
    let trace_point_name = trace_point_name(macro_args[0].clone())
        .unwrap();
    println!("Trace point name: {}", trace_point_name);


    let mut json = opt_json.unwrap();
    // Uh... for each invocation?
    let mut mapping: HashMap<String, u8> = json.members_mut()
        .map(|obj| {
            let name = obj.remove("name").as_str()
                .expect("Expected 'name' property as a string.")
                .to_string();
            let value = obj.remove("value").as_u8()
                .expect("Expected 'value' property as a u8.");

            (name, value)
        })
        .collect();

    if let Some(val) = mapping.get(&trace_point_name) {
        let code = format!(r#"
{{
  use crate::hil::gpio_trace;
  gpio_trace::INSTANCE.map(|trace| trace.signal({}, None));
}}"#, val);
        println!("Emitting code for {}:\n{}", trace_point_name, code);

        code
            .parse()
            .unwrap()
    } else {
        format!(r#"compile_error!("Trace point '{}' not specified in spec file.")"#,
                trace_point_name)
            .parse()
            .unwrap()
    }
}

fn load_json() -> Result<Option<JsonValue>, String> {
    if let Some(path) = option_env!("TRACE_SPEC_PATH") {
        let mut trace_spec_file = File::open(path)
            .map_err(|err| format!("Failed to open trace spec file: {}", err))?;

        let mut json_text = String::new();
        trace_spec_file.read_to_string(&mut json_text)
            .map_err(|err| format!("Failed to read trace spec file: {}", err))?;
        let trace_json = json::parse(&json_text)
            .map_err(|err| format!("Failed to parse trace spec file: {}", err))?;

        Ok(Some(trace_json))
    } else {
        Ok(None)
    }
}

fn stream_to_args(stream: TokenStream) -> Vec<TokenStream> {
    let mut stream_args = Vec::new();
    let mut token_stream_iter = stream.into_iter();
    loop {
        let arg_tokens = token_stream_iter
            .by_ref()
            .take_while(|token| {
                match token {
                    TokenTree::Punct(p) => p.as_char() != ',',
                    _ => true,
                }
            });
        let arg_token_stream = TokenStream::from_iter(arg_tokens);
        if arg_token_stream.is_empty() {
            break;
        } else {
            stream_args.push(arg_token_stream);
        }
    }

    stream_args
}

fn trace_point_name(name_stream: TokenStream) -> Result<String, String> {
    let raw_name = name_stream.to_string();
    let mut stream_iter = name_stream.into_iter();
    let mut name = String::new();

    loop {
        if let Some(TokenTree::Ident(s)) = stream_iter.next() {
            name.push_str(&s.to_string());
            match stream_iter.next() {
                Some(TokenTree::Punct(punct_char)) => {
                    if punct_char.as_char() != '/' {
                        return Err(format!("Malformed trace point name: {} (expected '/').", raw_name));
                    } else {
                        name.push('/');
                    }
                },
                None => return Ok(name),
                _ => return Err(format!("Malformed trace point name (expected '/')."))
            };
        } else {
            return Err(format!("Malformed trace point name: {}", raw_name));
        }
    }
}
