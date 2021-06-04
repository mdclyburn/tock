use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::iter::FromIterator;

use json;
use json::JsonValue;
use proc_macro::{
    TokenStream,
    TokenTree
};

#[derive(Debug)]
struct TracePoint {
    name: String,
    signal_value: u16,
}

impl TracePoint {
    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_signal_value(&self) -> u16 {
        self.signal_value
    }
}

impl TryFrom<&JsonValue> for TracePoint {
    type Error = String;

    fn try_from(json: &JsonValue) -> Result<Self, Self::Error> {
        let mut name: Option<String> = None;
        let mut value: Option<u16> = None;

        for (k, v) in json.entries() {
            match k {
                "name" => {
                    if let Some(trace_point_name) = v.as_str() {
                        name = Some(trace_point_name.to_string());
                    } else {
                        return Err("'name' property is not a string.".to_string());
                    }
                },

                "value" => {
                    let val = v.as_u16().expect("'value' property is not a u16.");
                    value = Some(val);
                },

                _ => {  },
            }
        }

        if name.is_none() {
            Err("Name property is missing.".to_string())
        } else if value.is_none() {
            Err("Value property is missing.".to_string())
        } else {
            Ok(TracePoint {
                name: name.unwrap(),
                signal_value: value.unwrap(),
            })
        }
    }
}

#[proc_macro]
pub fn trace_init(input: TokenStream) -> TokenStream {
    let load_result = load_json();
    if let Err(e) = load_result {
        return format!(r#"compile_error!("Failed to parse JSON: {}")"#, e)
            .parse()
            .unwrap();
    }

    let opt_trace_points = load_result.unwrap();
    if opt_trace_points.is_none() {
        return "None".parse().unwrap();
    }
    let trace_points = opt_trace_points.unwrap();

    let macro_args = stream_to_args(input);
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
    let (req_states, possible_states) = (trace_points.len() as u32,
                                         2u32.pow(trace_pin_count as u32) - 1);
    // Number of pins needed for state is ceiling of log_2 of number of states plus one
    // since all pins set to low is the default that I'm not counting as a state.
    let state_pins = ((req_states + 1) as f32)
        .log2()
        .ceil() as usize;

    if possible_states < req_states {
        let e = format!(r#"compile_error!("Not enough states available; need to represent {} but can only represent {}.")"#,
                        req_states,
                        possible_states);
        return e.parse().unwrap();
    }

    // Remaining pins can be used for transmitting additional information.
    let data_pins = trace_pin_count - state_pins;

    // Argument #3: GPIO capsule.
    let gpio = &macro_args[2];

    let generated_code = format!(r#"
{{
  let ___macro__trace_capsule = static_init!(
        capsules::trace::ParallelGPIOTrace<'static, {}>,
        capsules::trace::ParallelGPIOTrace::new({}, &{}, {}));

  hil::trace::INSTANCE.put(___macro__trace_capsule);

  Some(___macro__trace_capsule)
}}
    "#, pin_type.to_string(), gpio.to_string(), slice_code, trace_pin_count);

    if verbose() {
        println!("Generated tracing initialization:\n{}", generated_code);
        println!("Trace pins:  {:2}", trace_pin_count);
        println!("States used: {:2} / {:2}", req_states, possible_states);
        println!("State pins:  {:2} / {:2}", state_pins, trace_pin_count);
        println!("Data pins:   {:2}", data_pins);
    }

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

    let opt_trace_points = load_result.unwrap();
    if opt_trace_points.is_none() {
        return "".parse().unwrap();
    }

    let macro_args = stream_to_args(input);
    if macro_args.len() == 0 || macro_args.len() > 2 {
        return
            r#"compile_error!("Macro accepts one or two arguments: name, [ extra data ]")"#
            .parse()
            .unwrap()
    }

    let trace_point_name = trace_point_name(macro_args[0].clone())
        .unwrap();
    let trace_point_data = if macro_args.len() == 2 {
        Some(macro_args[1].to_string())
    } else {
        None
    };

    let trace_points = opt_trace_points.unwrap();
    let find_trace_point = trace_points.iter()
        .find(|tp| tp.get_name() == &trace_point_name);
    if let Some(trace_point) = find_trace_point {
        let optional_data_code = if let Some(data) = trace_point_data {
            format!("Some({})", data)
        } else {
            "None".to_string()
        };
        let import = macro_args[0].clone().into_iter()
            .next()
            .map(|token| {
                if let TokenTree::Ident(ident) = token {
                    let s = ident.to_string();
                    if &s == "kernel" {
                        "crate::hil::trace"
                    } else {
                        "kernel::hil::trace"
                    }
                } else {
                    panic!("First part of trace point name is not an identifier.");
                }
            })
            .unwrap();
        let code = format!(r#"
unsafe {{
  use {};
  trace::INSTANCE.map(|trace| trace.signal({}, {}));
}}"#, import, trace_point.get_signal_value(), optional_data_code);
        if verbose() {
            println!("Generated trace point for {}:\n{}", trace_point_name, code);
        }

        code
            .parse()
            .unwrap()
    } else {
        "".parse().unwrap()
    }
}

fn load_json() -> Result<Option<Vec<TracePoint>>, String> {
    if let Some(path) = option_env!("TRACE_SPEC_PATH") {
        let mut trace_spec_file = File::open(path)
            .map_err(|err| format!("Failed to open trace spec file: {}", err))?;

        let mut json_text = String::new();
        trace_spec_file.read_to_string(&mut json_text)
            .map_err(|err| format!("Failed to read trace spec file: {}", err))?;
        let trace_json = json::parse(&json_text)
            .map_err(|err| format!("Failed to parse trace spec file: {}", err))
            .and_then(|json_val| {
                if json_val.is_object() {
                    Ok(json_val)
                } else {
                    Err("Expected JSON object.".to_string())
                }
            })?;

        // Check version.
        let compat_version = 1;
        let version = trace_json.entries()
            .find(|(k, v)| *k == "_version" && v.is_number())
            .map(|(_k, version)| version.as_u64().expect("Version should be unsigned (u64)."))
            .expect("Missing '_version' in trace spec file.");
        if version != 1 {
            Err(format!("Need version {}, not version {}", compat_version, version))
        } else {
            let trace_points: Vec<TracePoint> = trace_json.entries()
                .find(|(k, v)| *k == "trace-points" && v.is_array())
                .map(|(_k, arr)| arr)
                .expect("Missing 'trace-points' array.")
                .members()
                .map(|tp_obj| {
                    TracePoint::try_from(tp_obj)
                        .map_err::<Result<TracePoint, String>, _>(|e| {
                            Err(format!("Malformed trace spec: '{}'", e))
                        })
                        .unwrap()
                })
                .collect();
            Ok(Some(trace_points))
        }
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

fn verbose() -> bool {
    if let Some(_value) = option_env!("TRACE_VERBOSE") {
        true
    } else {
        false
    }
}
