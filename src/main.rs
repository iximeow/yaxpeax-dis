use yaxpeax_arch::{AddressBase, Arch, Decoder, Instruction, LengthedInstruction};

use clap::*;
use num_traits::identities::Zero;

use std::fmt;
use std::fs::File;
use std::io::Read;

fn main() {
    let _ = include_str!("../Cargo.toml");
    let app = app_from_crate!()
        .arg(
            Arg::with_name("arch")
                .short("a")
                .long("--architecture")
                .takes_value(true)
                .possible_values(&[
                    "x86_64", "x86:32", "armv7", "armv8", "avr", "mips", "msp430", "pic17",
                    "pic18", "m16c",
                ])
                .help("architecture to disassemble input as."),
        )
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .takes_value(true)
                .help("file of bytes to decode"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("--verbose")
                .help("increased detail when decoding instructions"),
        )
        .arg(Arg::with_name("data").help(
            "hex bytes to decode by the selected architecture. for example, try -a x86_64 33c0c3",
        ));

    let matches = app.get_matches();

    let arch_str = matches.value_of("arch").unwrap_or("x86_64");
    let buf: Vec<u8> = match matches.value_of("data") {
        Some(data) => match hex::decode(data) {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("Invalid input, {}. Expected a sequence of bytes as hex", e);
                return;
            }
        },
        None => {
            let mut v = Vec::new();
            match matches.value_of("file") {
                Some(name) => match File::open(name) {
                    Ok(mut f) => {
                        f.read_to_end(&mut v).expect("can read the file");
                        v
                    }
                    Err(e) => {
                        eprintln!("error opening {}: {}", name, e);
                        return;
                    }
                },
                None => {
                    eprintln!("data must be provided by either an argument consisting of hex bytes, or by the --file argument.");
                    return;
                }
            }
        }
    };
    let verbose = matches.occurrences_of("verbose") > 0;

    match arch_str {
        "x86_64" => decode_input::<yaxpeax_x86::long_mode::Arch>(&buf, verbose),
        "x86:32" => decode_input::<yaxpeax_x86::protected_mode::Arch>(&buf, verbose),
        "avr" => decode_input::<yaxpeax_avr::AVR>(&buf, verbose),
        "armv7" => decode_input::<yaxpeax_arm::armv7::ARMv7>(&buf, verbose),
        "armv8" => decode_input::<yaxpeax_arm::armv8::a64::ARMv8>(&buf, verbose),
        "mips" => decode_input::<yaxpeax_mips::MIPS>(&buf, verbose),
        "msp430" => decode_input::<yaxpeax_msp430::MSP430>(&buf, verbose),
        "pic17" => decode_input::<yaxpeax_pic17::PIC17>(&buf, verbose),
        "pic18" => decode_input::<yaxpeax_pic18::PIC18>(&buf, verbose),
        "m16c" => decode_input::<yaxpeax_m16c::M16C>(&buf, verbose),
        //        "pic24" => decode_input::<yaxpeax_pic24::PIC24>(buf),
        other => {
            println!("unsupported architecture: {}", other);
        }
    }
}

fn decode_input<A: Arch>(buf: &[u8], verbose: bool)
where
    A::Instruction: fmt::Display,
{
    let decoder = A::Decoder::default();
    let start = A::Address::zero();
    let mut addr = start;
    loop {
        match decoder.decode(buf[addr.to_linear()..].iter().cloned()) {
            Ok(inst) => {
                println!(
                    "{:#010x}: {:14}: {}",
                    addr.to_linear(),
                    hex::encode(
                        &buf[addr.to_linear()..]
                            [..A::Address::zero().wrapping_offset(inst.len()).to_linear()]
                    ),
                    inst
                );
                if verbose {
                    println!("  {:?}", inst);
                    if !inst.well_defined() {
                        println!("  not well-defined");
                    }
                }
                addr += inst.len();
            }
            Err(e) => {
                println!("{:#010x}: {}", addr.to_linear(), e);
                addr += A::Instruction::min_size();
            }
        }
        if addr.to_linear() >= buf.len() {
            break;
        }
    }
}
