use yaxpeax_arch::{Address, Arch, Decoder, Instruction, LengthedInstruction};

use clap::{Arg, App};
use num_traits::identities::Zero;

use std::fmt;

fn main() {
    let matches = App::new("yaxpeax disassembler")
        .version("0.0.1")
        .author("iximeow <me@iximeow.net>")
        .about("disassembly tool using yaxpeax decoders")
        .arg(Arg::with_name("arch")
             .short("a")
             .long("architecture")
             .takes_value(true)
             .help("architecture to disassemble input as"))
        .arg(Arg::with_name("file")
             .short("f")
             .long("file")
             .takes_value(true)
             .help("file of bytes to decode"))
        .arg(Arg::with_name("verbose")
             .short("v")
             .long("verbose")
             .help("increased detail when decoding instructions"))
        .arg(Arg::with_name("data")
             .index(1))
        .get_matches();

    let arch_str = matches.value_of("arch").unwrap_or("x86_64");
    eprintln!("disassembling as {}", arch_str);
//    let file = matches.value_of("file").unwrap();
    let buf: &str = matches.value_of("data").unwrap_or("");
    let verbose = matches.occurrences_of("verbose") > 0;

    match arch_str {
        "x86_64" => decode_input::<yaxpeax_x86::x86_64>(buf, verbose),
        "armv7" => decode_input::<yaxpeax_arm::armv7::ARMv7>(buf, verbose),
        "armv8" => decode_input::<yaxpeax_arm::armv8::a64::ARMv8>(buf, verbose),
        "mips" => decode_input::<yaxpeax_mips::MIPS>(buf, verbose),
        "msp430" => decode_input::<yaxpeax_msp430_mc::MSP430>(buf, verbose),
        "pic17" => decode_input::<yaxpeax_pic17::PIC17>(buf, verbose),
        "pic18" => decode_input::<yaxpeax_pic18::PIC18>(buf, verbose),
//        "pic24" => decode_input::<yaxpeax_pic24::PIC24>(buf),
        other => {
            println!("unsupported architecture: {}", other);
        }
    }
}

fn decode_input<A: Arch>(buf: &str, verbose: bool) where A::Instruction: fmt::Display {
    let buf = match hex::decode(buf) {
        Ok(buf) => buf,
        Err(e) => {
            eprintln!("Invalid input, {}. Expected a sequence of bytes as hex", e);
            return;
        }
    };
    let decoder = A::Decoder::default();
    let start = A::Address::zero();
    let mut addr = start;
    loop {
        match decoder.decode(buf[addr.to_linear()..].iter().cloned()) {
            Ok(inst) => {
                println!("{:#010x}: {:14}: {}", addr.to_linear(), hex::encode(&buf[addr.to_linear()..][..inst.len().to_linear()]), inst);
                if verbose {
                    println!("  {:?}", inst);
                    if !inst.well_defined() {
                        println!("  not well-defined");
                    }
                }
                addr += inst.len();
            },
            Err(e) => { println!("{:#010x}: {}", addr.to_linear(), e); break; },
        }
        if addr.to_linear() >= buf.len() {
            break;
        }
    }
}
