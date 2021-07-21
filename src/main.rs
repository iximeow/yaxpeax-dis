use clap::*;

use std::fs::File;
use std::io::Read;
use std::collections::BTreeSet;

fn main() {
    let _ = include_str!("../Cargo.toml");
    let app = app_from_crate!()
        .arg(
            Arg::with_name("arch")
                .short("a")
                .long("--architecture")
                .takes_value(true)
                .validator(|a| {
                    if ["x86_64", "x86_32", "x86_16",
                        "x86:64", "x86:32", "x86:16",
                        "ia64", "armv7", "armv8", "avr", "mips", "msp430",
                        "pic17", "pic18", "m16c", "6502", "lc87"].contains(&&a[..]) ||
                       (["sh", "sh2", "sh3", "sh4", "j2"].contains(
                             &&a[0..a.find(|c| c == '+' || c == '-').unwrap_or(a.len())]) &&
                        a.split(|c| c == '+' || c == '-').skip(1).all(
                            |f| ["be", "mmu", "fpu", "f64", "j2"].contains(&f))) {
                        Ok(())
                    } else {
                        Err("possible values: x86_64, x86_32, x86_16, x86:64, x86:32, x86:16, \
                                              ia64, armv7, armv8, avr, mips, msp430, pic17, pic18, \
                                              m16c, 6502, lc87, {sh{,2,3,4},j2}[[+-]{be,mmu,fpu,f64,j2}]*"
                            .to_string())
                    }
                })
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
        "x86_64" |
        "x86:64" => crate::current_arch::decode_input::<yaxpeax_x86::long_mode::Arch>(&buf, verbose),
        "x86_32" |
        "x86:32" => crate::current_arch::decode_input::<yaxpeax_x86::protected_mode::Arch>(&buf, verbose),
        "x86_16" |
        "x86:16" => crate::current_arch::decode_input::<yaxpeax_x86::real_mode::Arch>(&buf, verbose),
        "ia64" => crate::current_arch::decode_input::<yaxpeax_ia64::IA64>(&buf, verbose),
        "avr" => crate::current_arch::decode_input::<yaxpeax_avr::AVR>(&buf, verbose),
        "armv7" => crate::current_arch::decode_input::<yaxpeax_arm::armv7::ARMv7>(&buf, verbose),
        "armv8" => crate::current_arch::decode_input::<yaxpeax_arm::armv8::a64::ARMv8>(&buf, verbose),
        "mips" => crate::current_arch::decode_input::<yaxpeax_mips::MIPS>(&buf, verbose),
        "msp430" => crate::current_arch::decode_input::<yaxpeax_msp430::MSP430>(&buf, verbose),
        "pic17" => crate::current_arch::decode_input::<yaxpeax_pic17::PIC17>(&buf, verbose),
        "pic18" => crate::current_arch::decode_input::<yaxpeax_pic18::PIC18>(&buf, verbose),
        "m16c" => crate::current_arch::decode_input::<yaxpeax_m16c::M16C>(&buf, verbose),
        "6502" => crate::legacy_arch::decode_input::<yaxpeax_6502::N6502>(&buf, verbose),
        "lc87" => crate::current_arch::decode_input::<yaxpeax_lc87::LC87>(&buf, verbose),
        //        "pic24" => decode_input::<yaxpeax_pic24::PIC24>(buf),
        other => {
            let seg_idx = arch_str.find(|c| c == '+' || c == '-').unwrap_or(arch_str.len());
            let wps = |base| with_parsed_superh(base, &arch_str[seg_idx..],
                |decoder| crate::legacy_arch::decode_input_with_decoder::<yaxpeax_superh::SuperH>(decoder, &buf, verbose));
            match &arch_str[0..seg_idx] {
                "sh" => wps(yaxpeax_superh::SuperHDecoder::SH1),
                "sh2" => wps(yaxpeax_superh::SuperHDecoder::SH2),
                "sh3" => wps(yaxpeax_superh::SuperHDecoder::SH3),
                "sh4" => wps(yaxpeax_superh::SuperHDecoder::SH4),
                "j2" => wps(yaxpeax_superh::SuperHDecoder::J2),
                _ => println!("unsupported architecture: {}", other),
            }
        }
    }
}

fn with_parsed_superh<F: FnOnce(yaxpeax_superh::SuperHDecoder)>(
    mut based_on: yaxpeax_superh::SuperHDecoder, mut from: &str, func: F
) {
    let mut features = based_on.features.iter().copied().collect::<BTreeSet<_>>();

    while !from.is_empty() {
        // This would be Not Trash if split_inclusive were stable; alas
        let op = from.chars().next().unwrap();
        from = &from[1..];

        let next_feat_idx = from.find(|c| c == '+' || c == '-').unwrap_or(from.len());
        let feat = &from[0..next_feat_idx];
        from = &from[next_feat_idx..];

        match (op, feat) {
            ('+', "be") => based_on.little_endian = false,
            ('-', "be") => based_on.little_endian = true,
            ('+', "f64") => based_on.fpscr_sz = true,
            ('-', "f64") => based_on.fpscr_sz = false,

            ('+', "mmu") => { features.insert(yaxpeax_superh::SuperHFeature::MMU); },
            ('-', "mmu") => { features.remove(&yaxpeax_superh::SuperHFeature::MMU); },
            ('+', "fpu") => { features.insert(yaxpeax_superh::SuperHFeature::FPU); },
            ('-', "fpu") => { features.remove(&yaxpeax_superh::SuperHFeature::FPU); },
            ('+', "j2") => { features.insert(yaxpeax_superh::SuperHFeature::J2); },
            ('-', "j2") => { features.remove(&yaxpeax_superh::SuperHFeature::J2); },

            pair => panic!("Who is {:?} and why was it not caught at parse time?", pair),
        }
    }

    func(yaxpeax_superh::SuperHDecoder {
        features: &features.into_iter().collect::<Vec<_>>()[..],
        ..based_on
    })
}

// yaxpeax-arch, implemented by all decoders here, is required at incompatible versions by
// different decoders. implement the actual decode-and-print behavior on both versions of
// yaxpeax-arch while older decoders are still being updated.
mod current_arch {
    use yaxpeax_arch_02::{AddressBase, Arch, Decoder, Instruction, LengthedInstruction, Reader, U8Reader};
    use std::fmt;
    use num_traits::identities::Zero;

    pub(crate) fn decode_input<A: Arch>(buf: &[u8], verbose: bool)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        decode_input_with_decoder::<A>(A::Decoder::default(), buf, verbose);
    }

    pub(crate) fn decode_input_with_decoder<A: Arch>(decoder: A::Decoder, buf: &[u8], verbose: bool)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        let start = A::Address::zero();
        let mut addr = start;
        loop {
            let mut reader = U8Reader::new(&buf[addr.to_linear()..]);
            match decoder.decode(&mut reader) {
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
}

mod legacy_arch {
    use yaxpeax_arch_01::{AddressBase, Arch, Decoder, Instruction, LengthedInstruction};
    use std::fmt;
    use num_traits::identities::Zero;

    pub(crate) fn decode_input<A: Arch>(buf: &[u8], verbose: bool)
    where
        A::Instruction: fmt::Display,
    {
        decode_input_with_decoder::<A>(A::Decoder::default(), buf, verbose);
    }

    pub(crate) fn decode_input_with_decoder<A: Arch>(decoder: A::Decoder, buf: &[u8], verbose: bool)
    where
        A::Instruction: fmt::Display,
    {
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
}
