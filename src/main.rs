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
        "x86:64" => crate::current_arch::decode_input_with_annotation::<yaxpeax_x86::long_mode::Arch>(&buf, verbose),
        "x86_32" |
        "x86:32" => crate::current_arch::decode_input_with_annotation::<yaxpeax_x86::protected_mode::Arch>(&buf, verbose),
        "x86_16" |
        "x86:16" => crate::current_arch::decode_input_with_annotation::<yaxpeax_x86::real_mode::Arch>(&buf, verbose),
        // "ia64" => crate::current_arch::decode_input_with_annotation::<yaxpeax_ia64::IA64>(&buf, verbose),
        "ia64" => crate::current_arch::decode_input::<yaxpeax_ia64::IA64>(&buf, verbose),
        "avr" => crate::current_arch::decode_input::<yaxpeax_avr::AVR>(&buf, verbose),
        "armv7" => crate::current_arch::decode_input::<yaxpeax_arm::armv7::ARMv7>(&buf, verbose),
        "armv8" => crate::current_arch::decode_input::<yaxpeax_arm::armv8::a64::ARMv8>(&buf, verbose),
        "mips" => crate::current_arch::decode_input::<yaxpeax_mips::MIPS>(&buf, verbose),
        // "msp430" => crate::current_arch::decode_input_with_annotation::<yaxpeax_msp430::MSP430>(&buf, verbose),
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
    use yaxpeax_arch_02::{AnnotatingDecoder, FieldDescription, VecSink};
    use std::fmt;
    use num_traits::identities::Zero;

    fn col2bit(col: usize) -> usize {
       // ia64
       // 127 - col
       // msp430
            /*
        let word = col >> 4;
        let bit = 15 - (col & 0xf);

        (word << 4) | bit
        */
        // x86
        let byte = col / 8;
        let bit = (7 - (col % 8));
        let bit = byte * 8 + bit;
        bit
    }
    fn bit2col(bit: usize) -> usize {
        let byte = bit / 8;
        let bit = (7 - (bit % 8));
        let bit = byte * 8 + bit;
        bit
    }

    #[derive(Debug)]
    struct BitRange {
        start: u32,
        end: u32,
        lhs: u32,
        rhs: u32,
    }

    impl BitRange {
        fn across(start: u32, end: u32) -> BitRange {
            let mut lhs = bit2col(start as usize) as u32;
            let mut rhs = bit2col(start as usize) as u32;
            for bit in start..=end {
                lhs = std::cmp::min(lhs, bit2col(bit as usize) as u32);
                rhs = std::cmp::max(rhs, bit2col(bit as usize) as u32);
            }
            BitRange { start, end, lhs, rhs }
        }
    }

    struct ItemDescription<A: Arch> where A::Decoder: AnnotatingDecoder<A> {
        ranges: Vec<BitRange>,
        description: <<A as Arch>::Decoder as AnnotatingDecoder<A>>::FieldDescription,
    }

    impl<A: Arch> fmt::Debug for ItemDescription<A> where A::Decoder: AnnotatingDecoder<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{{ ranges: {:?}, description: {} }}", &self.ranges, &self.description)
        }
    }

    // spans grouped together in some decoder-specified logical structure by
    // `id`. `id` is a hint that data should be considered related for display
    // purposes.
    struct FieldRecord<A: Arch> where A::Decoder: AnnotatingDecoder<A> {
        // spans grouped together by `FieldDescription` - one field may be
        // described by multiple distinct spans, so those spans are recorded
        // here. elements are ordered by the lowest bit of spans describing an
        // element.
        elements: Vec<ItemDescription<A>>,
        id: u32,
    }

    impl<A: Arch> fmt::Debug for FieldRecord<A> where A::Decoder: AnnotatingDecoder<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{{ elements: {:?}, id: {} }}", &self.elements, &self.id)
        }
    }

    fn show_field_descriptions<A: Arch>(fields: &[FieldRecord<A>], data: &[u8]) where A::Decoder: AnnotatingDecoder<A> {
        let mut boundaries = [false; 256];
        let mut separators = [false; 256];
        let mut bits = [false; 256];
        let mut rhs = [false; 256];
        let mut lhs = [false; 256];
        let mut field_order: Vec<(usize, usize)> = Vec::new();
        let mut boundary_order: Vec<(usize, usize)> = Vec::new();

        for (fi, field) in fields.iter().enumerate() {
            for (ei, element) in field.elements.iter().enumerate() {
                if element.description.is_separator() {
                    for (_ri, range) in element.ranges.iter().enumerate() {
                        boundaries[range.start as usize + 1] = true;
                        boundary_order.push((fi, range.start as usize + 1));
                    }
                    continue;
                }
                field_order.push((fi, ei));
                for (_ri, range) in element.ranges.iter().enumerate() {
                    for i in range.start..=range.end {
                        bits[i as usize] = true;
                    }
                    separators[range.start as usize] = true;
                    lhs[range.lhs as usize] = true;
                    rhs[range.rhs as usize] = true;
                }
            }
        }
        boundary_order.sort_by(|l, r| r.1.cmp(&l.1));

        // regardless of sections, the left-hand side of the terminal is a free boundary
        lhs[0] = false;

        let mut res = String::new();
        res.push_str("                                \n");

        let mut fudge_bits = [false; 160];

        for i in 0..160 {
            if (i >> 3) >= data.len() {
                continue;
            }

            let mut fudge = false;

            if lhs[i] {
                fudge = true;
            }

            if i > 0 && rhs[i - 1] {
                fudge = true;
            }

            if fudge {
                fudge_bits[i] = true;
            }
        }

        let mut fudge = 0;
        let mut col = [b' '; 160];

        for i in 0..160 {
            if (i >> 3) >= data.len() {
                continue;
            }

            let bit = col2bit(i);

            if fudge_bits[i] {
                fudge += 1;
            }

            if data[(bit >> 3) as usize] & (1 << (bit as u8 & 7)) != 0 {
                col[i + fudge] = b'1';
            } else {
                col[i + fudge] = b'0';
            }
        }
        res.push_str(unsafe { std::str::from_utf8_unchecked(&col) });
        res.push_str("\n");

        for (fi, ei) in field_order.iter() {
            let mut col = [b' '; 160];

            for range in &fields[*fi as usize].elements[*ei as usize].ranges {
                let mut fudge = 0;

                for c in 0..128 {
                    let bit = col2bit(c as usize);

                    if boundaries[c] {
                        col[c + fudge] = b'|';
                    }
                    if fudge_bits[c as usize] {
                        fudge += 1;
                    }

                    if bit >= range.start as usize && bit <= range.end as usize {
                        let data_bit = data[(bit >> 3) as usize] & (1 << (bit as u8 & 7)) != 0;
                        col[c as usize + fudge] = if data_bit { b'1' } else { b'0' };
                    }
                }
            }

            res.push_str(unsafe { std::str::from_utf8_unchecked(&col[..(data.len() * 8 + 30)]) });
            res.push_str(" ");
            res.push_str(&fields[*fi as usize].elements[*ei as usize].description.to_string());
            res.push_str("\n");
        }

        let mut fudge = 0;
        let mut col = [b' '; 160];

        for i in 0..160 {
            if (i >> 3) >= data.len() {
                continue;
            }

            if boundaries[i] {
                col[i + fudge] = b'|';
            }
            if fudge_bits[i] {
                fudge += 1;
            }
        }
        res.push_str(unsafe { std::str::from_utf8_unchecked(&col) });
        res.push_str("\n");

        for (field_index, bit) in boundary_order {
            let mut fudge = 0;
            let mut col = [b' '; 160];

            for i in 0..160 {
                if (i >> 3) >= data.len() {
                    continue;
                }

                if i == bit {
                    res.push_str(unsafe { std::str::from_utf8_unchecked(&col[..i + fudge]) });
                    break;
                }

                if boundaries[i] {
                    col[i + fudge] = b'|';
                }
                if fudge_bits[i] {
                    fudge += 1;
                }
            }
            use std::fmt::Write;
            let _ = write!(res, "{}", fields[field_index].elements[0].description);
            res.push_str("\n");
        }

        println!("{}", res);
    }

    pub(crate) fn decode_input<A: Arch>(buf: &[u8], verbose: bool)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        decode_input_with_decoder::<A>(A::Decoder::default(), buf, verbose);
    }

    pub(crate) fn decode_input_with_annotation<A: Arch>(buf: &[u8], verbose: bool)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
        A::Decoder: AnnotatingDecoder<A>,
    {
        decode_input_with_decoder_and_annotation::<A>(A::Decoder::default(), buf, verbose);
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

    pub(crate) fn decode_input_with_decoder_and_annotation<A: Arch>(decoder: A::Decoder, buf: &[u8], verbose: bool)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
        A::Decoder: AnnotatingDecoder<A>,
    {
        let start = A::Address::zero();
        let mut addr = start;
        loop {
            let mut sink: VecSink<<A::Decoder as AnnotatingDecoder<A>>::FieldDescription> = VecSink::new();
            let mut reader = U8Reader::new(&buf[addr.to_linear()..]);
            let mut inst = A::Instruction::default();
            match decoder.decode_with_annotation(&mut inst, &mut reader, &mut sink) {
                Ok(()) => {
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
                        let mut fields: Vec<FieldRecord<A>> = Vec::new();

                        use itertools::Itertools;
                        let mut vs = sink.records;
                        vs.sort_by_key(|rec| rec.2.id());
                        for (id, group) in &vs.iter().group_by(|x| x.2.id()) {
                            let mut field = FieldRecord {
                                elements: Vec::new(),
                                id: id,
                            };

                            for (desc, spans) in &group.group_by(|x| x.2.to_owned()) {
                                let mut item = ItemDescription {
                                    ranges: Vec::new(),
                                    description: desc,
                                };

                                for span in spans {
                                    item.ranges.push(BitRange::across(span.0, span.1));
                                }
                                field.elements.push(item);
                            }
                            fields.push(field);
                        }
                        show_field_descriptions(
                            &fields,
                            &buf[addr.to_linear()..]
                                [..A::Address::zero().wrapping_offset(inst.len()).to_linear()]
                        );
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
