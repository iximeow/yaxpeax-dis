use std::fs::File;
use std::io::{Read, Write};
use std::{fmt, io};
use std::collections::BTreeSet;

fn main() {
    use clap::*;
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
                        "ia64", "armv7", "armv7-t","armv8", "avr", "mips", "msp430",
                        "pic17", "pic18", "m16c", "6502", "lc87"].contains(&&a[..]) ||
                       (["sh", "sh2", "sh3", "sh4", "j2"].contains(
                             &&a[0..a.find(|c| c == '+' || c == '-').unwrap_or(a.len())]) &&
                        a.split(|c| c == '+' || c == '-').skip(1).all(
                            |f| ["be", "mmu", "fpu", "f64", "j2"].contains(&f))) {
                        Ok(())
                    } else {
                        Err("possible values: x86_64, x86_32, x86_16, x86:64, x86:32, x86:16, \
                                              ia64, armv7, armv7-t, armv8, avr, mips, msp430, pic17, pic18, \
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

    let printer = Printer { stdout: io::stdout(), verbose };

    match arch_str {
        "x86_64" |
        "x86:64" => arch_02::decode_input_and_annotate::<yaxpeax_x86::long_mode::Arch>(&buf, &printer),
        "x86_32" |
        "x86:32" => arch_02::decode_input_and_annotate::<yaxpeax_x86::protected_mode::Arch>(&buf, &printer),
        "x86_16" |
        "x86:16" => arch_02::decode_input_and_annotate::<yaxpeax_x86::real_mode::Arch>(&buf, &printer),
        "ia64" => arch_02::decode_input::<yaxpeax_ia64::IA64>(&buf, &printer),
        "avr" => arch_02::decode_input::<yaxpeax_avr::AVR>(&buf, &printer),
        "armv7" => arch_02::decode_input::<yaxpeax_arm::armv7::ARMv7>(&buf, &printer),
        "armv7-t" => arch_02::decode_armv7_thumb(&buf, &printer),
        "armv8" => arch_02::decode_input::<yaxpeax_arm::armv8::a64::ARMv8>(&buf, &printer),
        "mips" => arch_02::decode_input::<yaxpeax_mips::MIPS>(&buf, &printer),
        "msp430" => arch_02::decode_input_and_annotate::<yaxpeax_msp430::MSP430>(&buf, &printer),
        "pic17" => arch_02::decode_input::<yaxpeax_pic17::PIC17>(&buf, &printer),
        "pic18" => arch_02::decode_input::<yaxpeax_pic18::PIC18>(&buf, &printer),
        "m16c" => arch_02::decode_input::<yaxpeax_m16c::M16C>(&buf, &printer),
        "6502" => arch_02::decode_input::<yaxpeax_6502::N6502>(&buf, &printer),
        "lc87" => arch_02::decode_input::<yaxpeax_lc87::LC87>(&buf, &printer),
        //        "pic24" => decode_input::<yaxpeax_pic24::PIC24>(buf),
        other => {
            let seg_idx = arch_str.find(|c| c == '+' || c == '-').unwrap_or(arch_str.len());
            let wps = |base| with_parsed_superh(base, &arch_str[seg_idx..],
                |decoder| arch_02::decode_input_with_decoder::<yaxpeax_superh::SuperH>(decoder, &buf, &printer));
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

struct Printer {
    stdout: io::Stdout,
    verbose: bool,
}

impl Printer {
    // shared generic function to keep display logic consistent regardless of yaxpeax-arch version
    fn print_instr<I, E>(&self, rest: &[u8], addr: usize, inst_res: Result<InstDetails<I>, E>)
    where
        I: fmt::Display + fmt::Debug,
        E: fmt::Display,
    {
        // TODO: lock stdout for the whole time? What if an arch implementation tries to log something?
        let mut stdout = self.stdout.lock();
        write!(stdout, "{:#010x}: ", addr).unwrap();
        match inst_res {
            Ok(InstDetails { inst_len, well_defined, inst, field_descriptions }) => {
                writeln!(stdout, "{:14}: {}", hex::encode(&rest[..inst_len]), inst)
                    .unwrap();
                if self.verbose {
                    if !well_defined {
                        writeln!(stdout, "  not well-defined").unwrap();
                    }

                    // if we can show detailed information about the instruction's interpretation,
                    // do that. otherwise, debug impl of the instruction and hope for the best.
                    if let Some((mapper, fields)) = field_descriptions {
                        let bits_layout = fmt_field_descriptions(
                            &mapper,
                            &fields,
                            &rest[..inst_len]
                        );
                        write!(stdout, "{}", bits_layout).unwrap();
                    } else {
                        writeln!(stdout, "  {:?}", inst).unwrap();
                    }
                }
            }
            Err(e) => {
                writeln!(stdout, "{}", e).unwrap();
            }
        }
    }
}

struct InstDetails<I: fmt::Debug + fmt::Display> {
    inst_len: usize,
    well_defined: bool,
    inst: I,
    field_descriptions: Option<(BitPosition, Vec<FieldRecord>)>,
}

// yaxpeax-arch, implemented by all decoders here, may be required at incompatible versions by
// different decoders if/when a new version releases. implement the actual decode-and-print
// behavior independent of yaxpeax-arch so decoders using different version can exist in parallel.
mod arch_02 {
    use super::Printer;
    use num_traits::identities::Zero;
    use std::fmt;
    use yaxpeax_arch_02::{
        AddressBase, Arch, Decoder, Instruction, LengthedInstruction, Reader, U8Reader,
    };
    use yaxpeax_arch_02::annotation::{AnnotatingDecoder, FieldDescription, VecSink};

    use crate::{FieldRecord, ItemDescription};


    pub(crate) fn decode_input<A: Arch>(buf: &[u8], printer: &Printer)
    where
        A::Instruction: fmt::Display,
        for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        decode_input_with_decoder::<A>(A::Decoder::default(), buf, printer);
    }

    pub(crate) fn decode_input_and_annotate<A: Arch + crate::ArchBitMapper>(buf: &[u8], printer: &Printer)
    where
        A::Instruction: fmt::Display,
        A::Decoder: AnnotatingDecoder<A>,
        for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        decode_input_with_annotation::<A>(A::Decoder::default(), buf, printer);
    }

    pub(crate) fn decode_armv7_thumb(buf: &[u8], printer: &Printer) {
        let decoder = yaxpeax_arm::armv7::InstDecoder::default_thumb();
        decode_input_with_decoder::<yaxpeax_arm::armv7::ARMv7>(decoder, buf, printer);
    }

    pub(crate) fn decode_input_with_decoder<A: Arch>(
        decoder: A::Decoder,
        buf: &[u8],
        printer: &Printer,
    ) where
        A::Instruction: fmt::Display,
        for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        let mut addr = A::Address::zero();
        while let Some(rest) = buf.get(addr.to_linear()..).filter(|v| !v.is_empty()) {
            let mut reader = U8Reader::new(rest);
            let res = decoder.decode(&mut reader);
            let advance_addr = match &res {
                Ok(inst) => inst.len(),
                Err(_) => A::Instruction::min_size(),
            };
            let generic_res = res.map(|inst| {
                crate::InstDetails {
                    inst_len: A::Address::zero().wrapping_offset(inst.len()).to_linear(),
                    well_defined: inst.well_defined(),
                    inst,
                    field_descriptions: None,
                }
            });
            printer.print_instr(rest, addr.to_linear(), generic_res);
            addr += advance_addr;
        }
    }

    fn field_descs_to_record<A: Arch + crate::ArchBitMapper>(sink: VecSink<<A::Decoder as AnnotatingDecoder<A>>::FieldDescription>) -> Vec<FieldRecord> where A::Decoder: AnnotatingDecoder<A> {
        let mut fields: Vec<FieldRecord> = Vec::new();
        let bit_mapper = A::mapper();

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
                    description: desc.to_string(),
                    separator: desc.is_separator(),
                };

                for span in spans {
                    item.ranges.push(crate::BitRange::across(bit_mapper, span.0, span.1));
                }
                field.elements.push(item);
            }
            fields.push(field);
        }

        fields
    }

    pub(crate) fn decode_input_with_annotation<A: Arch + crate::ArchBitMapper>(
        decoder: A::Decoder,
        buf: &[u8],
        printer: &Printer,
    ) where
        A::Instruction: fmt::Display,
        A::Decoder: AnnotatingDecoder<A>,
        for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        let mut addr = A::Address::zero();
        while let Some(rest) = buf.get(addr.to_linear()..).filter(|v| !v.is_empty()) {
            let mut sink: VecSink<<A::Decoder as AnnotatingDecoder<A>>::FieldDescription> = VecSink::new();
            let mut reader = U8Reader::new(rest);
            let mut inst = A::Instruction::default();
            let res = decoder.decode_with_annotation(&mut inst, &mut reader, &mut sink);
            let advance_addr = match &res {
                Ok(_) => inst.len(),
                Err(_) => A::Instruction::min_size(),
            };
            let generic_res = res.map(|_| {
                let records = field_descs_to_record::<A>(sink);
                crate::InstDetails {
                    inst_len: A::Address::zero().wrapping_offset(inst.len()).to_linear(),
                    well_defined: inst.well_defined(),
                    inst,
                    field_descriptions: Some((A::mapper(), records)),
                }
            });
            printer.print_instr(rest, addr.to_linear(), generic_res);
            addr += advance_addr;
        }
    }
}

/// any architecture with an `AnnotatingDecoder` implementation will have annotations reported at
/// positions of bits in the instruction. `yaxpeax-dis` requires some description of how to convert
/// between a column and a bit for a given architecture.
#[derive(Copy, Clone, Debug)]
struct BitPosition {
    word_size: usize,
}

impl BitPosition {
    fn col2bit(&self, col: usize) -> usize {
        let word = col / self.word_size;
        let bit = (self.word_size - 1) - (col % self.word_size);
        let bit = word * self.word_size + bit;
        bit
    }

    fn bit2col(&self, bit: usize) -> usize {
        let word = bit / self.word_size;
        let col = (self.word_size - 1) - (bit % self.word_size);
        let col = word * self.word_size + col;
        col
    }
}

const IA64_POSITIONS: BitPosition = BitPosition {
    word_size: 128
};

const WORD_POSITIONS: BitPosition = BitPosition {
    word_size: 16
};

const BYTE_POSITIONS: BitPosition = BitPosition {
    word_size: 8
};

trait ArchBitMapper {
    fn mapper() -> BitPosition;
}

impl ArchBitMapper for yaxpeax_x86::real_mode::Arch {
    fn mapper() -> BitPosition {
        BYTE_POSITIONS
    }
}

impl ArchBitMapper for yaxpeax_x86::protected_mode::Arch {
    fn mapper() -> BitPosition {
        BYTE_POSITIONS
    }
}

impl ArchBitMapper for yaxpeax_x86::long_mode::Arch {
    fn mapper() -> BitPosition {
        BYTE_POSITIONS
    }
}

impl ArchBitMapper for yaxpeax_msp430::MSP430 {
    fn mapper() -> BitPosition {
        WORD_POSITIONS
    }
}

impl ArchBitMapper for yaxpeax_ia64::IA64 {
    fn mapper() -> BitPosition {
        IA64_POSITIONS
    }
}

#[derive(Debug)]
struct BitRange {
    start: u32,
    end: u32,
    lhs: u32,
    rhs: u32,
}

impl BitRange {
    fn across(bit_mapper: BitPosition, start: u32, end: u32) -> BitRange {
        let mut lhs = bit_mapper.bit2col(start as usize) as u32;
        let mut rhs = bit_mapper.bit2col(start as usize) as u32;
        for bit in start..=end {
            lhs = std::cmp::min(lhs, bit_mapper.bit2col(bit as usize) as u32);
            rhs = std::cmp::max(rhs, bit_mapper.bit2col(bit as usize) as u32);
        }
        BitRange { start, end, lhs, rhs }
    }
}

/// a representation of a decoder's `Annotation` type that does not actually reference
/// `yaxpeax_arch`. this is important so we can have a whole shared display routine reused across
/// `yaxpeax_arch` versions - there may be more than one in use at a time in `yaxpeax-dis`.
struct ItemDescription {
    ranges: Vec<BitRange>,
    description: String,
    separator: bool,
}

impl fmt::Debug for ItemDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ ranges: {:?}, description: {}, separator: {} }}", &self.ranges, &self.description, self.separator)
    }
}

// spans grouped together in some decoder-specified logical structure by
// `id`. `id` is a hint that data should be considered related for display
// purposes.
struct FieldRecord {
    // spans grouped together by `FieldDescription` - one field may be
    // described by multiple distinct spans, so those spans are recorded
    // here. elements are ordered by the lowest bit of spans describing an
    // element.
    elements: Vec<ItemDescription>,
    id: u32,
}

impl fmt::Debug for FieldRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ elements: {:?}, id: {} }}", &self.elements, &self.id)
    }
}

fn fmt_field_descriptions(bit_mapper: &BitPosition, fields: &[FieldRecord], data: &[u8]) -> String {
    let mut boundaries = [false; 256];
    let mut separators = [false; 256];
    let mut bits = [false; 256];
    let mut rhs = [false; 256];
    let mut lhs = [false; 256];
    let mut field_order: Vec<(usize, usize)> = Vec::new();
    let mut boundary_order: Vec<(usize, usize)> = Vec::new();

    for (fi, field) in fields.iter().enumerate() {
        for (ei, element) in field.elements.iter().enumerate() {
            if element.separator {
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

        let bit = bit_mapper.col2bit(i);

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
                let bit = bit_mapper.col2bit(c as usize);

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
        res.push_str(&fields[*fi as usize].elements[*ei as usize].description);
        res.push_str("\n");
    }

    let mut fudge = 0;
    let mut col = [b' '; 160];

    let mut line_end = 0;
    for i in 0..160 {
        if (i >> 3) > data.len() {
            continue;
        }

        if boundaries[i] {
            col[i + fudge] = b'|';
            line_end = i + fudge + 1;
        }
        if fudge_bits[i] {
            fudge += 1;
        }
    }
    res.push_str(unsafe { std::str::from_utf8_unchecked(&col[..line_end]) });
    res.push_str("\n");

    for (field_index, bit) in boundary_order {
        let mut fudge = 0;
        let mut col = [b' '; 160];

        for i in 0..160 {
            if (i >> 3) > data.len() {
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
        res.push_str("\n");
    }

    res
}
