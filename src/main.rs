use std::io::Write;
use std::{fmt, io, fs};
use std::str::FromStr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug)]
enum Architecture {
    X86_64,
    X86_32,
    X86_16,
    IA64,
    AVR,
    ARMv7,
    ARMv7Thumb,
    ARMv8,
    MIPS,
    MSP430,
    PIC17,
    PIC18,
    M16C,
    N6502,
    LC87,
    // PIC24,
    SuperH(yaxpeax_superh::SuperHDecoder),
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl FromStr for Architecture {
    type Err = &'static str;
    fn from_str(arch_str: &str) -> Result<Self, Self::Err> {
        use Architecture::*;
        let err_str = "possible values: x86_64, x86_32, x86_16, x86:64, x86:32, x86:16, \
                                        ia64, armv7, armv7-t, armv8, avr, mips, msp430, pic17, pic18, \
                                        m16c, 6502, lc87, {sh{,2,3,4},j2}[[+-]{be,mmu,fpu,f64,j2}]*";
        let arch = match arch_str {
            "x86_64" | "x86:64" => X86_64,
            "x86_32" | "x86:32" => X86_32,
            "x86_16" | "x86:16" => X86_16,
            "ia64" => IA64,
            "avr" => AVR,
            "armv7" => ARMv7,
            "armv7-t" => ARMv7Thumb,
            "armv8" => ARMv8,
            "mips" => MIPS,
            "msp430" => MSP430,
            "pic17" => PIC17,
            "pic18" => PIC18,
            "m16c" => M16C,
            "6502" => N6502,
            "lc87" => LC87,
            //        "pic24" => PIC24,
            _ => {
                let seg_idx = arch_str.find(&['+', '-'][..]).unwrap_or(arch_str.len());
                let (base, features) = arch_str.split_at(seg_idx);
                let decoder = match base {
                    "sh" => yaxpeax_superh::SuperHDecoder::SH1,
                    "sh2" => yaxpeax_superh::SuperHDecoder::SH2,
                    "sh3" => yaxpeax_superh::SuperHDecoder::SH3,
                    "sh4" => yaxpeax_superh::SuperHDecoder::SH4,
                    "j2" => yaxpeax_superh::SuperHDecoder::J2,
                    _ => return Err(err_str),
                };
                SuperH(parse_superh(decoder, features))
            }
        };
        Ok(arch)
    }
}

#[derive(Parser)]
#[clap(about, version, author)]
struct Args {
    /// architecture to disassemble input as.
    #[clap(short, long, default_value = "x86_64")]
    architecture: Architecture,

    /// file of bytes to decode
    #[clap(short, long, parse(from_os_str), conflicts_with = "data")]
    file: Option<PathBuf>,

    /// increased detail when decoding instructions
    #[clap(short, long, parse(from_occurrences))]
    verbose: u8,

    /// hex bytes to decode by the selected architecture. for example, try -a x86_64 33c0c3
    #[clap(required_unless_present = "file")]
    data: Option<String>,
}

fn main() {
    let args = Args::parse();

    let buf: Vec<u8> = match args.data {
        Some(data) => match hex::decode(data) {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("Invalid input, {}. Expected a sequence of bytes as hex", e);
                return;
            }
        },
        None => {
            let name = args.file.unwrap();
            match fs::read(&name) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error reading {}: {}", name.display(), e);
                    return;
                }
            }
        }
    };
    let verbose = args.verbose > 0;

    let printer = Printer { stdout: io::stdout(), verbose };

    use Architecture::*;
    match args.architecture {
        X86_64 => arch_02::decode_input_and_annotate::<yaxpeax_x86::long_mode::Arch>(&buf, &printer),
        X86_32 => arch_02::decode_input_and_annotate::<yaxpeax_x86::protected_mode::Arch>(&buf, &printer),
        X86_16 => arch_02::decode_input_and_annotate::<yaxpeax_x86::real_mode::Arch>(&buf, &printer),
        IA64 => arch_02::decode_input::<yaxpeax_ia64::IA64>(&buf, &printer),
        AVR => arch_02::decode_input::<yaxpeax_avr::AVR>(&buf, &printer),
        ARMv7 => arch_02::decode_input::<yaxpeax_arm::armv7::ARMv7>(&buf, &printer),
        ARMv7Thumb => arch_02::decode_armv7_thumb(&buf, &printer),
        ARMv8 => arch_02::decode_input::<yaxpeax_arm::armv8::a64::ARMv8>(&buf, &printer),
        MIPS => arch_02::decode_input::<yaxpeax_mips::MIPS>(&buf, &printer),
        MSP430 => arch_02::decode_input_and_annotate::<yaxpeax_msp430::MSP430>(&buf, &printer),
        PIC17 => arch_02::decode_input::<yaxpeax_pic17::PIC17>(&buf, &printer),
        PIC18 => arch_02::decode_input::<yaxpeax_pic18::PIC18>(&buf, &printer),
        M16C => arch_02::decode_input::<yaxpeax_m16c::M16C>(&buf, &printer),
        N6502 => arch_02::decode_input::<yaxpeax_6502::N6502>(&buf, &printer),
        LC87 => arch_02::decode_input::<yaxpeax_lc87::LC87>(&buf, &printer),
        //        PIC24 => decode_input::<yaxpeax_pic24::PIC24>(buf),
        SuperH(decoder) => arch_02::decode_input_with_decoder::<yaxpeax_superh::SuperH>(decoder, &buf, &printer),
    }
}

fn parse_superh(mut based_on: yaxpeax_superh::SuperHDecoder, mut from: &str)
    -> yaxpeax_superh::SuperHDecoder
{
    while !from.is_empty() {
        let op = from.chars().next().unwrap();
        from = &from[1..];

        let next_feat_idx = from.find(&['+', '-'][..]).unwrap_or(from.len());
        let feat = &from[0..next_feat_idx];
        from = &from[next_feat_idx..];

        match (op, feat) {
            ('+', "be") => based_on.little_endian = false,
            ('-', "be") => based_on.little_endian = true,
            ('+', "f64") => based_on.fpscr_sz = true,
            ('-', "f64") => based_on.fpscr_sz = false,

            ('+', "mmu") => based_on.features.insert(yaxpeax_superh::SuperHFeatures::MMU),
            ('-', "mmu") => based_on.features.remove(yaxpeax_superh::SuperHFeatures::MMU),
            ('+', "fpu") => based_on.features.insert(yaxpeax_superh::SuperHFeatures::FPU),
            ('-', "fpu") => based_on.features.remove(yaxpeax_superh::SuperHFeatures::FPU),
            ('+', "j2") => based_on.features.insert(yaxpeax_superh::SuperHFeatures::J2),
            ('-', "j2") => based_on.features.remove(yaxpeax_superh::SuperHFeatures::J2),

            pair => panic!("Who is {:?} and why was it not caught at parse time?", pair),
        }
    }

    based_on
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

    for (_field_index, bit) in boundary_order {
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
