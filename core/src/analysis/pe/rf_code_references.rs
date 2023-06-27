//! Train a machine learning model on the functions that are currently known.
//! Then search for pointers to functions that may not yet be known,
//! using the machine learning model to score and accept/reject those
//! candidates.
use std::{collections::BTreeSet, vec};

use anyhow::Result;
use byteorder::ByteOrder;
use log::debug;
use rand::RngCore;
use smartcore::{
    ensemble::random_forest_classifier::{RandomForestClassifier, RandomForestClassifierParameters},
    model_selection::train_test_split,
};

use crate::{
    analysis::{
        cfg, dis,
        dis::zydis::{DecodedInstruction, Decoder},
        pe::Function,
    },
    aspace::AddressSpace,
    loader::pe::PE,
    module::Permissions,
    VA,
};

pub fn find_pe_nonrelocated_executable_pointers(pe: &PE) -> Result<Vec<VA>> {
    // list of candidates: (address of pointer, address pointed to)
    let mut candidates: Vec<(VA, VA)> = vec![];

    let min_addr = pe.module.address_space.base_address;
    let max_addr = pe
        .module
        .sections
        .iter()
        .map(|section| section.virtual_range.end)
        .max()
        .unwrap();

    // look for hardcoded pointers into the executable section of the PE.
    // note: this often finds jump tables, too. more filtering is below.
    // note: also finds many exception handlers. see filtering below.
    for section in pe.module.sections.iter() {
        let vstart: VA = section.virtual_range.start;
        let vsize = (section.virtual_range.end - section.virtual_range.start) as usize;
        let sec_buf = pe.module.address_space.read_bytes(vstart, vsize)?;

        debug!(
            "pointers: scanning section {:#x}-{:#x}",
            section.virtual_range.start, section.virtual_range.end
        );

        if let crate::arch::Arch::X64 = pe.module.arch {
            candidates.extend(
                sec_buf
                    // using windows for unaligned pointers,
                    // rather than chunks for aligned pointers.
                    .windows(std::mem::size_of::<u64>())
                    .map(|b| byteorder::LittleEndian::read_u64(b) as VA)
                    .enumerate()
                    // naive range filter that is very fast
                    .filter(|&(_, va)| va >= min_addr && va < max_addr)
                    .filter(|&(_, va)| pe.module.probe_va(va, Permissions::X))
                    .map(|(i, va)| (vstart + (i as u64), va)),
            )
        } else {
            candidates.extend(
                sec_buf
                    // using windows for unaligned pointers
                    // rather than chunks for aligned pointers.
                    .windows(std::mem::size_of::<u32>())
                    .map(|b| byteorder::LittleEndian::read_u32(b) as VA)
                    .enumerate()
                    // naive range filter that is very fast
                    .filter(|&(_, va)| va >= min_addr && va < max_addr)
                    .filter(|&(_, va)| pe.module.probe_va(va, Permissions::X))
                    .map(|(i, va)| (vstart + (i as u64), va)),
            )
        }
    }

    Ok(candidates
        .into_iter()
        .map(|(src, dst)| {
            debug!(
                "pointers: candidate pointer: {:#x} points to valid content at {:#x}",
                src, dst
            );
            dst
        })
        .collect())
}

#[derive(Clone, Copy)]
struct RandomData {
    data: [u8; 260],
}

impl Default for RandomData {
    fn default() -> Self {
        let mut data = [0u8; 260];
        rand::thread_rng().fill_bytes(&mut data);
        RandomData { data }
    }
}

// padding values, from: https://gist.github.com/stevemk14ebr/d117e8d0fd1432fb2a92354a034ce5b9
#[derive(Clone, Copy, Debug)]
enum ByteDescriptor {
    /// value is not present, such as beyond the bounds of the section.
    NONE  = 1,
    /// 0x90, NOP
    NOP   = 2,
    /// 0xCC, breakpoint
    CC    = 3,
    /// 0x00
    ZERO  = 4,
    /// ret, retf, retn
    /// 0xC3, 0xC2, 0xCA, 0xCB
    RET   = 5,
    // anything else
    OTHER = 6,
}

#[derive(Clone, Copy, Debug)]
enum MnemonicDescriptor {
    /// value is not present, such as beyond the bounds of the section or basic
    /// block.
    NONE    = 1,
    PUSH    = 2,
    POP     = 3,
    MOV     = 4,
    LEA     = 5,
    CALL    = 6,
    RET     = 7,
    COMPARE = 8,
    JMP     = 9,
    CJMP    = 10,
    /// add, sub, xor, mul, div, etc.
    ARITH   = 11,
    OTHER   = 12,
    /// failed to decode
    INVALID = 13,
}

#[derive(Debug)]
struct CodeFeatures {
    // capped at: 255 bytes
    size_of_basic_block:     u8,
    // when disassembling the first basic block,
    // do we encounter an invalid instruction?
    has_invalid_instruction: bool,

    // 4 bytes before the candidate address.
    // categorical.
    prebytes: [ByteDescriptor; 4],

    // 8 instructions of the first basic block.
    // categorical.
    mnemonics: [MnemonicDescriptor; 8],
}

impl CodeFeatures {
    fn to_feature_vec(&self) -> Vec<u8> {
        let mut features = vec![];

        features.push(self.size_of_basic_block);
        features.push(self.has_invalid_instruction as u8);

        for prebyte in self.prebytes.iter() {
            features.push(*prebyte as u8);
        }

        for mnemonic in self.mnemonics.iter() {
            features.push(*mnemonic as u8);
        }

        features
    }

    // indices of feature_vec that contain categorical values.
    const fn cat_idx() -> [usize; 8] {
        return [
            // 0: size_of_basic_block
            // 1: has_invalid_instruction

            // prebytes
            2, 3, 4, 5, // mnemonics
            6, 7, 8, 9,
        ];
    }
}

fn extract_prebyte_feature(byte: u8) -> ByteDescriptor {
    match byte {
        0x90 => ByteDescriptor::NOP,
        0xCC => ByteDescriptor::CC,
        0x00 => ByteDescriptor::ZERO,
        0xC3 | 0xC2 | 0xCA | 0xCB => ByteDescriptor::RET,
        _ => ByteDescriptor::OTHER,
    }
}

fn extract_mnemonic_feature(insn: &DecodedInstruction) -> MnemonicDescriptor {
    match insn.mnemonic {
        zydis::Mnemonic::PUSH => MnemonicDescriptor::PUSH,
        zydis::Mnemonic::POP => MnemonicDescriptor::POP,

        zydis::Mnemonic::MOV => MnemonicDescriptor::MOV,
        zydis::Mnemonic::LEA => MnemonicDescriptor::LEA,

        zydis::Mnemonic::CALL => MnemonicDescriptor::CALL,
        zydis::Mnemonic::RET | zydis::Mnemonic::IRET | zydis::Mnemonic::IRETD | zydis::Mnemonic::IRETQ => {
            MnemonicDescriptor::RET
        }

        zydis::Mnemonic::CMP => MnemonicDescriptor::COMPARE,
        zydis::Mnemonic::TEST => MnemonicDescriptor::COMPARE,

        zydis::Mnemonic::JMP => MnemonicDescriptor::JMP,

        zydis::Mnemonic::JB
        | zydis::Mnemonic::JBE
        | zydis::Mnemonic::JCXZ
        | zydis::Mnemonic::JECXZ
        | zydis::Mnemonic::JKNZD
        | zydis::Mnemonic::JKZD
        | zydis::Mnemonic::JL
        | zydis::Mnemonic::JLE
        | zydis::Mnemonic::JNB
        | zydis::Mnemonic::JNBE
        | zydis::Mnemonic::JNL
        | zydis::Mnemonic::JNLE
        | zydis::Mnemonic::JNO
        | zydis::Mnemonic::JNP
        | zydis::Mnemonic::JNS
        | zydis::Mnemonic::JNZ
        | zydis::Mnemonic::JO
        | zydis::Mnemonic::JP
        | zydis::Mnemonic::JRCXZ
        | zydis::Mnemonic::JS
        | zydis::Mnemonic::JZ => MnemonicDescriptor::CJMP,

        zydis::Mnemonic::CMOVB
        | zydis::Mnemonic::CMOVBE
        | zydis::Mnemonic::CMOVL
        | zydis::Mnemonic::CMOVLE
        | zydis::Mnemonic::CMOVNB
        | zydis::Mnemonic::CMOVNBE
        | zydis::Mnemonic::CMOVNL
        | zydis::Mnemonic::CMOVNLE
        | zydis::Mnemonic::CMOVNO
        | zydis::Mnemonic::CMOVNP
        | zydis::Mnemonic::CMOVNS
        | zydis::Mnemonic::CMOVNZ
        | zydis::Mnemonic::CMOVO
        | zydis::Mnemonic::CMOVP
        | zydis::Mnemonic::CMOVS
        | zydis::Mnemonic::CMOVZ => MnemonicDescriptor::CJMP,

        zydis::Mnemonic::ADD
        | zydis::Mnemonic::SUB
        | zydis::Mnemonic::XOR
        | zydis::Mnemonic::MUL
        | zydis::Mnemonic::DIV
        | zydis::Mnemonic::IMUL
        | zydis::Mnemonic::IDIV
        | zydis::Mnemonic::INC
        | zydis::Mnemonic::DEC
        | zydis::Mnemonic::NEG
        | zydis::Mnemonic::NOT
        | zydis::Mnemonic::AND
        | zydis::Mnemonic::OR
        | zydis::Mnemonic::SHL
        | zydis::Mnemonic::SHR
        | zydis::Mnemonic::SAR
        | zydis::Mnemonic::ROL
        | zydis::Mnemonic::ROR
        | zydis::Mnemonic::RCL
        | zydis::Mnemonic::RCR => MnemonicDescriptor::ARITH,

        _ => MnemonicDescriptor::OTHER,
    }
}

fn extract_features_for_data(decoder: &Decoder, buf: &[u8]) -> CodeFeatures {
    assert!(buf.len() >= 260);

    let prebytes4 = extract_prebyte_feature(buf[0]);
    let prebytes3 = extract_prebyte_feature(buf[1]);
    let prebytes2 = extract_prebyte_feature(buf[2]);
    let prebytes1 = extract_prebyte_feature(buf[3]);

    let prebytes = [prebytes4, prebytes3, prebytes2, prebytes1];

    let mut size_of_basic_block = 0u8;
    let mut has_invalid_instruction = false;
    let mut mnemonics = [MnemonicDescriptor::NONE; 8];
    for (i, (offset, insn)) in dis::linear_disassemble(&decoder, &buf[4..260]).enumerate() {
        if let Ok(Some(insn)) = insn {
            size_of_basic_block = size_of_basic_block.saturating_add(insn.length as u8);

            let mnem = extract_mnemonic_feature(&insn);
            if i < 8 {
                mnemonics[i] = mnem;
            }

            if matches!(
                mnem,
                MnemonicDescriptor::JMP | MnemonicDescriptor::CJMP | MnemonicDescriptor::RET
            ) {
                // end of basic block
                break;
            };

            if size_of_basic_block == u8::MAX {
                // we've reached the maximum size of a basic block.
                // we're not recording instructions beyond this, anyways.
                break;
            }
        } else {
            if i < 8 {
                mnemonics[i] = MnemonicDescriptor::INVALID;
            }

            if offset < 256 - 0x10 {
                has_invalid_instruction = true;
            } else {
                // once we get close to the end of the data buffer,
                // its reasonable that we might fail to decode a truncated
                // instruction.
            }

            break;
        }
    }

    CodeFeatures {
        prebytes,
        size_of_basic_block,
        has_invalid_instruction,
        mnemonics,
    }
}

pub fn find_functions_by_pointers(pe: &PE, existing_functions: Vec<Function>) -> Result<Vec<VA>> {
    let decoder = dis::get_disassembler(&pe.module)?;

    let RANDOM_SAMPLES = 1000;
    let SUCCESSOR_SAMPLES = 0;

    let random_samples = (0..RANDOM_SAMPLES)
        .map(|_| RandomData::default())
        .map(|data| extract_features_for_data(&decoder, &data.data))
        .collect::<Vec<_>>();

    // this is code that isn't found at the start of a function
    let mut successor_samples: Vec<CodeFeatures> = Default::default();

    let function_addresses: BTreeSet<VA> = existing_functions
        .iter()
        .flat_map(|f| match f {
            Function::Local(va) => Some(va),
            Function::Thunk(_) => None,
            Function::Import(_) => None,
        })
        .cloned()
        .collect();

    let mut function_samples: Vec<CodeFeatures> = Default::default();
    for function_address in function_addresses.iter() {
        let buf = pe.module.address_space.read_bytes(function_address - 4, 260);
        let buf = match buf {
            Ok(buf) => buf,
            Err(_) => continue,
        };

        let features = extract_features_for_data(&decoder, &buf);

        //debug!("features: {:?}", features);
        function_samples.push(features);
    }

    let mut insns: cfg::InstructionIndex = Default::default();
    for function_address in function_addresses.iter() {
        if let Err(_) = insns.build_index(&pe.module, *function_address) {
            continue;
        }
    }

    if let Ok(cfg) = cfg::CFG::from_instructions(&pe.module, insns) {
        for bb in cfg.basic_blocks.blocks_by_address.values() {
            if function_addresses.contains(&bb.address) {
                // don't consider the function entry as a negative case
                continue;
            }

            let buf = pe.module.address_space.read_bytes(bb.address - 4, 260);
            let buf = match buf {
                Ok(buf) => buf,
                Err(_) => continue,
            };

            let features = extract_features_for_data(&decoder, &buf);

            //debug!("features: {:?}", features);
            successor_samples.push(features);

            if successor_samples.len() >= SUCCESSOR_SAMPLES {
                break;
            }
        }
    }

    use smartcore::{
        linalg::basic::matrix::DenseMatrix,
        preprocessing::categorical::{OneHotEncoder, OneHotEncoderParams},
    };

    let mut data: Vec<Vec<f32>> = Default::default();

    log::info!("function_samples: {}", function_samples.len());
    data.extend(
        function_samples
            .iter()
            .map(|features| features.to_feature_vec().iter().map(|&v| v as f32).collect()),
    );

    log::info!("random_samples: {}", random_samples.len());
    data.extend(
        random_samples
            .iter()
            .map(|features| features.to_feature_vec().iter().map(|&v| v as f32).collect()),
    );

    log::info!("successor_samples: {}", successor_samples.len());
    data.extend(
        successor_samples
            .iter()
            .map(|features| features.to_feature_vec().iter().map(|&v| v as f32).collect()),
    );

    let x = DenseMatrix::from_2d_vec(&data);

    let encoder_params = OneHotEncoderParams::from_cat_idx(&CodeFeatures::cat_idx());
    // Infer number of categories from data and return a reusable encoder
    let encoder = OneHotEncoder::fit(&x, encoder_params).expect("failed to fit encoder");
    // Transform categorical to one-hot encoded (can transform similar)
    let oh_x = encoder
        .transform(&x)
        .expect("failed to transform categorical variables");

    let mut y: Vec<u8> = Default::default();
    for _ in 0..function_samples.len() {
        y.push(1);
    }
    for _ in 0..random_samples.len() {
        y.push(0);
    }
    for _ in 0..successor_samples.len() {
        y.push(0);
    }

    let (x_train, x_test, y_train, y_test) = train_test_split(&oh_x, &y, 0.2, true, None);

    let classifier = RandomForestClassifier::fit(
        &x_train,
        &y_train,
        RandomForestClassifierParameters::default()
            //.with_max_depth(4)
            .with_n_trees(2_000),
    )
    .expect("failed to train model");

    let y_hat = classifier.predict(&x_test).expect("failed to predict");

    {
        use smartcore::metrics::{ClassificationMetrics, Metrics};

        let y_test = y_test.iter().map(|&v| v as f32).collect::<Vec<_>>();
        let y_hat = y_hat.iter().map(|&v| v as f32).collect::<Vec<_>>();

        log::info!(
            "precision: {}",
            ClassificationMetrics::precision().get_score(&y_test, &y_hat)
        );
        log::info!("recall: {}", ClassificationMetrics::recall().get_score(&y_test, &y_hat));
        log::info!("f1: {}", ClassificationMetrics::f1(1.0).get_score(&y_test, &y_hat));
        log::info!(
            "auc: {}",
            ClassificationMetrics::roc_auc_score().get_score(&y_test, &y_hat)
        );
    }

    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::pe::{rf_code_references::*, Function},
        rsrc::*,
    };
    use anyhow::Result;

    #[test]
    fn push_function_pointer() -> Result<()> {
        // recognize a function pointer being pushed onto the stack
        // such as a call to CreateThread
        //
        // in this case, we have function sub_4010E0
        // that is referenced at 0x41FA0C:
        //
        // ```
        // mov     edi, [ebp+arg_0]
        // push    offset sub_40116C
        // push    offset sub_4010E0  ; @ 0x41FA0C
        // push    10h
        // push    4
        // lea     eax, [edi+8]
        // push    eax
        // call    ??_L@YGXPAXIHP6EX0@Z1@Z ;
        // ```
        crate::test::init_logging();

        let buf = get_buf(Rsrc::DED0);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let ptrs = find_pe_nonrelocated_executable_pointers(&pe)?;
        assert!(ptrs.contains(&0x4010E0));

        let existing = crate::analysis::pe::find_functions(&pe)?;
        assert!(!existing.contains(&Function::Local(0x4010E0)));

        let found = find_functions_by_pointers(&pe, existing)?;
        assert!(found.contains(&0x4010E0));

        Ok(())
    }
}
