#![allow(clippy::upper_case_acronyms)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Not,
};

use anyhow::Result;
use chrono;
use log::warn;
use prost::Message;

use crate::{
    analysis::{
        cfg::{self, flow::Flow, thunk::get_thunk_target},
        dis::{self, Target},
        pe::ImportedSymbol,
    },
    arch::Arch,
    aspace::AddressSpace,
    module::Permissions,
    util,
    workspace::{export::pb, FunctionFlags, Workspace},
    RVA, VA,
};

/// Deduplicated list of values.
///
/// As you add entries to the list, you get back the index,
/// which may be at the end if the value was new,
/// or somewhere earlier in the list, if it was seen before.
#[derive(Default)]
struct ValueIndex<T: std::hash::Hash + std::cmp::Eq + Clone> {
    values:               Vec<T>,
    value_index_by_value: HashMap<T, i32>,
}

impl<T: std::hash::Hash + std::cmp::Eq + Clone> ValueIndex<T> {
    /// Add the given value to the index,
    /// returning its position in the value list.
    fn add(&mut self, value: T) -> i32 {
        *self.value_index_by_value.entry(value.clone()).or_insert_with(|| {
            let index = self.values.len();
            self.values.push(value);
            index as i32
        })
    }
}

type StringIndex = ValueIndex<String>;
type ExpressionIndex = ValueIndex<pb::bin_export2::Expression>;
type OperandIndex = ValueIndex<pb::bin_export2::Operand>;

impl std::hash::Hash for pb::bin_export2::Expression {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.r#type.hash(state);
        self.symbol.hash(state);
        self.immediate.hash(state);
        self.parent_index.hash(state);
        self.is_relocation.hash(state);
    }
}

impl std::cmp::Eq for pb::bin_export2::Expression {}

impl std::hash::Hash for pb::bin_export2::Operand {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.expression_index.hash(state);
    }
}

impl std::cmp::Eq for pb::bin_export2::Operand {}

impl std::hash::Hash for pb::bin_export2::Mnemonic {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl std::cmp::Eq for pb::bin_export2::Mnemonic {}

struct MnemonicIndex {
    inner: ValueIndex<pb::bin_export2::Mnemonic>,
}

impl MnemonicIndex {
    fn add(&mut self, value: String) -> i32 {
        self.inner.add(pb::bin_export2::Mnemonic { name: Some(value) })
    }
}

impl Default for MnemonicIndex {
    fn default() -> MnemonicIndex {
        let mut index = MnemonicIndex {
            inner: ValueIndex::default(),
        };
        // Pre-populate the most common mnemonics,
        // via: https://www.strchr.com/x86_machine_code_statistics
        index.add("mov".to_string());
        index.add("push".to_string());
        index.add("call".to_string());
        index.add("cmp".to_string());
        index.add("add".to_string());
        index.add("pop".to_string());
        index.add("lea".to_string());
        index.add("test".to_string());

        index
    }
}

fn add_operator(
    expressions: &mut ExpressionIndex,
    expression_indexes: &mut Vec<i32>,
    symbol: &str,
    parent: i32,
) -> i32 {
    let expression = expressions.add(pb::bin_export2::Expression {
        r#type:        Some(pb::bin_export2::expression::Type::Operator.into()),
        symbol:        Some(symbol.into()),
        immediate:     None,
        parent_index:  Some(parent),
        is_relocation: Some(false),
    });
    expression_indexes.push(expression);
    expression
}

fn add_int(expressions: &mut ExpressionIndex, expression_indexes: &mut Vec<i32>, i: u64, parent: i32) -> i32 {
    let expression = expressions.add(pb::bin_export2::Expression {
        r#type:        Some(pb::bin_export2::expression::Type::ImmediateInt.into()),
        symbol:        None,
        immediate:     Some(i),
        parent_index:  Some(parent),
        is_relocation: Some(false),
    });
    expression_indexes.push(expression);
    expression
}

fn add_reg(
    expressions: &mut ExpressionIndex,
    expression_indexes: &mut Vec<i32>,
    reg: dis::zydis::Register,
    parent: i32,
) -> i32 {
    let expression = expressions.add(pb::bin_export2::Expression {
        r#type:        Some(pb::bin_export2::expression::Type::Register.into()),
        symbol:        reg.get_string().map(|v| v.to_string()),
        immediate:     None,
        parent_index:  Some(parent),
        is_relocation: Some(false),
    });
    expression_indexes.push(expression);
    expression
}

fn collect_instruction_call_targets(
    ws: &dyn Workspace,
    bb: &cfg::BasicBlock,
    insn_va: VA,
    vertex_index_by_address: &BTreeMap<u64, usize>,
    call_targets_by_basic_block: &mut BTreeMap<u64, Vec<u64>>,
) -> Vec<u64> {
    // The list of all functions (tail-)called by this instruction.
    let call_targets = ws
        .cfg()
        .flows
        .flows_by_src
        .get(&insn_va)
        .map(|flows| {
            flows
                .into_iter()
                .map(|&flow| match flow {
                    Flow::Fallthrough(va) => va,
                    Flow::Call(Target::Direct(va)) => va,
                    // If indirect, the VA is the address of the pointer,
                    // which might be, e.g., an import entry.
                    Flow::Call(Target::Indirect(va)) => va,
                    Flow::UnconditionalJump(Target::Direct(va)) => va,
                    // If indirect, the VA is the address of the pointer,
                    // which might be, e.g., a jump table entry.
                    Flow::UnconditionalJump(Target::Indirect(va)) => va,
                    Flow::ConditionalJump(va) => va,
                })
                .filter(|target| vertex_index_by_address.contains_key(target))
                .collect::<Vec<u64>>()
        })
        .unwrap_or_default();

    call_targets_by_basic_block
        .entry(bb.address)
        .or_default()
        .extend(call_targets.iter());

    call_targets
}

fn collect_instruction_references(
    ws: &dyn Workspace,
    instruction_index: usize,
    insn_va: u64,
    insn: &dis::zydis::DecodedInstruction,
    strings: &mut ValueIndex<String>,
    string_references: &mut Vec<pb::bin_export2::Reference>,
    data_references: &mut Vec<pb::bin_export2::DataReference>,
) {
    if dis::is_control_flow_instruction(insn).not() {
        for (i, op) in dis::get_operands(insn).enumerate() {
            if let Ok(Some(target)) = dis::get_operand_xref(ws.module(), insn_va, insn, op) {
                match target {
                    Target::Direct(target) => {
                        // Insert a string reference, *or* a data reference, but not both.
                        if let Ok(s) = ws.module().address_space.read_ascii(target, 4) {
                            let string_index = strings.add(s);
                            string_references.push(pb::bin_export2::Reference {
                                instruction_index:         Some(instruction_index as i32),
                                instruction_operand_index: Some(i as i32),
                                operand_expression_index:  None,
                                string_table_index:        Some(string_index),
                            });
                        } else {
                            data_references.push(pb::bin_export2::DataReference {
                                instruction_index: Some(instruction_index as i32),
                                address:           Some(target),
                            });
                        }
                    }
                    Target::Indirect(target) => {
                        if target == 0x0 {
                            // Skip null-pointer deferences,
                            // which `get_operand_xref` will provide for register operands.
                            continue;
                        }

                        data_references.push(pb::bin_export2::DataReference {
                            instruction_index: Some(instruction_index as i32),
                            address:           Some(target),
                        });

                        // try to deref the pointer
                        if let Ok(target) = ws.module().read_va_at_va(target) {
                            if ws.module().probe_va(target, Permissions::R) {
                                if let Ok(s) = ws.module().address_space.read_ascii(target, 4) {
                                    let string_index = strings.add(s);
                                    string_references.push(pb::bin_export2::Reference {
                                        instruction_index:         Some(instruction_index as i32),
                                        instruction_operand_index: Some(i as i32),
                                        operand_expression_index:  None,
                                        string_table_index:        Some(string_index),
                                    });
                                } else {
                                    data_references.push(pb::bin_export2::DataReference {
                                        instruction_index: Some(instruction_index as i32),
                                        address:           Some(target),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Collect functions found within the code of the program.
/// BinExport2 uses a Vertex to describe an element within the call graph.
/// Note that there is not necessarily disassembly/control flow graph associated
/// with a Vertex, such as an imported function.
fn collect_vertices(
    ws: &dyn Workspace,
    libraries: &[pb::bin_export2::Library],
) -> Vec<pb::bin_export2::call_graph::Vertex> {
    // Map from DLL name to library index,
    // so that we can link imported functions to the library entry.
    let library_index_by_name: BTreeMap<String, usize> = libraries
        .iter()
        .enumerate()
        .map(|(index, library)| (library.name.clone().unwrap(), index))
        .collect();

    let mut vertices = vec![];

    //
    // We'll do two passes:
    //
    //   1. recognized functions with code
    //   2. imported functions

    // Pass 1: Recognized functions with code.
    vertices.extend(ws.analysis().functions.iter().map(|(&address, f)| {
        pb::bin_export2::call_graph::Vertex {
            address:       Some(address),
            r#type:        Some(match f.flags.intersects(FunctionFlags::THUNK) {
                true => pb::bin_export2::call_graph::vertex::Type::Thunk.into(),
                false => pb::bin_export2::call_graph::vertex::Type::Normal.into(),
            }),
            mangled_name:  ws
                .analysis()
                .names
                .names_by_address
                .get(&address)
                .map(|v| v.to_string()),
            library_index: None,

            demangled_name: None,
            module_index:   None,
        }
    }));

    // Pass 2: Imported functions.
    vertices.extend(
        ws.analysis()
            .imports
            .iter()
            .map(|(&address, imp)| pb::bin_export2::call_graph::Vertex {
                address:       Some(address),
                r#type:        Some(pb::bin_export2::call_graph::vertex::Type::Imported.into()),
                mangled_name:  Some(match &imp.symbol {
                    ImportedSymbol::Ordinal(ord) => format!("#{}", ord),
                    ImportedSymbol::Name(name) => name.clone(),
                }),
                library_index: library_index_by_name.get(&imp.dll).map(|&v| v as i32),

                demangled_name: None,
                module_index:   None,
            }),
    );

    // BinExport2 requires that Vertices to be sorted by address.
    vertices.sort_by_key(|v| v.address.unwrap());

    vertices
}

fn collect_instruction_operands(
    ws: &dyn Workspace,
    insn_va: VA,
    insn: &dis::zydis::DecodedInstruction,
    expressions: &mut ValueIndex<pb::bin_export2::Expression>,
    operands: &mut ValueIndex<pb::bin_export2::Operand>,
) -> Vec<i32> {
    let mut operand_indexes: Vec<i32> = vec![];
    for op in dis::get_operands(insn) {
        let expression_indexes: Vec<i32> = match op.ty {
            dis::zydis::OperandType::UNUSED => {
                continue;
            }
            dis::zydis::OperandType::IMMEDIATE => {
                let v = if op.imm.is_signed {
                    util::u64_i64(op.imm.value) as u64
                } else {
                    op.imm.value
                };

                // TODO: how is FP handled? XMM?

                vec![expressions.add(pb::bin_export2::Expression {
                    r#type:        Some(pb::bin_export2::expression::Type::ImmediateInt.into()),
                    symbol:        None,
                    immediate:     Some(v),
                    parent_index:  None,
                    is_relocation: Some(false),
                })]
            }
            dis::zydis::OperandType::REGISTER => vec![expressions.add(pb::bin_export2::Expression {
                r#type:        Some(pb::bin_export2::expression::Type::Register.into()),
                symbol:        op.reg.get_string().map(|v| v.to_string()),
                immediate:     None,
                parent_index:  None,
                is_relocation: Some(false),
            })],
            dis::zydis::OperandType::MEMORY => {
                let mut expression_indexes: Vec<i32> = Default::default();
                let mut current_expression: Option<i32> = None;

                let psize_in_bits = ws.module().arch.pointer_size() * 8;

                let element_size = match op.element_size {
                    0 => None,
                    // skip the hint when it matches the architecture size,
                    // which I find to be too noisy.
                    element_size if element_size as usize == psize_in_bits => None,
                    8 => Some("byte".to_string()),
                    16 => Some("word".to_string()),
                    32 => Some("dword".to_string()),
                    64 => Some("qword".to_string()),
                    128 => Some("dqword".to_string()),
                    256 => Some("yword".to_string()),
                    512 => Some("zword".to_string()),
                    element_size => {
                        // fnsave uses 864
                        warn!("unexpected operand element size: {insn_va:#x}: {element_size}");
                        None
                    }
                };

                if let Some(element_size) = element_size {
                    current_expression = Some(expressions.add(pb::bin_export2::Expression {
                        r#type:        Some(pb::bin_export2::expression::Type::SizePrefix.into()),
                        symbol:        Some(element_size),
                        immediate:     None,
                        parent_index:  None,
                        is_relocation: Some(false),
                    }));
                    expression_indexes.push(current_expression.unwrap());
                }

                if op.mem.segment != dis::zydis::Register::NONE {
                    // like dis::zydis::Register:DS

                    let reg_name = op.mem.segment.get_string().expect("reg has no name");
                    let reg_name = reg_name.to_lowercase();
                    let symbol = format!("{reg_name}:");

                    current_expression = Some(expressions.add(pb::bin_export2::Expression {
                        r#type:        Some(pb::bin_export2::expression::Type::Operator.into()),
                        symbol:        Some(symbol),
                        immediate:     None,
                        parent_index:  current_expression,
                        is_relocation: Some(false),
                    }));
                    expression_indexes.push(current_expression.unwrap());
                }

                current_expression = Some(expressions.add(pb::bin_export2::Expression {
                    r#type:        Some(pb::bin_export2::expression::Type::Dereference.into()),
                    symbol:        Some("[".into()),
                    immediate:     None,
                    parent_index:  current_expression,
                    is_relocation: Some(false),
                }));
                expression_indexes.push(current_expression.unwrap());

                // base + (index * scale) + disp
                let has_base = op.mem.base != dis::zydis::Register::NONE;
                let has_index = op.mem.index != dis::zydis::Register::NONE;
                let has_scale = op.mem.scale != 0;
                let has_disp = op.mem.disp.has_displacement;

                match (has_base, has_index, has_scale, has_disp) {
                    // ```
                    // ds:[eax+ebx*2+0xC]
                    //      \   \ /   /
                    //       \   *   /    C
                    //        \ /   /
                    //         +   /      B
                    //          \ /
                    //           +        A
                    //
                    // ds:[eax+ebx*2-0xC]
                    //      \   \ /   /
                    //       \   *   /    C
                    //        \ /   /
                    //         +   /      B
                    //          \ /
                    //           -        A
                    // ```
                    (true, true, true, true) => {
                        let (a_sym, disp) = if op.mem.disp.displacement < 0 {
                            ("-", -op.mem.disp.displacement as u64)
                        } else {
                            ("+", op.mem.disp.displacement as u64)
                        };

                        let a_expr =
                            add_operator(expressions, &mut expression_indexes, a_sym, current_expression.unwrap());
                        let b_expr = add_operator(expressions, &mut expression_indexes, "+", a_expr);

                        add_reg(expressions, &mut expression_indexes, op.mem.base, b_expr);

                        let c_expr = add_operator(expressions, &mut expression_indexes, "*", b_expr);

                        add_reg(expressions, &mut expression_indexes, op.mem.index, c_expr);
                        add_int(expressions, &mut expression_indexes, 1 << op.mem.scale, c_expr);

                        add_int(expressions, &mut expression_indexes, disp, a_expr);
                    }

                    // ```
                    // ds:[eax+ebx+0xC]
                    //        \ /   /
                    //         +   /      B
                    //          \ /
                    //           +        A
                    //
                    // ds:[eax+ebx-0xC]
                    //        \ /   /
                    //         +   /      B
                    //          \ /
                    //           -        A
                    // ```
                    (true, true, false, true) => {
                        let (a_sym, disp) = if op.mem.disp.displacement < 0 {
                            ("-", -op.mem.disp.displacement as u64)
                        } else {
                            ("+", op.mem.disp.displacement as u64)
                        };

                        let a_expr =
                            add_operator(expressions, &mut expression_indexes, a_sym, current_expression.unwrap());
                        let b_expr = add_operator(expressions, &mut expression_indexes, "+", a_expr);

                        add_reg(expressions, &mut expression_indexes, op.mem.base, b_expr);
                        add_reg(expressions, &mut expression_indexes, op.mem.index, b_expr);
                        add_int(expressions, &mut expression_indexes, disp, a_expr);
                    }

                    // ```
                    // ds:[eax+ebx*2]
                    //      \   \ /
                    //       \   *        B
                    //        \ /
                    //         +          A
                    // ```
                    (true, true, true, false) => {
                        let a_expr =
                            add_operator(expressions, &mut expression_indexes, "+", current_expression.unwrap());
                        add_reg(expressions, &mut expression_indexes, op.mem.base, a_expr);
                        let b_expr = add_operator(expressions, &mut expression_indexes, "*", a_expr);
                        add_reg(expressions, &mut expression_indexes, op.mem.index, b_expr);
                        add_int(expressions, &mut expression_indexes, 1 << op.mem.scale, b_expr);
                    }

                    // ```
                    // ds:[eax+ebx]
                    //      \ /
                    //       +       A
                    // ```
                    (true, true, false, false) => {
                        let a_expr =
                            add_operator(expressions, &mut expression_indexes, "+", current_expression.unwrap());
                        add_reg(expressions, &mut expression_indexes, op.mem.base, a_expr);
                        add_reg(expressions, &mut expression_indexes, op.mem.index, a_expr);
                    }

                    // ds:[eax]
                    (true, false, false, false) => {
                        add_reg(
                            expressions,
                            &mut expression_indexes,
                            op.mem.base,
                            current_expression.unwrap(),
                        );
                    }

                    // ds:[ebx]
                    (false, true, false, false) => {
                        add_reg(
                            expressions,
                            &mut expression_indexes,
                            op.mem.index,
                            current_expression.unwrap(),
                        );
                    }

                    // ```
                    // ds:[ebx*2]
                    //      \ /
                    //       *     A
                    // ```
                    (false, true, true, false) => {
                        let a_expr =
                            add_operator(expressions, &mut expression_indexes, "*", current_expression.unwrap());
                        add_reg(expressions, &mut expression_indexes, op.mem.index, a_expr);
                        add_int(expressions, &mut expression_indexes, 1 << op.mem.scale, a_expr);
                    }

                    // ds:[0x401000]
                    (false, false, false, true) => {
                        add_int(
                            expressions,
                            &mut expression_indexes,
                            util::i64_u64(op.mem.disp.displacement),
                            current_expression.unwrap(),
                        );
                    }

                    // ```
                    // ds:[ebx*2+0xC]
                    //      \ /   /
                    //       *   /    B
                    //        \ /
                    //         +      A
                    //
                    // ds:[ebx*2-0xC]
                    //      \ /   /
                    //       *   /    B
                    //        \ /
                    //         -      A
                    // ```
                    (false, true, true, true) => {
                        let (a_sym, disp) = if op.mem.disp.displacement < 0 {
                            ("-", -op.mem.disp.displacement as u64)
                        } else {
                            ("+", op.mem.disp.displacement as u64)
                        };

                        let a_expr =
                            add_operator(expressions, &mut expression_indexes, a_sym, current_expression.unwrap());
                        let b_expr = add_operator(expressions, &mut expression_indexes, "*", a_expr);
                        add_reg(expressions, &mut expression_indexes, op.mem.index, b_expr);
                        add_int(expressions, &mut expression_indexes, 1 << op.mem.scale, b_expr);
                        add_int(expressions, &mut expression_indexes, disp, a_expr);
                    }

                    // ```
                    // ds:[ebx+0xC]
                    //      \ /
                    //       +       A
                    //
                    // ds:[ebx-0xC]
                    //      \ /
                    //       -       A
                    // ```
                    (false, true, false, true) => {
                        let (a_sym, disp) = if op.mem.disp.displacement < 0 {
                            ("-", -op.mem.disp.displacement as u64)
                        } else {
                            ("+", op.mem.disp.displacement as u64)
                        };

                        let a_expr =
                            add_operator(expressions, &mut expression_indexes, a_sym, current_expression.unwrap());
                        add_reg(expressions, &mut expression_indexes, op.mem.index, a_expr);
                        add_int(expressions, &mut expression_indexes, disp, a_expr);
                    }

                    // ```
                    // ds:[ebx+0xC]
                    //      \ /
                    //       +       A
                    //
                    // ds:[ebx-0xC]
                    //      \ /
                    //       -       A
                    // ```
                    (true, false, false, true) => {
                        let (a_sym, disp) = if op.mem.disp.displacement < 0 {
                            ("-", -op.mem.disp.displacement as u64)
                        } else {
                            ("+", op.mem.disp.displacement as u64)
                        };

                        let a_expr =
                            add_operator(expressions, &mut expression_indexes, a_sym, current_expression.unwrap());
                        add_reg(expressions, &mut expression_indexes, op.mem.base, a_expr);
                        add_int(expressions, &mut expression_indexes, disp, a_expr);
                    }

                    (_, false, true, _) => unimplemented!("scale with no index"),

                    (false, false, false, false) => unimplemented!("no terms"),
                };

                expression_indexes
            }
            // Lancelot doesn't support this operand type in its analysis
            // so we also don't know what to do here.
            dis::zydis::OperandType::POINTER => {
                warn!("unsupported: pointer operand: 0x{insn_va:x}");
                Default::default()
            }
        };

        let operand_index = operands.add(pb::bin_export2::Operand {
            expression_index: expression_indexes,
        });

        operand_indexes.push(operand_index);
    }
    operand_indexes
}

fn collect_flow_graphs(
    ws: &dyn Workspace,
    basic_block_index_by_address: BTreeMap<u64, usize>,
) -> Vec<pb::bin_export2::FlowGraph> {
    let flow_graphs: Vec<_> = ws
        .analysis()
        .functions
        .iter()
        // there isn't control flow found at the function's address.
        .filter(|(address, _)| basic_block_index_by_address.contains_key(address))
        .map(|(&address, f)| {
            if f.flags.intersects(FunctionFlags::THUNK) {
                let block_index = *basic_block_index_by_address.get(&address).unwrap() as i32;
                return pb::bin_export2::FlowGraph {
                    basic_block_index:       vec![block_index],
                    entry_basic_block_index: Some(block_index),
                    edge:                    vec![],
                };
            }

            let mut block_addresses = ws
                .cfg()
                .get_reaches_from(address)
                .map(|bb| bb.address)
                .collect::<Vec<_>>();
            block_addresses.sort();

            let block_indices = block_addresses
                .iter()
                .map(|&address| *basic_block_index_by_address.get(&address).unwrap() as i32)
                .collect::<Vec<_>>();

            let entry_block_index = *basic_block_index_by_address.get(&address).unwrap() as i32;

            let mut edges: Vec<pb::bin_export2::flow_graph::Edge> = vec![];
            for block in ws.cfg().get_reaches_from(address) {
                let source_block_index = *basic_block_index_by_address.get(&block.address).unwrap();
                edges.extend(
                    ws.cfg()
                        .flows
                        .flows_by_src
                        .get(&block.address_of_last_insn)
                        .map(|flows| {
                            flows
                                .into_iter()
                                .filter(|flow| !matches!(flow, Flow::Call(_)))
                                .map(|&flow| match flow {
                                    Flow::Fallthrough(va) => {
                                        if flows.len() == 1 {
                                            (va, pb::bin_export2::flow_graph::edge::Type::Unconditional)
                                        } else {
                                            (va, pb::bin_export2::flow_graph::edge::Type::ConditionFalse)
                                        }
                                    }
                                    Flow::ConditionalJump(va) => {
                                        (va, pb::bin_export2::flow_graph::edge::Type::ConditionTrue)
                                    }
                                    Flow::UnconditionalJump(Target::Direct(va)) => {
                                        (va, pb::bin_export2::flow_graph::edge::Type::Unconditional)
                                    }
                                    Flow::UnconditionalJump(Target::Indirect(va)) => {
                                        (va, pb::bin_export2::flow_graph::edge::Type::Switch)
                                    }

                                    Flow::Call(_) => unreachable!(),
                                })
                                .filter(|(target, _)| basic_block_index_by_address.contains_key(target))
                                .map(|(target, r#type)| pb::bin_export2::flow_graph::Edge {
                                    source_basic_block_index: Some(source_block_index as i32),
                                    target_basic_block_index: Some(
                                        *basic_block_index_by_address.get(&target).unwrap() as i32
                                    ),
                                    r#type:                   Some(r#type.into()),
                                    is_back_edge:             None, // TODO
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                );
            }

            pb::bin_export2::FlowGraph {
                basic_block_index:       block_indices,
                entry_basic_block_index: Some(entry_block_index),
                edge:                    edges,
            }
        })
        .collect();
    flow_graphs
}

fn collect_call_graphs(
    ws: &dyn Workspace,
    vertexes: Vec<pb::bin_export2::call_graph::Vertex>,
    vertex_index_by_address: BTreeMap<u64, usize>,
    call_targets_by_basic_block: BTreeMap<u64, Vec<u64>>,
) -> pb::bin_export2::CallGraph {
    let mut call_graph_edges: BTreeSet<(usize, usize)> = Default::default();
    let functions = ws.analysis().functions.iter();
    for (&function_address, &anal) in functions {
        if let Some(&source_vertex_index) = vertex_index_by_address.get(&function_address) {
            if anal.flags.intersects(FunctionFlags::THUNK) {
                // For a thunk, which looks like `jmp sub_401000`, we add a call graph edge.
                // (Even though we don't see a `call` instruction. But this is like a tail
                // call.)
                if let Some(target) = get_thunk_target(ws.cfg(), function_address) {
                    if let Some(&target_vertex_index) = vertex_index_by_address.get(&target) {
                        call_graph_edges.insert((source_vertex_index, target_vertex_index));
                    } else {
                        warn!("no vertex for address 0x{target:x}");
                    }
                } else {
                    warn!("no thunk target for thunk at 0x{function_address:x}");
                }
            } else {
                for block in ws.cfg().get_reaches_from(function_address) {
                    for target in call_targets_by_basic_block.get(&block.address).unwrap_or(&vec![]) {
                        if let Some(&target_vertex_index) = vertex_index_by_address.get(target) {
                            call_graph_edges.insert((source_vertex_index, target_vertex_index));
                        }
                    }
                }
            }
        } else {
            warn!("no vertex for address 0x{function_address:x}");
        }
    }

    pb::bin_export2::CallGraph {
        vertex: vertexes,
        edge:   call_graph_edges
            .into_iter()
            .map(|(source, target)| pb::bin_export2::call_graph::Edge {
                source_vertex_index: Some(source as i32),
                target_vertex_index: Some(target as i32),
            })
            .collect(),
    }
}

pub fn export_workspace_to_binexport2(
    ws: &dyn Workspace,
    sha256: String,
    executable_name: Option<String>,
) -> Result<Vec<u8>> {
    let meta = pb::bin_export2::Meta {
        executable_name,

        executable_id: Some(sha256),

        // This enum isn't codified, so do what the IDA plugin does.
        // See: https://github.com/google/binexport/issues/114
        architecture_name: Some(match ws.module().arch {
            Arch::X32 => "x86-32".to_string(),
            Arch::X64 => "x86-64".to_string(),
        }),

        timestamp: Some(chrono::Utc::now().timestamp()),
    };

    let sections = ws
        .module()
        .sections
        .iter()
        .map(|section| pb::bin_export2::Section {
            address: Some(section.virtual_range.start),
            size:    Some(section.virtual_range.end - section.virtual_range.start),
            flag_r:  Some(section.permissions.intersects(Permissions::R)),
            flag_w:  Some(section.permissions.intersects(Permissions::W)),
            flag_x:  Some(section.permissions.intersects(Permissions::X)),
        })
        .collect();

    // Record imported DLLs as library entries.
    let libraries = ws
        .analysis()
        .imports
        .values()
        .map(|import| import.dll.clone())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .map(|dll| pb::bin_export2::Library {
            name:         Some(dll),
            is_static:    Some(false),
            load_address: None,
        })
        .collect::<Vec<pb::bin_export2::Library>>();

    let vertices = collect_vertices(ws, &libraries);

    // Map from function address to Vertex index.
    // Used for checking if an address is a function, for example.
    let vertex_index_by_address: BTreeMap<u64, usize> = vertices
        .iter()
        .enumerate()
        .map(|(index, vertex)| (vertex.address.unwrap(), index))
        .collect();

    let mut mnemonics = MnemonicIndex::default();

    let mut expressions = ExpressionIndex::default();

    let mut operands = OperandIndex::default();

    let mut instructions: Vec<pb::bin_export2::Instruction> = Vec::with_capacity(ws.cfg().insns.insns_by_address.len());

    let mut basic_blocks: Vec<pb::bin_export2::BasicBlock> =
        Vec::with_capacity(ws.cfg().basic_blocks.blocks_by_address.len());

    let mut basic_block_index_by_address: BTreeMap<u64, usize> = Default::default();

    // The list of all functions (tail-)called by each basic block.
    // Subsequently aggregated by function and used to construct
    // the call graph, linking Vertex to Vertex.
    let mut call_targets_by_basic_block: BTreeMap<u64, Vec<u64>> = Default::default();

    let mut data_references: Vec<pb::bin_export2::DataReference> = Default::default();

    let mut strings = StringIndex::default();

    let mut string_references: Vec<pb::bin_export2::Reference> = Default::default();

    let decoder = dis::get_disassembler(ws.module()).unwrap();
    for bb in ws.cfg().basic_blocks.blocks_by_address.values() {
        // Need to over-read the bb buffer, to account for the final instructions.
        let buf = ws
            .module()
            .address_space
            .read_bytes(bb.address, bb.length as usize + 0x10)?;

        let mut instruction_indexes: Vec<usize> = vec![];

        for (offset, insn) in dis::linear_disassemble(&decoder, &buf) {
            // Because we over-read the bb buffer,
            // discard the instructions found after it.
            if offset >= bb.length as usize {
                break;
            }

            if let Ok(Some(insn)) = insn {
                let va = bb.address + offset as RVA;
                let instruction_index = instructions.len();

                let instruction_call_targets = collect_instruction_call_targets(
                    ws,
                    bb,
                    va,
                    &vertex_index_by_address,
                    &mut call_targets_by_basic_block,
                );

                let mnemonic_index = mnemonics.add(insn.mnemonic.get_string().unwrap().to_string());

                collect_instruction_references(
                    ws,
                    instruction_index,
                    va,
                    &insn,
                    &mut strings,
                    &mut string_references,
                    &mut data_references,
                );

                let operand_indexes = collect_instruction_operands(ws, va, &insn, &mut expressions, &mut operands);

                instructions.push(pb::bin_export2::Instruction {
                    address:        if offset == 0 { Some(va) } else { None },
                    call_target:    instruction_call_targets,
                    mnemonic_index: Some(mnemonic_index),
                    operand_index:  operand_indexes,
                    raw_bytes:      Some(buf[offset..offset + insn.length as usize].into()),
                    comment_index:  vec![],
                });

                instruction_indexes.push(instruction_index);
            }
        }

        let index_range = pb::bin_export2::basic_block::IndexRange {
            begin_index: Some(*instruction_indexes.first().unwrap() as i32),
            end_index:   if instruction_indexes.len() > 1 {
                Some((*instruction_indexes.last().unwrap() + 1) as i32)
            } else {
                None
            },
        };

        basic_blocks.push(pb::bin_export2::BasicBlock {
            instruction_index: vec![index_range],
        });
        basic_block_index_by_address.insert(bb.address, basic_blocks.len() - 1);
    }

    let flow_graphs = collect_flow_graphs(ws, basic_block_index_by_address);

    let call_graph = collect_call_graphs(ws, vertices, vertex_index_by_address, call_targets_by_basic_block);

    #[allow(deprecated)]
    let be2 = pb::BinExport2 {
        meta_information: Some(meta),
        section: sections,
        library: libraries,
        mnemonic: mnemonics.inner.values,
        expression: expressions.values,
        operand: operands.values,
        instruction: instructions,
        basic_block: basic_blocks,
        flow_graph: flow_graphs,
        call_graph: Some(call_graph),
        data_reference: data_references,
        string_reference: string_references,
        string_table: strings.values,
        // We don't record user comments, so this is empty.
        comment: vec![],
        #[allow(deprecated)]
        address_comment: vec![],
        // Stores substitutions for subtrees within expressions,
        // like when IDA recognizes a stack variable and gives it a name.
        // Since we don't do that sort of analysis here, this is empty.
        expression_substitution: vec![],
        // Names, such as Java class names. Not relevant for native code analysis.
        module: vec![],
    };

    let out = {
        let mut buf = Vec::with_capacity(be2.encoded_len());
        // Unwrap is safe, since we have reserved sufficient capacity in the vector.
        be2.encode(&mut buf).unwrap();
        buf
    };

    Ok(out)
}
