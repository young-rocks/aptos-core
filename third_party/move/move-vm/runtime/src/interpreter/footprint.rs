use std::{collections::BTreeMap, sync::Arc};

use move_binary_format::{
    errors::PartialVMResult, file_format::Bytecode, file_format_common::Opcodes,
    internals::ModuleIndex,
};
use move_vm_types::values::{IntegerValue, StructRef, Value, VectorRef, VMValueCast};

use crate::{
    interpreter::{Frame, Interpreter},
    loader::{Function, Resolver},
    witnessing::{
        BinaryIntegerOperationType,
        CallerInfo, EntryCall, Footprint, Operation, traced_value::{Integer, Reference, TracedValue, TracedValueBuilder},
    },
};

#[derive(Default, Clone)]
pub(crate) struct Footprints {
    state: FootprintState,
    pub data: Vec<Footprint>,
}

#[derive(Default, Clone)]
pub(crate) struct FootprintState {
    // frame_index -> (local_index -> addressing)
    local_value_addressings: BTreeMap<usize, BTreeMap<usize, BTreeMap<usize, Vec<usize>>>>,
    // raw_address -> (frame_index, local_index, sub_index)
    reverse_local_value_addressings: BTreeMap<usize, Reference>,
}

impl FootprintState {
    fn add_local(
        &mut self,
        frame_index: usize,
        local_index: usize,
        sub_indexes: BTreeMap<usize, Vec<usize>>,
    ) {
        let _ = self
            .local_value_addressings
            .entry(frame_index)
            .or_default()
            .insert(local_index, sub_indexes.clone());
        for (raw_address, sub_index) in sub_indexes {
            self.reverse_local_value_addressings.insert(
                raw_address,
                Reference::new(frame_index, local_index, sub_index),
            );
        }
    }

    fn remove_local(&mut self, frame_index: usize, local_index: usize) {
        self.local_value_addressings
            .entry(frame_index)
            .or_default()
            .remove(&local_index);
        // delete any in (frame_index, local_index)
        self.reverse_local_value_addressings
            .retain(|_k, v| !(v.frame_index == frame_index && v.local_index == local_index));
    }

    fn remove_locals(&mut self, frame_index: usize) {
        self.local_value_addressings.remove(&frame_index);
        self.reverse_local_value_addressings
            .retain(|_k, v| v.frame_index != frame_index);
    }
}

pub(crate) fn footprint_args_processing(function: &Arc<Function>, args: &Vec<Value>, footprints: &mut Footprints) {
    let module_id = function.module_id();
    let function_index = function.index().into_index();
    let mut values = Vec::new();
    for (i, value) in args.into_iter().enumerate() {
        let TracedValue {
            items: value_items,
            container_sub_indexes: value_indexes,
        } = TracedValueBuilder::new(value)
            .build(&footprints.state.reverse_local_value_addressings);
        footprints.state.add_local(0, i, value_indexes);
        values.push(value_items);
    }
    footprints.data.push(Footprint {
        op: 0,
        module_id: None,
        function_id: 0,
        pc: 0,
        frame_index: 0,
        stack_pointer: 0,
        aux0: None,
        aux1: None,
        data: Operation::Start {
            entry_call: EntryCall {
                module_id: module_id.cloned(),
                function_index,
                args: values,
            },
        },
    });
}

#[macro_export]
macro_rules! footprint {
    ($frame:expr, $instr:tt, $resolver:expr, $interp:expr, $footprints:expr) => {
        // only do footprint when the feature enabled
        $crate::interpreter::footprint::footprinting($frame, $instr, $resolver, $interp, $footprints)
    };
}

pub(crate) fn footprinting(
    frame: &mut Frame,
    instr: &Bytecode,
    resolver: &Resolver,
    interp: &mut Interpreter,
    footprints: &mut Footprints,
) -> PartialVMResult<()> {
    let function_desc = &frame.function;
    let locals = &frame.locals;
    let pc = frame.pc;

    let frame_index = interp.call_stack.0.len();
    let module_id = function_desc.module_id().cloned();
    let function_index = function_desc.index();
    let stack_pointer = interp.operand_stack.value.len();

    let _caller_frame = interp.call_stack.0.last();

    let operation = match instr {
        Bytecode::Pop => {
            let val = interp.operand_stack.last_n(1)?.last().unwrap();
            Operation::Pop {
                poped_value: TracedValueBuilder::new(val)
                    .build_as_plain_value()
                    .unwrap()
                    .items,
            }
        },
        Bytecode::Ret => {
            let caller = _caller_frame.map(|caller| CallerInfo {
                frame_index: frame_index - 1,
                module_id: caller.function.module_id().cloned(),
                function_id: caller.function.index().into_index(),
                pc: caller.pc,
            });
            footprints.state.remove_locals(frame_index);
            Operation::Ret { caller }
        },
        Bytecode::BrTrue(offset) => {
            let val = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()
                .unwrap()
                .value_as()?;
            Operation::BrTrue {
                cond_val: val,
                code_offset: *offset,
            }
        },
        Bytecode::BrFalse(offset) => {
            let val = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .cast()?;
            Operation::BrFalse {
                cond_val: val,
                code_offset: *offset,
            }
        },
        Bytecode::Branch(offset) => Operation::Branch(*offset),
        Bytecode::LdU8(v) => Operation::LdSimple(Integer::U8(*v)),
        Bytecode::LdU64(v) => Operation::LdSimple(Integer::U64(*v)),
        Bytecode::LdU128(v) => Operation::LdSimple(Integer::U128(*v)),
        Bytecode::LdU16(v) => Operation::LdSimple(Integer::U16(*v)),
        Bytecode::LdU32(v) => Operation::LdSimple(Integer::U32(*v)),
        Bytecode::LdU256(v) => Operation::LdSimple(Integer::U256(*v)),
        Bytecode::LdTrue => Operation::LdTrue,
        Bytecode::LdFalse => Operation::LdFalse,
        Bytecode::LdConst(idx) => Operation::LdConst {
            const_pool_index: idx.0,
        },

        Bytecode::CastU8 => {
            let val: IntegerValue = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .value_as()?;
            Operation::CastU8 { origin: val.into() }
        },
        Bytecode::CastU64 => {
            let val: IntegerValue = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .value_as()?;
            Operation::CastU64 { origin: val.into() }
        },
        Bytecode::CastU128 => {
            let val: IntegerValue = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .value_as()?;
            Operation::CastU128 { origin: val.into() }
        },
        Bytecode::CastU16 => {
            let val: IntegerValue = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .value_as()?;
            Operation::CastU16 { origin: val.into() }
        },
        Bytecode::CastU32 => {
            let val: IntegerValue = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .value_as()?;
            Operation::CastU32 { origin: val.into() }
        },
        Bytecode::CastU256 => {
            let val: IntegerValue = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .value_as()?;
            Operation::CastU256 { origin: val.into() }
        },
        Bytecode::CopyLoc(idx) => {
            let local = locals.copy_loc(*idx as usize)?;
            Operation::CopyLoc {
                local_index: *idx,
                local: TracedValueBuilder::new(&local)
                    .build(&footprints.state.reverse_local_value_addressings)
                    .items,
            }
        },
        Bytecode::MoveLoc(idx) => {
            footprints
                .state
                .remove_local(frame_index, *idx as usize);
            let local = locals.copy_loc(*idx as usize)?;
            Operation::MoveLoc {
                local_index: *idx,
                local: TracedValueBuilder::new(&local)
                    .build(&footprints.state.reverse_local_value_addressings)
                    .items,
            }
        },
        Bytecode::StLoc(idx) => {
            let new_value = interp.operand_stack.last_n(1)?.last().unwrap();
            let new_value = TracedValueBuilder::new(&new_value)
                .build(&footprints.state.reverse_local_value_addressings);

            footprints
                .state
                .remove_local(frame_index, *idx as usize);
            // value stored to loc only have 1 reference on it
            // so we can hook here to index every sub items by it rc-ptr.
            footprints.state.add_local(
                frame_index,
                *idx as usize,
                new_value.container_sub_indexes,
            );
            let old_local = if locals.is_invalid(*idx as usize)? {
                None
            } else {
                Some(locals.copy_loc(*idx as usize)?)
            };

            Operation::StLoc {
                local_index: *idx,
                old_local: old_local.map(|v| {
                    TracedValueBuilder::new(&v)
                        .build(&footprints.state.reverse_local_value_addressings)
                        .items
                }),
                new_value: new_value.items,
            }
        },
        Bytecode::Call(fh_idx) => {
            let func = resolver.function_from_handle(*fh_idx)?;
            Operation::Call {
                fh_idx: fh_idx.0,
                args: interp
                    .operand_stack
                    .last_n(func.param_count())?
                    .map(|t| TracedValueBuilder::new(t).build(&footprints.state.reverse_local_value_addressings).items)
                    .collect::<Vec<_>>(),
            }
        },
        Bytecode::CallGeneric(fh_idx) => {
            let func = resolver.function_from_instantiation(*fh_idx)?;

            Operation::CallGeneric {
                fh_idx: fh_idx.0,
                args: interp
                    .operand_stack
                    .last_n(func.param_count())?
                    .map(|t| TracedValueBuilder::new(t).build(&footprints.state.reverse_local_value_addressings).items)
                    .collect::<Vec<_>>(),
            }
        },
        Bytecode::Pack(sd_idx) => {
            let field_count = resolver.field_count(*sd_idx);

            Operation::Pack {
                sd_idx: sd_idx.0,
                num: field_count as u64,
                args: interp
                    .operand_stack
                    .last_n(field_count as usize)?
                    .map(|t| TracedValueBuilder::new(t).build(&footprints.state.reverse_local_value_addressings).items)
                    .collect::<Vec<_>>(),
            }
        },
        Bytecode::PackGeneric(si_idx) => {
            let field_count = resolver.field_instantiation_count(*si_idx);
            Operation::PackGeneric {
                si_idx: si_idx.0,
                num: field_count as u64,
                args: interp
                    .operand_stack
                    .last_n(field_count as usize)?
                    .map(|t| TracedValueBuilder::new(t).build(&footprints.state.reverse_local_value_addressings).items)
                    .collect::<Vec<_>>(),
            }
        },
        Bytecode::Unpack(sd_idx) => {
            let field_count = resolver.field_count(*sd_idx);
            Operation::Unpack {
                sd_idx: sd_idx.0,
                num: field_count as u64,
                arg: interp
                    .operand_stack
                    .last_n(1)?
                    .last()
                    .map(|t| TracedValueBuilder::new(t).build(&footprints.state.reverse_local_value_addressings).items)
                    .unwrap(),
            }
        },
        Bytecode::UnpackGeneric(sd_idx) => {
            let field_count = resolver.field_instantiation_count(*sd_idx);
            Operation::UnpackGeneric {
                sd_idx: sd_idx.0,
                num: field_count as u64,
                arg: interp
                    .operand_stack
                    .last_n(1)?
                    .last()
                    .map(|t| TracedValueBuilder::new(t).build(&footprints.state.reverse_local_value_addressings).items)
                    .unwrap(),
            }
        },
        Bytecode::ReadRef => {
            let reference_value = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?;
            let reference = TracedValueBuilder::new(&reference_value).build_as_reference(&footprints.state.reverse_local_value_addressings).unwrap();
            let value = reference_value
                .value_as::<move_vm_types::values::Reference>()?
                .read_ref()?;

            Operation::ReadRef {
                reference,
                value: TracedValueBuilder::new(&value).build_as_plain_value().unwrap().items,
            }
        },
        Bytecode::WriteRef => {
            let reference_value = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?;

            let reference = TracedValueBuilder::new(&reference_value).build_as_reference(&footprints.state.reverse_local_value_addressings).unwrap();

            let old_value = reference_value
                .value_as::<move_vm_types::values::Reference>()?
                .read_ref()?;

            let new_value = interp
                .operand_stack
                .last_n(2)?
                .next()
                .unwrap()
                .copy_value()?;
            Operation::WriteRef {
                reference,
                old_value: TracedValueBuilder::new(&old_value).build_as_plain_value().unwrap().items,
                new_value: TracedValueBuilder::new(&new_value).build_as_plain_value().unwrap().items,
            }
        },
        Bytecode::FreezeRef => Operation::FreezeRef,
        Bytecode::MutBorrowLoc(idx) => Operation::BorrowLoc {
            imm: false,
            local_index: *idx,
            // reference: Reference::new(frame_index, *idx as usize, vec![0]),
        },
        Bytecode::ImmBorrowLoc(idx) => Operation::BorrowLoc {
            imm: true,
            local_index: *idx,
            // not need, as outside can build the reference themselves
            // reference: Reference::new(frame_index, *idx as usize, vec![0]), // TODO: should add 0 or not
        },
        Bytecode::MutBorrowField(fh_idx) => {
            let reference: StructRef = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .cast()?;
            let addr = reference.raw_address();
            let reference = footprints
                .state
                .reverse_local_value_addressings
                .get(&addr)
                .cloned()
                .expect("index by ptr ok");
            let offset = resolver.field_offset(*fh_idx);
            Operation::BorrowField {
                fh_idx: fh_idx.0,
                imm: false,
                reference,
                field_offset: offset,
            }
        },
        Bytecode::MutBorrowFieldGeneric(fi_idx) => {
            let reference: StructRef = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .cast()?;
            let addr = reference.raw_address();
            let reference = footprints
                .state
                .reverse_local_value_addressings
                .get(&addr)
                .cloned()
                .expect("index by ptr ok");
            let offset = resolver.field_instantiation_offset(*fi_idx);
            Operation::BorrowFieldGeneric {
                fi_idx: fi_idx.0,
                imm: false,
                reference,
                field_offset: offset,
            }
        },
        Bytecode::ImmBorrowField(fh_idx) => {
            let reference: StructRef = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .cast()?;
            let addr = reference.raw_address();

            let offset = resolver.field_offset(*fh_idx);
            Operation::BorrowField {
                fh_idx: fh_idx.0,
                imm: true,
                reference: footprints
                    .state
                    .reverse_local_value_addressings
                    .get(&addr)
                    .cloned()
                    .expect("index by ptr ok"),
                field_offset: offset,
            }
        },
        Bytecode::ImmBorrowFieldGeneric(fi_idx) => {
            let reference: StructRef = interp
                .operand_stack
                .last_n(1)?
                .last()
                .unwrap()
                .copy_value()?
                .cast()?;
            let addr = reference.raw_address();
            let reference = footprints
                .state
                .reverse_local_value_addressings
                .get(&addr)
                .cloned()
                .expect("index by ptr ok");
            let offset = resolver.field_instantiation_offset(*fi_idx);
            Operation::BorrowFieldGeneric {
                fi_idx: fi_idx.0,
                imm: true,
                reference,
                field_offset: offset,
            }
        },
        Bytecode::Add
        | Bytecode::Sub
        | Bytecode::Mul
        | Bytecode::Mod
        | Bytecode::Div
        | Bytecode::BitOr
        | Bytecode::BitAnd
        | Bytecode::Xor
        | Bytecode::Lt
        | Bytecode::Gt
        | Bytecode::Le
        | Bytecode::Ge => {
            let mut operands = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value().and_then(|v| v.value_as::<IntegerValue>()))
                .collect::<PartialVMResult<Vec<_>>>()?;
            Operation::BinaryOp {
                ty: BinaryIntegerOperationType::try_from(instr.clone()).unwrap(),
                rhs: operands.pop().unwrap().into(),
                lhs: operands.pop().unwrap().into(),
            }
        },

        Bytecode::Or => {
            let mut operands = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value().and_then(|v| v.value_as::<bool>()))
                .collect::<PartialVMResult<Vec<_>>>()?;
            Operation::Or {
                rhs: operands.pop().unwrap(),
                lhs: operands.pop().unwrap(),
            }
        },
        Bytecode::And => {
            let mut operands = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value().and_then(|v| v.value_as::<bool>()))
                .collect::<PartialVMResult<Vec<_>>>()?;
            Operation::And {
                rhs: operands.pop().unwrap(),
                lhs: operands.pop().unwrap(),
            }
        },
        Bytecode::Not => {
            let mut operands = interp
                .operand_stack
                .last_n(1)?
                .map(|v| v.copy_value().and_then(|v| v.value_as::<bool>()))
                .collect::<PartialVMResult<Vec<_>>>()?;
            Operation::Not {
                value: operands.pop().unwrap(),
            }
        },
        Bytecode::Eq => {
            let mut operands = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?;
            Operation::Eq {
                rhs: TracedValueBuilder::new(&operands.pop().unwrap()).build_as_plain_value().unwrap().items,
                lhs: TracedValueBuilder::new(&operands.pop().unwrap()).build_as_plain_value().unwrap().items,
            }
        },
        Bytecode::Neq => {
            let mut operands = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?;
            Operation::Neq {
                rhs: TracedValueBuilder::new(&operands.pop().unwrap()).build_as_plain_value().unwrap().items,
                lhs: TracedValueBuilder::new(&operands.pop().unwrap()).build_as_plain_value().unwrap().items,
            }
        },

        Bytecode::Abort => {
            let value = interp
                .operand_stack
                .last_n(1)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?
                .pop()
                .unwrap();
            Operation::Abort {
                error_code: value.value_as()?,
            }
        },
        Bytecode::Nop => Operation::Nop,
        Bytecode::Shl => {
            let mut operands = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?;
            Operation::Shl {
                rhs: operands.pop().unwrap().value_as()?,
                lhs: operands.pop().unwrap().value_as::<IntegerValue>()?.into(),
            }
        },
        Bytecode::Shr => {
            let mut operands = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?;
            Operation::Shr {
                rhs: operands.pop().unwrap().value_as()?,
                lhs: operands.pop().unwrap().value_as::<IntegerValue>()?.into(),
            }
        },
        Bytecode::VecPack(si, num) => Operation::VecPack {
            si: si.0,
            num: *num,
            args: interp
                .operand_stack
                .last_n(*num as usize)?
                .map(|t| TracedValueBuilder::new(t).build_as_plain_value().unwrap().items)
                .collect::<Vec<_>>(),
        },
        Bytecode::VecUnpack(si, num) => Operation::VecUnpack {
            si: si.0,
            num: *num,
            arg: interp
                .operand_stack
                .last_n(1)?
                .last()
                .map(|t| TracedValueBuilder::new(t).build_as_plain_value().unwrap().items)
                .unwrap(),
        },
        Bytecode::VecLen(si) => {
            let vec_ref = interp
                .operand_stack
                .last_n(1)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?
                .pop()
                .unwrap();
            let reference = TracedValueBuilder::new(&vec_ref).build_as_reference(&footprints
                .state
                .reverse_local_value_addressings).unwrap();

            let vec_ref = vec_ref.value_as::<VectorRef>()?;

            let len = {
                let (ty, _ty_count) =
                    frame
                        .ty_cache
                        .get_signature_index_type(*si, resolver, &frame.ty_args)?;
                vec_ref.len(ty)?
            };
            Operation::VecLen {
                si: si.0,

                vec_ref: reference,
                len: len.value_as()?,
            }
        },
        Bytecode::VecImmBorrow(si) | Bytecode::VecMutBorrow(si) => {
            let mut values = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?;
            let idx: u64 = values.pop().unwrap().value_as()?;
            let vec_ref = values.pop().unwrap();
            let reference = TracedValueBuilder::new(&vec_ref).build_as_reference(&footprints
                .state
                .reverse_local_value_addressings).unwrap();
            // let vec_ref = vec_ref.value_as::<VectorRef>()?;
            // let elem = {
            //     let (ty, _ty_count) =
            //         frame
            //             .ty_cache
            //             .get_signature_index_type(*si, resolver, &frame.ty_args)?;
            //     vec_ref.borrow_elem(idx as usize, ty)?
            // };
            Operation::VecBorrow {
                si: si.0,

                imm: matches!(instr, Bytecode::VecImmBorrow(_)),
                idx,
                vec_ref: reference
            }
        },
        Bytecode::VecPushBack(si) => {
            let mut values = interp
                .operand_stack
                .last_n(2)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?;
            let elem = values.pop().unwrap();
            let vec_ref = values.pop().unwrap();

            let reference = TracedValueBuilder::new(&vec_ref).build_as_reference(&footprints
                .state
                .reverse_local_value_addressings).unwrap();

            let vec_ref = vec_ref.value_as::<VectorRef>()?;
            let (ty, _ty_count) =
                frame
                    .ty_cache
                    .get_signature_index_type(*si, resolver, &frame.ty_args)?;

            let vec_len = vec_ref.len(ty)?;

            Operation::VecPushBack {
                si: si.0,

                vec_ref: reference,

                elem: TracedValueBuilder::new(&elem).build_as_plain_value().unwrap().items,
                vec_len: vec_len.value_as()?,
            }
        },
        Bytecode::VecPopBack(si) => {
            let mut values = interp
                .operand_stack
                .last_n(1)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?;
            let vec_ref = values.pop().unwrap();
            let reference = TracedValueBuilder::new(&vec_ref).build_as_reference(&footprints
                .state
                .reverse_local_value_addressings).unwrap();

            let vec_ref = vec_ref.value_as::<VectorRef>()?;
            let (ty, _ty_count) =
                frame
                    .ty_cache
                    .get_signature_index_type(*si, resolver, &frame.ty_args)?;

            let vec_len: u64 = vec_ref.len(ty)?.value_as()?;

            let elem = vec_ref
                .borrow_elem((vec_len - 1) as usize, ty)?
                .value_as::<move_vm_types::values::Reference>()?
                .read_ref()?;

            Operation::VecPopBack {
                si: si.0,

                vec_len,
                vec_ref: reference,

                elem: TracedValueBuilder::new(&elem).build_as_plain_value().unwrap().items
            }
        },

        Bytecode::VecSwap(si) => {
            let mut values = interp
                .operand_stack
                .last_n(3)?
                .map(|v| v.copy_value())
                .collect::<PartialVMResult<Vec<_>>>()?;
            let idx2: u64 = values.pop().unwrap().value_as()?;
            let idx1: u64 = values.pop().unwrap().value_as()?;
            let vec_ref = values.pop().unwrap();
            let reference = TracedValueBuilder::new(&vec_ref).build_as_reference(&footprints
                .state
                .reverse_local_value_addressings).unwrap();
            let vec_ref = vec_ref.value_as::<VectorRef>()?;
            let (ty, _ty_count) =
                frame
                    .ty_cache
                    .get_signature_index_type(*si, resolver, &frame.ty_args)?;
            let vec_len: u64 = vec_ref.len(ty)?.value_as()?;
            let idx2_elem = vec_ref
                .borrow_elem(idx2 as usize, ty)?
                .value_as::<move_vm_types::values::Reference>()?
                .read_ref()?;
            let idx1_elem = vec_ref
                .borrow_elem(idx1 as usize, ty)?
                .value_as::<move_vm_types::values::Reference>()?
                .read_ref()?;

            Operation::VecSwap {
                si: si.0,

                vec_len,
                vec_ref: reference,
                idx2,
                idx1,
                idx2_elem: TracedValueBuilder::new(&idx2_elem).build_as_plain_value().unwrap().items,
                idx1_elem: TracedValueBuilder::new(&idx1_elem).build_as_plain_value().unwrap().items
            }
        },
        Bytecode::MutBorrowGlobal(_)
        | Bytecode::MutBorrowGlobalGeneric(_)
        | Bytecode::Exists(_)
        | Bytecode::ExistsGeneric(_)
        | Bytecode::MoveFrom(_)
        | Bytecode::MoveFromGeneric(_)
        | Bytecode::MoveTo(_)
        | Bytecode::MoveToGeneric(_)
        | Bytecode::ImmBorrowGlobal(_)
        | Bytecode::ImmBorrowGlobalGeneric(_) => {
            unimplemented!("unsupported instruction")
        },
    };

    let inst = serialize_instruction(instr);
    footprints.data.push(Footprint {
        op: inst.opcodes as u8,
        aux0: inst.aux0,
        aux1: inst.aux1,
        module_id,
        function_id: function_index.into_index(),
        pc,
        frame_index,
        stack_pointer,
        data: operation,
    });
    Ok(())
}

#[derive(Copy, Clone, Debug)]
struct Instruction {
    opcodes: Opcodes,
    aux0: Option<u128>,
    aux1: Option<u128>,
}

impl Instruction {
    pub fn new(opcodes: Opcodes, aux0: Option<u128>, aux1: Option<u128>) -> Self {
        Self {
            opcodes,
            aux0,
            aux1,
        }
    }
}

/// the logic is similar to third_party/move/move-binary-format/src/serializer.rs#serialize_instruction_inner
fn serialize_instruction(opcode: &Bytecode) -> Instruction {
    match opcode {
        Bytecode::FreezeRef => Instruction::new(Opcodes::FREEZE_REF, None, None),
        Bytecode::Pop => Instruction::new(Opcodes::POP, None, None),
        Bytecode::Ret => Instruction::new(Opcodes::RET, None, None),
        Bytecode::BrTrue(code_offset) => {
            Instruction::new(Opcodes::BR_TRUE, Some(*code_offset as u128), None)
        },
        Bytecode::BrFalse(code_offset) => {
            Instruction::new(Opcodes::BR_FALSE, Some(*code_offset as u128), None)
        },
        Bytecode::Branch(code_offset) => {
            Instruction::new(Opcodes::BRANCH, Some(*code_offset as u128), None)
        },
        Bytecode::LdU8(value) => Instruction::new(Opcodes::LD_U8, Some(*value as u128), None),
        Bytecode::LdU64(value) => Instruction::new(Opcodes::LD_U64, Some(*value as u128), None),
        Bytecode::LdU128(value) => Instruction::new(Opcodes::LD_U128, Some(*value), None),
        Bytecode::CastU8 => Instruction::new(Opcodes::CAST_U8, None, None),
        Bytecode::CastU64 => Instruction::new(Opcodes::CAST_U64, None, None),
        Bytecode::CastU128 => Instruction::new(Opcodes::CAST_U128, None, None),
        Bytecode::LdConst(const_idx) => {
            Instruction::new(Opcodes::LD_CONST, Some(const_idx.0 as u128), None)
        },
        Bytecode::LdTrue => Instruction::new(Opcodes::LD_TRUE, None, None),
        Bytecode::LdFalse => Instruction::new(Opcodes::LD_FALSE, None, None),
        Bytecode::CopyLoc(local_idx) => {
            Instruction::new(Opcodes::COPY_LOC, Some(*local_idx as u128), None)
        },
        Bytecode::MoveLoc(local_idx) => {
            Instruction::new(Opcodes::MOVE_LOC, Some(*local_idx as u128), None)
        },
        Bytecode::StLoc(local_idx) => {
            Instruction::new(Opcodes::ST_LOC, Some(*local_idx as u128), None)
        },
        Bytecode::MutBorrowLoc(local_idx) => {
            Instruction::new(Opcodes::MUT_BORROW_LOC, Some(*local_idx as u128), None)
        },
        Bytecode::ImmBorrowLoc(local_idx) => {
            Instruction::new(Opcodes::IMM_BORROW_LOC, Some(*local_idx as u128), None)
        },
        Bytecode::MutBorrowField(field_idx) => {
            Instruction::new(Opcodes::MUT_BORROW_FIELD, Some(field_idx.0 as u128), None)
        },
        Bytecode::MutBorrowFieldGeneric(field_idx) => Instruction::new(
            Opcodes::MUT_BORROW_FIELD_GENERIC,
            Some(field_idx.0 as u128),
            None,
        ),
        Bytecode::ImmBorrowField(field_idx) => {
            Instruction::new(Opcodes::IMM_BORROW_FIELD, Some(field_idx.0 as u128), None)
        },
        Bytecode::ImmBorrowFieldGeneric(field_idx) => Instruction::new(
            Opcodes::IMM_BORROW_FIELD_GENERIC,
            Some(field_idx.0 as u128),
            None,
        ),
        Bytecode::Call(method_idx) => {
            Instruction::new(Opcodes::CALL, Some(method_idx.0 as u128), None)
        },
        Bytecode::Pack(class_idx) => {
            Instruction::new(Opcodes::PACK, Some(class_idx.0 as u128), None)
        },
        Bytecode::Unpack(class_idx) => {
            Instruction::new(Opcodes::UNPACK, Some(class_idx.0 as u128), None)
        },
        Bytecode::CallGeneric(method_idx) => {
            Instruction::new(Opcodes::CALL_GENERIC, Some(method_idx.0 as u128), None)
        },
        Bytecode::PackGeneric(class_idx) => {
            Instruction::new(Opcodes::PACK_GENERIC, Some(class_idx.0 as u128), None)
        },
        Bytecode::UnpackGeneric(class_idx) => {
            Instruction::new(Opcodes::UNPACK_GENERIC, Some(class_idx.0 as u128), None)
        },
        Bytecode::ReadRef => Instruction::new(Opcodes::READ_REF, None, None),
        Bytecode::WriteRef => Instruction::new(Opcodes::WRITE_REF, None, None),
        Bytecode::Add => Instruction::new(Opcodes::ADD, None, None),
        Bytecode::Sub => Instruction::new(Opcodes::SUB, None, None),
        Bytecode::Mul => Instruction::new(Opcodes::MUL, None, None),
        Bytecode::Mod => Instruction::new(Opcodes::MOD, None, None),
        Bytecode::Div => Instruction::new(Opcodes::DIV, None, None),
        Bytecode::BitOr => Instruction::new(Opcodes::BIT_OR, None, None),
        Bytecode::BitAnd => Instruction::new(Opcodes::BIT_AND, None, None),
        Bytecode::Xor => Instruction::new(Opcodes::XOR, None, None),
        Bytecode::Shl => Instruction::new(Opcodes::SHL, None, None),
        Bytecode::Shr => Instruction::new(Opcodes::SHR, None, None),
        Bytecode::Or => Instruction::new(Opcodes::OR, None, None),
        Bytecode::And => Instruction::new(Opcodes::AND, None, None),
        Bytecode::Not => Instruction::new(Opcodes::NOT, None, None),
        Bytecode::Eq => Instruction::new(Opcodes::EQ, None, None),
        Bytecode::Neq => Instruction::new(Opcodes::NEQ, None, None),
        Bytecode::Lt => Instruction::new(Opcodes::LT, None, None),
        Bytecode::Gt => Instruction::new(Opcodes::GT, None, None),
        Bytecode::Le => Instruction::new(Opcodes::LE, None, None),
        Bytecode::Ge => Instruction::new(Opcodes::GE, None, None),
        Bytecode::Abort => Instruction::new(Opcodes::ABORT, None, None),
        Bytecode::Nop => Instruction::new(Opcodes::NOP, None, None),
        Bytecode::Exists(class_idx) => {
            Instruction::new(Opcodes::EXISTS, Some(class_idx.0 as u128), None)
        },
        Bytecode::MutBorrowGlobal(class_idx) => {
            Instruction::new(Opcodes::MUT_BORROW_GLOBAL, Some(class_idx.0 as u128), None)
        },
        Bytecode::ImmBorrowGlobal(class_idx) => {
            Instruction::new(Opcodes::IMM_BORROW_GLOBAL, Some(class_idx.0 as u128), None)
        },
        Bytecode::MoveFrom(class_idx) => {
            Instruction::new(Opcodes::MOVE_FROM, Some(class_idx.0 as u128), None)
        },
        Bytecode::MoveTo(class_idx) => {
            Instruction::new(Opcodes::MOVE_TO, Some(class_idx.0 as u128), None)
        },
        Bytecode::ExistsGeneric(class_idx) => {
            Instruction::new(Opcodes::EXISTS_GENERIC, Some(class_idx.0 as u128), None)
        },
        Bytecode::MutBorrowGlobalGeneric(class_idx) => Instruction::new(
            Opcodes::MUT_BORROW_GLOBAL_GENERIC,
            Some(class_idx.0 as u128),
            None,
        ),
        Bytecode::ImmBorrowGlobalGeneric(class_idx) => Instruction::new(
            Opcodes::IMM_BORROW_GLOBAL_GENERIC,
            Some(class_idx.0 as u128),
            None,
        ),
        Bytecode::MoveFromGeneric(class_idx) => {
            Instruction::new(Opcodes::MOVE_FROM_GENERIC, Some(class_idx.0 as u128), None)
        },
        Bytecode::MoveToGeneric(class_idx) => {
            Instruction::new(Opcodes::MOVE_TO_GENERIC, Some(class_idx.0 as u128), None)
        },
        Bytecode::VecPack(sig_idx, num) => Instruction::new(
            Opcodes::VEC_PACK,
            Some(sig_idx.0 as u128),
            Some(*num as u128),
        ),
        Bytecode::VecLen(sig_idx) => {
            Instruction::new(Opcodes::VEC_LEN, Some(sig_idx.0 as u128), None)
        },
        Bytecode::VecImmBorrow(sig_idx) => {
            Instruction::new(Opcodes::VEC_IMM_BORROW, Some(sig_idx.0 as u128), None)
        },
        Bytecode::VecMutBorrow(sig_idx) => {
            Instruction::new(Opcodes::VEC_MUT_BORROW, Some(sig_idx.0 as u128), None)
        },
        Bytecode::VecPushBack(sig_idx) => {
            Instruction::new(Opcodes::VEC_PUSH_BACK, Some(sig_idx.0 as u128), None)
        },
        Bytecode::VecPopBack(sig_idx) => {
            Instruction::new(Opcodes::VEC_POP_BACK, Some(sig_idx.0 as u128), None)
        },
        Bytecode::VecUnpack(sig_idx, num) => Instruction::new(
            Opcodes::VEC_UNPACK,
            Some(sig_idx.0 as u128),
            Some(*num as u128),
        ),
        Bytecode::VecSwap(sig_idx) => {
            Instruction::new(Opcodes::VEC_SWAP, Some(sig_idx.0 as u128), None)
        },
        Bytecode::LdU16(value) => Instruction::new(Opcodes::LD_U16, Some(*value as u128), None),
        Bytecode::LdU32(value) => Instruction::new(Opcodes::LD_U32, Some(*value as u128), None),
        Bytecode::LdU256(value) => {
            let hi = (*value >> 128).unchecked_as_u128();
            let lo = (*value << 128u8 >> 128).unchecked_as_u128();
            Instruction::new(Opcodes::LD_U256, Some(lo), Some(hi))
        },
        Bytecode::CastU16 => Instruction::new(Opcodes::CAST_U16, None, None),
        Bytecode::CastU32 => Instruction::new(Opcodes::CAST_U32, None, None),
        Bytecode::CastU256 => Instruction::new(Opcodes::CAST_U256, None, None),
    }
}
