use serde::{Deserialize, Serialize};

use move_binary_format::errors::PartialVMError;
use move_binary_format::file_format::Bytecode;
use move_core_types::language_storage::ModuleId;
use move_core_types::vm_status::StatusCode;

use crate::witnessing::traced_value::{Integer, Reference, ValueItems};

pub mod traced_value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallerInfo {
    pub frame_index: usize,
    pub module_id: Option<ModuleId>,
    pub function_id: usize,
    pub pc: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntryCall {
    pub module_id: Option<ModuleId>,
    pub function_index: usize,
    pub args: Vec<ValueItems>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Operation {
    Start {
        entry_call: EntryCall,
    },
    Pop {
        poped_value: ValueItems,
    },
    Ret { caller: Option<CallerInfo> },
    BrTrue {
        cond_val: bool,
        code_offset: u16,
    },
    BrFalse {
        cond_val: bool,
        code_offset: u16,
    },
    Branch(u16),
    LdSimple(Integer), // LdU{8,16,32,64,128,256}
    LdTrue,
    LdFalse,
    LdConst { const_pool_index: u16 },
    CopyLoc {
        local_index: u8,
        local: ValueItems,
    },
    MoveLoc {
        local_index: u8,
        local: ValueItems,
    },
    StLoc {
        local_index: u8,
        old_local: Option<ValueItems>,
        new_value: ValueItems,
    },
    Call {
        fh_idx: u16,
        args: Vec<ValueItems>,
    },
    CallGeneric {
        fh_idx: u16,
        args: Vec<ValueItems>,
    },
    Pack {
        sd_idx: u16,
        num: u64,
        args: Vec<ValueItems>,
    },
    PackGeneric {
        si_idx: u16,
        num: u64,
        args: Vec<ValueItems>,
    },
    Unpack {
        sd_idx: u16,
        num: u64,
        arg: ValueItems,
    },
    UnpackGeneric {
        sd_idx: u16,
        num: u64,
        arg: ValueItems,
    },
    ReadRef {
        reference: Reference,
        value: ValueItems,
    },
    WriteRef {
        reference: Reference,
        old_value: ValueItems,
        new_value: ValueItems,
    },
    FreezeRef,
    BinaryOp {
        ty: BinaryIntegerOperationType,
        lhs: Integer,
        rhs: Integer,
    },
    Or {
        lhs: bool,
        rhs: bool,
    },
    And {
        lhs: bool,
        rhs: bool,
    },
    Not {
        value: bool,
    },
    Shl {
        rhs: u8,
        lhs: Integer,
    },
    Shr {
        rhs: u8,
        lhs: Integer,
    },
    Eq {
        lhs: ValueItems,
        rhs: ValueItems,
    },
    Neq {
        lhs: ValueItems,
        rhs: ValueItems,
    },
    Abort {
        error_code: u64,
    },
    Nop,
    VecPack {
        si: u16,
        num: u64,
        args: Vec<ValueItems>,
    },
    VecUnpack {
        si: u16,
        num: u64,
        arg: ValueItems,
    },
    VecLen {
        si: u16,
        vec_ref: Reference,
        len: u64,
    },
    VecBorrow {
        si: u16,
        imm: bool,
        idx: u64,
        vec_ref: Reference,
        //elem: ValueItems,
    },
    VecPushBack {
        si: u16,
        vec_len: u64,
        vec_ref: Reference,
        elem: ValueItems,
    },
    VecPopBack {
        si: u16,
        vec_len: u64,
        vec_ref: Reference,
        elem: ValueItems,
    },

    VecSwap {
        si: u16,
        vec_ref: Reference,
        vec_len: u64,
        idx1: u64,
        idx2: u64,
        idx1_elem: ValueItems,
        idx2_elem: ValueItems,
    },
    BorrowLoc {
        imm: bool,
        local_index: u8,
    },

    BorrowField {
        imm: bool,
        fh_idx: u16,
        reference: Reference,
        field_offset: usize,
    },
    BorrowFieldGeneric {
        fi_idx: u16,
        imm: bool,
        reference: Reference,
        field_offset: usize,
    },
    CastU8 {
        origin: Integer,
    },
    CastU16 {
        origin: Integer,
    },
    CastU32 {
        origin: Integer,
    },
    CastU64 {
        origin: Integer,
    },
    CastU128 {
        origin: Integer,
    },
    CastU256 {
        origin: Integer,
    },
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum BinaryIntegerOperationType {
    Add,
    Sub,
    Mul,
    Mod,
    Div,
    BitOr,
    BitAnd,
    Xor,
    Lt,
    Gt,
    Le,
    Ge,
}

impl TryFrom<Bytecode> for BinaryIntegerOperationType {
    type Error = PartialVMError;

    fn try_from(value: Bytecode) -> Result<Self, Self::Error> {
        Ok(match value {
            Bytecode::Add => BinaryIntegerOperationType::Add,
            Bytecode::Sub => BinaryIntegerOperationType::Sub,
            Bytecode::Mul => BinaryIntegerOperationType::Mul,
            Bytecode::Mod => BinaryIntegerOperationType::Mod,
            Bytecode::Div => BinaryIntegerOperationType::Div,
            Bytecode::BitOr => BinaryIntegerOperationType::BitOr,
            Bytecode::BitAnd => BinaryIntegerOperationType::BitAnd,
            Bytecode::Xor => BinaryIntegerOperationType::Xor,
            Bytecode::Lt => BinaryIntegerOperationType::Lt,
            Bytecode::Gt => BinaryIntegerOperationType::Gt,
            Bytecode::Le => BinaryIntegerOperationType::Le,
            Bytecode::Ge => BinaryIntegerOperationType::Ge,
            _ => {
                return Err(PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR)
                    .with_message(format!("{:?} is not a binary operation", value)));
            }
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Footprint {
    pub module_id: Option<ModuleId>,
    pub function_id: usize,
    pub pc: u16,
    pub frame_index: usize,
    pub stack_pointer: usize,
    pub op: u8,
    pub aux0: Option<u128>,
    pub aux1: Option<u128>,
    pub data: Operation,
}

