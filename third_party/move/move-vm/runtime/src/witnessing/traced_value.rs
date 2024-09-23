use std::collections::BTreeMap;
use std::ops::Shl;

use serde::{Deserialize, Serialize};

use move_core_types::{account_address::AccountAddress, u256, u256::U256};
use move_vm_types::{
    delayed_values::delayed_field_id::DelayedFieldID,
    values::{IntegerValue, Value},
    views::{ValueView, ValueVisitor},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SimpleValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U256(U256),
    Bool(bool),
    Address(AccountAddress),
    Reference(Reference),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Integer {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U256(U256),
}

impl From<IntegerValue> for Integer {
    fn from(value: IntegerValue) -> Self {
        match value {
            IntegerValue::U8(v) => { Self::U8(v) }
            IntegerValue::U16(v) => { Self::U16(v) }
            IntegerValue::U32(v) => Self::U32(v),
            IntegerValue::U64(v) => Self::U64(v),
            IntegerValue::U128(v) => Self::U128(v),
            IntegerValue::U256(v) => Self::U256(v),
        }
    }
}

impl From<Integer> for IntegerValue {
    fn from(value: Integer) -> Self {
        match value {
            Integer::U8(v) => Self::U8(v),
            Integer::U16(v) => Self::U16(v),
            Integer::U32(v) => Self::U32(v),
            Integer::U64(v) => Self::U64(v),
            Integer::U128(v) => Self::U128(v),
            Integer::U256(v) => Self::U256(v),
        }
    }
}

impl From<Integer> for SimpleValue {
    fn from(value: Integer) -> Self {
        match value {
            Integer::U8(v) => Self::U8(v),
            Integer::U16(v) => Self::U16(v),
            Integer::U32(v) => Self::U32(v),
            Integer::U64(v) => Self::U64(v),
            Integer::U128(v) => Self::U128(v),
            Integer::U256(v) => Self::U256(v),
        }
    }
}

impl TryFrom<SimpleValue> for Integer {
    type Error = anyhow::Error;

    fn try_from(value: SimpleValue) -> anyhow::Result<Integer> {
        match value {
            SimpleValue::U8(v) => Ok(Integer::U8(v)),
            SimpleValue::U16(v) => Ok(Integer::U16(v)),
            SimpleValue::U32(v) => Ok(Integer::U32(v)),
            SimpleValue::U64(v) => Ok(Integer::U64(v)),
            SimpleValue::U128(v) => Ok(Integer::U128(v)),
            SimpleValue::U256(v) => Ok(Integer::U256(v)),
            _ => Err(anyhow::anyhow!(
                "Invalid SimpleValue type for converting into Integer"
            )),
        }
    }
}

/// Return lower and higher 128-bits of of an Integer as u128 pair
impl From<Integer> for (u128 /*lo*/, u128 /*hi*/) {
    fn from(value: Integer) -> (u128, u128) {
        match value {
            Integer::U8(v) => (v as u128, 0u128),
            Integer::U16(v) => (v as u128, 0u128),
            Integer::U32(v) => (v as u128, 0u128),
            Integer::U64(v) => (v as u128, 0u128),
            Integer::U128(v) => (v as u128, 0u128),
            Integer::U256(v) => {
                let bytes = v.to_le_bytes();
                let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
                let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());
                (lo, hi)
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub frame_index: usize,
    pub local_index: usize,
    pub sub_index: Vec<usize>,
}


impl Reference {
    pub fn new(frame_index: usize, local_index: usize, sub_index: Vec<usize>) -> Self {
        Reference {
            frame_index,
            local_index,
            sub_index,
        }
    }

    pub fn ref_child(mut self, child: usize) -> Self {
        while let Some(v) = self.sub_index.pop() {
            if v != 0 {
                self.sub_index.push(v);
                break;
            }
        }
        self.sub_index.push(child);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueItem {
    pub sub_index: Vec<usize>,
    pub header: bool,
    pub value: SimpleValue,
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct LevelState {
    depth: usize,
    len: usize,
    counter: usize,
}

pub struct TracedValue {
    pub items: Vec<ValueItem>,
    pub container_sub_indexes: BTreeMap<usize, Vec<usize>>,
}

#[derive(Clone)]
pub struct TracedValueBuilder {
    visitor: Result<PlainValueVisitor, ReferenceValueVisitor>,
}


impl TracedValueBuilder {
    pub fn new(value: &Value) -> Self {
        Self {
            visitor: if !value.is_ref_value() {
                let mut visitor = PlainValueVisitor::default();
                value.visit(&mut visitor);
                Ok(visitor)
            } else {
                let mut visitor = ReferenceValueVisitor::default();
                value.visit(&mut visitor);
                Err(visitor)
            }
        }
    }

    pub fn is_ref_value(&self) -> bool {
        self.visitor.is_err()
    }
    pub fn build_as_reference(self, reverse_local_value_addressings: &BTreeMap<usize, Reference>) -> Option<Reference> {
        match self.visitor {
            Ok(_) => None,
            Err(visitor) => {
                let parent = reverse_local_value_addressings.get(&visitor.reference_pointer).expect("reference by pointer shold exist").clone();
                Some(parent.ref_child(visitor.indexed.map(|i| i + 1).unwrap_or_default()))
            }
        }
    }
    pub fn build_as_plain_value(self) -> Option<TracedValue> {
        match self.visitor {
            Ok(visitor) => Some(visitor.get_trace_value()),
            _ => None
        }
    }
    pub fn build(self, reverse_local_value_addressings: &BTreeMap<usize, Reference>) -> TracedValue {
        match self.visitor {
            Ok(visitor) => { visitor.get_trace_value() },
            Err(visitor) => {
                let parent = reverse_local_value_addressings.get(&visitor.reference_pointer).expect("reference by pointer shold exist").clone();
                let reference = parent.ref_child(visitor.indexed.map(|i| i + 1).unwrap_or_default());
                TracedValue {
                    items: vec![ValueItem {
                        sub_index: vec![],
                        header: false,
                        value: SimpleValue::Reference(reference),
                    }],
                    container_sub_indexes: Default::default(),
                }
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct PlainValueVisitor {
    visit_stack: Vec<LevelState>,
    items: Vec<ValueItem>,
    container_sub_indexes: BTreeMap<usize, Vec<usize>>,
}

pub type ValueItems = Vec<ValueItem>;


impl PlainValueVisitor {
    fn get_trace_value(mut self) -> TracedValue {
        while self
            .visit_stack
            .last()
            .filter(|s| s.counter == s.len)
            .is_some()
        {
            self.visit_stack.pop();
        }

        assert!(self.visit_stack.is_empty());
        add_flen(&mut self.items);
        TracedValue { container_sub_indexes: self.container_sub_indexes, items: self.items }
    }
}

fn add_flen(items: &mut ValueItems) {
    let mut builder = trie_rs::TrieBuilder::new();

    /// strip the tail 0s
    #[inline]
    fn strip_zero(v: &mut Vec<usize>) {
        while let Some(e) = v.pop() {
            if e != 0 {
                v.push(e);
                break;
            }
        }
    }

    for x in items.iter_mut() {
        strip_zero(&mut x.sub_index);
        // skip root
        if !x.sub_index.is_empty() {
            builder.push(&x.sub_index);
        }
    }
    let tree = builder.build();
    let item_num = items.len() as u64;
    for item in items.iter_mut() {
        if item.sub_index.is_empty() {
            if item.header {
                match &item.value {
                    SimpleValue::U64(len) => {
                        item.value = SimpleValue::U256(U256::from(*len).shl(128u32) + item_num.into());
                    },
                    SimpleValue::U256(_) => {},
                    _ => unreachable!()
                };
            }
            continue;
        }
        let prefixed_node_num = tree
            .predictive_search(&item.sub_index)
            .collect::<Vec<Vec<usize>>>()
            .len() as u64;
        if item.header {
            match &item.value {
                SimpleValue::U64(len) => {
                    item.value = SimpleValue::U256(U256::from(*len).shl(128u32) + prefixed_node_num.into());
                },
                SimpleValue::U256(_) => {},
                _ => unreachable!()
            };
        } else {
            debug_assert_eq!(prefixed_node_num, 1);
        }
    }
}

impl PlainValueVisitor {
    pub fn current_sub_index(&self) -> Vec<usize> {
        self.visit_stack.iter().map(|s| s.counter).collect()
    }
    fn visit_simple(&mut self, depth: usize, value: SimpleValue) {
        let sub_index = match self.visit_stack.last_mut() {
            Some(frame) => {
                frame.counter += 1;
                assert_eq!(frame.depth + 1, depth);
                self.current_sub_index()
            },
            None => {
                assert_eq!(depth, 0);
                vec![0]
            },
        };
        self.items.push(ValueItem {
            sub_index,
            header: false,
            value,
        });

        // trace-up to the top un-finished frame
        while self
            .visit_stack
            .last()
            .filter(|s| s.counter == s.len)
            .is_some()
        {
            self.visit_stack.pop();
        }
    }
}

impl ValueVisitor for PlainValueVisitor {
    fn visit_delayed(&mut self, _depth: usize, _id: DelayedFieldID) {
        unreachable!()
    }

    fn visit_u8(&mut self, depth: usize, val: u8) {
        self.visit_simple(depth, SimpleValue::U8(val))
    }

    fn visit_u16(&mut self, depth: usize, val: u16) {
        self.visit_simple(depth, SimpleValue::U16(val))
    }

    fn visit_u32(&mut self, depth: usize, val: u32) {
        self.visit_simple(depth, SimpleValue::U32(val))
    }

    fn visit_u64(&mut self, depth: usize, val: u64) {
        self.visit_simple(depth, SimpleValue::U64(val))
    }

    fn visit_u128(&mut self, depth: usize, val: u128) {
        self.visit_simple(depth, SimpleValue::U128(val))
    }

    fn visit_u256(&mut self, depth: usize, val: u256::U256) {
        self.visit_simple(depth, SimpleValue::U256(val))
    }

    fn visit_bool(&mut self, depth: usize, val: bool) {
        self.visit_simple(depth, SimpleValue::Bool(val))
    }

    fn visit_address(&mut self, depth: usize, val: AccountAddress) {
        self.visit_simple(depth, SimpleValue::Address(val))
    }

    fn visit_container(&mut self, raw_address: usize, depth: usize) {
        match self.visit_stack.last_mut() {
            Some(last_frame) => {
                last_frame.counter += 1;
                assert_eq!(last_frame.depth + 1, depth);
            },
            None => {
                assert_eq!(depth, 0);
            },
        }
        let mut sub_index = self.current_sub_index();
        sub_index.push(0);
        self.container_sub_indexes.insert(raw_address, sub_index);
    }

    fn visit_struct(&mut self, depth: usize, len: usize) -> bool {
        let new_level = LevelState {
            depth,
            len,
            counter: 0,
        };
        self.visit_stack.push(new_level);
        self.items.push(ValueItem {
            header: true,
            sub_index: self.current_sub_index(),
            value: SimpleValue::U64(len as u64),
        });
        true
    }

    fn visit_vec(&mut self, depth: usize, len: usize) -> bool {
        let new_frame = LevelState {
            depth,
            len,
            counter: 0,
        };
        self.visit_stack.push(new_frame);
        self.items.push(ValueItem {
            header: true,
            sub_index: self.current_sub_index(),
            value: SimpleValue::U64(len as u64),
        });
        true
    }

    fn visit_ref(&mut self, _depth: usize, _is_global: bool) -> bool {
        panic!("ref cannot be a field of container")
    }
}

#[derive(Copy, Clone, Default)]
struct ReferenceValueVisitor {
    reference_pointer: usize,
    indexed: Option<usize>,
}
//
// impl ReferenceValueVisitor {
//     pub fn into_ref_and_child(self) -> (usize, Option<usize>) {
//         (self.reference_pointer, self.indexed)
//     }
// }

impl ValueVisitor for ReferenceValueVisitor {
    fn visit_delayed(&mut self, _depth: usize, _id: DelayedFieldID) {}

    fn visit_u8(&mut self, _depth: usize, _val: u8) {}

    fn visit_u16(&mut self, _depth: usize, _val: u16) {}

    fn visit_u32(&mut self, _depth: usize, _val: u32) {}

    fn visit_u64(&mut self, _depth: usize, _val: u64) {}

    fn visit_u128(&mut self, _depth: usize, _val: u128) {}

    fn visit_u256(&mut self, _depth: usize, _val: U256) {}

    fn visit_bool(&mut self, _depth: usize, _val: bool) {}

    fn visit_address(&mut self, _depth: usize, _val: AccountAddress) {}

    fn visit_struct(&mut self, _depth: usize, _len: usize) -> bool {
        false
    }

    fn visit_vec(&mut self, _depth: usize, _len: usize) -> bool {
        false
    }

    fn visit_ref(&mut self, _depth: usize, _is_global: bool) -> bool {
        true
    }

    fn visit_container(&mut self, raw_address: usize, depth: usize) {
        if depth == 1 {
            self.reference_pointer = raw_address;
        } else {
            unreachable!()
        }
    }

    fn visit_indexed(&mut self, raw_address: usize, depth: usize, idx: usize) {
        if depth == 0 {
            self.reference_pointer = raw_address;
            self.indexed = Some(idx);
        } else {
            unreachable!()
        }
    }
}
