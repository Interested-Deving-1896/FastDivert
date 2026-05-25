/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

#![allow(dead_code)]
#![allow(non_upper_case_globals)]

// Minimal cBPF interpreter for kernel-space packet filtering

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// Instruction classes
const BPF_CLASS_MASK: u16 = 0x07;
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

// ld/ldx fields
const BPF_SIZE_MASK: u16 = 0x18;
const BPF_W: u16 = 0x00; // 32-bit
const BPF_H: u16 = 0x08; // 16-bit
const BPF_B: u16 = 0x10; // 8-bit

const BPF_MODE_MASK: u16 = 0xe0;
const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_MSH: u16 = 0xa0;

// alu/jmp fields
const BPF_OP_MASK: u16 = 0xf0;
const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

const BPF_SRC_MASK: u16 = 0x08;
const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;

const BPF_ADDR_FLAGS_OFFSET: u32 = 0xfffff000;
const BPF_ADDR_IF_IDX_OFFSET: u32 = 0xfffff004;
const BPF_ADDR_SUB_IF_IDX_OFFSET: u32 = 0xfffff008;
const BPF_ADDR_PROCESS_ID_OFFSET: u32 = 0xfffff00c;
const BPF_ADDR_LAYER_OFFSET: u32 = 0xfffff010;

pub struct BpfContext<'a> {
    pub packet: &'a [u8],
    pub address: &'a crate::ioctl_user::DivertAddress,
}

impl<'a> BpfContext<'a> {
    fn load_word(&self, offset: usize) -> Option<u32> {
        if offset + 4 <= self.packet.len() {
            let bytes: [u8; 4] = self.packet[offset..offset + 4].try_into().unwrap();
            Some(u32::from_be_bytes(bytes))
        } else {
            None
        }
    }

    fn load_half(&self, offset: usize) -> Option<u16> {
        if offset + 2 <= self.packet.len() {
            let bytes: [u8; 2] = self.packet[offset..offset + 2].try_into().unwrap();
            Some(u16::from_be_bytes(bytes))
        } else {
            None
        }
    }

    fn load_byte(&self, offset: usize) -> Option<u8> {
        self.packet.get(offset).copied()
    }
}

pub fn bpf_run_filter(insns: &[BpfInsn], ctx: &BpfContext) -> u32 {
    if insns.is_empty() {
        return u32::MAX; // Default allow if no filter
    }

    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut m: [u32; 16] = [0; 16];
    let mut pc: usize = 0;

    while pc < insns.len() {
        let insn = &insns[pc];
        pc += 1;

        match insn.code & BPF_CLASS_MASK {
            BPF_LD => {
                let val = match insn.code & BPF_MODE_MASK {
                    BPF_IMM => insn.k,
                    BPF_ABS => {
                        let offset = insn.k;
                        if offset >= 0xfffff000 {
                            match offset {
                                BPF_ADDR_FLAGS_OFFSET => ctx.address.flags,
                                BPF_ADDR_IF_IDX_OFFSET => unsafe { ctx.address.data.network.if_idx },
                                BPF_ADDR_SUB_IF_IDX_OFFSET => unsafe { ctx.address.data.network.sub_if_idx },
                                BPF_ADDR_PROCESS_ID_OFFSET => unsafe {
                                    let l = ctx.address.layer();
                                    if l == crate::ioctl_user::LAYER_SOCKET as u8 {
                                        ctx.address.data.socket.process_id
                                    } else if l == crate::ioctl_user::LAYER_FLOW as u8 {
                                        ctx.address.data.flow.process_id
                                    } else {
                                        0
                                    }
                                },
                                BPF_ADDR_LAYER_OFFSET => ctx.address.layer() as u32,
                                _ => return 0,
                            }
                        } else {
                            let offset = offset as usize;
                            match insn.code & BPF_SIZE_MASK {
                                BPF_W => match ctx.load_word(offset) {
                                    Some(v) => v,
                                    None => return 0,
                                },
                                BPF_H => match ctx.load_half(offset) {
                                    Some(v) => v as u32,
                                    None => return 0,
                                },
                                BPF_B => match ctx.load_byte(offset) {
                                    Some(v) => v as u32,
                                    None => return 0,
                                },
                                _ => return 0,
                            }
                        }
                    }
                    BPF_IND => {
                        let offset = (x.wrapping_add(insn.k)) as usize;
                        match insn.code & BPF_SIZE_MASK {
                            BPF_W => match ctx.load_word(offset) {
                                Some(v) => v,
                                None => return 0,
                            },
                            BPF_H => match ctx.load_half(offset) {
                                Some(v) => v as u32,
                                None => return 0,
                            },
                            BPF_B => match ctx.load_byte(offset) {
                                Some(v) => v as u32,
                                None => return 0,
                            },
                            _ => return 0,
                        }
                    }
                    BPF_MEM => m[(insn.k & 0xf) as usize],
                    BPF_LEN => ctx.packet.len() as u32,
                    _ => return 0,
                };
                a = val;
            }
            BPF_LDX => {
                let val = match insn.code & BPF_MODE_MASK {
                    BPF_IMM => insn.k,
                    BPF_MEM => m[(insn.k & 0xf) as usize],
                    BPF_LEN => ctx.packet.len() as u32,
                    BPF_MSH => {
                        let offset = insn.k as usize;
                        match ctx.load_byte(offset) {
                            Some(v) => ((v & 0xf) << 2) as u32,
                            None => return 0,
                        }
                    }
                    _ => return 0,
                };
                x = val;
            }
            BPF_ST => {
                m[(insn.k & 0xf) as usize] = a;
            }
            BPF_STX => {
                m[(insn.k & 0xf) as usize] = x;
            }
            BPF_ALU => {
                let src = if (insn.code & BPF_SRC_MASK) == BPF_X {
                    x
                } else {
                    insn.k
                };
                match insn.code & BPF_OP_MASK {
                    BPF_ADD => a = a.wrapping_add(src),
                    BPF_SUB => a = a.wrapping_sub(src),
                    BPF_MUL => a = a.wrapping_mul(src),
                    BPF_DIV => {
                        if src == 0 {
                            return 0;
                        }
                        a /= src;
                    }
                    BPF_OR => a |= src,
                    BPF_AND => a &= src,
                    BPF_LSH => a = a.wrapping_shl(src & 31),
                    BPF_RSH => a = a.wrapping_shr(src & 31),
                    BPF_NEG => a = a.wrapping_neg(),
                    _ => return 0,
                }
            }
            BPF_JMP => {
                let src = if (insn.code & BPF_SRC_MASK) == BPF_X {
                    x
                } else {
                    insn.k
                };
                let jump = match insn.code & BPF_OP_MASK {
                    BPF_JA => {
                        match pc.checked_add(insn.k as usize) {
                            Some(target) if target < insns.len() => {
                                pc = target;
                                continue;
                            }
                            _ => return 0,
                        }
                    }
                    BPF_JEQ => a == src,
                    BPF_JGT => a > src,
                    BPF_JGE => a >= src,
                    BPF_JSET => (a & src) != 0,
                    _ => return 0,
                };
                let offset = if jump { insn.jt } else { insn.jf } as usize;
                match pc.checked_add(offset) {
                    Some(target) if target < insns.len() => {
                        pc = target;
                    }
                    _ => return 0,
                }
            }
            BPF_RET => {
                return if (insn.code & BPF_SRC_MASK) == BPF_X {
                    x
                } else {
                    insn.k
                };
            }
            _ => return 0,
        }
    }
    0
}