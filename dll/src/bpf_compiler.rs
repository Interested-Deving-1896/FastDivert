//! A BPF compiler for user space that supports tcpdump-like filter syntax.
//! Supports basic syntax like:
//! `tcp`, `udp`, `icmp`, `ip`, `port 80`, `src port 80`, `dst port 80`,
//! `host 1.2.3.4`, `src host 1.2.3.4`, `dst host 1.2.3.4`
//! and combinators: `and` (`&&`), `or` (`||`), `not` (`!`), `(` and `)`.

use std::str::FromStr;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// Instruction classes
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

// ld/ldx fields
const BPF_W: u16 = 0x00; // 32-bit
const BPF_H: u16 = 0x08; // 16-bit
const BPF_B: u16 = 0x10; // 8-bit

// modes
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;

// alu/jmp operations
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RSH: u16 = 0x70;

// Virtual offsets for DivertAddress fields
const BPF_ADDR_FLAGS_OFFSET: u32 = 0xfffff000;
const BPF_ADDR_IF_IDX_OFFSET: u32 = 0xfffff004;
const BPF_ADDR_SUB_IF_IDX_OFFSET: u32 = 0xfffff008;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    And,
    Or,
    Not,
    LParen,
    RParen,
    Tcp,
    Udp,
    Icmp,
    Ip,
    Port,
    Host,
    Src,
    Dst,
    Outbound,
    Inbound,
    Loopback,
    Impostor,
    IfIndex,
    SubIfIndex,
    Ident(String),
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '(' {
            tokens.push(Token::LParen);
            chars.next();
        } else if c == ')' {
            tokens.push(Token::RParen);
            chars.next();
        } else if c == '&' {
            chars.next();
            if chars.peek() == Some(&'&') {
                chars.next();
            }
            tokens.push(Token::And);
        } else if c == '|' {
            chars.next();
            if chars.peek() == Some(&'|') {
                chars.next();
            }
            tokens.push(Token::Or);
        } else if c == '!' {
            tokens.push(Token::Not);
            chars.next();
        } else if c.is_alphanumeric() || c == '.' || c == '_' {
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '.' || c == '_' {
                    word.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            match word.to_lowercase().as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                "tcp" => tokens.push(Token::Tcp),
                "udp" => tokens.push(Token::Udp),
                "icmp" => tokens.push(Token::Icmp),
                "ip" => tokens.push(Token::Ip),
                "port" => tokens.push(Token::Port),
                "host" => tokens.push(Token::Host),
                "src" => tokens.push(Token::Src),
                "dst" => tokens.push(Token::Dst),
                "outbound" => tokens.push(Token::Outbound),
                "inbound" => tokens.push(Token::Inbound),
                "loopback" => tokens.push(Token::Loopback),
                "impostor" => tokens.push(Token::Impostor),
                "ifindex" => tokens.push(Token::IfIndex),
                "sub_ifindex" => tokens.push(Token::SubIfIndex),
                _ => tokens.push(Token::Ident(word)),
            }
        } else {
            return Err(format!("Unexpected character: {}", c));
        }
    }
    Ok(tokens)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Dir {
    Src,
    Dst,
    SrcOrDst,
    SrcAndDst,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Tcp,
    Udp,
    Icmp,
    Ip,
    Host(Dir, u32),
    Port(Dir, u16),
    Outbound,
    Inbound,
    Loopback,
    Impostor,
    IfIndex(u32),
    SubIfIndex(u32),
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn parse_expr(&mut self) -> Result<Expr, String> {
        let mut node = self.parse_term()?;
        while self.pos < self.tokens.len() {
            if self.tokens[self.pos] == Token::Or {
                self.pos += 1;
                let right = self.parse_term()?;
                node = Expr::Or(Box::new(node), Box::new(right));
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_term(&mut self) -> Result<Expr, String> {
        let mut node = self.parse_factor()?;
        while self.pos < self.tokens.len() {
            if self.tokens[self.pos] == Token::And {
                self.pos += 1;
                let right = self.parse_factor()?;
                node = Expr::And(Box::new(node), Box::new(right));
            } else if self.tokens[self.pos] == Token::Or || self.tokens[self.pos] == Token::RParen {
                break;
            } else {
                // implicit AND when an adjacent token acts as a primitive start
                let right = self.parse_factor()?;
                node = Expr::And(Box::new(node), Box::new(right));
            }
        }
        Ok(node)
    }

    fn parse_factor(&mut self) -> Result<Expr, String> {
        if self.pos >= self.tokens.len() {
            return Err("Unexpected end of input".to_string());
        }
        match &self.tokens[self.pos] {
            Token::Not => {
                self.pos += 1;
                let inner = self.parse_factor()?;
                Ok(Expr::Not(Box::new(inner)))
            }
            Token::LParen => {
                self.pos += 1;
                let inner = self.parse_expr()?;
                if self.pos >= self.tokens.len() || self.tokens[self.pos] != Token::RParen {
                    return Err("Expected ')'".to_string());
                }
                self.pos += 1;
                Ok(inner)
            }
            _ => self.parse_primitive(),
        }
    }

    fn parse_primitive(&mut self) -> Result<Expr, String> {
        let mut dir = Dir::SrcOrDst;
        if self.pos < self.tokens.len() {
            match &self.tokens[self.pos] {
                Token::Src => { dir = Dir::Src; self.pos += 1; }
                Token::Dst => { dir = Dir::Dst; self.pos += 1; }
                _ => {}
            }
        }
        if self.pos >= self.tokens.len() {
            return Err("Unexpected end of input".to_string());
        }
        match &self.tokens[self.pos] {
            Token::Tcp => { self.pos += 1; Ok(Expr::Tcp) }
            Token::Udp => { self.pos += 1; Ok(Expr::Udp) }
            Token::Icmp => { self.pos += 1; Ok(Expr::Icmp) }
            Token::Ip => { self.pos += 1; Ok(Expr::Ip) }
            Token::Outbound => { self.pos += 1; Ok(Expr::Outbound) }
            Token::Inbound => { self.pos += 1; Ok(Expr::Inbound) }
            Token::Loopback => { self.pos += 1; Ok(Expr::Loopback) }
            Token::Impostor => { self.pos += 1; Ok(Expr::Impostor) }
            Token::IfIndex => {
                self.pos += 1;
                if self.pos >= self.tokens.len() {
                    return Err("Expected interface index after 'ifindex'".to_string());
                }
                if let Token::Ident(val_str) = &self.tokens[self.pos] {
                    self.pos += 1;
                    let val = val_str.parse::<u32>().map_err(|_| format!("Invalid interface index: {}", val_str))?;
                    Ok(Expr::IfIndex(val))
                } else {
                    Err("Expected interface index after 'ifindex'".to_string())
                }
            }
            Token::SubIfIndex => {
                self.pos += 1;
                if self.pos >= self.tokens.len() {
                    return Err("Expected sub interface index after 'sub_ifindex'".to_string());
                }
                if let Token::Ident(val_str) = &self.tokens[self.pos] {
                    self.pos += 1;
                    let val = val_str.parse::<u32>().map_err(|_| format!("Invalid sub interface index: {}", val_str))?;
                    Ok(Expr::SubIfIndex(val))
                } else {
                    Err("Expected sub interface index after 'sub_ifindex'".to_string())
                }
            }
            Token::Host => {
                self.pos += 1;
                if self.pos >= self.tokens.len() {
                    return Err("Expected IP after 'host'".to_string());
                }
                if let Token::Ident(ip_str) = &self.tokens[self.pos] {
                    self.pos += 1;
                    let ip = std::net::Ipv4Addr::from_str(ip_str).map_err(|_| format!("Invalid IP: {}", ip_str))?;
                    Ok(Expr::Host(dir, u32::from_be_bytes(ip.octets())))
                } else {
                    Err("Expected IP after 'host'".to_string())
                }
            }
            Token::Port => {
                self.pos += 1;
                if self.pos >= self.tokens.len() {
                    return Err("Expected port number after 'port'".to_string());
                }
                if let Token::Ident(port_str) = &self.tokens[self.pos] {
                    self.pos += 1;
                    let port = port_str.parse::<u16>().map_err(|_| format!("Invalid port: {}", port_str))?;
                    Ok(Expr::Port(dir, port))
                } else {
                    Err("Expected port number after 'port'".to_string())
                }
            }
            _ => Err(format!("Unexpected token: {:?}", self.tokens[self.pos]))
        }
    }
}

#[allow(dead_code)]
enum IrInsn {
    Insn(BpfInsn),
    Jmp(usize),
    JmpCond(u16, u32, usize, usize),
    Label(usize),
}

struct Compiler {
    insns: Vec<IrInsn>,
    next_label: usize,
}

impl Compiler {
    fn new_label(&mut self) -> usize {
        let l = self.next_label;
        self.next_label += 1;
        l
    }

    fn emit_label(&mut self, label: usize) {
        self.insns.push(IrInsn::Label(label));
    }

    fn emit(&mut self, insn: BpfInsn) {
        self.insns.push(IrInsn::Insn(insn));
    }

    fn compile_expr(&mut self, expr: &Expr, label_true: usize, label_false: usize) {
        match expr {
            Expr::And(left, right) => {
                let l_next = self.new_label();
                self.compile_expr(left, l_next, label_false);
                self.emit_label(l_next);
                self.compile_expr(right, label_true, label_false);
            }
            Expr::Or(left, right) => {
                let l_next = self.new_label();
                self.compile_expr(left, label_true, l_next);
                self.emit_label(l_next);
                self.compile_expr(right, label_true, label_false);
            }
            Expr::Not(inner) => {
                self.compile_expr(inner, label_false, label_true);
            }
            Expr::Tcp => {
                self.emit(BpfInsn { code: BPF_LD | BPF_B | BPF_ABS, jt: 0, jf: 0, k: 9 });
                self.insns.push(IrInsn::JmpCond(BPF_JEQ, 6, label_true, label_false));
            }
            Expr::Udp => {
                self.emit(BpfInsn { code: BPF_LD | BPF_B | BPF_ABS, jt: 0, jf: 0, k: 9 });
                self.insns.push(IrInsn::JmpCond(BPF_JEQ, 17, label_true, label_false));
            }
            Expr::Icmp => {
                self.emit(BpfInsn { code: BPF_LD | BPF_B | BPF_ABS, jt: 0, jf: 0, k: 9 });
                self.insns.push(IrInsn::JmpCond(BPF_JEQ, 1, label_true, label_false));
            }
            Expr::Ip => {
                self.emit(BpfInsn { code: BPF_LD | BPF_B | BPF_ABS, jt: 0, jf: 0, k: 0 }); // IP first byte
                self.emit(BpfInsn { code: BPF_ALU | BPF_RSH | BPF_K, jt: 0, jf: 0, k: 4 }); // >> 4
                self.insns.push(IrInsn::JmpCond(BPF_JEQ, 4, label_true, label_false));
            }
            Expr::Host(dir, ip) => {
                match dir {
                    Dir::Src => {
                        self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 12 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, *ip, label_true, label_false));
                    }
                    Dir::Dst => {
                        self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 16 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, *ip, label_true, label_false));
                    }
                    Dir::SrcOrDst => {
                        let l_next = self.new_label();
                        self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 12 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, *ip, label_true, l_next));
                        self.emit_label(l_next);
                        self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 16 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, *ip, label_true, label_false));
                    }
                    Dir::SrcAndDst => {
                        let l_next = self.new_label();
                        self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 12 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, *ip, l_next, label_false));
                        self.emit_label(l_next);
                        self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 16 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, *ip, label_true, label_false));
                    }
                }
            }
            Expr::Port(dir, port) => {
                // load X with IHL
                self.emit(BpfInsn { code: BPF_LDX | BPF_B | BPF_MSH, jt: 0, jf: 0, k: 0 });
                let p = *port as u32;
                match dir {
                    Dir::Src => {
                        self.emit(BpfInsn { code: BPF_LD | BPF_H | BPF_IND, jt: 0, jf: 0, k: 0 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, p, label_true, label_false));
                    }
                    Dir::Dst => {
                        self.emit(BpfInsn { code: BPF_LD | BPF_H | BPF_IND, jt: 0, jf: 0, k: 2 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, p, label_true, label_false));
                    }
                    Dir::SrcOrDst => {
                        let l_next = self.new_label();
                        self.emit(BpfInsn { code: BPF_LD | BPF_H | BPF_IND, jt: 0, jf: 0, k: 0 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, p, label_true, l_next));
                        self.emit_label(l_next);
                        self.emit(BpfInsn { code: BPF_LD | BPF_H | BPF_IND, jt: 0, jf: 0, k: 2 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, p, label_true, label_false));
                    }
                    Dir::SrcAndDst => {
                        let l_next = self.new_label();
                        self.emit(BpfInsn { code: BPF_LD | BPF_H | BPF_IND, jt: 0, jf: 0, k: 0 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, p, l_next, label_false));
                        self.emit_label(l_next);
                        self.emit(BpfInsn { code: BPF_LD | BPF_H | BPF_IND, jt: 0, jf: 0, k: 2 });
                        self.insns.push(IrInsn::JmpCond(BPF_JEQ, p, label_true, label_false));
                    }
                }
            }
            Expr::Outbound => {
                self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: BPF_ADDR_FLAGS_OFFSET });
                self.insns.push(IrInsn::JmpCond(BPF_JSET, 1 << 17, label_true, label_false));
            }
            Expr::Inbound => {
                self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: BPF_ADDR_FLAGS_OFFSET });
                self.insns.push(IrInsn::JmpCond(BPF_JSET, 1 << 17, label_false, label_true));
            }
            Expr::Loopback => {
                self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: BPF_ADDR_FLAGS_OFFSET });
                self.insns.push(IrInsn::JmpCond(BPF_JSET, 1 << 18, label_true, label_false));
            }
            Expr::Impostor => {
                self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: BPF_ADDR_FLAGS_OFFSET });
                self.insns.push(IrInsn::JmpCond(BPF_JSET, 1 << 19, label_true, label_false));
            }
            Expr::IfIndex(if_idx) => {
                self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: BPF_ADDR_IF_IDX_OFFSET });
                self.insns.push(IrInsn::JmpCond(BPF_JEQ, *if_idx, label_true, label_false));
            }
            Expr::SubIfIndex(sub_if_idx) => {
                self.emit(BpfInsn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: BPF_ADDR_SUB_IF_IDX_OFFSET });
                self.insns.push(IrInsn::JmpCond(BPF_JEQ, *sub_if_idx, label_true, label_false));
            }
        }
    }
}

fn resolve_insns(ir: Vec<IrInsn>) -> Result<Vec<BpfInsn>, String> {
    let mut label_offsets = std::collections::HashMap::new();
    let mut real_insn_idx = 0;

    for insn in &ir {
        if let IrInsn::Label(id) = insn {
            label_offsets.insert(*id, real_insn_idx);
        } else {
            real_insn_idx += 1;
        }
    }

    let mut final_insns = Vec::new();
    real_insn_idx = 0;

    for insn in &ir {
        match insn {
            IrInsn::Label(_) => {},
            IrInsn::Insn(i) => {
                final_insns.push(*i);
                real_insn_idx += 1;
            },
            IrInsn::Jmp(l) => {
                let target = *label_offsets.get(l).unwrap();
                let offset = target as isize - real_insn_idx as isize - 1;
                if offset < 0 {
                    return Err("Negative jump offset not supported".to_string());
                }
                final_insns.push(BpfInsn {
                    code: BPF_JMP | BPF_JA,
                    jt: 0,
                    jf: 0,
                    k: offset as u32,
                });
                real_insn_idx += 1;
            },
            IrInsn::JmpCond(op, k, jt_label, jf_label) => {
                let target_t = *label_offsets.get(jt_label).unwrap();
                let target_f = *label_offsets.get(jf_label).unwrap();
                let offset_t = target_t as isize - real_insn_idx as isize - 1;
                let offset_f = target_f as isize - real_insn_idx as isize - 1;
                if offset_t < 0 || offset_t > 255 || offset_f < 0 || offset_f > 255 {
                    return Err("Conditional jump offset out of bounds".to_string());
                }
                final_insns.push(BpfInsn {
                    code: BPF_JMP | *op | BPF_K,
                    jt: offset_t as u8,
                    jf: offset_f as u8,
                    k: *k,
                });
                real_insn_idx += 1;
            }
        }
    }

    Ok(final_insns)
}

pub fn compile_bpf(filter: &str) -> Result<Vec<BpfInsn>, String> {
    if filter.trim().is_empty() || filter.trim() == "true" {
        return Ok(vec![
            BpfInsn { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: u32::MAX }
        ]);
    }

    let tokens = tokenize(filter)?;
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_expr()?;

    if parser.pos < parser.tokens.len() {
        return Err(format!("Unexpected trailing tokens starting at {:?}", parser.tokens[parser.pos]));
    }

    let mut compiler = Compiler {
        insns: Vec::new(),
        next_label: 0,
    };

    let label_true = compiler.new_label();
    let label_false = compiler.new_label();

    compiler.compile_expr(&expr, label_true, label_false);

    compiler.emit_label(label_true);
    compiler.emit(BpfInsn { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: u32::MAX });
    compiler.emit_label(label_false);
    compiler.emit(BpfInsn { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: 0 });

    resolve_insns(compiler.insns)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BpfContext<'a> {
        packet: &'a [u8],
        address: &'a crate::DivertAddress,
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

    fn bpf_run_filter(insns: &[BpfInsn], ctx: &BpfContext) -> u32 {
        if insns.is_empty() {
            return u32::MAX;
        }

        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut m: [u32; 16] = [0; 16];
        let mut pc: usize = 0;

        while pc < insns.len() {
            let insn = &insns[pc];
            pc += 1;

            match insn.code & 0x07 {
                0x00 => { // BPF_LD
                    let val = match insn.code & 0xe0 {
                        0x00 => insn.k, // BPF_IMM
                        0x20 => { // BPF_ABS
                            let offset = insn.k;
                            if offset >= 0xfffff000 {
                                match offset {
                                    0xfffff000 => ctx.address.flags,
                                    0xfffff004 => unsafe { ctx.address.data.network.if_idx },
                                    0xfffff008 => unsafe { ctx.address.data.network.sub_if_idx },
                                    _ => return 0,
                                }
                            } else {
                                let offset = offset as usize;
                                match insn.code & 0x18 {
                                    0x00 => match ctx.load_word(offset) {
                                        Some(v) => v,
                                        None => return 0,
                                    },
                                    0x08 => match ctx.load_half(offset) {
                                        Some(v) => v as u32,
                                        None => return 0,
                                    },
                                    0x10 => match ctx.load_byte(offset) {
                                        Some(v) => v as u32,
                                        None => return 0,
                                    },
                                    _ => return 0,
                                }
                            }
                        }
                        0x40 => { // BPF_IND
                            let offset = (x.wrapping_add(insn.k)) as usize;
                            match insn.code & 0x18 {
                                0x00 => match ctx.load_word(offset) {
                                    Some(v) => v,
                                    None => return 0,
                                },
                                0x08 => match ctx.load_half(offset) {
                                    Some(v) => v as u32,
                                    None => return 0,
                                },
                                0x10 => match ctx.load_byte(offset) {
                                    Some(v) => v as u32,
                                    None => return 0,
                                },
                                _ => return 0,
                            }
                        }
                        0x60 => m[(insn.k & 0xf) as usize],
                        0x80 => ctx.packet.len() as u32,
                        _ => return 0,
                    };
                    a = val;
                }
                0x01 => { // BPF_LDX
                    let val = match insn.code & 0xe0 {
                        0x00 => insn.k,
                        0x60 => m[(insn.k & 0xf) as usize],
                        0x80 => ctx.packet.len() as u32,
                        0xa0 => { // BPF_MSH
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
                0x02 => { // BPF_ST
                    m[(insn.k & 0xf) as usize] = a;
                }
                0x03 => { // BPF_STX
                    m[(insn.k & 0xf) as usize] = x;
                }
                0x04 => { // BPF_ALU
                    let src = if (insn.code & 0x08) == 0x08 {
                        x
                    } else {
                        insn.k
                    };
                    match insn.code & 0xf0 {
                        0x00 => a = a.wrapping_add(src),
                        0x10 => a = a.wrapping_sub(src),
                        0x20 => a = a.wrapping_mul(src),
                        0x30 => {
                            if src == 0 {
                                return 0;
                            }
                            a /= src;
                        }
                        0x40 => a |= src,
                        0x50 => a &= src,
                        0x60 => a = a.wrapping_shl(src & 31),
                        0x70 => a = a.wrapping_shr(src & 31),
                        0x80 => a = a.wrapping_neg(),
                        _ => return 0,
                    }
                }
                0x05 => { // BPF_JMP
                    let src = if (insn.code & 0x08) == 0x08 {
                        x
                    } else {
                        insn.k
                    };
                    let jump = match insn.code & 0xf0 {
                        0x00 => { // BPF_JA
                            match pc.checked_add(insn.k as usize) {
                                Some(target) if target < insns.len() => {
                                    pc = target;
                                    continue;
                                }
                                _ => return 0,
                            }
                        }
                        0x10 => a == src,
                        0x20 => a > src,
                        0x30 => a >= src,
                        0x40 => (a & src) != 0,
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
                0x06 => { // BPF_RET
                    return if (insn.code & 0x08) == 0x08 {
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

    fn create_test_address(flags: u32, if_idx: u32, sub_if_idx: u32) -> crate::DivertAddress {
        crate::DivertAddress {
            timestamp: 0,
            flags,
            reserved2: 0,
            data: crate::types::DivertAddressData {
                network: crate::types::DivertDataNetwork {
                    if_idx,
                    sub_if_idx,
                }
            }
        }
    }

    fn create_test_ipv4_packet(proto: u8, src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0; 40];
        pkt[0] = 0x45; // IPv4, IHL = 20 bytes
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        
        // TCP/UDP Ports
        let sp_bytes = src_port.to_be_bytes();
        let dp_bytes = dst_port.to_be_bytes();
        pkt[20..22].copy_from_slice(&sp_bytes);
        pkt[22..24].copy_from_slice(&dp_bytes);
        pkt
    }

    #[test]
    fn test_compile_outbound_and_tcp_port() {
        let insns = compile_bpf("outbound & tcp port 80").unwrap();
        assert!(!insns.is_empty());
        let has_flags_load = insns.iter().any(|insn| insn.k == BPF_ADDR_FLAGS_OFFSET);
        assert!(has_flags_load, "Should load address flags");
        let has_port_80 = insns.iter().any(|insn| insn.k == 80);
        assert!(has_port_80, "Should compile port 80 check");
    }

    #[test]
    fn test_empty_filter() {
        let insns = compile_bpf("").unwrap();
        let addr = create_test_address(0, 0, 0);
        let ctx = BpfContext { packet: &[], address: &addr };
        let res = bpf_run_filter(&insns, &ctx);
        assert_eq!(res, u32::MAX);

        let insns_true = compile_bpf("true").unwrap();
        let res_true = bpf_run_filter(&insns_true, &ctx);
        assert_eq!(res_true, u32::MAX);
    }

    #[test]
    fn test_metadata_flags() {
        // 1. outbound
        let insns_out = compile_bpf("outbound").unwrap();
        let addr_out = create_test_address(1 << 17, 0, 0);
        let ctx_out = BpfContext { packet: &[], address: &addr_out };
        assert_eq!(bpf_run_filter(&insns_out, &ctx_out), u32::MAX);

        let addr_in = create_test_address(0, 0, 0);
        let ctx_in = BpfContext { packet: &[], address: &addr_in };
        assert_eq!(bpf_run_filter(&insns_out, &ctx_in), 0);

        // 2. inbound
        let insns_in = compile_bpf("inbound").unwrap();
        assert_eq!(bpf_run_filter(&insns_in, &ctx_in), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_in, &ctx_out), 0);

        // 3. loopback
        let insns_loop = compile_bpf("loopback").unwrap();
        let addr_loop = create_test_address(1 << 18, 0, 0);
        let ctx_loop = BpfContext { packet: &[], address: &addr_loop };
        assert_eq!(bpf_run_filter(&insns_loop, &ctx_loop), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_loop, &ctx_in), 0);

        // 4. impostor
        let insns_imp = compile_bpf("impostor").unwrap();
        let addr_imp = create_test_address(1 << 19, 0, 0);
        let ctx_imp = BpfContext { packet: &[], address: &addr_imp };
        assert_eq!(bpf_run_filter(&insns_imp, &ctx_imp), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_imp, &ctx_in), 0);
    }

    #[test]
    fn test_interface_index() {
        let insns_if = compile_bpf("ifindex 5").unwrap();
        let addr_match = create_test_address(0, 5, 0);
        let ctx_match = BpfContext { packet: &[], address: &addr_match };
        assert_eq!(bpf_run_filter(&insns_if, &ctx_match), u32::MAX);

        let addr_mismatch = create_test_address(0, 10, 0);
        let ctx_mismatch = BpfContext { packet: &[], address: &addr_mismatch };
        assert_eq!(bpf_run_filter(&insns_if, &ctx_mismatch), 0);

        let insns_sub = compile_bpf("sub_ifindex 2").unwrap();
        let addr_sub_match = create_test_address(0, 0, 2);
        let ctx_sub_match = BpfContext { packet: &[], address: &addr_sub_match };
        assert_eq!(bpf_run_filter(&insns_sub, &ctx_sub_match), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_sub, &ctx_match), 0);
    }

    #[test]
    fn test_protocols() {
        let insns_tcp = compile_bpf("tcp").unwrap();
        let insns_udp = compile_bpf("udp").unwrap();
        let insns_icmp = compile_bpf("icmp").unwrap();
        let insns_ip = compile_bpf("ip").unwrap();

        let tcp_pkt = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        let udp_pkt = create_test_ipv4_packet(17, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 53);
        let icmp_pkt = create_test_ipv4_packet(1, [10, 0, 0, 1], [10, 0, 0, 2], 0, 0);

        let addr = create_test_address(0, 0, 0);

        assert_eq!(bpf_run_filter(&insns_tcp, &BpfContext { packet: &tcp_pkt, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_tcp, &BpfContext { packet: &udp_pkt, address: &addr }), 0);

        assert_eq!(bpf_run_filter(&insns_udp, &BpfContext { packet: &udp_pkt, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_udp, &BpfContext { packet: &tcp_pkt, address: &addr }), 0);

        assert_eq!(bpf_run_filter(&insns_icmp, &BpfContext { packet: &icmp_pkt, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_icmp, &BpfContext { packet: &tcp_pkt, address: &addr }), 0);

        assert_eq!(bpf_run_filter(&insns_ip, &BpfContext { packet: &tcp_pkt, address: &addr }), u32::MAX);
    }

    #[test]
    fn test_hosts() {
        let insns_host = compile_bpf("host 192.168.1.100").unwrap();
        let insns_src = compile_bpf("src host 10.0.0.1").unwrap();
        let insns_dst = compile_bpf("dst host 10.0.0.2").unwrap();

        let pkt1 = create_test_ipv4_packet(6, [192, 168, 1, 100], [10, 0, 0, 2], 1234, 80);
        let pkt2 = create_test_ipv4_packet(6, [10, 0, 0, 1], [192, 168, 1, 100], 1234, 80);
        let pkt3 = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);

        let addr = create_test_address(0, 0, 0);

        assert_eq!(bpf_run_filter(&insns_host, &BpfContext { packet: &pkt1, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_host, &BpfContext { packet: &pkt2, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_host, &BpfContext { packet: &pkt3, address: &addr }), 0);

        assert_eq!(bpf_run_filter(&insns_src, &BpfContext { packet: &pkt3, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_src, &BpfContext { packet: &pkt1, address: &addr }), 0);

        assert_eq!(bpf_run_filter(&insns_dst, &BpfContext { packet: &pkt3, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_dst, &BpfContext { packet: &pkt2, address: &addr }), 0);
    }

    #[test]
    fn test_ports() {
        let insns_port = compile_bpf("port 80").unwrap();
        let insns_src = compile_bpf("src port 443").unwrap();
        let insns_dst = compile_bpf("dst port 8080").unwrap();

        let pkt1 = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 80, 1234);
        let pkt2 = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        let pkt3 = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 443, 8080);
        let pkt4 = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 1234);

        let addr = create_test_address(0, 0, 0);

        assert_eq!(bpf_run_filter(&insns_port, &BpfContext { packet: &pkt1, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_port, &BpfContext { packet: &pkt2, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_port, &BpfContext { packet: &pkt4, address: &addr }), 0);

        assert_eq!(bpf_run_filter(&insns_src, &BpfContext { packet: &pkt3, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_src, &BpfContext { packet: &pkt1, address: &addr }), 0);

        assert_eq!(bpf_run_filter(&insns_dst, &BpfContext { packet: &pkt3, address: &addr }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns_dst, &BpfContext { packet: &pkt2, address: &addr }), 0);
    }

    #[test]
    fn test_complex_expressions() {
        let insns = compile_bpf("outbound & tcp port 80").unwrap();
        let match_pkt = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        let non_match_pkt = create_test_ipv4_packet(17, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        
        let addr_out = create_test_address(1 << 17, 0, 0);
        let addr_in = create_test_address(0, 0, 0);

        assert_eq!(bpf_run_filter(&insns, &BpfContext { packet: &match_pkt, address: &addr_out }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns, &BpfContext { packet: &match_pkt, address: &addr_in }), 0);
        assert_eq!(bpf_run_filter(&insns, &BpfContext { packet: &non_match_pkt, address: &addr_out }), 0);

        let insns2 = compile_bpf("(inbound | loopback) & udp port 53").unwrap();
        let udp_dns_pkt = create_test_ipv4_packet(17, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 53);
        
        let addr_loop = create_test_address(1 << 18, 0, 0);
        let addr_out_only = create_test_address(1 << 17, 0, 0);

        assert_eq!(bpf_run_filter(&insns2, &BpfContext { packet: &udp_dns_pkt, address: &addr_in }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns2, &BpfContext { packet: &udp_dns_pkt, address: &addr_loop }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns2, &BpfContext { packet: &udp_dns_pkt, address: &addr_out_only }), 0);

        // "not outbound and (tcp or udp) and port 443"
        let insns3 = compile_bpf("not outbound and (tcp or udp) and port 443").unwrap();
        let tcp_443 = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 443);
        let udp_443 = create_test_ipv4_packet(17, [10, 0, 0, 1], [10, 0, 0, 2], 443, 1234);
        let tcp_80 = create_test_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);

        assert_eq!(bpf_run_filter(&insns3, &BpfContext { packet: &tcp_443, address: &addr_in }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns3, &BpfContext { packet: &udp_443, address: &addr_in }), u32::MAX);
        assert_eq!(bpf_run_filter(&insns3, &BpfContext { packet: &tcp_443, address: &addr_out }), 0); // outbound
        assert_eq!(bpf_run_filter(&insns3, &BpfContext { packet: &tcp_80, address: &addr_in }), 0); // port mismatch
    }

    #[test]
    fn test_safety_div_by_zero() {
        let addr = create_test_address(0, 0, 0);
        let ctx = BpfContext { packet: &[], address: &addr };

        // 1. Division by zero with immediate value
        let insns_div_k = vec![
            BpfInsn { code: 0x00, jt: 0, jf: 0, k: 10 }, // BPF_LD | BPF_IMM
            BpfInsn { code: 0x04 | 0x30 | 0x00, jt: 0, jf: 0, k: 0 }, // BPF_ALU | BPF_DIV | BPF_K (div by 0)
            BpfInsn { code: 0x06, jt: 0, jf: 0, k: u32::MAX }, // BPF_RET | BPF_K
        ];
        assert_eq!(bpf_run_filter(&insns_div_k, &ctx), 0); // Should safely return 0 (reject) instead of panicking

        // 2. Division by zero with X register
        let insns_div_x = vec![
            BpfInsn { code: 0x00, jt: 0, jf: 0, k: 10 }, // BPF_LD | BPF_IMM, A = 10
            BpfInsn { code: 0x01, jt: 0, jf: 0, k: 0 },  // BPF_LDX | BPF_IMM, X = 0
            BpfInsn { code: 0x04 | 0x30 | 0x08, jt: 0, jf: 0, k: 0 }, // BPF_ALU | BPF_DIV | BPF_X (div by X which is 0)
            BpfInsn { code: 0x06, jt: 0, jf: 0, k: u32::MAX }, // BPF_RET
        ];
        assert_eq!(bpf_run_filter(&insns_div_x, &ctx), 0); // Should safely return 0
    }

    #[test]
    fn test_safety_oob_packet_reads() {
        let insns = compile_bpf("tcp port 80").unwrap();
        let addr = create_test_address(0, 0, 0);

        // Empty packet buffer
        assert_eq!(bpf_run_filter(&insns, &BpfContext { packet: &[], address: &addr }), 0);

        // Short packet buffer (e.g., only 10 bytes)
        assert_eq!(bpf_run_filter(&insns, &BpfContext { packet: &[0; 10], address: &addr }), 0);
    }

    #[test]
    fn test_safety_jump_out_of_bounds() {
        let addr = create_test_address(0, 0, 0);
        let ctx = BpfContext { packet: &[], address: &addr };

        // 1. Unconditional jump out of bounds (positive overflow/OOB)
        let insns_ja_oob = vec![
            BpfInsn { code: 0x05 | 0x00, jt: 0, jf: 0, k: 100 }, // BPF_JMP | BPF_JA, target pc = 0 + 100 + 1 = 101 (OOB)
            BpfInsn { code: 0x06, jt: 0, jf: 0, k: u32::MAX },
        ];
        assert_eq!(bpf_run_filter(&insns_ja_oob, &ctx), 0); // Should safely abort with 0

        // 2. Unconditional jump with overflow (u32::MAX)
        let insns_ja_overflow = vec![
            BpfInsn { code: 0x05 | 0x00, jt: 0, jf: 0, k: u32::MAX }, // BPF_JMP | BPF_JA, target pc = 0 + u32::MAX + 1 (overflow)
            BpfInsn { code: 0x06, jt: 0, jf: 0, k: u32::MAX },
        ];
        assert_eq!(bpf_run_filter(&insns_ja_overflow, &ctx), 0); // Should safely abort with 0

        // 3. Conditional jump out of bounds
        let insns_jmp_cond_oob = vec![
            BpfInsn { code: 0x00, jt: 0, jf: 0, k: 5 }, // BPF_LD | BPF_IMM, A = 5
            BpfInsn { code: 0x05 | 0x10, jt: 50, jf: 50, k: 5 }, // BPF_JMP | BPF_JEQ, jt = 50 (OOB), jf = 50 (OOB)
            BpfInsn { code: 0x06, jt: 0, jf: 0, k: u32::MAX },
        ];
        assert_eq!(bpf_run_filter(&insns_jmp_cond_oob, &ctx), 0); // Should safely abort with 0
    }

    #[test]
    fn test_safety_invalid_opcodes() {
        let addr = create_test_address(0, 0, 0);
        let ctx = BpfContext { packet: &[], address: &addr };

        // Bytecode with an invalid instruction class / code (e.g. 0xff)
        let insns_invalid = vec![
            BpfInsn { code: 0xff, jt: 0, jf: 0, k: 0 },
            BpfInsn { code: 0x06, jt: 0, jf: 0, k: u32::MAX },
        ];
        assert_eq!(bpf_run_filter(&insns_invalid, &ctx), 0); // Should safely abort with 0
    }
}