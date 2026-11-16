//! Instruction decoding and control-flow classification via Capstone.
//!
//! Only the information required for CFG/call-graph and cycle estimation is
//! exposed: branch class, conditional flag, direct target and instruction text.

use capstone::arch::{ArchDetail, arm, arm64, riscv, x86};
use capstone::prelude::*;
use capstone::{Capstone, InsnGroupType, RegId};

use crate::error::{Error, Result};
use crate::loader::ArchKind;

/// A simple register-value effect used for bounded spawn-entry recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueSource {
    /// Constant value.
    Immediate(u64),
    /// Address value, for example `adr`/`lea` of a function.
    Address(u64),
    /// Load a pointer-sized value from this address.
    LoadAddress(u64),
    /// Load a pointer-sized value from `[base + disp]`.
    LoadFromRegister {
        /// Base register holding the address.
        base: RegId,
        /// Signed displacement.
        disp: i64,
    },
    /// Copy from another register.
    Copy(RegId),
    /// Add an immediate to another register (or the PC).
    AddImmediate {
        /// Base register.
        base: RegId,
        /// Signed immediate.
        imm: i64,
    },
    /// OR an immediate into another register, as in `AArch64` `movk`.
    OrImmediate {
        /// Base register.
        base: RegId,
        /// Unsigned immediate.
        imm: u64,
    },
}

/// A single-destination register value effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueEffect {
    /// Destination register.
    pub dest: RegId,
    /// How the value is produced.
    pub source: ValueSource,
}

/// A statically identifiable indirect branch/call target expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndirectTarget {
    /// Target address is held in a register.
    Register(RegId),
    /// Target address is `[base + displacement]`.
    RegisterMemory {
        /// Base register.
        base: RegId,
        /// Signed displacement.
        disp: i64,
    },
    /// Target pointer is stored at an absolute memory address.
    Memory(u64),
    /// Target address is `register + offset` (RISC-V `jalr`).
    RegisterOffset {
        /// Base register.
        register: RegId,
        /// Signed immediate offset.
        offset: i64,
    },
}

/// A register stored through a base register plus displacement.
///
/// This is intentionally limited to a single register source. It lets origin
/// tracking follow a value spilled to the stack (common at `-O0`) without a
/// full memory SSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryWrite {
    /// Base register.
    pub base: RegId,
    /// Signed displacement.
    pub disp: i64,
    /// Stored register.
    pub source: RegId,
}

/// A decoded instruction with normalized control-flow metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecodedInsn {
    /// Instruction address.
    pub address: u64,
    /// Instruction size in bytes.
    pub size: u8,
    /// Lowercase mnemonic.
    pub mnemonic: String,
    /// Operand text.
    pub operands: String,
    /// Call instruction.
    pub is_call: bool,
    /// Jump/branch instruction (excluding calls).
    pub is_jump: bool,
    /// Return/interrupt-return instruction.
    pub is_return: bool,
    /// Conditional branch (only meaningful for jumps).
    pub is_conditional: bool,
    /// Direct branch/call target, when statically known.
    pub direct_target: Option<u64>,
    /// Single-destination value effect, when modeled.
    pub value: Option<ValueEffect>,
    /// Register store effect, when modeled.
    pub memory_write: Option<MemoryWrite>,
    /// Indirect branch/call target expression, when modeled.
    pub indirect: Option<IndirectTarget>,
}

impl DecodedInsn {
    /// Whether this instruction ends a basic block.
    #[must_use]
    pub fn terminates_block(&self) -> bool {
        self.is_return || self.is_jump
    }

    /// Whether execution can continue at the next sequential instruction.
    #[must_use]
    pub fn has_fallthrough(&self) -> bool {
        if self.is_return {
            return false;
        }
        if self.is_jump {
            return self.is_conditional;
        }
        true
    }
}

/// Per-architecture Capstone decoder.
pub struct Decoder {
    cs: Capstone,
    arch: ArchKind,
}

impl Decoder {
    /// Creates a decoder for `arch`.
    ///
    /// # Errors
    ///
    /// Returns an error if Capstone cannot initialize the selected
    /// architecture or mode.
    pub fn new(arch: ArchKind) -> Result<Self> {
        let cs = match arch {
            ArchKind::Thumb => Capstone::new()
                .arm()
                .mode(arm::ArchMode::Thumb)
                .extra_mode([arm::ArchExtraMode::MClass].into_iter())
                .detail(true)
                .build(),
            ArchKind::Arm => Capstone::new()
                .arm()
                .mode(arm::ArchMode::Arm)
                .detail(true)
                .build(),
            ArchKind::Aarch64 => Capstone::new()
                .arm64()
                .mode(arm64::ArchMode::Arm)
                .detail(true)
                .build(),
            ArchKind::Riscv32 => Capstone::new()
                .riscv()
                .mode(riscv::ArchMode::RiscV32)
                .extra_mode([riscv::ArchExtraMode::RiscVC].into_iter())
                .detail(true)
                .build(),
            ArchKind::Riscv64 => Capstone::new()
                .riscv()
                .mode(riscv::ArchMode::RiscV64)
                .extra_mode([riscv::ArchExtraMode::RiscVC].into_iter())
                .detail(true)
                .build(),
            ArchKind::X86_64 => Capstone::new()
                .x86()
                .mode(x86::ArchMode::Mode64)
                .detail(true)
                .build(),
        }
        .map_err(|error| Error::DecoderInit {
            arch: arch.schema_name(),
            message: error.to_string(),
        })?;
        Ok(Self { cs, arch })
    }

    /// Returns the decoder architecture.
    #[must_use]
    pub fn arch(&self) -> ArchKind {
        self.arch
    }

    /// Decodes a single instruction at `address`.
    ///
    /// Returns `Ok(None)` when Capstone cannot decode an instruction from the
    /// supplied bytes (for example truncated data).
    ///
    /// # Errors
    ///
    /// Returns an error when Capstone itself fails.
    pub fn decode_one(&self, bytes: &[u8], address: u64) -> Result<Option<DecodedInsn>> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let insns = self
            .cs
            .disasm_count(bytes, address, 1)
            .map_err(|error| Error::Decode {
                address,
                message: error.to_string(),
            })?;
        let Some(insn) = insns.iter().next() else {
            return Ok(None);
        };
        let size = u8::try_from(insn.bytes().len()).unwrap_or(u8::MAX);
        if size == 0 {
            return Ok(None);
        }
        let mnemonic = insn.mnemonic().unwrap_or("").to_ascii_lowercase();
        let operands = insn.op_str().unwrap_or("").to_owned();
        let detail = self.cs.insn_detail(insn).map_err(|error| Error::Decode {
            address,
            message: error.to_string(),
        })?;
        let groups = detail.groups();
        let is_call = groups
            .iter()
            .any(|group| u32::from(group.0) == InsnGroupType::CS_GRP_CALL);
        let is_jump_group = groups
            .iter()
            .any(|group| u32::from(group.0) == InsnGroupType::CS_GRP_JUMP);
        let group_return = groups.iter().any(|group| {
            u32::from(group.0) == InsnGroupType::CS_GRP_RET
                || u32::from(group.0) == InsnGroupType::CS_GRP_IRET
        });
        let is_return = group_return || is_return_mnemonic(self.arch, &mnemonic, &operands);
        let is_jump = is_jump_group && !is_call && !is_return;
        let is_conditional = is_jump && is_conditional_mnemonic(self.arch, &mnemonic);

        let direct_target = if is_call || is_jump {
            direct_target(self.arch, &detail, &mnemonic, &operands, address)
        } else {
            None
        };
        let value = value_effect(self.arch, &detail, address, size, &mnemonic);
        let memory_write = memory_write_effect(self.arch, &detail, &mnemonic);
        let indirect = if (is_call || is_jump) && direct_target.is_none() {
            indirect_target(self.arch, &detail, &mnemonic, address, size)
        } else {
            None
        };

        Ok(Some(DecodedInsn {
            address,
            size,
            mnemonic,
            operands,
            is_call,
            is_jump,
            is_return,
            is_conditional,
            direct_target,
            value,
            memory_write,
            indirect,
        }))
    }
}

fn direct_target(
    arch: ArchKind,
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
    operands: &str,
    address: u64,
) -> Option<u64> {
    match arch {
        ArchKind::Thumb | ArchKind::Arm => first_arm_imm(detail),
        ArchKind::Aarch64 => first_arm64_imm(detail),
        ArchKind::Riscv32 | ArchKind::Riscv64 => {
            if is_riscv_indirect_branch(mnemonic) {
                None
            } else {
                riscv_target(detail, operands, address)
            }
        }
        ArchKind::X86_64 => parse_hex_target(operands).or_else(|| first_x86_imm(detail)),
    }
}

fn first_arm_imm(detail: &capstone::InsnDetail<'_>) -> Option<u64> {
    let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
        return None;
    };
    detail.operands().find_map(|operand| match operand.op_type {
        arm::ArmOperandType::Imm(value) => u64::try_from(value).ok(),
        _ => None,
    })
}

fn first_arm64_imm(detail: &capstone::InsnDetail<'_>) -> Option<u64> {
    let ArchDetail::Arm64Detail(detail) = detail.arch_detail() else {
        return None;
    };
    detail.operands().find_map(|operand| match operand.op_type {
        arm64::Arm64OperandType::Imm(value) => u64::try_from(value).ok(),
        _ => None,
    })
}

fn riscv_target(detail: &capstone::InsnDetail<'_>, operands: &str, address: u64) -> Option<u64> {
    let ArchDetail::RiscVDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let offset = detail
        .operands()
        .filter_map(|operand| match operand {
            riscv::RiscVOperand::Imm(value) => Some(value),
            _ => None,
        })
        .last();
    offset
        .and_then(|value| {
            let base = i64::try_from(address).ok()?;
            let target = base.checked_add(value)?;
            u64::try_from(target).ok()
        })
        .or_else(|| parse_hex_target(operands))
}

fn first_x86_imm(detail: &capstone::InsnDetail<'_>) -> Option<u64> {
    let ArchDetail::X86Detail(detail) = detail.arch_detail() else {
        return None;
    };
    detail.operands().find_map(|operand| match operand.op_type {
        x86::X86OperandType::Imm(value) => u64::try_from(value).ok(),
        _ => None,
    })
}

fn is_riscv_indirect_branch(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "jalr" | "jr" | "c.jr" | "c.jalr" | "ret" | "c.ret"
    )
}

fn value_effect(
    arch: ArchKind,
    detail: &capstone::InsnDetail<'_>,
    address: u64,
    size: u8,
    mnemonic: &str,
) -> Option<ValueEffect> {
    match arch {
        ArchKind::Thumb | ArchKind::Arm => {
            arm_value_effect(detail, address, mnemonic, arch == ArchKind::Thumb)
        }
        ArchKind::X86_64 => x86_value_effect(detail, address, size, mnemonic),
        ArchKind::Aarch64 => aarch64_value_effect(detail, mnemonic),
        ArchKind::Riscv32 | ArchKind::Riscv64 => riscv_value_effect(detail, address, mnemonic),
    }
}

#[allow(clippy::cast_possible_truncation)]
fn indirect_target(
    arch: ArchKind,
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
    address: u64,
    size: u8,
) -> Option<IndirectTarget> {
    match arch {
        ArchKind::X86_64 => {
            let ArchDetail::X86Detail(detail) = detail.arch_detail() else {
                return None;
            };
            let operands: Vec<_> = detail.operands().collect();
            match operands.first()?.op_type {
                x86::X86OperandType::Reg(register) => {
                    Some(IndirectTarget::Register(x86_64_register(register)))
                }
                x86::X86OperandType::Mem(memory) if memory.index().0 == 0 => {
                    if memory.base() == RegId(x86::X86Reg::X86_REG_RIP as u16) {
                        Some(IndirectTarget::Memory(
                            address
                                .wrapping_add(u64::from(size))
                                .wrapping_add_signed(memory.disp()),
                        ))
                    } else if memory.base().0 == 0 {
                        u64::try_from(memory.disp())
                            .ok()
                            .map(IndirectTarget::Memory)
                    } else {
                        Some(IndirectTarget::RegisterMemory {
                            base: x86_64_register(memory.base()),
                            disp: memory.disp(),
                        })
                    }
                }
                _ => None,
            }
        }
        ArchKind::Aarch64 => {
            if !matches!(mnemonic, "blr" | "br" | "braa" | "brab") {
                return None;
            }
            let ArchDetail::Arm64Detail(detail) = detail.arch_detail() else {
                return None;
            };
            let arm64::Arm64OperandType::Reg(register) = &detail.operands().next()?.op_type else {
                return None;
            };
            Some(IndirectTarget::Register(*register))
        }
        ArchKind::Thumb | ArchKind::Arm => {
            if !matches!(mnemonic, "blx" | "bx" | "bxj") {
                return None;
            }
            let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
                return None;
            };
            let arm::ArmOperandType::Reg(register) = detail.operands().next()?.op_type else {
                return None;
            };
            Some(IndirectTarget::Register(register))
        }
        ArchKind::Riscv32 | ArchKind::Riscv64 => {
            let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(mnemonic);
            if !matches!(mnemonic, "jalr" | "jr") {
                return None;
            }
            let ArchDetail::RiscVDetail(detail) = detail.arch_detail() else {
                return None;
            };
            let operands: Vec<_> = detail.operands().collect();
            let register = if operands.len() >= 2 {
                match operands.get(1)? {
                    riscv::RiscVOperand::Reg(register) => *register,
                    _ => return None,
                }
            } else {
                match operands.first()? {
                    riscv::RiscVOperand::Reg(register) => *register,
                    _ => return None,
                }
            };
            let offset = operands
                .get(2)
                .and_then(|operand| match operand {
                    riscv::RiscVOperand::Imm(value) => Some(*value),
                    _ => None,
                })
                .unwrap_or(0);
            if offset == 0 {
                Some(IndirectTarget::Register(register))
            } else {
                Some(IndirectTarget::RegisterOffset { register, offset })
            }
        }
    }
}

fn memory_write_effect(
    arch: ArchKind,
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
) -> Option<MemoryWrite> {
    match arch {
        ArchKind::X86_64 => x86_memory_write(detail, mnemonic),
        ArchKind::Aarch64 => aarch64_memory_write(detail, mnemonic),
        ArchKind::Thumb | ArchKind::Arm => arm_memory_write(detail, mnemonic),
        ArchKind::Riscv32 | ArchKind::Riscv64 => riscv_memory_write(detail, mnemonic),
    }
}

fn x86_memory_write(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<MemoryWrite> {
    if !matches!(mnemonic, "mov" | "movq" | "movl" | "movw" | "movb") {
        return None;
    }
    let ArchDetail::X86Detail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let x86::X86OperandType::Mem(memory) = operands.first()?.op_type else {
        return None;
    };
    if memory.index().0 != 0 {
        return None;
    }
    let x86::X86OperandType::Reg(source) = operands.get(1)?.op_type else {
        return None;
    };
    (memory.base().0 != 0).then_some(MemoryWrite {
        base: x86_64_register(memory.base()),
        disp: memory.disp(),
        source,
    })
}

fn aarch64_memory_write(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<MemoryWrite> {
    if !(mnemonic.starts_with("str") || mnemonic.starts_with("stur")) {
        return None;
    }
    let ArchDetail::Arm64Detail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let arm64::Arm64OperandType::Reg(source) = &operands.first()?.op_type else {
        return None;
    };
    let arm64::Arm64OperandType::Mem(memory) = &operands.get(1)?.op_type else {
        return None;
    };
    if memory.index().0 != 0 {
        return None;
    }
    (memory.base().0 != 0).then_some(MemoryWrite {
        base: memory.base(),
        disp: i64::from(memory.disp()),
        source: *source,
    })
}

fn arm_memory_write(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<MemoryWrite> {
    let mnemonic = mnemonic
        .strip_suffix(".w")
        .or_else(|| mnemonic.strip_suffix(".n"))
        .unwrap_or(mnemonic);
    if !mnemonic.starts_with("str") || mnemonic.starts_with("strd") {
        return None;
    }
    let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let arm::ArmOperandType::Reg(source) = operands.first()?.op_type else {
        return None;
    };
    let arm::ArmOperandType::Mem(memory) = operands.get(1)?.op_type else {
        return None;
    };
    if memory.index().0 != 0 {
        return None;
    }
    (memory.base().0 != 0).then_some(MemoryWrite {
        base: memory.base(),
        disp: i64::from(memory.disp()),
        source,
    })
}

fn riscv_memory_write(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<MemoryWrite> {
    let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(mnemonic);
    if !matches!(mnemonic, "sd" | "sw" | "sh" | "sb") {
        return None;
    }
    let ArchDetail::RiscVDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let Some(riscv::RiscVOperand::Reg(source)) = operands.first() else {
        return None;
    };
    let Some(riscv::RiscVOperand::Mem(memory)) = operands.get(1) else {
        return None;
    };
    (memory.base().0 != 0).then_some(MemoryWrite {
        base: memory.base(),
        disp: memory.disp(),
        source: *source,
    })
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn arm64_shift(shift: arm64::Arm64Shift) -> u32 {
    match shift {
        arm64::Arm64Shift::Lsl(value)
        | arm64::Arm64Shift::Msl(value)
        | arm64::Arm64Shift::Lsr(value)
        | arm64::Arm64Shift::Asr(value)
        | arm64::Arm64Shift::Ror(value) => value,
        arm64::Arm64Shift::Invalid => 0,
    }
}

fn aarch64_value_effect(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<ValueEffect> {
    let ArchDetail::Arm64Detail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let arm64::Arm64OperandType::Reg(dest) = &operands.first()?.op_type else {
        return None;
    };
    let dest = *dest;
    let mnemonic = mnemonic.strip_suffix(".w").unwrap_or(mnemonic);
    match mnemonic {
        "adr" | "adrp" => {
            let arm64::Arm64OperandType::Imm(value) = &operands.get(1)?.op_type else {
                return None;
            };
            Some(ValueEffect {
                dest,
                source: ValueSource::Address(u64::try_from(*value).ok()?),
            })
        }
        "ldr" | "ldur" => match &operands.get(1)?.op_type {
            arm64::Arm64OperandType::Imm(value) => Some(ValueEffect {
                dest,
                source: ValueSource::LoadAddress(u64::try_from(*value).ok()?),
            }),
            arm64::Arm64OperandType::Mem(memory) if memory.index().0 == 0 => Some(ValueEffect {
                dest,
                source: ValueSource::LoadFromRegister {
                    base: memory.base(),
                    disp: i64::from(memory.disp()),
                },
            }),
            _ => None,
        },
        "mov" => {
            let source = match &operands.get(1)?.op_type {
                arm64::Arm64OperandType::Reg(register) => ValueSource::Copy(*register),
                arm64::Arm64OperandType::Imm(value) => {
                    ValueSource::Immediate(u64::try_from(*value).ok()?)
                }
                _ => return None,
            };
            Some(ValueEffect { dest, source })
        }
        "add" | "adds" => {
            let arm64::Arm64OperandType::Reg(base) = &operands.get(1)?.op_type else {
                return None;
            };
            let arm64::Arm64OperandType::Imm(value) = &operands.get(2)?.op_type else {
                return None;
            };
            let shift = arm64_shift(operands.get(2)?.shift);
            let value = value.checked_shl(shift).unwrap_or(*value);
            Some(ValueEffect {
                dest,
                source: ValueSource::AddImmediate {
                    base: *base,
                    imm: value,
                },
            })
        }
        "movz" => {
            let arm64::Arm64OperandType::Imm(value) = &operands.get(1)?.op_type else {
                return None;
            };
            let shift = arm64_shift(operands.get(1)?.shift);
            let value = u64::try_from(*value).ok()?.checked_shl(shift)?;
            Some(ValueEffect {
                dest,
                source: ValueSource::Immediate(value),
            })
        }
        "movk" => {
            let arm64::Arm64OperandType::Imm(value) = &operands.get(1)?.op_type else {
                return None;
            };
            let shift = arm64_shift(operands.get(1)?.shift);
            let value = u64::try_from(*value).ok()?.checked_shl(shift)?;
            Some(ValueEffect {
                dest,
                source: ValueSource::OrImmediate {
                    base: dest,
                    imm: value,
                },
            })
        }
        _ => None,
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
fn riscv_value_effect(
    detail: &capstone::InsnDetail<'_>,
    address: u64,
    mnemonic: &str,
) -> Option<ValueEffect> {
    let ArchDetail::RiscVDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let Some(riscv::RiscVOperand::Reg(dest)) = operands.first() else {
        return None;
    };
    let dest = *dest;
    let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(mnemonic);
    match mnemonic {
        "auipc" => {
            let Some(riscv::RiscVOperand::Imm(value)) = operands.get(1) else {
                return None;
            };
            let offset = value.wrapping_shl(12);
            Some(ValueEffect {
                dest,
                source: ValueSource::Address(address.wrapping_add_signed(offset)),
            })
        }
        "lui" => {
            let Some(riscv::RiscVOperand::Imm(value)) = operands.get(1) else {
                return None;
            };
            let shifted = (*value as i32) << 12;
            Some(ValueEffect {
                dest,
                source: ValueSource::Immediate(i64::from(shifted) as u64),
            })
        }
        "addi" | "addiw" => {
            let zero = RegId(riscv::RiscVReg::RISCV_REG_ZERO as u16);
            // Compressed `c.addi rd, imm` has no explicit source register.
            let (base, value) = match (operands.get(1), operands.get(2)) {
                (
                    Some(riscv::RiscVOperand::Reg(register)),
                    Some(riscv::RiscVOperand::Imm(value)),
                ) => (*register, *value),
                (Some(riscv::RiscVOperand::Imm(value)), None) => (dest, *value),
                _ => return None,
            };
            let source = if base == zero {
                ValueSource::Immediate(value as u64)
            } else if value == 0 {
                ValueSource::Copy(base)
            } else {
                ValueSource::AddImmediate { base, imm: value }
            };
            Some(ValueEffect { dest, source })
        }
        "li" => {
            let Some(riscv::RiscVOperand::Imm(value)) = operands.get(1) else {
                return None;
            };
            Some(ValueEffect {
                dest,
                source: ValueSource::Immediate(*value as u64),
            })
        }
        "mv" => {
            let Some(riscv::RiscVOperand::Reg(register)) = operands.get(1) else {
                return None;
            };
            Some(ValueEffect {
                dest,
                source: ValueSource::Copy(*register),
            })
        }
        "ld" | "lw" => {
            let Some(riscv::RiscVOperand::Mem(memory)) = operands.get(1) else {
                return None;
            };
            Some(ValueEffect {
                dest,
                source: ValueSource::LoadFromRegister {
                    base: memory.base(),
                    disp: memory.disp(),
                },
            })
        }
        _ => None,
    }
}

#[allow(clippy::cast_possible_truncation)]
fn arm_value_effect(
    detail: &capstone::InsnDetail<'_>,
    address: u64,
    mnemonic: &str,
    thumb: bool,
) -> Option<ValueEffect> {
    let mnemonic = mnemonic
        .strip_suffix(".w")
        .or_else(|| mnemonic.strip_suffix(".n"))
        .unwrap_or(mnemonic);
    let writes_move = mnemonic.starts_with("mov") && !mnemonic.starts_with("movt");
    let writes_load = mnemonic.starts_with("ldr") && !mnemonic.starts_with("ldrd");
    let is_address = mnemonic.starts_with("adr");
    let is_addition = mnemonic.starts_with("add");
    if !(writes_move || writes_load || is_address || is_addition) {
        return None;
    }
    let ArchDetail::ArmDetail(arm) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = arm.operands().collect();
    let arm::ArmOperandType::Reg(dest) = operands.first()?.op_type else {
        return None;
    };

    if is_addition {
        let arm::ArmOperandType::Reg(base) = operands.get(1)?.op_type else {
            return None;
        };
        let immediate = match operands.get(2)?.op_type {
            arm::ArmOperandType::Imm(value)
            | arm::ArmOperandType::Cimm(value)
            | arm::ArmOperandType::Pimm(value) => i64::from(value),
            _ => return None,
        };
        return Some(ValueEffect {
            dest,
            source: ValueSource::AddImmediate {
                base,
                imm: immediate,
            },
        });
    }

    let source = match operands.get(1)?.op_type {
        arm::ArmOperandType::Reg(register) => ValueSource::Copy(register),
        arm::ArmOperandType::Imm(value)
        | arm::ArmOperandType::Cimm(value)
        | arm::ArmOperandType::Pimm(value) => {
            let value = u64::try_from(value).ok()?;
            if is_address {
                ValueSource::Address(value)
            } else {
                ValueSource::Immediate(value)
            }
        }
        arm::ArmOperandType::Mem(memory) => {
            if !writes_load {
                return None;
            }
            let pc = RegId(arm::ArmReg::ARM_REG_PC as u16);
            if memory.base() != pc {
                return None;
            }
            let pc_value = if thumb {
                (address + 4) & !3
            } else {
                (address + 8) & !3
            };
            let literal = pc_value.wrapping_add_signed(i64::from(memory.disp()));
            ValueSource::LoadAddress(literal)
        }
        _ => return None,
    };
    Some(ValueEffect { dest, source })
}

#[allow(clippy::cast_possible_truncation)]
fn x86_64_register(register: RegId) -> RegId {
    let value = register.0;
    let mapping = [
        (x86::X86Reg::X86_REG_EAX, x86::X86Reg::X86_REG_RAX),
        (x86::X86Reg::X86_REG_EBX, x86::X86Reg::X86_REG_RBX),
        (x86::X86Reg::X86_REG_ECX, x86::X86Reg::X86_REG_RCX),
        (x86::X86Reg::X86_REG_EDX, x86::X86Reg::X86_REG_RDX),
        (x86::X86Reg::X86_REG_ESI, x86::X86Reg::X86_REG_RSI),
        (x86::X86Reg::X86_REG_EDI, x86::X86Reg::X86_REG_RDI),
        (x86::X86Reg::X86_REG_EBP, x86::X86Reg::X86_REG_RBP),
        (x86::X86Reg::X86_REG_ESP, x86::X86Reg::X86_REG_RSP),
        (x86::X86Reg::X86_REG_R8D, x86::X86Reg::X86_REG_R8),
        (x86::X86Reg::X86_REG_R9D, x86::X86Reg::X86_REG_R9),
        (x86::X86Reg::X86_REG_R10D, x86::X86Reg::X86_REG_R10),
        (x86::X86Reg::X86_REG_R11D, x86::X86Reg::X86_REG_R11),
        (x86::X86Reg::X86_REG_R12D, x86::X86Reg::X86_REG_R12),
        (x86::X86Reg::X86_REG_R13D, x86::X86Reg::X86_REG_R13),
        (x86::X86Reg::X86_REG_R14D, x86::X86Reg::X86_REG_R14),
        (x86::X86Reg::X86_REG_R15D, x86::X86Reg::X86_REG_R15),
    ];
    mapping
        .iter()
        .find_map(|(from, to)| (value == *from as u16).then_some(RegId(*to as u16)))
        .unwrap_or(register)
}

#[allow(clippy::cast_possible_truncation)]
fn x86_value_effect(
    detail: &capstone::InsnDetail<'_>,
    address: u64,
    size: u8,
    mnemonic: &str,
) -> Option<ValueEffect> {
    if !matches!(
        mnemonic,
        "mov" | "movabs" | "movq" | "lea" | "leaq" | "xor" | "xorl" | "xorq"
    ) {
        return None;
    }
    let ArchDetail::X86Detail(x86_detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = x86_detail.operands().collect();
    let x86::X86OperandType::Reg(dest) = operands.first()?.op_type else {
        return None;
    };
    // Writing a 32-bit GPR zero-extends into its 64-bit parent. GCC emits
    // `mov $func,%edi` for an argument at -O0, so normalize both sides.
    let dest = x86_64_register(dest);
    let source = match operands.get(1)?.op_type {
        x86::X86OperandType::Reg(register) => {
            let source = x86_64_register(register);
            if mnemonic.starts_with("xor") && source == dest {
                ValueSource::Immediate(0)
            } else {
                ValueSource::Copy(source)
            }
        }
        x86::X86OperandType::Imm(value) => {
            ValueSource::Immediate(u64::from_ne_bytes(value.to_ne_bytes()))
        }
        x86::X86OperandType::Mem(memory) => {
            if memory.index().0 != 0 {
                return None;
            }
            let rip = RegId(x86::X86Reg::X86_REG_RIP as u16);
            if memory.base() == rip {
                let target = address
                    .wrapping_add(u64::from(size))
                    .wrapping_add_signed(memory.disp());
                if mnemonic.starts_with("lea") {
                    ValueSource::Address(target)
                } else {
                    ValueSource::LoadAddress(target)
                }
            } else if mnemonic.starts_with("lea") {
                return None;
            } else {
                ValueSource::LoadFromRegister {
                    base: x86_64_register(memory.base()),
                    disp: memory.disp(),
                }
            }
        }
        x86::X86OperandType::Invalid => return None,
    };
    Some(ValueEffect { dest, source })
}

/// Returns the ABI register holding argument `index`, for architectures with
/// M1 spawn-entry recovery.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn argument_register(arch: ArchKind, index: usize) -> Option<RegId> {
    let register = match arch {
        ArchKind::Thumb | ArchKind::Arm => match index {
            0 => arm::ArmReg::ARM_REG_R0 as u16,
            1 => arm::ArmReg::ARM_REG_R1 as u16,
            2 => arm::ArmReg::ARM_REG_R2 as u16,
            3 => arm::ArmReg::ARM_REG_R3 as u16,
            _ => return None,
        },
        ArchKind::X86_64 => match index {
            0 => x86::X86Reg::X86_REG_RDI as u16,
            1 => x86::X86Reg::X86_REG_RSI as u16,
            2 => x86::X86Reg::X86_REG_RDX as u16,
            3 => x86::X86Reg::X86_REG_RCX as u16,
            4 => x86::X86Reg::X86_REG_R8 as u16,
            5 => x86::X86Reg::X86_REG_R9 as u16,
            _ => return None,
        },
        ArchKind::Aarch64 => match index {
            0 => arm64::Arm64Reg::ARM64_REG_X0 as u16,
            1 => arm64::Arm64Reg::ARM64_REG_X1 as u16,
            2 => arm64::Arm64Reg::ARM64_REG_X2 as u16,
            3 => arm64::Arm64Reg::ARM64_REG_X3 as u16,
            4 => arm64::Arm64Reg::ARM64_REG_X4 as u16,
            5 => arm64::Arm64Reg::ARM64_REG_X5 as u16,
            6 => arm64::Arm64Reg::ARM64_REG_X6 as u16,
            7 => arm64::Arm64Reg::ARM64_REG_X7 as u16,
            _ => return None,
        },
        ArchKind::Riscv32 | ArchKind::Riscv64 => match index {
            0 => riscv::RiscVReg::RISCV_REG_A0 as u16,
            1 => riscv::RiscVReg::RISCV_REG_A1 as u16,
            2 => riscv::RiscVReg::RISCV_REG_A2 as u16,
            3 => riscv::RiscVReg::RISCV_REG_A3 as u16,
            4 => riscv::RiscVReg::RISCV_REG_A4 as u16,
            5 => riscv::RiscVReg::RISCV_REG_A5 as u16,
            6 => riscv::RiscVReg::RISCV_REG_A6 as u16,
            7 => riscv::RiscVReg::RISCV_REG_A7 as u16,
            _ => return None,
        },
    };
    Some(RegId(register))
}

/// Returns the ABI argument index for a register, when it is one of the
/// incoming argument registers.
#[must_use]
pub fn argument_index_for_register(arch: ArchKind, register: RegId) -> Option<usize> {
    for index in 0..8 {
        if argument_register(arch, index) == Some(register) {
            return Some(index);
        }
        if arch == ArchKind::X86_64
            && argument_register(arch, index) == Some(x86_64_register(register))
        {
            return Some(index);
        }
    }
    None
}

/// Returns the program-counter register for value-origin resolution.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn pc_register(arch: ArchKind) -> Option<RegId> {
    match arch {
        ArchKind::Thumb | ArchKind::Arm => Some(RegId(arm::ArmReg::ARM_REG_PC as u16)),
        ArchKind::X86_64 => Some(RegId(x86::X86Reg::X86_REG_RIP as u16)),
        ArchKind::Aarch64 | ArchKind::Riscv32 | ArchKind::Riscv64 => None,
    }
}

/// Pointer size used when reading a function-pointer literal.
#[must_use]
pub fn pointer_size(arch: ArchKind) -> usize {
    match arch {
        ArchKind::Thumb | ArchKind::Arm | ArchKind::Riscv32 => 4,
        ArchKind::Aarch64 | ArchKind::Riscv64 | ArchKind::X86_64 => 8,
    }
}

fn is_return_mnemonic(arch: ArchKind, mnemonic: &str, operands: &str) -> bool {
    match arch {
        ArchKind::Thumb | ArchKind::Arm => {
            (mnemonic == "bx" && operands.contains("lr"))
                || (matches!(mnemonic, "pop" | "ldm" | "ldmia" | "ldmfd")
                    && operands.contains("pc"))
                || (matches!(mnemonic, "mov" | "movs")
                    && operands.trim_start().starts_with("pc")
                    && operands.contains("lr"))
        }
        ArchKind::Aarch64 => mnemonic == "ret",
        ArchKind::Riscv32 | ArchKind::Riscv64 => {
            matches!(mnemonic, "ret" | "c.ret") || (mnemonic == "c.jr" && operands.trim() == "ra")
        }
        ArchKind::X86_64 => matches!(mnemonic, "ret" | "retq" | "iret" | "iretq"),
    }
}

fn is_conditional_mnemonic(arch: ArchKind, mnemonic: &str) -> bool {
    match arch {
        ArchKind::Thumb | ArchKind::Arm => {
            let mnemonic = mnemonic
                .strip_suffix(".w")
                .or_else(|| mnemonic.strip_suffix(".n"))
                .unwrap_or(mnemonic);
            matches!(mnemonic, "cbz" | "cbnz")
                || (mnemonic.starts_with('b') && !matches!(mnemonic, "b" | "bx" | "bl" | "blx"))
        }
        ArchKind::Aarch64 => {
            mnemonic.contains('.')
                || mnemonic.starts_with("cbz")
                || mnemonic.starts_with("cbnz")
                || mnemonic.starts_with("tbz")
                || mnemonic.starts_with("tbnz")
        }
        ArchKind::Riscv32 | ArchKind::Riscv64 => {
            let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(mnemonic);
            mnemonic.starts_with('b')
        }
        ArchKind::X86_64 => !matches!(mnemonic, "jmp" | "ljmp" | "jmpq"),
    }
}

fn parse_hex_target(operands: &str) -> Option<u64> {
    if operands.contains('[') || operands.contains('(') {
        return None;
    }
    let lower = operands.to_ascii_lowercase();
    let start = lower.find("0x")?;
    let digits = &lower[start + 2..];
    let end = digits
        .find(|character: char| !character.is_ascii_hexdigit())
        .unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    u64::from_str_radix(&digits[..end], 16).ok()
}

#[cfg(test)]
mod tests {
    use super::{Decoder, parse_hex_target};
    use crate::loader::ArchKind;

    #[test]
    fn x86_direct_call() {
        let decoder = Decoder::new(ArchKind::X86_64).unwrap();
        let insn = decoder
            .decode_one(&[0xe8, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .unwrap()
            .expect("call must decode");
        assert!(insn.is_call);
        assert!(!insn.is_return);
        assert_eq!(insn.direct_target, Some(0x1005));
    }

    #[test]
    fn x86_indirect_call() {
        let decoder = Decoder::new(ArchKind::X86_64).unwrap();
        let insn = decoder
            .decode_one(&[0xff, 0xd0], 0x1000)
            .unwrap()
            .expect("call must decode");
        assert!(insn.is_call);
        assert_eq!(insn.direct_target, None);
    }

    #[test]
    fn x86_conditional_jump() {
        let decoder = Decoder::new(ArchKind::X86_64).unwrap();
        let insn = decoder
            .decode_one(&[0x74, 0x05], 0x1000)
            .unwrap()
            .expect("je must decode");
        assert!(insn.is_jump);
        assert!(insn.is_conditional);
        assert_eq!(insn.direct_target, Some(0x1007));
    }

    #[test]
    fn aarch64_bl() {
        let decoder = Decoder::new(ArchKind::Aarch64).unwrap();
        let insn = decoder
            .decode_one(&[0x02, 0x00, 0x00, 0x94], 0x1000)
            .unwrap()
            .expect("bl must decode");
        assert!(insn.is_call);
        assert_eq!(insn.direct_target, Some(0x1008));
    }

    #[test]
    fn thumb_bl() {
        let decoder = Decoder::new(ArchKind::Thumb).unwrap();
        let insn = decoder
            .decode_one(&[0x00, 0xf0, 0x00, 0xf8], 0x1000)
            .unwrap()
            .expect("bl must decode");
        assert!(insn.is_call);
        assert_eq!(insn.direct_target, Some(0x1004));
    }

    #[test]
    fn thumb_bx_lr_is_return() {
        let decoder = Decoder::new(ArchKind::Thumb).unwrap();
        let insn = decoder
            .decode_one(&[0x70, 0x47], 0x1000)
            .unwrap()
            .expect("bx lr must decode");
        assert!(insn.is_return);
    }

    #[test]
    fn riscv_jal() {
        let decoder = Decoder::new(ArchKind::Riscv32).unwrap();
        let insn = decoder
            .decode_one(&[0x6f, 0x00, 0x80, 0x00], 0x1000)
            .unwrap()
            .expect("jal must decode");
        assert!(insn.is_call || insn.is_jump);
        assert_eq!(insn.direct_target, Some(0x1008));
    }

    #[test]
    fn x86_lea_produces_address_effect() {
        let decoder = Decoder::new(ArchKind::X86_64).unwrap();
        let insn = decoder
            .decode_one(&[0x48, 0x8d, 0x15, 0x09, 0x00, 0x00, 0x00], 0x1000)
            .unwrap()
            .expect("lea must decode");
        let value = insn.value.expect("value effect");
        assert_eq!(value.source, super::ValueSource::Address(0x1010));
    }

    #[test]
    fn thumb_literal_load_produces_load_effect() {
        let decoder = Decoder::new(ArchKind::Thumb).unwrap();
        let insn = decoder
            .decode_one(&[0x01, 0x48], 0x1000)
            .unwrap()
            .expect("ldr must decode");
        let value = insn.value.expect("value effect");
        assert_eq!(value.source, super::ValueSource::LoadAddress(0x1008));
    }

    #[test]
    fn parses_hex_target() {
        assert_eq!(parse_hex_target("0x1005"), Some(0x1005));
        assert_eq!(parse_hex_target("qword ptr [rip + 0x10]"), None);
        assert_eq!(parse_hex_target("rax"), None);
    }
}
