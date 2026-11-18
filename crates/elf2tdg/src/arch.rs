//! Instruction decoding and control-flow classification via Capstone.
//!
//! Only the information required for CFG/call-graph and cycle estimation is
//! exposed: branch class, conditional flag, direct target and instruction text.

use capstone::arch::{ArchDetail, arm, arm64, riscv, x86};
use capstone::prelude::*;
use capstone::{AccessType, Capstone, InsnGroupType, RegId};

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
    /// Add a shifted register to a register value.
    AddRegister {
        /// Base register (the old destination value).
        base: RegId,
        /// Register added to the base.
        addend: RegId,
        /// Left shift applied to the addend.
        shift: u8,
    },
    /// Shift a register left by a constant.
    ShiftRegister {
        /// Base register.
        base: RegId,
        /// Left shift amount.
        shift: u8,
    },
    /// Choose one of two registers based on a condition.
    Select {
        /// Value when the condition is true.
        left: RegId,
        /// Value when the condition is false.
        right: RegId,
    },
    /// Signed or unsigned load from an indexed table entry.
    IndexedLoad {
        /// Optional base register; `None` means an absolute table address.
        base: Option<RegId>,
        /// Index register.
        index: RegId,
        /// Index scale and access width in bytes.
        scale: u8,
        /// Signed displacement from the base.
        disp: i64,
        /// Whether the loaded value is sign-extended.
        signed: bool,
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
    /// Indexed memory operand used by jump tables.
    IndexedMemory {
        /// Optional base register; `None` means an absolute table address.
        base: Option<RegId>,
        /// Index register.
        index: RegId,
        /// Access size and index scale in bytes.
        scale: u8,
        /// Signed displacement from the base or absolute table address.
        disp: i64,
    },
    /// ARM `tbb`/`tbh` table branch.
    TableBranch {
        /// Optional table base register; `None` means the PC-relative table.
        base: Option<RegId>,
        /// Index register.
        index: RegId,
        /// Whether entries are halfwords (`tbh`) instead of bytes (`tbb`).
        halfword: bool,
    },
    /// ARM A32 `ldr pc, [table + index*4]` absolute-address table.
    TableLoad {
        /// Optional table base register; `None` means the PC-relative table.
        base: Option<RegId>,
        /// Index register.
        index: RegId,
        /// Signed displacement from the base or PC.
        disp: i64,
    },
    /// ARM A32 `add pc, base, index, lsl #2` branch-instruction table.
    BranchTable {
        /// Optional table base register; `None` means the PC-relative table.
        base: Option<RegId>,
        /// Index register.
        index: RegId,
    },
}

/// Value stored by a memory write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryWriteSource {
    /// A register value.
    Register(RegId),
    /// A constant written directly to memory.
    Immediate(u64),
}

/// A value stored through a base register plus displacement.
///
/// This is intentionally limited to one register or immediate source. It lets
/// origin tracking follow a value spilled to the stack (common at `-O0`)
/// without a full memory SSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryWrite {
    /// Base register.
    pub base: RegId,
    /// Signed displacement.
    pub disp: i64,
    /// Stored value.
    pub source: MemoryWriteSource,
}

/// Kind of data-memory access performed by an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryAccessKind {
    /// Load/read access.
    Read,
    /// Store/write access.
    Write,
    /// Read-modify-write or atomic access.
    ReadWrite,
}

/// One data-memory access decoded from an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryAccess {
    /// Whether the operand is read, written or both.
    pub kind: MemoryAccessKind,
    /// Access width in bytes; zero when it cannot be inferred.
    pub width: u8,
    /// Base register, or `None` for an absolute address.
    pub base: Option<RegId>,
    /// Index register for indexed addressing.
    pub index: Option<RegId>,
    /// Signed displacement from the base or absolute address.
    pub disp: i64,
    /// Absolute address when the operand encodes it directly.
    pub absolute: Option<u64>,
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
    /// Data-memory accesses decoded from the instruction, including implicit
    /// stack traffic for `push`/`pop`.
    pub memory_accesses: Vec<MemoryAccess>,
    /// Indirect branch/call target expression, when modeled.
    pub indirect: Option<IndirectTarget>,
    /// Registers read by this instruction, including implicit reads reported by
    /// Capstone. Used by the pipeline dependency model.
    pub regs_read: Vec<RegId>,
    /// Registers written by this instruction, including implicit writes.
    pub regs_write: Vec<RegId>,
    /// Register/immediate comparison, used to bound jump tables.
    pub compare: Option<(RegId, u64)>,
    /// Two-register branch operands. RISC-V tables guard the index with
    /// `bltu bound, index` rather than an immediate compare.
    pub branch_registers: Option<(RegId, RegId)>,
    /// Two-register `cmp` operands, used when a table bound is materialized in
    /// a register (for example Thumb `movw` followed by `cmp`).
    pub compare_registers: Option<(RegId, RegId)>,
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

    /// Returns Capstone's canonical name for a register.
    #[must_use]
    pub fn register_name(&self, register: RegId) -> Option<String> {
        self.cs.reg_name(register)
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
        // Capstone groups RISC-V `jr` (jalr with rd=x0) as a call even though
        // it does not write a link register. Treat it as the indirect jump it
        // is so jump-table dispatch is analyzed on this path too.
        let riscv_jump_pseudo =
            matches!(self.arch, ArchKind::Riscv32 | ArchKind::Riscv64) && mnemonic == "jr";
        let mut is_call = groups
            .iter()
            .any(|group| u32::from(group.0) == InsnGroupType::CS_GRP_CALL);
        if riscv_jump_pseudo {
            is_call = false;
        }
        let is_jump_group = groups
            .iter()
            .any(|group| u32::from(group.0) == InsnGroupType::CS_GRP_JUMP);
        let group_return = groups.iter().any(|group| {
            u32::from(group.0) == InsnGroupType::CS_GRP_RET
                || u32::from(group.0) == InsnGroupType::CS_GRP_IRET
        });
        let is_return = group_return || is_return_mnemonic(self.arch, &mnemonic, &operands);
        let mut is_jump = (is_jump_group || riscv_jump_pseudo) && !is_call && !is_return;
        let mut is_conditional = is_jump && is_conditional_mnemonic(self.arch, &mnemonic);
        let mut direct_target = if is_call || is_jump {
            direct_target(self.arch, &detail, &mnemonic, &operands, address)
        } else {
            None
        };
        let value = value_effect(self.arch, &detail, address, size, &mnemonic);
        let memory_write = memory_write_effect(self.arch, &detail, &mnemonic);
        let memory_accesses = memory_access_effects(self.arch, &detail, address, size, &mnemonic);
        let mut indirect = if (is_call || is_jump) && direct_target.is_none() {
            indirect_target(self.arch, &detail, &mnemonic, address, size)
        } else {
            None
        };
        if let Some((table, conditional)) =
            arm_table_load(&detail, &mnemonic).or_else(|| arm_add_pc_table(&detail, &mnemonic))
        {
            is_jump = true;
            is_conditional = conditional;
            direct_target = None;
            indirect = Some(table);
        }
        let compare = match self.arch {
            ArchKind::X86_64 => x86_compare(&detail, &mnemonic),
            ArchKind::Aarch64 => aarch64_compare(&detail, &mnemonic),
            ArchKind::Thumb | ArchKind::Arm => arm_compare(&detail, &mnemonic),
            ArchKind::Riscv32 | ArchKind::Riscv64 => None,
        };
        let branch_registers = match self.arch {
            ArchKind::Riscv32 | ArchKind::Riscv64 => riscv_branch_registers(&detail, &mnemonic),
            _ => None,
        };
        let compare_registers = match self.arch {
            ArchKind::Thumb | ArchKind::Arm => arm_compare_registers(&detail, &mnemonic),
            ArchKind::Aarch64 => aarch64_compare_registers(&detail, &mnemonic),
            ArchKind::X86_64 => x86_compare_registers(&detail, &mnemonic),
            ArchKind::Riscv32 | ArchKind::Riscv64 => None,
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
            memory_accesses,
            indirect,
            regs_read: detail.regs_read().to_vec(),
            regs_write: detail.regs_write().to_vec(),
            compare,
            branch_registers,
            compare_registers,
        }))
    }
}

#[allow(clippy::cast_possible_truncation)]
fn arm_table_load(
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
) -> Option<(IndirectTarget, bool)> {
    if !mnemonic.starts_with("ldr") {
        return None;
    }
    let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let pc = RegId(arm::ArmReg::ARM_REG_PC as u16);
    let operands: Vec<_> = detail.operands().collect();
    let arm::ArmOperandType::Reg(dest) = operands.first()?.op_type else {
        return None;
    };
    if dest != pc {
        return None;
    }
    let arm::ArmOperandType::Mem(memory) = operands.get(1)?.op_type else {
        return None;
    };
    if memory.index().0 == 0 {
        return None;
    }
    let conditional = !matches!(
        detail.cc(),
        arm::ArmCC::ARM_CC_AL | arm::ArmCC::ARM_CC_INVALID
    );
    Some((
        IndirectTarget::TableLoad {
            base: (memory.base() != pc).then_some(memory.base()),
            index: memory.index(),
            disp: i64::from(memory.disp()),
        },
        conditional,
    ))
}

#[allow(clippy::cast_possible_truncation)]
fn arm_add_pc_table(
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
) -> Option<(IndirectTarget, bool)> {
    if !mnemonic.starts_with("add") {
        return None;
    }
    let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let pc = RegId(arm::ArmReg::ARM_REG_PC as u16);
    let operands: Vec<_> = detail.operands().collect();
    let arm::ArmOperandType::Reg(dest) = operands.first()?.op_type else {
        return None;
    };
    let arm::ArmOperandType::Reg(base) = operands.get(1)?.op_type else {
        return None;
    };
    let arm::ArmOperandType::Reg(index) = operands.get(2)?.op_type else {
        return None;
    };
    if dest != pc || !matches!(operands.get(2)?.shift, arm::ArmShift::Lsl(2)) {
        return None;
    }
    let conditional = !matches!(
        detail.cc(),
        arm::ArmCC::ARM_CC_AL | arm::ArmCC::ARM_CC_INVALID
    );
    Some((
        IndirectTarget::BranchTable {
            base: (base != pc).then_some(base),
            index,
        },
        conditional,
    ))
}

#[allow(clippy::cast_possible_truncation)]
fn x86_indirect_target(
    detail: &capstone::InsnDetail<'_>,
    address: u64,
    size: u8,
) -> Option<IndirectTarget> {
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
        x86::X86OperandType::Mem(memory) => {
            let scale = u8::try_from(memory.scale()).ok()?;
            if !matches!(scale, 1 | 2 | 4 | 8) {
                return None;
            }
            let base = (memory.base().0 != 0).then(|| x86_64_register(memory.base()));
            Some(IndirectTarget::IndexedMemory {
                base,
                index: x86_64_register(memory.index()),
                scale,
                disp: memory.disp(),
            })
        }
        _ => None,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
fn aarch64_register(register: RegId) -> RegId {
    const MAPPING: &[(u16, u16)] = &[
        (
            arm64::Arm64Reg::ARM64_REG_W0 as u16,
            arm64::Arm64Reg::ARM64_REG_X0 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W1 as u16,
            arm64::Arm64Reg::ARM64_REG_X1 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W2 as u16,
            arm64::Arm64Reg::ARM64_REG_X2 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W3 as u16,
            arm64::Arm64Reg::ARM64_REG_X3 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W4 as u16,
            arm64::Arm64Reg::ARM64_REG_X4 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W5 as u16,
            arm64::Arm64Reg::ARM64_REG_X5 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W6 as u16,
            arm64::Arm64Reg::ARM64_REG_X6 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W7 as u16,
            arm64::Arm64Reg::ARM64_REG_X7 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W8 as u16,
            arm64::Arm64Reg::ARM64_REG_X8 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W9 as u16,
            arm64::Arm64Reg::ARM64_REG_X9 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W10 as u16,
            arm64::Arm64Reg::ARM64_REG_X10 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W11 as u16,
            arm64::Arm64Reg::ARM64_REG_X11 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W12 as u16,
            arm64::Arm64Reg::ARM64_REG_X12 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W13 as u16,
            arm64::Arm64Reg::ARM64_REG_X13 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W14 as u16,
            arm64::Arm64Reg::ARM64_REG_X14 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W15 as u16,
            arm64::Arm64Reg::ARM64_REG_X15 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W16 as u16,
            arm64::Arm64Reg::ARM64_REG_X16 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W17 as u16,
            arm64::Arm64Reg::ARM64_REG_X17 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W18 as u16,
            arm64::Arm64Reg::ARM64_REG_X18 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W19 as u16,
            arm64::Arm64Reg::ARM64_REG_X19 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W20 as u16,
            arm64::Arm64Reg::ARM64_REG_X20 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W21 as u16,
            arm64::Arm64Reg::ARM64_REG_X21 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W22 as u16,
            arm64::Arm64Reg::ARM64_REG_X22 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W23 as u16,
            arm64::Arm64Reg::ARM64_REG_X23 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W24 as u16,
            arm64::Arm64Reg::ARM64_REG_X24 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W25 as u16,
            arm64::Arm64Reg::ARM64_REG_X25 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W26 as u16,
            arm64::Arm64Reg::ARM64_REG_X26 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W27 as u16,
            arm64::Arm64Reg::ARM64_REG_X27 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W28 as u16,
            arm64::Arm64Reg::ARM64_REG_X28 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W29 as u16,
            arm64::Arm64Reg::ARM64_REG_X29 as u16,
        ),
        (
            arm64::Arm64Reg::ARM64_REG_W30 as u16,
            arm64::Arm64Reg::ARM64_REG_X30 as u16,
        ),
    ];
    MAPPING
        .iter()
        .find_map(|(from, to)| (register.0 == *from).then_some(RegId(*to)))
        .unwrap_or(register)
}

fn aarch64_compare(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<(RegId, u64)> {
    if mnemonic != "cmp" {
        return None;
    }
    let ArchDetail::Arm64Detail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let arm64::Arm64OperandType::Reg(register) = &operands.first()?.op_type else {
        return None;
    };
    let arm64::Arm64OperandType::Imm(value) = &operands.get(1)?.op_type else {
        return None;
    };
    u64::try_from(*value)
        .ok()
        .map(|value| (aarch64_register(*register), value))
}

fn arm_compare(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<(RegId, u64)> {
    if !mnemonic.starts_with("cmp") {
        return None;
    }
    let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let arm::ArmOperandType::Reg(register) = &operands.first()?.op_type else {
        return None;
    };
    let arm::ArmOperandType::Imm(value) = &operands.get(1)?.op_type else {
        return None;
    };
    u64::try_from(*value).ok().map(|value| (*register, value))
}

fn arm_compare_registers(
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
) -> Option<(RegId, RegId)> {
    if !mnemonic.starts_with("cmp") {
        return None;
    }
    let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let arm::ArmOperandType::Reg(lhs) = operands.first()?.op_type else {
        return None;
    };
    let arm::ArmOperandType::Reg(rhs) = operands.get(1)?.op_type else {
        return None;
    };
    Some((lhs, rhs))
}

fn aarch64_compare_registers(
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
) -> Option<(RegId, RegId)> {
    if mnemonic != "cmp" {
        return None;
    }
    let ArchDetail::Arm64Detail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let arm64::Arm64OperandType::Reg(lhs) = operands.first()?.op_type else {
        return None;
    };
    let arm64::Arm64OperandType::Reg(rhs) = operands.get(1)?.op_type else {
        return None;
    };
    Some((aarch64_register(lhs), aarch64_register(rhs)))
}

fn x86_compare_registers(
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
) -> Option<(RegId, RegId)> {
    if !mnemonic.starts_with("cmp") {
        return None;
    }
    let ArchDetail::X86Detail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let (x86::X86OperandType::Reg(lhs), x86::X86OperandType::Reg(rhs)) =
        (&operands.first()?.op_type, &operands.get(1)?.op_type)
    else {
        return None;
    };
    Some((x86_64_register(*lhs), x86_64_register(*rhs)))
}

fn riscv_branch_registers(
    detail: &capstone::InsnDetail<'_>,
    mnemonic: &str,
) -> Option<(RegId, RegId)> {
    if !is_conditional_mnemonic(ArchKind::Riscv64, mnemonic) {
        return None;
    }
    let ArchDetail::RiscVDetail(detail) = detail.arch_detail() else {
        return None;
    };
    let mut registers = detail.operands().filter_map(|operand| match operand {
        riscv::RiscVOperand::Reg(register) => Some(register),
        _ => None,
    });
    Some((registers.next()?, registers.next()?))
}

fn x86_compare(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<(RegId, u64)> {
    if !mnemonic.starts_with("cmp") {
        return None;
    }
    let ArchDetail::X86Detail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let (register, value) = match (&operands.first()?.op_type, &operands.get(1)?.op_type) {
        (x86::X86OperandType::Reg(register), x86::X86OperandType::Imm(value))
        | (x86::X86OperandType::Imm(value), x86::X86OperandType::Reg(register)) => {
            (*register, *value)
        }
        _ => return None,
    };
    u64::try_from(value)
        .ok()
        .map(|value| (x86_64_register(register), value))
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
        ArchKind::X86_64 => x86_indirect_target(detail, address, size),
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
            let normalized = mnemonic
                .strip_suffix(".w")
                .or_else(|| mnemonic.strip_suffix(".n"))
                .unwrap_or(mnemonic);
            if matches!(normalized, "tbb" | "tbh") {
                let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
                    return None;
                };
                let arm::ArmOperandType::Mem(memory) = detail.operands().next()?.op_type else {
                    return None;
                };
                let pc = RegId(arm::ArmReg::ARM_REG_PC as u16);
                return Some(IndirectTarget::TableBranch {
                    base: (memory.base() != pc).then_some(memory.base()),
                    index: memory.index(),
                    halfword: normalized == "tbh",
                });
            }
            if !matches!(normalized, "blx" | "bx" | "bxj") {
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

fn memory_access_effects(
    arch: ArchKind,
    detail: &capstone::InsnDetail<'_>,
    address: u64,
    size: u8,
    mnemonic: &str,
) -> Vec<MemoryAccess> {
    let mut accesses = match arch {
        ArchKind::X86_64 => x86_memory_accesses(detail, address, size, mnemonic),
        ArchKind::Aarch64 => aarch64_memory_accesses(detail, mnemonic),
        ArchKind::Thumb | ArchKind::Arm => {
            arm_memory_accesses(detail, address, size, mnemonic, arch == ArchKind::Thumb)
        }
        ArchKind::Riscv32 | ArchKind::Riscv64 => riscv_memory_accesses(detail, mnemonic),
    };
    if let Some(access) = implicit_stack_access(arch, mnemonic) {
        accesses.push(access);
    }
    accesses
}

#[allow(clippy::cast_possible_truncation)]
fn implicit_stack_access(arch: ArchKind, mnemonic: &str) -> Option<MemoryAccess> {
    let mnemonic = normalize_arm_mnemonic(mnemonic);
    let (base, width, kind) = match arch {
        ArchKind::Thumb | ArchKind::Arm => (
            RegId(arm::ArmReg::ARM_REG_SP as u16),
            4,
            match mnemonic {
                "push" => MemoryAccessKind::Write,
                "pop" => MemoryAccessKind::Read,
                _ => return None,
            },
        ),
        ArchKind::X86_64 => (
            RegId(x86::X86Reg::X86_REG_RSP as u16),
            8,
            match mnemonic {
                "push" | "pushq" | "pushw" | "pushf" | "pushfq" => MemoryAccessKind::Write,
                "pop" | "popq" | "popw" | "popf" | "popfq" => MemoryAccessKind::Read,
                _ => return None,
            },
        ),
        ArchKind::Aarch64 | ArchKind::Riscv32 | ArchKind::Riscv64 => return None,
    };
    Some(MemoryAccess {
        kind,
        width,
        base: Some(base),
        index: None,
        disp: 0,
        absolute: None,
    })
}

const fn access_kind(access: AccessType) -> MemoryAccessKind {
    match access {
        AccessType::ReadOnly => MemoryAccessKind::Read,
        AccessType::WriteOnly => MemoryAccessKind::Write,
        AccessType::ReadWrite => MemoryAccessKind::ReadWrite,
    }
}

fn next_pc(arch: ArchKind, address: u64, size: u8) -> Option<u64> {
    match arch {
        ArchKind::Thumb => Some((address + 4) & !3),
        ArchKind::Arm => Some((address + 8) & !3),
        ArchKind::X86_64 => Some(address.wrapping_add(u64::from(size))),
        ArchKind::Aarch64 | ArchKind::Riscv32 | ArchKind::Riscv64 => None,
    }
}

#[allow(clippy::cast_possible_truncation)]
fn x86_memory_accesses(
    detail: &capstone::InsnDetail<'_>,
    address: u64,
    size: u8,
    mnemonic: &str,
) -> Vec<MemoryAccess> {
    if matches!(mnemonic, "lea" | "nop") || mnemonic.starts_with("prefetch") {
        return Vec::new();
    }
    let ArchDetail::X86Detail(detail) = detail.arch_detail() else {
        return Vec::new();
    };
    let rip = RegId(x86::X86Reg::X86_REG_RIP as u16);
    detail
        .operands()
        .filter_map(|operand| {
            let x86::X86OperandType::Mem(memory) = operand.op_type else {
                return None;
            };
            let base = (memory.base().0 != 0).then_some(memory.base());
            let index = (memory.index().0 != 0).then_some(memory.index());
            let absolute = if index.is_none() {
                if base == Some(rip) {
                    next_pc(ArchKind::X86_64, address, size)
                        .map(|pc| pc.wrapping_add_signed(memory.disp()))
                } else if base.is_none() {
                    Some(memory.disp().cast_unsigned())
                } else {
                    None
                }
            } else {
                None
            };
            Some(MemoryAccess {
                kind: operand
                    .access
                    .map_or(MemoryAccessKind::ReadWrite, access_kind),
                width: operand.size,
                base,
                index,
                disp: memory.disp(),
                absolute,
            })
        })
        .collect()
}

fn normalize_arm_mnemonic(mnemonic: &str) -> &str {
    mnemonic
        .strip_suffix(".w")
        .or_else(|| mnemonic.strip_suffix(".n"))
        .unwrap_or(mnemonic)
}

fn arm_memory_width(mnemonic: &str) -> u8 {
    let mnemonic = normalize_arm_mnemonic(mnemonic);
    if mnemonic.starts_with("ldm") || mnemonic.starts_with("stm") {
        return 4;
    }
    if mnemonic.ends_with('d') {
        return 8;
    }
    if mnemonic.ends_with('h') {
        return 2;
    }
    if mnemonic.ends_with('b') {
        return 1;
    }
    4
}

fn arm_memory_kind(mnemonic: &str) -> MemoryAccessKind {
    let mnemonic = normalize_arm_mnemonic(mnemonic);
    if mnemonic.starts_with("ldr") || mnemonic.starts_with("ldm") || mnemonic == "pop" {
        MemoryAccessKind::Read
    } else if mnemonic.starts_with("str") || mnemonic.starts_with("stm") || mnemonic == "push" {
        MemoryAccessKind::Write
    } else {
        MemoryAccessKind::ReadWrite
    }
}

#[allow(clippy::cast_possible_truncation)]
fn arm_memory_accesses(
    detail: &capstone::InsnDetail<'_>,
    address: u64,
    size: u8,
    mnemonic: &str,
    thumb: bool,
) -> Vec<MemoryAccess> {
    let normalized = normalize_arm_mnemonic(mnemonic);
    if normalized.starts_with("pld") || normalized.starts_with("pli") {
        return Vec::new();
    }
    let ArchDetail::ArmDetail(detail) = detail.arch_detail() else {
        return Vec::new();
    };
    let width = arm_memory_width(mnemonic);
    let default_kind = arm_memory_kind(mnemonic);
    let pc = RegId(arm::ArmReg::ARM_REG_PC as u16);
    let arch = if thumb {
        ArchKind::Thumb
    } else {
        ArchKind::Arm
    };
    detail
        .operands()
        .filter_map(|operand| {
            let arm::ArmOperandType::Mem(memory) = operand.op_type else {
                return None;
            };
            let base = (memory.base().0 != 0).then_some(memory.base());
            let index = (memory.index().0 != 0).then_some(memory.index());
            let disp = i64::from(memory.disp());
            let absolute = if index.is_none() {
                if base == Some(pc) {
                    next_pc(arch, address, size).map(|pc| pc.wrapping_add_signed(disp))
                } else if base.is_none() {
                    Some(disp.cast_unsigned())
                } else {
                    None
                }
            } else {
                None
            };
            Some(MemoryAccess {
                kind: operand.access.map_or(default_kind, access_kind),
                width,
                base,
                index,
                disp,
                absolute,
            })
        })
        .collect()
}

fn aarch64_memory_width(mnemonic: &str, register_width: u8) -> u8 {
    let mnemonic = mnemonic.strip_suffix(".w").unwrap_or(mnemonic);
    if mnemonic.starts_with("ldpsw") || mnemonic.starts_with("stpsw") {
        return 8;
    }
    if mnemonic.starts_with("ldp") || mnemonic.starts_with("stp") {
        return register_width.saturating_mul(2);
    }
    if mnemonic.ends_with('b') {
        return 1;
    }
    if mnemonic.ends_with('h') {
        return 2;
    }
    if mnemonic.ends_with("sw") {
        return 4;
    }
    register_width
}

fn aarch64_memory_kind(mnemonic: &str) -> MemoryAccessKind {
    let mnemonic = mnemonic.strip_suffix(".w").unwrap_or(mnemonic);
    if mnemonic.starts_with("ld") {
        MemoryAccessKind::Read
    } else if mnemonic.starts_with("st") {
        MemoryAccessKind::Write
    } else {
        MemoryAccessKind::ReadWrite
    }
}

fn aarch64_memory_accesses(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Vec<MemoryAccess> {
    if mnemonic.starts_with("prfm") {
        return Vec::new();
    }
    let ArchDetail::Arm64Detail(detail) = detail.arch_detail() else {
        return Vec::new();
    };
    let operands: Vec<_> = detail.operands().collect();
    let register_width = match operands.first().map(|operand| &operand.op_type) {
        Some(arm64::Arm64OperandType::Reg(register))
            if aarch64_register(*register) != *register =>
        {
            4
        }
        _ => 8,
    };
    let width = aarch64_memory_width(mnemonic, register_width);
    let default_kind = aarch64_memory_kind(mnemonic);
    let mut accesses: Vec<MemoryAccess> = operands
        .iter()
        .filter_map(|operand| {
            let arm64::Arm64OperandType::Mem(memory) = &operand.op_type else {
                return None;
            };
            let base = (memory.base().0 != 0).then_some(memory.base());
            let index = (memory.index().0 != 0).then_some(memory.index());
            Some(MemoryAccess {
                kind: operand.access.map_or(default_kind, access_kind),
                width,
                base,
                index,
                disp: i64::from(memory.disp()),
                absolute: None,
            })
        })
        .collect();
    // AArch64 literal loads encode a PC-relative data address as an immediate
    // instead of a memory operand.
    if matches!(default_kind, MemoryAccessKind::Read)
        && let Some(arm64::Arm64OperandType::Imm(value)) =
            operands.get(1).map(|operand| &operand.op_type)
        && let Ok(address) = u64::try_from(*value)
    {
        accesses.push(MemoryAccess {
            kind: MemoryAccessKind::Read,
            width: width.min(8),
            base: None,
            index: None,
            disp: 0,
            absolute: Some(address),
        });
    }
    accesses
}

fn riscv_memory_width(mnemonic: &str) -> u8 {
    let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(mnemonic);
    match mnemonic {
        "lb" | "lbu" | "sb" => 1,
        "lh" | "lhu" | "sh" => 2,
        "lw" | "lwu" | "sw" | "flw" | "fsw" | "lwsp" | "swsp" => 4,
        "ld" | "sd" | "fld" | "fsd" | "ldsp" | "sdsp" => 8,
        _ => match mnemonic.rsplit_once('.').map(|(_, suffix)| suffix) {
            Some("b") => 1,
            Some("h") => 2,
            Some("d") => 8,
            _ => 4,
        },
    }
}

fn riscv_memory_kind(mnemonic: &str) -> MemoryAccessKind {
    let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(mnemonic);
    if mnemonic.starts_with('l') {
        MemoryAccessKind::Read
    } else if mnemonic.starts_with('s') {
        MemoryAccessKind::Write
    } else {
        MemoryAccessKind::ReadWrite
    }
}

#[allow(clippy::cast_possible_truncation)]
fn riscv_memory_accesses(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Vec<MemoryAccess> {
    let ArchDetail::RiscVDetail(detail) = detail.arch_detail() else {
        return Vec::new();
    };
    let width = riscv_memory_width(mnemonic);
    let kind = riscv_memory_kind(mnemonic);
    let zero = RegId(riscv::RiscVReg::RISCV_REG_ZERO as u16);
    detail
        .operands()
        .filter_map(|operand| {
            let riscv::RiscVOperand::Mem(memory) = operand else {
                return None;
            };
            let base = (memory.base() != zero).then_some(memory.base());
            let disp = memory.disp();
            Some(MemoryAccess {
                kind,
                width,
                base,
                index: None,
                disp,
                absolute: base.is_none().then(|| disp.cast_unsigned()),
            })
        })
        .collect()
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
    let source = match operands.get(1)?.op_type {
        x86::X86OperandType::Reg(source) => MemoryWriteSource::Register(x86_64_register(source)),
        x86::X86OperandType::Imm(value) => {
            MemoryWriteSource::Immediate(u64::from_ne_bytes(value.to_ne_bytes()))
        }
        _ => return None,
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
        source: MemoryWriteSource::Register(*source),
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
        source: MemoryWriteSource::Register(source),
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
        source: MemoryWriteSource::Register(*source),
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

#[allow(clippy::too_many_lines)]
fn aarch64_value_effect(detail: &capstone::InsnDetail<'_>, mnemonic: &str) -> Option<ValueEffect> {
    let ArchDetail::Arm64Detail(detail) = detail.arch_detail() else {
        return None;
    };
    let operands: Vec<_> = detail.operands().collect();
    let arm64::Arm64OperandType::Reg(dest) = &operands.first()?.op_type else {
        return None;
    };
    let raw_dest = *dest;
    let dest = aarch64_register(raw_dest);
    let dest_width = if aarch64_register(raw_dest) == raw_dest {
        8
    } else {
        4
    };
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
        "ldr" | "ldur" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" | "ldursw" => {
            match &operands.get(1)?.op_type {
                arm64::Arm64OperandType::Imm(value) => Some(ValueEffect {
                    dest,
                    source: ValueSource::LoadAddress(u64::try_from(*value).ok()?),
                }),
                arm64::Arm64OperandType::Mem(memory) if memory.index().0 == 0 => {
                    Some(ValueEffect {
                        dest,
                        source: ValueSource::LoadFromRegister {
                            base: aarch64_register(memory.base()),
                            disp: i64::from(memory.disp()),
                        },
                    })
                }
                arm64::Arm64OperandType::Mem(memory) => {
                    let (scale, signed) = match mnemonic {
                        "ldrb" => (1, false),
                        "ldrsb" => (1, true),
                        "ldrh" => (2, false),
                        "ldrsh" => (2, true),
                        "ldrsw" | "ldursw" => (4, true),
                        _ => (dest_width, false),
                    };
                    Some(ValueEffect {
                        dest,
                        source: ValueSource::IndexedLoad {
                            base: (memory.base().0 != 0).then(|| aarch64_register(memory.base())),
                            index: aarch64_register(memory.index()),
                            scale,
                            disp: i64::from(memory.disp()),
                            signed,
                        },
                    })
                }
                _ => None,
            }
        }
        "csel" => {
            let arm64::Arm64OperandType::Reg(left) = &operands.get(1)?.op_type else {
                return None;
            };
            let arm64::Arm64OperandType::Reg(right) = &operands.get(2)?.op_type else {
                return None;
            };
            Some(ValueEffect {
                dest,
                source: ValueSource::Select {
                    left: aarch64_register(*left),
                    right: aarch64_register(*right),
                },
            })
        }
        "mov" => {
            let source = match &operands.get(1)?.op_type {
                arm64::Arm64OperandType::Reg(register) => {
                    ValueSource::Copy(aarch64_register(*register))
                }
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
            match &operands.get(2)?.op_type {
                arm64::Arm64OperandType::Imm(value) => {
                    let shift = arm64_shift(operands.get(2)?.shift);
                    let value = value.checked_shl(shift).unwrap_or(*value);
                    Some(ValueEffect {
                        dest,
                        source: ValueSource::AddImmediate {
                            base: aarch64_register(*base),
                            imm: value,
                        },
                    })
                }
                arm64::Arm64OperandType::Reg(addend) => {
                    let shift = u8::try_from(arm64_shift(operands.get(2)?.shift)).ok()?;
                    Some(ValueEffect {
                        dest,
                        source: ValueSource::AddRegister {
                            base: aarch64_register(*base),
                            addend: aarch64_register(*addend),
                            shift,
                        },
                    })
                }
                _ => None,
            }
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
    clippy::cast_sign_loss,
    clippy::too_many_lines
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
        "add" | "addw" => {
            let (base, addend) = match (operands.get(1), operands.get(2)) {
                (Some(riscv::RiscVOperand::Reg(base)), Some(riscv::RiscVOperand::Reg(addend))) => {
                    (*base, *addend)
                }
                (Some(riscv::RiscVOperand::Reg(addend)), None) => (dest, *addend),
                _ => return None,
            };
            Some(ValueEffect {
                dest,
                source: ValueSource::AddRegister {
                    base,
                    addend,
                    shift: 0,
                },
            })
        }
        "slli" | "slliw" => {
            let (base, shift) = match (operands.get(1), operands.get(2)) {
                (Some(riscv::RiscVOperand::Reg(base)), Some(riscv::RiscVOperand::Imm(shift))) => {
                    (*base, *shift)
                }
                (Some(riscv::RiscVOperand::Imm(shift)), None) => (dest, *shift),
                _ => return None,
            };
            Some(ValueEffect {
                dest,
                source: ValueSource::ShiftRegister {
                    base,
                    shift: u8::try_from(shift).ok()?,
                },
            })
        }
        "ld" | "lw" => {
            let (base, disp) = match (operands.get(1), operands.get(2)) {
                (Some(riscv::RiscVOperand::Mem(memory)), _) => (memory.base(), memory.disp()),
                (Some(riscv::RiscVOperand::Imm(disp)), Some(riscv::RiscVOperand::Reg(base))) => {
                    (*base, *disp)
                }
                _ => return None,
            };
            Some(ValueEffect {
                dest,
                source: ValueSource::LoadFromRegister { base, disp },
            })
        }
        _ => None,
    }
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::too_many_lines)]
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
    let writes_top_half = mnemonic == "movt";
    // Only model pointer-sized LDR; byte/halfword loads do not produce a
    // pointer value and must not feed function-pointer resolution.
    let writes_load = mnemonic == "ldr";
    let is_address = mnemonic.starts_with("adr");
    let is_addition = mnemonic.starts_with("add");
    if !(writes_move || writes_top_half || writes_load || is_address || is_addition) {
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

    if writes_top_half {
        let immediate = match operands.get(1)?.op_type {
            arm::ArmOperandType::Imm(value)
            | arm::ArmOperandType::Cimm(value)
            | arm::ArmOperandType::Pimm(value) => u64::try_from(value).ok()?,
            _ => return None,
        };
        return Some(ValueEffect {
            dest,
            source: ValueSource::OrImmediate {
                base: dest,
                imm: immediate << 16,
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
            if memory.base() == pc {
                let pc_value = if thumb {
                    (address + 4) & !3
                } else {
                    (address + 8) & !3
                };
                let literal = pc_value.wrapping_add_signed(i64::from(memory.disp()));
                ValueSource::LoadAddress(literal)
            } else if memory.base().0 == 0 {
                return None;
            } else if memory.index().0 != 0 {
                // Fixed-width pointer tables use an indexed load, for example
                // Thumb `ldr.w r3, [r2, r1, lsl #2]`.
                let shift = match operands.get(1)?.shift {
                    arm::ArmShift::Invalid => 0,
                    arm::ArmShift::Lsl(shift) if shift <= 3 => shift,
                    _ => return None,
                };
                if memory.scale() < 0 {
                    return None;
                }
                ValueSource::IndexedLoad {
                    base: Some(memory.base()),
                    index: memory.index(),
                    scale: 1u8.checked_shl(shift)?,
                    disp: i64::from(memory.disp()),
                    signed: false,
                }
            } else {
                ValueSource::LoadFromRegister {
                    base: memory.base(),
                    disp: i64::from(memory.disp()),
                }
            }
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
        "mov"
            | "movabs"
            | "movq"
            | "movslq"
            | "movsxd"
            | "lea"
            | "leaq"
            | "xor"
            | "xorl"
            | "xorq"
            | "add"
            | "addl"
            | "addq"
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
            } else if mnemonic.starts_with("add") {
                ValueSource::AddRegister {
                    base: dest,
                    addend: source,
                    shift: 0,
                }
            } else {
                ValueSource::Copy(source)
            }
        }
        x86::X86OperandType::Imm(value) => {
            ValueSource::Immediate(u64::from_ne_bytes(value.to_ne_bytes()))
        }
        x86::X86OperandType::Mem(memory) => {
            if memory.index().0 != 0 {
                if !mnemonic.starts_with("mov") {
                    return None;
                }
                let scale = u8::try_from(memory.scale()).ok()?;
                if !matches!(scale, 1 | 2 | 4 | 8) {
                    return None;
                }
                let base = (memory.base().0 != 0).then(|| x86_64_register(memory.base()));
                return Some(ValueEffect {
                    dest,
                    source: ValueSource::IndexedLoad {
                        base,
                        index: x86_64_register(memory.index()),
                        scale,
                        disp: memory.disp(),
                        signed: matches!(
                            mnemonic,
                            "movslq"
                                | "movsxd"
                                | "movsx"
                                | "movsbl"
                                | "movswl"
                                | "movsbq"
                                | "movswq"
                        ),
                    },
                });
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

/// Returns the ABI register holding a scalar or pointer return value.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn return_register(arch: ArchKind) -> RegId {
    match arch {
        ArchKind::Thumb | ArchKind::Arm => RegId(arm::ArmReg::ARM_REG_R0 as u16),
        ArchKind::X86_64 => RegId(x86::X86Reg::X86_REG_RAX as u16),
        ArchKind::Aarch64 => RegId(arm64::Arm64Reg::ARM64_REG_X0 as u16),
        ArchKind::Riscv32 | ArchKind::Riscv64 => RegId(riscv::RiscVReg::RISCV_REG_A0 as u16),
    }
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

/// Returns whether `register` is conventionally used as a frame or stack
/// pointer, where a base-plus-displacement load names a local stack slot.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn is_frame_register(arch: ArchKind, register: RegId) -> bool {
    let candidates: &[u32] = match arch {
        ArchKind::Thumb | ArchKind::Arm => &[
            arm::ArmReg::ARM_REG_R7,
            arm::ArmReg::ARM_REG_R11,
            arm::ArmReg::ARM_REG_SP,
        ],
        ArchKind::X86_64 => &[x86::X86Reg::X86_REG_RBP, x86::X86Reg::X86_REG_RSP],
        ArchKind::Aarch64 => &[
            arm64::Arm64Reg::ARM64_REG_X29,
            arm64::Arm64Reg::ARM64_REG_SP,
        ],
        ArchKind::Riscv32 | ArchKind::Riscv64 => {
            &[riscv::RiscVReg::RISCV_REG_S0, riscv::RiscVReg::RISCV_REG_SP]
        }
    };
    candidates
        .iter()
        .any(|candidate| u16::try_from(*candidate).is_ok_and(|c| register.0 == c))
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
    use super::{Decoder, MemoryAccessKind, parse_hex_target};
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
    fn x86_decodes_load_and_store_memory_accesses() {
        let decoder = Decoder::new(ArchKind::X86_64).unwrap();
        let load = decoder
            .decode_one(&[0x8b, 0x43, 0x08], 0x1000)
            .unwrap()
            .expect("mov load must decode");
        assert_eq!(load.memory_accesses.len(), 1);
        let access = load.memory_accesses[0];
        assert_eq!(access.kind, MemoryAccessKind::Read);
        assert_eq!(access.width, 4);
        assert_eq!(access.disp, 8);
        assert_eq!(
            decoder.register_name(access.base.expect("base register")),
            Some("rbx".to_owned())
        );

        let store = decoder
            .decode_one(&[0x89, 0x43, 0x08], 0x1000)
            .unwrap()
            .expect("mov store must decode");
        assert_eq!(store.memory_accesses.len(), 1);
        assert_eq!(store.memory_accesses[0].kind, MemoryAccessKind::Write);
    }

    #[test]
    fn x86_rip_relative_load_has_an_absolute_address() {
        let decoder = Decoder::new(ArchKind::X86_64).unwrap();
        let insn = decoder
            .decode_one(&[0x8b, 0x05, 0x00, 0x10, 0x00, 0x00], 0x1000)
            .unwrap()
            .expect("rip-relative load must decode");
        assert_eq!(insn.memory_accesses.len(), 1);
        assert_eq!(insn.memory_accesses[0].absolute, Some(0x2006));
    }

    #[test]
    fn thumb_decodes_memory_access() {
        let decoder = Decoder::new(ArchKind::Thumb).unwrap();
        let insn = decoder
            .decode_one(&[0x48, 0x68], 0x1000)
            .unwrap()
            .expect("ldr must decode");
        assert_eq!(insn.memory_accesses.len(), 1);
        let access = insn.memory_accesses[0];
        assert_eq!(access.kind, MemoryAccessKind::Read);
        assert_eq!(access.width, 4);
        assert_eq!(access.disp, 4);
        assert_eq!(
            decoder.register_name(access.base.expect("base register")),
            Some("r1".to_owned())
        );
    }

    #[test]
    fn aarch64_decodes_memory_access() {
        let decoder = Decoder::new(ArchKind::Aarch64).unwrap();
        let insn = decoder
            .decode_one(&[0x20, 0x04, 0x40, 0xf9], 0x1000)
            .unwrap()
            .expect("ldr must decode");
        assert_eq!(insn.memory_accesses.len(), 1);
        let access = insn.memory_accesses[0];
        assert_eq!(access.kind, MemoryAccessKind::Read);
        assert_eq!(access.width, 8);
        assert_eq!(access.disp, 8);
        assert_eq!(
            decoder.register_name(access.base.expect("base register")),
            Some("x1".to_owned())
        );
    }

    #[test]
    fn riscv_decodes_memory_access() {
        let decoder = Decoder::new(ArchKind::Riscv32).unwrap();
        let insn = decoder
            .decode_one(&[0x03, 0xa5, 0x45, 0x00], 0x1000)
            .unwrap()
            .expect("lw must decode");
        assert_eq!(insn.memory_accesses.len(), 1);
        let access = insn.memory_accesses[0];
        assert_eq!(access.kind, MemoryAccessKind::Read);
        assert_eq!(access.width, 4);
        assert_eq!(access.disp, 4);
        assert_eq!(
            decoder.register_name(access.base.expect("base register")),
            Some("a1".to_owned())
        );
    }

    #[test]
    fn thumb_push_reports_an_implicit_stack_write() {
        let decoder = Decoder::new(ArchKind::Thumb).unwrap();
        let insn = decoder
            .decode_one(&[0x10, 0xb5], 0x1000)
            .unwrap()
            .expect("push must decode");
        assert_eq!(insn.memory_accesses.len(), 1);
        let access = insn.memory_accesses[0];
        assert_eq!(access.kind, MemoryAccessKind::Write);
        assert_eq!(access.width, 4);
        assert_eq!(
            decoder.register_name(access.base.expect("base register")),
            Some("sp".to_owned())
        );
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
    fn riscv_jr_is_an_indirect_jump_not_a_call() {
        let decoder = Decoder::new(ArchKind::Riscv64).unwrap();
        // jr a0
        let insn = decoder
            .decode_one(&[0x67, 0x00, 0x05, 0x00], 0x1000)
            .unwrap()
            .expect("jr must decode");
        assert!(!insn.is_call);
        assert!(insn.is_jump);
        assert!(matches!(
            insn.indirect,
            Some(super::IndirectTarget::Register(_))
        ));
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
