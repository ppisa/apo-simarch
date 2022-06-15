#!/usr/bin/python2

"""
Experimental tool for MIPS architecture assembly and binary code
analysis and simulation

It is developed for Computer Architectures course
teach at Czech Technical University

  https://cw.fel.cvut.cz/wiki/courses/b35apo/start
"""

import numbers
import collections
import sys
import operator

__author__ = "Pavel Pisa"
__copyright__ = "Copyright 2017-2019, Czech Technical University"
__license__ = "GPLv2+"
__version__ = "0.0.1"
__maintainer__ = "Pave Pisa"
__email__ = "pisa@cmp.felk.cvut.cz"
__status__ = "experimental"

"""
        operations:
        syscall, j, b, jr, beq, bne, lw, sw,
        slt, slti, add, addi, sub, subi, and, andi, or, ori, sll,
        sllv, srl, srlv, div, mul, xor, xori, move
"""
"""

   "1" 5 bit sync type (OP_*_SHAMT)
   "<" 5 bit shift amount (OP_*_SHAMT)
   ">" shift amount between 32 and 63, stored after subtracting 32 (OP_*_SHAMT)
   "a" 26 bit target address (OP_*_TARGET)
   "b" 5 bit base register (OP_*_RS)
   "c" 10 bit breakpoint code (OP_*_CODE)
   "d" 5 bit destination register specifier (OP_*_RD)
   "h" 5 bit prefx hint (OP_*_PREFX)
   "i" 16 bit unsigned immediate (OP_*_IMMEDIATE)
   "j" 16 bit signed immediate (OP_*_DELTA)
   "k" 5 bit cache opcode in target register position (OP_*_CACHE)
       Also used for immediate operands in vr5400 vector insns.
   "o" 16 bit signed offset (OP_*_DELTA)
   "p" 16 bit PC relative branch target address (OP_*_DELTA)
   "q" 10 bit extra breakpoint code (OP_*_CODE2)
   "r" 5 bit same register used as both source and target (OP_*_RS)
   "s" 5 bit source register specifier (OP_*_RS)
   "t" 5 bit target register (OP_*_RT)
   "u" 16 bit upper 16 bits of address (OP_*_IMMEDIATE)
   "v" 5 bit same register used as both source and destination (OP_*_RS)
   "w" 5 bit same register used as both target and destination (OP_*_RT)
   "U" 5 bit same destination register in both OP_*_RD and OP_*_RT
       (used by clo and clz)
   "C" 25 bit coprocessor function code (OP_*_COPZ)
   "B" 20 bit syscall/breakpoint function code (OP_*_CODE20)
   "J" 19 bit wait function code (OP_*_CODE19)
   "x" accept and ignore register name
   "z" must be zero register
   "K" 5 bit Hardware Register (rdhwr instruction) (OP_*_RD)
"""

argdes = collections.namedtuple('argdes', ['kind', 'loc', 'min', 'max', 'shift'])

argdesbycode = {
    '1': argdes('n', 'SHAMT', 0, 31, 0),    # 5 bit sync type (OP_*_SHAMT)
    '<': argdes('n', 'SHAMT', 0, 31, 0),    # 5 bit shift amount (OP_*_SHAMT)
    '>': argdes('n', 'SHAMT', 32, 63, 0),   # shift amount between 32 and 63, stored after subtracting 32 (OP_*_SHAMT)
    'a': argdes('a', 'TARGET', 0, 0x3ffffff, 2), # 26 bit target address (OP_*_TARGET)
    'b': argdes('g', 'RS', 0, 31, 0),    # 5 bit base register (OP_*_RS)
    'c': argdes('g', 'CODE', 0, 0x3ff, 0), # 10 bit breakpoint code (OP_*_CODE)
    'd': argdes('g', 'RD', 0, 31, 0),    # 5 bit destination register specifier (OP_*_RD)
    'h': argdes('h', 'PREFX', 0, 31, 0),    # 5 bit prefx hint (OP_*_PREFX)
    'i': argdes('n', 'IMMEDIATE', 0, 0xffff, 0) , # 16 bit unsigned immediate (OP_*_IMMEDIATE)
    'j': argdes('n', 'IMMEDIATE', -0x8000, 0x7fff, 0) , # 16 bit signed immediate (OP_*_DELTA)
    'k': argdes('n', 'CACHE', 0, 31, 0),       # 5 bit cache opcode in target register position (OP_*_CACHE)
                             # Also used for immediate operands in vr5400 vector insns.
    'o': argdes('o', 'DELTA', -0x8000, 0x7fff, 0) , # 16 bit signed offset (OP_*_DELTA)
    'p': argdes('p', 'DELTA', -0x8000, 0x7fff, 2) , # 16 bit PC relative branch target address (OP_*_DELTA)
    'q': argdes('n', 'CODE2', 0, 0x3ff, 0) , # 10 bit extra breakpoint code (OP_*_CODE2)
    'r': argdes('g', 'RS', 0, 31, 0) , # 5 bit same register used as both source and target (OP_*_RS)
    's': argdes('g', 'RS', 0, 31, 0) , # 5 bit source register specifier (OP_*_RS)
    't': argdes('g', 'RT', 0, 31, 0) , # 5 bit target register (OP_*_RT)
    'u': argdes('n', 'IMMEDIATE', 0, 0xffff, 0) , # 16 bit upper 16 bits of address (OP_*_IMMEDIATE)
    'v': argdes('g', 'RS', 0, 31, 0) , # 5 bit same register used as both source and destination (OP_*_RS)
    'w': argdes('g', 'RT', 0, 31, 0) , # 5 bit same register used as both target and destination (OP_*_RT)
    'U': argdes('g', 'RD', 0, 31, 0) , # 5 bit same destination register in both OP_*_RD and OP_*_RT
                             # (used by clo and clz)
    'C': argdes('n', 'COPZ', 0, 0x1ffffff, 0) , # 25 bit coprocessor function code (OP_*_COPZ)
    'B': argdes('n', 'CODE20', 0, 0xfffff, 0) , # 20 bit syscall/breakpoint function code (OP_*_CODE20)
    'J': argdes('n', 'CODE19', 0, 0x7ffff, 0) , # 19 bit wait function code (OP_*_CODE19)
    'x': argdes('g', 'ign', 0, 31, 0) , # accept and ignore register name
    'z': argdes('n', 'ign', 0, 0, 0) , # must be zero register
}

instdes = collections.namedtuple('instdes', ['name', 'args', 'match',
               'mask', 'pinfo', 'pinfo2', 'membership', 'exclusions'])

WR_t    = 0x00000001
WR_d    = 0x00000002
RD_s    = 0x00000004
UBD     = 0x00000008
WR_31   = 0x00000010
RD_t    = 0x00000020
CBD     = 0x00000040
TRAP    = 0x00000080
LCD     = 0x00000100
RD_C0   = 0x00000200
COD     = 0x00000400
WR_CC   = 0x00000800
WR_HILO = 0x00001000
LDD     = 0x00002000
RD_b    = 0x00004000
CLD     = 0x00008000
RD_HI   = 0x00010000
RD_LO   = 0x00020000
WR_C0   = 0x00040000
WR_HI   = 0x00080000
WR_LO   = 0x00100000
IS_M    = 0x00200000
SM      = 0x00400000
RD_C2   = 0x00800000
RD_C3   = 0x01000000
INSN_TLB= 0x02000000
RD_CC   = 0x04000000
WR_C2   = 0x08000000
WR_C3   = 0x10000000
CP      = 0x20000000

INSN2_ALIAS = 0x00000001

I1      = 0x00000001
T3      = 0x00000002

IOCT    = 0x00000001
IOCTP   = 0x00000002
IOCT2   = 0x00000004

DEP_RAW   = 1
DEP_WAW   = 2
DEP_MEM_POSSIBLE  = 4

# Instructions array extracted from GNU binutils
instdeslist = [
    instdes("nop", [], 0x00000000, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
    instdes("ssnop", [], 0x00000040, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
    instdes("ehb", [], 0x000000c0, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
    instdes("li", ['t','j'], 0x24000000, 0xffe00000, WR_t, INSN2_ALIAS, I1, 0),
    instdes("li", ['t','i'], 0x34000000, 0xffe00000, WR_t, INSN2_ALIAS, I1, 0),
    instdes("move", ['d','s'], 0x00000021, 0xfc1f07ff, WR_d|RD_s, INSN2_ALIAS, I1, 0),
    instdes("move", ['d','s'], 0x00000025, 0xfc1f07ff, WR_d|RD_s, INSN2_ALIAS, I1, 0),
    instdes("b", ['p'], 0x10000000, 0xffff0000, UBD, INSN2_ALIAS, I1, 0),
    instdes("b", ['p'], 0x04010000, 0xffff0000, UBD, INSN2_ALIAS, I1, 0),
    instdes("bal", ['p'], 0x04110000, 0xffff0000, UBD|WR_31, INSN2_ALIAS, I1, 0),
    instdes("add", ['d','v','t'], 0x00000020, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("addi", ['t','r','j'], 0x20000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("addiu", ['t','r','j'], 0x24000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("addu", ['d','v','t'], 0x00000021, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("and", ['d','v','t'], 0x00000024, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("andi", ['t','r','i'], 0x30000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("beqz", ['s','p'], 0x10000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("beq", ['s','t','p'], 0x10000000, 0xfc000000, CBD|RD_s|RD_t, 0, I1, 0),
    instdes("bgez", ['s','p'], 0x04010000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bgezal", ['s','p'], 0x04110000, 0xfc1f0000, CBD|RD_s|WR_31, 0, I1, 0),
    instdes("bgtz", ['s','p'], 0x1c000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("blez", ['s','p'], 0x18000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bltz", ['s','p'], 0x04000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bltzal", ['s','p'], 0x04100000, 0xfc1f0000, CBD|RD_s|WR_31, 0, I1, 0),
    instdes("bnez", ['s','p'], 0x14000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bne", ['s','t','p'], 0x14000000, 0xfc000000, CBD|RD_s|RD_t, 0, I1, 0),
    instdes("break", [], 0x0000000d, 0xffffffff, TRAP, 0, I1, 0),
    instdes("break", ['c'], 0x0000000d, 0xfc00ffff, TRAP, 0, I1, 0),
    instdes("break", ['c','q'], 0x0000000d, 0xfc00003f, TRAP, 0, I1, 0),
    instdes("cfc0", ['t','G'], 0x40400000, 0xffe007ff, LCD|WR_t|RD_C0, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("ctc0", ['t','G'], 0x40c00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("div", ['z','s','t'], 0x0000001a, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("div", ['z','t'], 0x0000001a, 0xffe0ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("divu", ['z','s','t'], 0x0000001b, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("divu", ['z','t'], 0x0000001b, 0xffe0ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("jr", ['s'], 0x00000008, 0xfc1fffff, UBD|RD_s, 0, I1, 0),
    instdes("j", ['s'], 0x00000008, 0xfc1fffff, UBD|RD_s, 0, I1, 0),
    instdes("j", ['a'], 0x08000000, 0xfc000000, UBD, 0, I1, 0),
    instdes("jalr", ['s'], 0x0000f809, 0xfc1fffff, UBD|RD_s|WR_d, 0, I1, 0),
    instdes("jalr", ['d','s'], 0x00000009, 0xfc1f07ff, UBD|RD_s|WR_d, 0, I1, 0),
    instdes("jal", ['a'], 0x0c000000, 0xfc000000, UBD|WR_31, 0, I1, 0),
    instdes("jalx", ['a'], 0x74000000, 0xfc000000, UBD|WR_31, 0, I1, 0),
    instdes("lb", ['t','o(b)'], 0x80000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lbu", ['t','o(b)'], 0x90000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lh", ['t','o(b)'], 0x84000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lhu", ['t','o(b)'], 0x94000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lui", ['t','u'], 0x3c000000, 0xffe00000, WR_t, 0, I1, 0),
    instdes("lw", ['t','o(b)'], 0x8c000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lwc0", ['E','o(b)'], 0xc0000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwc2", ['E','o(b)'], 0xc8000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwc3", ['E','o(b)'], 0xcc000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwl", ['t','o(b)'], 0x88000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lwr", ['t','o(b)'], 0x98000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("mfc0", ['t','G'], 0x40000000, 0xffe007ff, LCD|WR_t|RD_C0, 0, I1, 0),
    instdes("mfhi", ['d'], 0x00000010, 0xffff07ff, WR_d|RD_HI, 0, I1, 0),
    instdes("mflo", ['d'], 0x00000012, 0xffff07ff, WR_d|RD_LO, 0, I1, 0),
    instdes("mtc0", ['t','G'], 0x40800000, 0xffe007ff, COD|RD_t|WR_C0|WR_CC, 0, I1, 0),
    instdes("mthi", ['s'], 0x00000011, 0xfc1fffff, RD_s|WR_HI, 0, I1, 0),
    instdes("mtlo", ['s'], 0x00000013, 0xfc1fffff, RD_s|WR_LO, 0, I1, 0),
    instdes("mult", ['s','t'], 0x00000018, 0xfc00ffff, RD_s|RD_t|WR_HILO|IS_M, 0, I1, 0),
    instdes("multu", ['s','t'], 0x00000019, 0xfc00ffff, RD_s|RD_t|WR_HILO|IS_M, 0, I1, 0),
    instdes("neg", ['d','w'], 0x00000022, 0xffe007ff, WR_d|RD_t, 0, I1, 0),
    instdes("negu", ['d','w'], 0x00000023, 0xffe007ff, WR_d|RD_t, 0, I1, 0),
    instdes("nor", ['d','v','t'], 0x00000027, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("not", ['d','v'], 0x00000027, 0xfc1f07ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("or", ['d','v','t'], 0x00000025, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("ori", ['t','r','i'], 0x34000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("rem", ['z','s','t'], 0x0000001a, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("remu", ['z','s','t'], 0x0000001b, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("rfe", [], 0x42000010, 0xffffffff, 0, 0, I1|T3, 0),
    instdes("sb", ['t','o(b)'], 0xa0000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("sh", ['t','o(b)'], 0xa4000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("sllv", ['d','t','s'], 0x00000004, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sll", ['d','w','s'], 0x00000004, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sll", ['d','w','<'], 0x00000000, 0xffe0003f, WR_d|RD_t, 0, I1, 0),
    instdes("slt", ['d','v','t'], 0x0000002a, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("slti", ['t','r','j'], 0x28000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("sltiu", ['t','r','j'], 0x2c000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("sltu", ['d','v','t'], 0x0000002b, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("srav", ['d','t','s'], 0x00000007, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sra", ['d','w','s'], 0x00000007, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sra", ['d','w','<'], 0x00000003, 0xffe0003f, WR_d|RD_t, 0, I1, 0),
    instdes("srlv", ['d','t','s'], 0x00000006, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("srl", ['d','w','s'], 0x00000006, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("srl", ['d','w','<'], 0x00000002, 0xffe0003f, WR_d|RD_t, 0, I1, 0),
    instdes("sub", ['d','v','t'], 0x00000022, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("subu", ['d','v','t'], 0x00000023, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("sw", ['t','o(b)'], 0xac000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("swc0", ['E','o(b)'], 0xe0000000, 0xfc000000, SM|RD_C0|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swc2", ['E','o(b)'], 0xe8000000, 0xfc000000, SM|RD_C2|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swc3", ['E','o(b)'], 0xec000000, 0xfc000000, SM|RD_C3|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swl", ['t','o(b)'], 0xa8000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("swr", ['t','o(b)'], 0xb8000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("syscall", [], 0x0000000c, 0xffffffff, TRAP, 0, I1, 0),
    instdes("syscall", ['B'], 0x0000000c, 0xfc00003f, TRAP, 0, I1, 0),
    instdes("tlbp", [], 0x42000008, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("tlbr", [], 0x42000001, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("tlbwi", [], 0x42000002, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("tlbwr", [], 0x42000006, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("xor", ['d','v','t'], 0x00000026, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("xori", ['t','r','j'], 0x38000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("bc2f", ['p'], 0x49000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc2t", ['p'], 0x49010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("cfc2", ['t','G'], 0x48400000, 0xffe007ff, LCD|WR_t|RD_C2, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("ctc2", ['t','G'], 0x48c00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("mfc2", ['t','G'], 0x48000000, 0xffe007ff, LCD|WR_t|RD_C2, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("mtc2", ['t','G'], 0x48800000, 0xffe007ff, COD|RD_t|WR_C2|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc3f", ['p'], 0x4d000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc3t", ['p'], 0x4d010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("cfc3", ['t','G'], 0x4c400000, 0xffe007ff, LCD|WR_t|RD_C3, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("ctc3", ['t','G'], 0x4cc00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("mfc3", ['t','G'], 0x4c000000, 0xffe007ff, LCD|WR_t|RD_C3, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("mtc3", ['t','G'], 0x4c800000, 0xffe007ff, COD|RD_t|WR_C3|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc0f", ['p'], 0x41000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc0t", ['p'], 0x41010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("c0", ['C'], 0x42000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("c2", ['C'], 0x4a000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("c3", ['C'], 0x4e000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
]

instdeslist_rv = [
    instdes("nop", [], 0x00000000, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
#    instdes("ssnop", [], 0x00000040, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
#    instdes("ehb", [], 0x000000c0, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
    instdes("li", ['t','j'], 0x24000000, 0xffe00000, WR_t, INSN2_ALIAS, I1, 0),
    instdes("li", ['t','i'], 0x34000000, 0xffe00000, WR_t, INSN2_ALIAS, I1, 0),
    instdes("move", ['d','s'], 0x00000021, 0xfc1f07ff, WR_d|RD_s, INSN2_ALIAS, I1, 0),
    instdes("move", ['d','s'], 0x00000025, 0xfc1f07ff, WR_d|RD_s, INSN2_ALIAS, I1, 0),
    instdes("b", ['p'], 0x10000000, 0xffff0000, UBD, INSN2_ALIAS, I1, 0),
    instdes("b", ['p'], 0x04010000, 0xffff0000, UBD, INSN2_ALIAS, I1, 0),
#    instdes("bal", ['p'], 0x04110000, 0xffff0000, UBD|WR_31, INSN2_ALIAS, I1, 0),
    instdes("add", ['d','v','t'], 0x00000020, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("addi", ['t','r','j'], 0x20000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("addiu", ['t','r','j'], 0x24000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("addu", ['d','v','t'], 0x00000021, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("and", ['d','v','t'], 0x00000024, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("andi", ['t','r','i'], 0x30000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("beqz", ['s','p'], 0x10000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("beq", ['s','t','p'], 0x10000000, 0xfc000000, CBD|RD_s|RD_t, 0, I1, 0),
    instdes("bgez", ['s','p'], 0x04010000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bgezal", ['s','p'], 0x04110000, 0xfc1f0000, CBD|RD_s|WR_31, 0, I1, 0),
    instdes("bgtz", ['s','p'], 0x1c000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("blez", ['s','p'], 0x18000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bltz", ['s','p'], 0x04000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bltzal", ['s','p'], 0x04100000, 0xfc1f0000, CBD|RD_s|WR_31, 0, I1, 0),
    instdes("bnez", ['s','p'], 0x14000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bne", ['s','t','p'], 0x14000000, 0xfc000000, CBD|RD_s|RD_t, 0, I1, 0),
    instdes("break", [], 0x0000000d, 0xffffffff, TRAP, 0, I1, 0),
    instdes("break", ['c'], 0x0000000d, 0xfc00ffff, TRAP, 0, I1, 0),
    instdes("break", ['c','q'], 0x0000000d, 0xfc00003f, TRAP, 0, I1, 0),
#    instdes("cfc0", ['t','G'], 0x40400000, 0xffe007ff, LCD|WR_t|RD_C0, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("ctc0", ['t','G'], 0x40c00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("div", ['z','s','t'], 0x0000001a, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("div", ['z','t'], 0x0000001a, 0xffe0ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("divu", ['z','s','t'], 0x0000001b, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("divu", ['z','t'], 0x0000001b, 0xffe0ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
#    instdes("jr", ['s'], 0x00000008, 0xfc1fffff, UBD|RD_s, 0, I1, 0),
#    instdes("j", ['s'], 0x00000008, 0xfc1fffff, UBD|RD_s, 0, I1, 0),
#    instdes("j", ['a'], 0x08000000, 0xfc000000, UBD, 0, I1, 0),
#    instdes("jalr", ['s'], 0x0000f809, 0xfc1fffff, UBD|RD_s|WR_d, 0, I1, 0),
#    instdes("jalr", ['d','s'], 0x00000009, 0xfc1f07ff, UBD|RD_s|WR_d, 0, I1, 0),
#    instdes("jal", ['a'], 0x0c000000, 0xfc000000, UBD|WR_31, 0, I1, 0),
#    instdes("jalx", ['a'], 0x74000000, 0xfc000000, UBD|WR_31, 0, I1, 0),
#    instdes("lb", ['t','o(b)'], 0x80000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
#    instdes("lbu", ['t','o(b)'], 0x90000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
#    instdes("lh", ['t','o(b)'], 0x84000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
#    instdes("lhu", ['t','o(b)'], 0x94000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lui", ['t','u'], 0x3c000000, 0xffe00000, WR_t, 0, I1, 0),
    instdes("lw", ['t','o(b)'], 0x8c000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
#    instdes("lwc0", ['E','o(b)'], 0xc0000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("lwc2", ['E','o(b)'], 0xc8000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("lwc3", ['E','o(b)'], 0xcc000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("lwl", ['t','o(b)'], 0x88000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
#    instdes("lwr", ['t','o(b)'], 0x98000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
#    instdes("mfc0", ['t','G'], 0x40000000, 0xffe007ff, LCD|WR_t|RD_C0, 0, I1, 0),
#    instdes("mfhi", ['d'], 0x00000010, 0xffff07ff, WR_d|RD_HI, 0, I1, 0),
#    instdes("mflo", ['d'], 0x00000012, 0xffff07ff, WR_d|RD_LO, 0, I1, 0),
#    instdes("mtc0", ['t','G'], 0x40800000, 0xffe007ff, COD|RD_t|WR_C0|WR_CC, 0, I1, 0),
#    instdes("mthi", ['s'], 0x00000011, 0xfc1fffff, RD_s|WR_HI, 0, I1, 0),
#    instdes("mtlo", ['s'], 0x00000013, 0xfc1fffff, RD_s|WR_LO, 0, I1, 0),
#    instdes("mult", ['s','t'], 0x00000018, 0xfc00ffff, RD_s|RD_t|WR_HILO|IS_M, 0, I1, 0),
#    instdes("multu", ['s','t'], 0x00000019, 0xfc00ffff, RD_s|RD_t|WR_HILO|IS_M, 0, I1, 0),
#    instdes("neg", ['d','w'], 0x00000022, 0xffe007ff, WR_d|RD_t, 0, I1, 0),
#    instdes("negu", ['d','w'], 0x00000023, 0xffe007ff, WR_d|RD_t, 0, I1, 0),
#    instdes("nor", ['d','v','t'], 0x00000027, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
#    instdes("not", ['d','v'], 0x00000027, 0xfc1f07ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("or", ['d','v','t'], 0x00000025, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("ori", ['t','r','i'], 0x34000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
#    instdes("rem", ['z','s','t'], 0x0000001a, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
#    instdes("remu", ['z','s','t'], 0x0000001b, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
#    instdes("rfe", [], 0x42000010, 0xffffffff, 0, 0, I1|T3, 0),
#    instdes("sb", ['t','o(b)'], 0xa0000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
#    instdes("sh", ['t','o(b)'], 0xa4000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
#    instdes("sllv", ['d','t','s'], 0x00000004, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sll", ['d','w','s'], 0x00000004, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("slli", ['d','v','<'], 0x00000000, 0xffe0003f, WR_d|RD_s, 0, I1, 0),
    instdes("slt", ['d','v','t'], 0x0000002a, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("slti", ['t','r','j'], 0x28000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("sltiu", ['t','r','j'], 0x2c000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("sltu", ['d','v','t'], 0x0000002b, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
#    instdes("srav", ['d','t','s'], 0x00000007, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sra", ['d','w','s'], 0x00000007, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("srai", ['d','v','<'], 0x00000003, 0xffe0003f, WR_d|RD_s, 0, I1, 0),
#    instdes("srlv", ['d','t','s'], 0x00000006, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("srl", ['d','v','s'], 0x00000006, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("srli", ['d','v','<'], 0x00000002, 0xffe0003f, WR_d|RD_s, 0, I1, 0),
    instdes("sub", ['d','v','t'], 0x00000022, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("subu", ['d','v','t'], 0x00000023, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("sw", ['t','o(b)'], 0xac000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
#    instdes("swc0", ['E','o(b)'], 0xe0000000, 0xfc000000, SM|RD_C0|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("swc2", ['E','o(b)'], 0xe8000000, 0xfc000000, SM|RD_C2|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("swc3", ['E','o(b)'], 0xec000000, 0xfc000000, SM|RD_C3|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("swl", ['t','o(b)'], 0xa8000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
#    instdes("swr", ['t','o(b)'], 0xb8000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
#    instdes("syscall", [], 0x0000000c, 0xffffffff, TRAP, 0, I1, 0),
#    instdes("syscall", ['B'], 0x0000000c, 0xfc00003f, TRAP, 0, I1, 0),
#    instdes("tlbp", [], 0x42000008, 0xffffffff, INSN_TLB, 0, I1, 0),
#    instdes("tlbr", [], 0x42000001, 0xffffffff, INSN_TLB, 0, I1, 0),
#    instdes("tlbwi", [], 0x42000002, 0xffffffff, INSN_TLB, 0, I1, 0),
#    instdes("tlbwr", [], 0x42000006, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("xor", ['d','v','t'], 0x00000026, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("xori", ['t','r','j'], 0x38000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
#    instdes("bc2f", ['p'], 0x49000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("bc2t", ['p'], 0x49010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("cfc2", ['t','G'], 0x48400000, 0xffe007ff, LCD|WR_t|RD_C2, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("ctc2", ['t','G'], 0x48c00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("mfc2", ['t','G'], 0x48000000, 0xffe007ff, LCD|WR_t|RD_C2, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("mtc2", ['t','G'], 0x48800000, 0xffe007ff, COD|RD_t|WR_C2|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("bc3f", ['p'], 0x4d000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("bc3t", ['p'], 0x4d010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("cfc3", ['t','G'], 0x4c400000, 0xffe007ff, LCD|WR_t|RD_C3, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("ctc3", ['t','G'], 0x4cc00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("mfc3", ['t','G'], 0x4c000000, 0xffe007ff, LCD|WR_t|RD_C3, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("mtc3", ['t','G'], 0x4c800000, 0xffe007ff, COD|RD_t|WR_C3|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("bc0f", ['p'], 0x41000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("bc0t", ['p'], 0x41010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("c0", ['C'], 0x42000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("c2", ['C'], 0x4a000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
#    instdes("c3", ['C'], 0x4e000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
]

instopdes = collections.namedtuple('instopdes', ['fnc', 'operator', 'info', 'size'])

def reg_to_sig(rv):
    if rv >= 0x80000000:
        rv -= 0x100000000
    return rv

def val_to_reg(val):
    if val < 0:
        val += 0x100000000
        if val < 0:
            val += 0x100000000 * (operator.div(-val, 0x100000000) + 1)
    elif val >= 0x100000000:
        val -= 0x100000000
        if val >= 0x100000000:
            val -= 0x100000000 * operator.div(val, 0x100000000)
    return val

def instop_alu(cpustate, inst, op):
    a = 0
    while len(inst.args) > a:
        if inst.args[a].wrdep and not inst.args[a].rddep:
            a += 1
        else:
            break
    aincnt = len(inst.args) - a
    argin = [0] * aincnt
    for i in range(0, aincnt):
        argin[i] = cpustate.rdarg(inst.args[a + i])
        if op.info == 's':
            argin[i] = reg_to_sig(argin[i])
    if aincnt == 1:
        res = op.operator(argin[0])
    elif aincnt == 2:
        res = op.operator(argin[0], argin[1])
    else:
        res = op.operator(argin[0], argin[1], argin[2])
    if isinstance(res, bool):
        if res:
            res = 1
        else:
            res = 0
    if inst.args[0].wrdep:
        cpustate.wrarg(inst.args[0], res)
    elif (inst.pinfo & WR_HILO) != 0:
        cpustate.mhi = val_to_reg(res >> 32)
        cpustate.mlo = val_to_reg(res)
    return
def instop_b(cpustate, inst, op):
    aincnt = len(inst.args) - 1
    if op.operator is not None:
        argin = [0] * 2
        for i in range(0, aincnt):
            argin[i] = reg_to_sig(cpustate.rdarg(inst.args[i]))
        if not op.operator(argin[0], argin[1]):
            return
    npc = cpustate.pc + 4
    cpustate.b_pend_pc = npc + (inst.args[aincnt].value << 2)
    if (inst.pinfo & WR_31) != 0:
        cpustate.wrgpreg(31, npc)
    return
def instop_break(cpustate, inst):
    return
def instop_j(cpustate, inst, op):
    a = inst.args[0]
    if len(inst.args) > 1:
        a = inst.args[1]
    npc = cpustate.pc + 4
    cpustate.b_pend_pc = npc & ~((1 << 28) - 1)
    cpustate.b_pend_pc |= a.value << 2
    if (inst.pinfo & (WR_31 | WR_d)) != 0:
        if len(inst.args) > 1:
            cpustate.wrarg(inst.args[0], res)
        else:
            cpustate.wrgpreg(31, npc)
    return
def instop_l(cpustate, inst, op):
    addr = cpustate.rdarg(inst.args[1])
    res = cpustate.rdmem(addr, op.size, op.info == 's')
    cpustate.wrarg(inst.args[0], res)
    return
def instop_mf(cpustate, inst, op):
    if op.info == 'h':
        cpustate.wrarg(inst.args[0], cpustate.mhi)
    elif op.info == 'l':
        cpustate.wrarg(inst.args[0], cpustate.mlo)
    return
def instop_mt(cpustate, inst, op):
    if op.info == 'h':
        cpustate.mhi = cpustate.rdarg(inst.args[0])
    elif op.info == 'l':
        cpustate.mlo = cpustate.rdarg(inst.args[0])
    return
def instop_s(cpustate, inst, op):
    addr = cpustate.rdarg(inst.args[1])
    res = cpustate.rdarg(inst.args[0])
    res = cpustate.wrmem(addr, op.size, res)
    return

def op_nor(a, b):
    return operator.inv(a | b)

def op_copy(a):
    return a

def op_lui(a):
    return a << 16

def op_div_rem(a, b):
    q = operator.div(a, b)
    r = operator.mod(a, b)
    return (r << 32) | q

instopdeslist = {
    'nop':   instopdes(None, None, 0, 32),
    'ssnop': instopdes(None, None, 0, 32),
    'ehb':   instopdes(None, None, 0, 32),
    'li':    instopdes(instop_alu, op_copy, 'u', 32),
    'move':  instopdes(instop_alu, op_copy, 'u', 32),
    'b':     instopdes(instop_b, None, None, 32),
    'bal':   instopdes(instop_b, None, None, 32),
    'add':   instopdes(instop_alu, operator.add, 's', 32),
    'addi':  instopdes(instop_alu, operator.add, 's', 32),
    'addiu': instopdes(instop_alu, operator.add, 'u', 32),
    'addu':  instopdes(instop_alu, operator.add, 'u', 32),
    'and':   instopdes(instop_alu, operator.and_, 'u', 32),
    'andi':  instopdes(instop_alu, operator.and_, 'u', 32),
    'beqz':  instopdes(instop_b, operator.eq, None, 32),
    'beq':   instopdes(instop_b, operator.eq, None, 32),
    'bgez':  instopdes(instop_b, operator.ge, None, 32),
    'bgezal':instopdes(instop_b, operator.ge, None, 32),
    'bgtz':  instopdes(instop_b, operator.gt, None, 32),
    'blez':  instopdes(instop_alu, operator.le, None, 32),
    'bltz':  instopdes(instop_alu, operator.lt, None, 32),
    'bltzal':instopdes(instop_alu, operator.lt, None, 32),
    'bnez':  instopdes(instop_alu, operator.ne, None, 32),
    'bne':   instopdes(instop_alu, operator.ne, None, 32),
    'break': instopdes(instop_break, None, None, 32),
    'cfc0':  instopdes(None, None, None, 32),
    'div':   instopdes(instop_alu, op_div_rem, 's', 32),
    'divu':  instopdes(instop_alu, op_div_rem, 'u', 32),
    'jr':    instopdes(instop_j, None, None, 32),
    'j':     instopdes(instop_j, None, None, 32),
    'jal':   instopdes(instop_j, None, None, 32),
    'jalr':  instopdes(instop_j, None, None, 32),
    'jalx':  instopdes(None, None, None, 32),
    'lb':    instopdes(instop_l, None, 's', 8),
    'lbu':   instopdes(instop_l, None, 'u', 8),
    'lh':    instopdes(instop_l, None, 's', 16),
    'lhu':   instopdes(instop_l, None, 'u', 16),
    'lui':   instopdes(instop_alu, op_lui, 'u', 32),
    'lw':    instopdes(instop_l, None, 's', 32),
    'lwc0':  instopdes(None, None, None, 32),
    'lwc2':  instopdes(None, None, None, 32),
    'lwc3':  instopdes(None, None, None, 32),
    'lwl':   instopdes(None, None, None, 32),
    'lwr':   instopdes(None, None, None, 32),
    'mfc0':  instopdes(None, None, None, 32),
    'mfhi':  instopdes(instop_mf, None, 'h', 32),
    'mflo':  instopdes(instop_mf, None, 'l', 32),
    'mtc0':  instopdes(None, None, None, 32),
    'mthi':  instopdes(instop_mt, None, 'h', 32),
    'mtlo':  instopdes(instop_mt, None, 'l', 32),
    'mult':  instopdes(instop_alu, operator.mul, 's', 32),
    'multu': instopdes(instop_alu, operator.mul, 'u', 32),
    'neg':   instopdes(instop_alu, operator.neg, 's', 32),
    'negu':  instopdes(instop_alu, operator.neg, 'u', 32),
    'nor':   instopdes(instop_alu, op_nor, 'u', 32),
    'not':   instopdes(instop_alu, operator.inv, 'u', 32),
    'or':    instopdes(instop_alu, operator.or_, 'u', 32),
    'ori':   instopdes(instop_alu, operator.or_, 'u', 32),
    'rem':   instopdes(instop_alu, operator.mod, 's', 32),
    'remu':  instopdes(instop_alu, operator.mod, 'u', 32),
    'rfe':   instopdes(None, None, None, 32),
    'sb':    instopdes(instop_s, None, None, 8),
    'sh':    instopdes(instop_s, None, None, 16),
    'sllv':  instopdes(instop_alu, operator.lshift, 'u', 32),
    'sll':   instopdes(instop_alu, operator.lshift, 'u', 32),
    'slli':   instopdes(instop_alu, operator.lshift, 'u', 32),
    'slt':   instopdes(instop_alu, operator.lt, 's', 32),
    'slti':  instopdes(instop_alu, operator.lt, 's', 32),
    'sltiu': instopdes(instop_alu, operator.lt, 'u', 32),
    'sltu':  instopdes(instop_alu, operator.lt, 'u', 32),
    'srav':  instopdes(instop_alu, operator.rshift, 's', 32),
    'sra':   instopdes(instop_alu, operator.rshift, 's', 32),
    'srai':   instopdes(instop_alu, operator.rshift, 's', 32),
    'srlv':  instopdes(instop_alu, operator.rshift, 'u', 32),
    'srl':   instopdes(instop_alu, operator.rshift, 'u', 32),
    'srli':   instopdes(instop_alu, operator.rshift, 'u', 32),
    'sub':   instopdes(instop_alu, operator.sub, 's', 32),
    'subu':  instopdes(instop_alu, operator.sub, 'u', 32),
    'sw':    instopdes(instop_s, None, None, 32),
    'swc0':  instopdes(None, None, None, 32),
    'swc2':  instopdes(None, None, None, 32),
    'swc3':  instopdes(None, None, None, 32),
    'swl':   instopdes(None, None, None, 32),
    'swr':   instopdes(None, None, None, 32),
    'syscall': instopdes(None, None, None, 32),
    'tlbp':  instopdes(None, None, None, 32),
    'tlbr':  instopdes(None, None, None, 32),
    'tlbwi': instopdes(None, None, None, 32),
    'tlbwr': instopdes(None, None, None, 32),
    'xor':   instopdes(instop_alu, operator.xor, 'u', 32),
    'xori':  instopdes(instop_alu, operator.xor, 's', 32),
    'bc2f':  instopdes(None, None, None, 32),
    'bc2t':  instopdes(None, None, None, 32),
    'cfc2':  instopdes(None, None, None, 32),
    'ctc2':  instopdes(None, None, None, 32),
    'mfc2':  instopdes(None, None, None, 32),
    'mtc2':  instopdes(None, None, None, 32),
    'bc3f':  instopdes(None, None, None, 32),
    'bc3t':  instopdes(None, None, None, 32),
    'cfc3':  instopdes(None, None, None, 32),
    'ctc3':  instopdes(None, None, None, 32),
    'mfc3':  instopdes(None, None, None, 32),
    'mtc3':  instopdes(None, None, None, 32),
    'bc0f':  instopdes(None, None, None, 32),
    'bc0t':  instopdes(None, None, None, 32),
    'c0':    instopdes(None, None, None, 32),
    'c2':    instopdes(None, None, None, 32),
    'c3':    instopdes(None, None, None, 32),
}

locdes = collections.namedtuple('locdes', ['rd_mask', 'wr_mask', 'startbit', 'bits'])

locdesbycode = {
    'RS' : locdes(RD_s | RD_b, 0, 21,  5),
    'RT' : locdes(RD_t,     WR_t, 16,  5),
    'RD' : locdes(0,        WR_d, 11,  5),
    'SHAMT' : locdes(0,        0,  6,  5),
    'IMMEDIATE' : locdes(0,    0,  0, 16),
    'DELTA' : locdes(0,        0,  0, 16),
}

regname2regnum = {
    'zero': 0, 'at': 1, 'v0':  2, 'v1':  3, 'a0':  4, 'a1':  5,
    'a2':  6, 'a3':  7, 't0':  8, 't1':  9, 't2': 10, 't3': 11,
    't4': 12, 't5': 13, 't6': 14, 't7': 15, 's0': 16, 's1': 17,
    's2': 18, 's3': 19, 's4': 20, 's5': 21, 's6': 22, 's7': 23,
    't8': 24, 't9': 25, 'k0': 26, 'k1': 27, 'gp': 28, 'sp': 29,
    's8': 30, 'ra': 31}

regnum2regname = {}

for r in regname2regnum:
    regnum2regname[regname2regnum[r]] = r

regname2regnum_rv = {
    'zero': 0, 'ra': 1, 'sp':  2, 'gp':  3, 'tp':  4, 't0':  5,
    't1':  6, 't2':  7, 's0':  8, 'fp':  8, 's1':  9, 'a0': 10, 'a1': 11,
    'a2': 12, 'a3': 13, 'a4': 14, 'a5': 15, 'a6': 16, 'a7': 17,
    's2': 18, 's3': 19, 's4': 20, 's5': 21, 's6': 22, 's7': 23,
    's8': 24, 's9': 25, 's10': 26, 's11': 27, 't3': 28, 't4': 29,
    't5': 30, 't6': 31}

regnum2regname_rv = {}

for r in regname2regnum_rv:
    regnum2regname_rv[regname2regnum_rv[r]] = r


instdesbyname = {}

for inst in instdeslist:
    if not inst.name in instdesbyname:
        instdesbyname[inst.name] = [inst]
    else:
        instdesbyname[inst.name].append(inst)

instdesbyname_rv = {}

for inst in instdeslist_rv:
    if not inst.name in instdesbyname_rv:
        instdesbyname_rv[inst.name] = [inst]
    else:
        instdesbyname_rv[inst.name].append(inst)


class simarg(object):
    def __init__(self, argspec, regkind = None, reg = None, value = 0, rddep = False, wrdep = False, encoding = 0, text = None):
        self.argspec = argspec
        self.regkind = regkind
        self.reg = reg
        self.value = value
        self.rddep = rddep
        self.wrdep = wrdep
        self.encoding = encoding
        self.text = text

class siminst(object):
    @staticmethod
    def regnum(regin):
        if isinstance(regin, numbers.Number):
            return int(regin)
        if regin[0] == '$':
            regin = regin[1:]
        if regin in regname2regnum:
            return regname2regnum[regin]
        return int(regin)
    @staticmethod
    def regnum_rv(regin):
        if regin[0] == 'x':
            if isinstance(regin[1:], numbers.Number):
                return int(regin[1:])
        if regin in regname2regnum_rv:
            return regname2regnum_rv[regin]
        return None
    @staticmethod
    def parse_argument(argspec, arg, pinfo):
        argtext = arg
        p = argspec.find('(')
        if p != -1:
            if argspec[-1] != ')':
                return None
            aspcs = [argspec[0 : p], argspec[p + 1: -1]]
            p = arg.find('(')
            if p != -1:
                if arg[-1] != ')':
                    return None
                arg = [ arg[0 : p], arg[p + 1: -1]]
            else:
                arg = [ arg[0 : p], None]
        else:
            aspcs = [argspec]
            arg = [arg]
        value = 0
        rddep = False
        wrdep = False
        rn = None
        regkind = None
        encoding = 0
        for i in range(0, len(aspcs)):
            if aspcs[i] not in argdesbycode:
                return None
            argdes = argdesbycode[aspcs[i]]
            if argdes.loc in locdesbycode:
                locdes = locdesbycode[argdes.loc]
            else:
                locdes = None
            a = arg[i]
            if (argdes.kind == 'n') or (argdes.kind == 'o'):
                if (argdes.kind == 'o') and (len(a) == 0):
                    continue
                try:
                    value = int(a, 0)
                except ValueError:
                    return None
                if (value < argdes.min) or (value > argdes.max):
                    return None
                if value >= value:  # TODO error
                    valunsig = value
                else:
                    valunsig = value + 0x100000000
                if locdes is not None:
                    valunsig &= (1 << locdes.bits) - 1
                    encoding |=  valunsig << locdes.startbit
            elif argdes.kind == 'g':
                reg = a
                regkind = argdes.kind
                if reg is None:
                    rn = 0
                elif (reg in regname2regnum) or (reg[0] == '$'):
                    rn = siminst.regnum(reg)
                    if rn is None:
                        return None
                    if rn != 0:
                        if locdes is not None:
                            if rn >= 1 << locdes.bits:
                                return None
                            if pinfo & locdes.rd_mask != 0:
                                rddep = True
                            if pinfo & locdes.wr_mask != 0:
                                wrdep = True
                else:
                    return None
                if locdes is not None:
                    encoding |= rn << locdes.startbit
            elif argdes.kind == 'p':
                try:
                    value = int(a, 0)
                except ValueError:
                    value = 0
                if value & ((1 << argdes.shift) - 1):
                    return None
                value >>= argdes.shift
                if (value < argdes.min) or (value > argdes.max):
                    return None
            elif argdes.kind == 'a':
                try:
                    value = int(a, 0)
                except ValueError:
                    value = 0
                if value & ((1 << argdes.shift) - 1):
                    return None
                value >>= argdes.shift
                if (value < argdes.min) or (value > argdes.max):
                    return None
            else:
                return None
        return simarg(argspec = argspec, regkind = regkind, reg = rn, value = value, rddep = rddep, wrdep = wrdep, encoding = encoding, text = argtext)
    @staticmethod
    def parse_argument_rv(argspec, argtext, pinfo):
        argtext = arg
        p = argspec.find('(')
        if p != -1:
            if argspec[-1] != ')':
                return None
            aspcs = [argspec[0 : p], argspec[p + 1: -1]]
            p = argtext.find('(')
            if p != -1:
                if argtext[-1] != ')':
                    return None
                arg = [ argtext[0 : p], argtext[p + 1: -1]]
            else:
                arg = [ argtext[0 : p], None]
        else:
            aspcs = [argspec]
            arg = [argtext]
        value = 0
        rddep = False
        wrdep = False
        rn = None
        regkind = None
        encoding = 0
        for i in range(0, len(aspcs)):
            if aspcs[i] not in argdesbycode:
                return None
            argdes = argdesbycode[aspcs[i]]
            if argdes.loc in locdesbycode:
                locdes = locdesbycode[argdes.loc]
            else:
                locdes = None
            a = arg[i]
            if (argdes.kind == 'n') or (argdes.kind == 'o'):
                if (argdes.kind == 'o') and (len(a) == 0):
                    continue
                try:
                    value = int(a, 0)
                except ValueError:
                    return None
                if (value < argdes.min) or (value > argdes.max):
                    return None
                if value >= 0:  # TODO error? value>=value
                    valunsig = value
                else:
                    valunsig = value + 0x100000000
                if locdes is not None:
                    valunsig &= (1 << locdes.bits) - 1
                    encoding |=  valunsig << locdes.startbit
            elif argdes.kind == 'g':
                reg = a
                regkind = argdes.kind
                if reg is None:
                    rn = 0
                elif (reg in regname2regnum_rv) or (reg[0] == 'x'):
                    rn = siminst.regnum(reg)
                    if rn is None:
                        return None
                    if rn != 0:
                        if locdes is not None:
                            if rn >= 1 << locdes.bits:
                                return None
                            if pinfo & locdes.rd_mask != 0:
                                rddep = True
                            if pinfo & locdes.wr_mask != 0:
                                wrdep = True
                else:
                    return None
                if locdes is not None:
                    encoding |= rn << locdes.startbit
            elif argdes.kind == 'p':
                try:
                    value = int(a, 0)
                except ValueError:
                    value = 0
                if value & ((1 << argdes.shift) - 1):
                    return None
                value >>= argdes.shift
                if (value < argdes.min) or (value > argdes.max):
                    return None
            elif argdes.kind == 'a':
                try:
                    value = int(a, 0)
                except ValueError:
                    value = 0
                if value & ((1 << argdes.shift) - 1):
                    return None
                value >>= argdes.shift
                if (value < argdes.min) or (value > argdes.max):
                    return None
            else:
                return None
        return simarg(argspec = argspec, regkind = regkind, reg = rn, value = value, rddep = rddep, wrdep = wrdep, encoding = encoding, text = argtext)
    @staticmethod
    def parse(asline):
        p = asline.find('#')
        if p >= 0:
            asline = asline[0:p]
        p = asline.find(':')
        label = None
        if p >= 0:
            label = asline[0:p].strip()
            asline = asline[p+1:]
        elem = asline.split(None, 1)
        operation = elem[0]
        args = []
        if len(elem) > 1:
            for a in elem[1].split(','):
                a = a.strip()
                if len(a) == 0:
                    sys.stderr.write('empty/missing argument in line "%s"\n'%(asline))
                    return None
                else:
                    args.append(a)
        if operation not in instdesbyname:
            sys.stderr.write('operation "%s" in line "%s" is not known\n'%(operation, asline))
        matchdes = None
        for des in instdesbyname[operation]:
            if len(args) != len(des.args):
                continue
            matchargs = []
            argmismatch = False
            for i in range(0,len(args)):
                ma = siminst.parse_argument(des.args[i], args[i], des.pinfo)
                if ma == None:
                    argmismatch = True
                    break
                matchargs.append(ma)
            if argmismatch:
                continue
            matchdes = des
            break
        if matchdes is None:
            sys.stderr.write('no matching argument combination for line "%s"\n'%(asline))
            return None
        encoding = matchdes.match
        for a in matchargs:
            encoding |= a.encoding
        return siminst(operation, matchargs, encoding, matchdes.pinfo)
    @staticmethod
    def parse_rv(asline):
        p = asline.find('#')
        if p >= 0:
            asline = asline[0:p]
        p = asline.find(':')
        label = None
        if p >= 0:
            label = asline[0:p].strip()
            asline = asline[p+1:]
        elem = asline.split(None, 1)
        operation = elem[0]
        args = []
        if len(elem) > 1:
            for a in elem[1].split(','):
                a = a.strip()
                if len(a) == 0:
                    sys.stderr.write('empty/missing argument in line "%s"\n'%(asline))
                    return None
                else:
                    args.append(a)
        if operation not in instdesbyname_rv:
            sys.stderr.write('operation "%s" in line "%s" is not known\n'%(operation, asline))
        matchdes = None
        for des in instdesbyname_rv[operation]:
            if len(args) != len(des.args):
                continue
            matchargs = []
            argmismatch = False
            for i in range(0,len(args)):
                ma = siminst.parse_argument(des.args[i], args[i], des.pinfo)
                if ma == None:
                    argmismatch = True
                    break
                matchargs.append(ma)
            if argmismatch:
                continue
            matchdes = des
            break
        if matchdes is None:
            sys.stderr.write('RISC V no matching argument combination for line "%s"\n'%(asline))
            return None
        encoding = matchdes.match
        for a in matchargs:
            encoding |= a.encoding
        return siminst(operation, matchargs, encoding, matchdes.pinfo)

    def __init__(self, operation = None, args = [], encoding = 0, pinfo = 0):
        self.operation = operation
        self.args = args
        self.encoding = encoding
        self.pinfo = pinfo
        self.stalls = 0
        self.forward = (0, 0)

    def depanalyze(self, instb, bidir = False):
        deps = 0
        for aself in self.args:
            for ainstb in instb.args:
                if (aself.regkind == ainstb.regkind) and (aself.reg == ainstb.reg):
                    if (aself.rddep) and (ainstb.wrdep):
                        deps |= DEP_RAW
                    if bidir and (aself.wrdep) and (ainstb.rddep):
                        deps |= DEP_RAW
                    if (aself.wrdep) and (ainstb.wrdep):
                        deps |= DEP_WAW
        if (self.pinfo & (LDD | SM)) and (instb.pinfo & (LDD | SM)):
            deps |= DEP_MEM_POSSIBLE
        return deps

    def astext(self, regsymbolic = True):
        s = self.operation
        if len(self.args) >= 1:
            s += ' '
            s = s.ljust(6)
            comarequired = False
            for a in self.args:
                if comarequired:
                    s += ','
                else:
                    comarequired = True
                if a.text is not None:
                    s += a.text
        return s

class simcpustate(object):
    def __init__(self):
        self.gpreg = [0] * 32
        self.pc = 0
        self.b_pend_pc = None
        self.mhi = 0
        self.mlo = 0
        self.memory = {}
    def executeinst(self, inst):
        op = instopdeslist[inst.operation]
        op.fnc(self, inst, op)
    def rdgpreg(self, regnum):
        return self.gpreg[regnum]
    def wrgpreg(self, regnum, val):
        if regnum != 0:
            self.gpreg[regnum] = val_to_reg(val)
    def rdreg(self, reg):
        if reg in regname2regnum:
            regnum = regname2regnum[reg]
            return self.rdgpreg(regnum)
        return None
    def wrreg(self, reg, val):
        if reg in regname2regnum:
            regnum = regname2regnum[reg]
            self.wrgpreg(regnum, val)
        return None
    def rdarg(self, arg):
        val = None
        if (arg.regkind is not None) and (arg.reg is not None):
            if arg.regkind == 'g':
                val = self.rdgpreg(arg.reg) + arg.value
        else:
            val = arg.value
        return val
    def wrarg(self, arg, val):
        if (arg.regkind is not None) and (arg.reg is not None):
            if arg.regkind == 'g':
                self.wrgpreg(arg.reg, val)
    def rdmem(self, addr, size, signed = False):
        addr = val_to_reg(addr)
        waddr = addr & ~3
        if waddr in self.memory:
            val = self.memory[waddr]
        else:
            sys.stderr.write('attemp to read uninitialized memory at address 0x%08x\n'%(addr))
            val = 0
        if size < 32:
            val >>= 32 - size - (addr - waddr) * 8
            val &= (1 << size) - 1
        if signed:
            if val & (1 << (size - 1)):
                val -= 1 << size
        return val
    def wrmem(self, addr, size, val):
        addr = val_to_reg(addr)
        waddr = addr & ~3
        if size < 32:
            if waddr in self.memory:
                old = self.memory[waddr]
            else:
                old = 0
            mask = (1 << size) - 1
            val &= mask
            sh = 32 - size - (addr - waddr) * 8
            mask <<= sh
            val <<= sh
            val = (old & ~mask) | val
        self.memory[waddr] = val
    def regsastext(self, regsymbolic = True):
        regstxt = []
        for i in range(0, len(self.gpreg)):
            rn = '$'+str(i)
            if regsymbolic and (i in regnum2regname):
                rn = regnum2regname[i]
            rn = rn.ljust(4)
            regstxt.append(rn + ':' + '%08x'%(self.gpreg[i]))
        regstxt.append('mhi :' + '%08x'%(self.mhi))
        regstxt.append('mlo :' + '%08x'%(self.mlo))
        return regstxt

class siminstlist(object):
    def __init__(self):
        self.instlist = []
    def append(self, inst):
        if isinstance(inst, basestring):
            inst = siminst.parse(inst)
        self.instlist.append(inst)
        return inst
    def append_rv(self, inst):
        if isinstance(inst, basestring):
            inst_code = siminst.parse_rv(inst)
        self.instlist.append(inst_code)
        return inst_code
    def listastext(self, regsymbolic = True):
        l = []
        for inst in self.instlist:
            l.append(inst.astext(regsymbolic = regsymbolic))
        return l
    def mutuate(self, mutvector, mutfrom = 0):
        iend = len(self.instlist)
        cycles = 4
        j = 0
        while j < len(mutvector):
            mutpossible = False
            for i in range(mutfrom, iend - 1):
                inst1 = self.instlist[i]
                inst2 = self.instlist[i + 1]
                if inst1.depanalyze(inst2, bidir = True) != 0:
                    continue
                mutpossible = True
                if mutvector[j]:
                    self.instlist[i] = inst2
                    self.instlist[i + 1] = inst1
                j += 1
                if j >= len(mutvector):
                    break
            if not mutpossible:
                break
    def analyze(self):
        iend = len(self.instlist)
        cycles = 4
        for i in range(0, iend):
            cycles += 1 + self.instlist[i].stalls
            for a in self.instlist[i].args:
               if a.wrdep:
                   regkind = a.regkind
                   reg = a.reg
                   latency = 3
                   distance = 0
                   j = i
                   while True:
                       j += 1
                       if j >= len(self.instlist):
                           break
                       instb = self.instlist[j]
                       distance += 1 + instb.stalls
                       if distance >= latency:
                           break
                       for argb in instb.args:
                           if argb.rddep:
                               if (argb.regkind == regkind) and (argb.reg == reg):
                                   # sys.stdout.write('i %d j %d latency %d distance %d\n'%(i, j, latency, distance))
                                   stalls = latency - distance
                                   instb.stalls += stalls
                                   distance += stalls
        return cycles

    def analyze_stall_forward(self):
        iend = len(self.instlist)
        cycles = 4
        for i in range(0, iend):
            distance = 0
            j = i
            insta = self.instlist[i]
            insta.stalls = 0;
            latency = 3
            ff_rs = 0
            ff_rt = 0
            while j > 0:
                distance += 1 + self.instlist[j].stalls
                if distance >= latency:
                    break
                j -= 1
                instb = self.instlist[j]
                if (instb.pinfo & LDD) and (distance == 1):
                    for argb in instb.args:
                        if not argb.wrdep:
                            continue
                        for arga in insta.args:
                            if (arga.regkind == argb.regkind) and (arga.reg == argb.reg):
                                if arga.rddep:
                                    insta.stalls += 2 - distance
                                    distance = 2
                for argb in instb.args:
                    if not argb.wrdep:
                        continue
                    for arga in insta.args:
                        if (arga.regkind == argb.regkind) and (arga.reg == argb.reg):
                            if arga.rddep:
                                aspec = arga.argspec
                                p = aspec.find('(')
                                if p != -1:
                                    aspec = aspec[p+1:-1]
                                if (argdesbycode[aspec].loc == "RS") and (ff_rs == 0):
                                    ff_rs = latency - distance
                                if (argdesbycode[aspec].loc == "RT") and (ff_rt == 0):
                                    ff_rt = latency - distance

            insta.forward = (ff_rs, ff_rt)
            cycles += 1 + self.instlist[i].stalls
        return cycles


if __name__ == '__main__':

    #print siminst.regnum('t9')
    #print siminst.regnum('$t9')
    #print siminst.regnum(9)
    #print siminst.regnum('9')

    #print siminst.parse('label1: add  v0,$0, $v1 # test')
    #print siminst.parse('label1: addi  v0,$s0,-100 # test')
    #print siminst.parse('        lw   $4,10(s0) # test')

    instlist = siminstlist()

    instlist.append(siminst.parse('add  t0,zero,zero'))
    instlist.append(siminst.parse('addi t1,zero,0x4410'))
    instlist.append(siminst.parse('addi t2,t1,-0x8000'))
    instlist.append(siminst.parse('add  t3,t0,t2'))
    instlist.append(siminst.parse('add  t4,t2,zero'))
    instlist.append(siminst.parse('sw   t3,10(t4)'))
    instlist.append(siminst.parse('lw   t2,-0x1000(t0)'))
    instlist.append(siminst.parse('beq  t0,t4,0x10'))
    instlist.append(siminst.parse('lui  t5,0x1234'))
    instlist.append(siminst.parse('sltiu t2,t0,20'))
    instlist.append(siminst.parse('slti t2,t2,20'))
    inst1 = instlist.append(siminst.parse('srlv t2,t2,t2'))
    inst2 = instlist.append(siminst.parse('sra  t2,t2,0'))

    sys.stdout.write('%08x\n'%(inst2.encoding))

    print inst2.depanalyze(inst1, bidir = False)

    print instlist.analyze()
    print instlist.analyze_stall_forward()

    cpu = simcpustate()

    instlist.append(siminst.parse('lui  s0,0x1234'))
    instlist.append(siminst.parse('ori  s0,s0,0x5678'))
    instlist.append(siminst.parse('lui  s1,0xFEDC'))
    instlist.append(siminst.parse('ori  s1,s1,0xBA98'))
    instlist.append(siminst.parse('sw   s0,(s1)'))
    instlist.append(siminst.parse('lw   s2,(s1)'))
    instlist.append(siminst.parse('lb   s3,(s1)'))
    instlist.append(siminst.parse('lb   s4,3(s1)'))
    instlist.append(siminst.parse('sh   s1,2(s1)'))
    instlist.append(siminst.parse('addi s1,s1,-4'))
    instlist.append(siminst.parse('lw   s5,4(s1)'))
    instlist.append(siminst.parse('beq  t0,t0,0x1234'))
    instlist.append(siminst.parse('li   k0,0x00000101'))
    instlist.append(siminst.parse('lui  k1,0x8000'))
    instlist.append(siminst.parse('ori  k1,k1,0x0000005A'))
    instlist.append(siminst.parse('mult k0,k1'))
    instlist.append(siminst.parse('mflo v0'))
    instlist.append(siminst.parse('mfhi v1'))
    instlist.append(siminst.parse('mthi k1'))


    for i in range(0, len(instlist.instlist)):
        c = 0
        sys.stdout.write(instlist.instlist[i].astext() + '\n')
        cpu.executeinst(instlist.instlist[i])
        sys.stdout.write('stalls ' + str(instlist.instlist[i].stalls))
        sys.stdout.write(' ff_rs ' + str(instlist.instlist[i].forward[0]))
        sys.stdout.write(' ff_rt ' + str(instlist.instlist[i].forward[1]) + '\n')
        for rstr in cpu.regsastext():
             sys.stdout.write(' ' + rstr)
             c += 1
             if c % 6 == 0:
                 sys.stdout.write('\n')
        if c % 6 != 0:
            sys.stdout.write('\n')
