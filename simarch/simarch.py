#!/usr/bin/python

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
__copyright__ = "Copyright 2017, Czech Technical University"
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

M_PREF_AB = 0
M_LI = 0
M_MOVE = 0
M_ABS = 0
M_ACLR_OB = 0
M_ACLR_AB = 0
M_ADD_I = 0
M_ADDU_I = 0
M_AND_I = 0
M_ASET_OB = 0
M_ASET_AB = 0
M_BEQ_I = 0
M_BEQL_I = 0
M_BGE = 0
M_BGE_I = 0
M_BGEL = 0
M_BGEL_I = 0
M_BGEU = 0
M_BGEU_I = 0
M_BGEUL = 0
M_BGEUL = 0
M_BGEUL_I = 0
M_BGT = 0
M_BGT_I = 0
M_BGTL = 0
M_BGTL_I = 0
M_BGTU = 0
M_BGTU_I = 0
M_BGTUL = 0
M_BGTUL_I = 0
M_BLE = 0
M_BLE_I = 0
M_BLEL = 0
M_BLEL_I = 0
M_BLEU = 0
M_BLEU_I = 0
M_BLEUL = 0
M_BLEUL_I = 0
M_BLT = 0
M_BLT_I = 0
M_BLTL = 0
M_BLTL_I = 0
M_BLTU = 0
M_BLTU_I = 0
M_BLTUL = 0
M_BLTUL_I = 0
M_BNE_I = 0
M_BNEL_I = 0
M_CACHE_AB = 0
M_DABS = 0
M_DADD_I = 0
M_DADDU_I = 0
M_DEXT = 0
M_DDIV_3 = 0
M_DDIV_3I = 0
M_DDIVU_3 = 0
M_DDIVU_3I = 0
M_DINS = 0
M_DIV_3 = 0
M_DIV_3I = 0
M_DIVU_3 = 0
M_DIVU_3I = 0
M_DLA_AB = 0
M_DLCA_AB = 0
M_DLI = 0
M_DMUL = 0
M_DMUL_I = 0
M_DMULO = 0
M_DMULO_I = 0
M_DMULOU = 0
M_DMULOU_I = 0
M_DREM_3 = 0
M_DREM_3I = 0
M_ABS = 0
M_ACLR_AB = 0
M_ACLR_OB = 0
M_ADD_I = 0
M_ADDU_I = 0
M_AND_I = 0
M_ASET_AB = 0
M_ASET_OB = 0
M_BALIGN = 0
M_BC1FL = 0
M_BC1TL = 0
M_BC2FL = 0
M_BC2TL = 0
M_BEQ = 0
M_BEQ_I = 0
M_BEQL = 0
M_BEQL_I = 0
M_BGE = 0
M_BGEL = 0
M_BGE_I = 0
M_BGEL_I = 0
M_BGEU = 0
M_BGEUL = 0
M_BGEU_I = 0
M_BGEUL_I = 0
M_BGEZ = 0
M_BGEZL = 0
M_BGEZALL = 0
M_BGT = 0
M_BGTL = 0
M_BGT_I = 0
M_BGTL_I = 0
M_BGTU = 0
M_BGTUL = 0
M_BGTU_I = 0
M_BGTUL_I = 0
M_BGTZ = 0
M_BGTZL = 0
M_BLE = 0
M_BLEL = 0
M_BLE_I = 0
M_BLEL_I = 0
M_BLEU = 0
M_BLEUL = 0
M_BLEU_I = 0
M_BLEUL_I = 0
M_BLEZ = 0
M_BLEZL = 0
M_BLT = 0
M_BLTL = 0
M_BLT_I = 0
M_BLTL_I = 0
M_BLTU = 0
M_BLTUL = 0
M_BLTU_I = 0
M_BLTUL_I = 0
M_BLTZ = 0
M_BLTZL = 0
M_BLTZALL = 0
M_BNE = 0
M_BNEL = 0
M_BNE_I = 0
M_BNEL_I = 0
M_CACHE_AB = 0
M_CACHE_OB = 0
M_DABS = 0
M_DADD_I = 0
M_DADDU_I = 0
M_DDIV_3 = 0
M_DDIV_3I = 0
M_DDIVU_3 = 0
M_DDIVU_3I = 0
M_DEXT = 0
M_DINS = 0
M_DIV_3 = 0
M_DIV_3I = 0
M_DIVU_3 = 0
M_DIVU_3I = 0
M_DLA_AB = 0
M_DLCA_AB = 0
M_DLI = 0
M_DMUL = 0
M_DMUL_I = 0
M_DMULO = 0
M_DMULO_I = 0
M_DMULOU = 0
M_DMULOU_I = 0
M_DREM_3 = 0
M_DREM_3I = 0
M_DREMU_3 = 0
M_DREMU_3I = 0
M_DSUB_I = 0
M_DSUBU_I = 0
M_DSUBU_I_2 = 0
M_J_A = 0
M_JAL_1 = 0
M_JAL_2 = 0
M_JAL_A = 0
M_JALS_1 = 0
M_JALS_2 = 0
M_JALS_A = 0
M_L_DOB = 0
M_L_DAB = 0
M_LA_AB = 0
M_LB_A = 0
M_LB_AB = 0
M_LBU_A = 0
M_LBU_AB = 0
M_LCA_AB = 0
M_LD_A = 0
M_LD_OB = 0
M_LD_AB = 0
M_LDC1_AB = 0
M_LDC2_AB = 0
M_LDC2_OB = 0
M_LDC3_AB = 0
M_LDL_AB = 0
M_LDL_OB = 0
M_LDM_AB = 0
M_LDM_OB = 0
M_LDP_AB = 0
M_LDP_OB = 0
M_LDR_AB = 0
M_LDR_OB = 0
M_LH_A = 0
M_LH_AB = 0
M_LHU_A = 0
M_LHU_AB = 0
M_LI = 0
M_LI_D = 0
M_LI_DD = 0
M_LI_S = 0
M_LI_SS = 0
M_LL_AB = 0
M_LL_OB = 0
M_LLD_AB = 0
M_LLD_OB = 0
M_LS_A = 0
M_LW_A = 0
M_LW_AB = 0
M_LWC0_A = 0
M_LWC0_AB = 0
M_LWC1_A = 0
M_LWC1_AB = 0
M_LWC2_A = 0
M_LWC2_AB = 0
M_LWC2_OB = 0
M_LWC3_A = 0
M_LWC3_AB = 0
M_LWL_A = 0
M_LWL_AB = 0
M_LWL_OB = 0
M_LWM_AB = 0
M_LWM_OB = 0
M_LWP_AB = 0
M_LWP_OB = 0
M_LWR_A = 0
M_LWR_AB = 0
M_LWR_OB = 0
M_LWU_AB = 0
M_LWU_OB = 0
M_MSGSND = 0
M_MSGLD = 0
M_MSGLD_T = 0
M_MSGWAIT = 0
M_MSGWAIT_T = 0
M_MOVE = 0
M_MUL = 0
M_MUL_I = 0
M_MULO = 0
M_MULO_I = 0
M_MULOU = 0
M_MULOU_I = 0
M_NOR_I = 0
M_OR_I = 0
M_PREF_AB = 0
M_PREF_OB = 0
M_REM_3 = 0
M_REM_3I = 0
M_REMU_3 = 0
M_REMU_3I = 0
M_DROL = 0
M_ROL = 0
M_DROL_I = 0
M_ROL_I = 0
M_DROR = 0
M_ROR = 0
M_DROR_I = 0
M_ROR_I = 0
M_S_DA = 0
M_S_DOB = 0
M_S_DAB = 0
M_S_S = 0
M_SAA_AB = 0
M_SAA_OB = 0
M_SAAD_AB = 0
M_SAAD_OB = 0
M_SC_AB = 0
M_SC_OB = 0
M_SCD_AB = 0
M_SCD_OB = 0
M_SD_A = 0
M_SD_OB = 0
M_SD_AB = 0
M_SDC1_AB = 0
M_SDC2_AB = 0
M_SDC2_OB = 0
M_SDC3_AB = 0
M_SDL_AB = 0
M_SDL_OB = 0
M_SDM_AB = 0
M_SDM_OB = 0
M_SDP_AB = 0
M_SDP_OB = 0
M_SDR_AB = 0
M_SDR_OB = 0
M_SEQ = 0
M_SEQ_I = 0
M_SGE = 0
M_SGE_I = 0
M_SGEU = 0
M_SGEU_I = 0
M_SGT = 0
M_SGT_I = 0
M_SGTU = 0
M_SGTU_I = 0
M_SLE = 0
M_SLE_I = 0
M_SLEU = 0
M_SLEU_I = 0
M_SLT_I = 0
M_SLTU_I = 0
M_SNE = 0
M_SNE_I = 0
M_SB_A = 0
M_SB_AB = 0
M_SH_A = 0
M_SH_AB = 0
M_SW_A = 0
M_SW_AB = 0
M_SWC0_A = 0
M_SWC0_AB = 0
M_SWC1_A = 0
M_SWC1_AB = 0
M_SWC2_A = 0
M_SWC2_AB = 0
M_SWC2_OB = 0
M_SWC3_A = 0
M_SWC3_AB = 0
M_SWL_A = 0
M_SWL_AB = 0
M_SWL_OB = 0
M_SWM_AB = 0
M_SWM_OB = 0
M_SWP_AB = 0
M_SWP_OB = 0
M_SWR_A = 0
M_SWR_AB = 0
M_SWR_OB = 0
M_SUB_I = 0
M_SUBU_I = 0
M_SUBU_I_2 = 0
M_TEQ_I = 0
M_TGE_I = 0
M_TGEU_I = 0
M_TLT_I = 0
M_TLTU_I = 0
M_TNE_I = 0
M_TRUNCWD = 0
M_TRUNCWS = 0
M_ULD = 0
M_ULD_A = 0
M_ULH = 0
M_ULH_A = 0
M_ULHU = 0
M_ULHU_A = 0
M_ULW = 0
M_ULW_A = 0
M_USH = 0
M_USH_A = 0
M_USW = 0
M_USW_A = 0
M_USD = 0
M_USD_A = 0
M_XOR_I = 0
M_COP0 = 0
M_COP1 = 0
M_COP2 = 0
M_COP3 = 0


INSN_MACRO = 0
FP_S = 0
RD_T = 0
WR_T = 0
WR_D = 0
RD_S = 0
FP_D = 0
NODS = 0
CBL = 0
RD_C1 = 0
RD_C2 = 0
WR_HILO = 0
WR_LO = 0
MOD_LO = 0
WR_S = 0
MOD_HILO = 0
RD_R = 0
IS_M = 0
MOD_a = 0
RD_a = 0
WR_a = 0
INSN_TLB = 0
DSP_VOLA = 0
RD_d = 0
WR_z = 0
RD_z = 0
WR_Z = 0
RD_Z = 0
WR_MACC = 0
INSN2_M_FP_D = 0
INSN2_M_FP_S = 0
RD_MACC = 0
I4_32 = 0
G3 = 0
I4_33 = 0
I1 = 0
I3 = 0
IL3A = 0
I5_33 = 0
IL2F = 0
IL2E = 0
MC = 0
MX = 0
SB1 = 0
N54 = 0
M3D = 0
IOCT = 0
I2 = 0
T3 = 0
L1 = 0
I3_32 = 0
I3_33 = 0
MT32 = 0
I32 = 0
N55 = 0
XLR = 0
N5 = 0
I64 = 0
G2 = 0
I65 = 0
I33 = 0
N412 = 0
N411 = 0
V1 = 0
IOCT2 = 0
D32 = 0
D64 = 0
SMT = 0
P3 = 0
G1 = 0
M1 = 0
IOCTP = 0
D33 = 0
IOCT = 0
IOCTP = 0
IOCT2 = 0

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
    instdes("pref", ['k','o(b)'], 0xcc000000, 0xfc000000, RD_b, 0, I4_32|G3, 0),
    instdes("pref", ['k','A(b)'], 0, M_PREF_AB, INSN_MACRO, 0, I4_32|G3, 0),
    instdes("prefx", ['h','t(b)'], 0x4c00000f, 0xfc0007ff, RD_b|RD_t|FP_S, 0, I4_33, 0),
    instdes("nop", [], 0x00000000, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
    instdes("ssnop", [], 0x00000040, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
    instdes("ehb", [], 0x000000c0, 0xffffffff, 0, INSN2_ALIAS, I1, 0),
    instdes("li", ['t','j'], 0x24000000, 0xffe00000, WR_t, INSN2_ALIAS, I1, 0),
    instdes("li", ['t','i'], 0x34000000, 0xffe00000, WR_t, INSN2_ALIAS, I1, 0),
    instdes("li", ['t','I'], 0, M_LI, INSN_MACRO, 0, I1, 0),
    instdes("move", ['d','s'], 0, M_MOVE, INSN_MACRO, 0, I1, 0),
    instdes("move", ['d','s'], 0x0000002d, 0xfc1f07ff, WR_d|RD_s, INSN2_ALIAS, I3, 0),
    instdes("move", ['d','s'], 0x00000021, 0xfc1f07ff, WR_d|RD_s, INSN2_ALIAS, I1, 0),
    instdes("move", ['d','s'], 0x00000025, 0xfc1f07ff, WR_d|RD_s, INSN2_ALIAS, I1, 0),
    instdes("b", ['p'], 0x10000000, 0xffff0000, UBD, INSN2_ALIAS, I1, 0),
    instdes("b", ['p'], 0x04010000, 0xffff0000, UBD, INSN2_ALIAS, I1, 0),
    instdes("bal", ['p'], 0x04110000, 0xffff0000, UBD|WR_31, INSN2_ALIAS, I1, 0),
    instdes("campi", ['d','s'], 0x70000075, 0xfc1f07ff, WR_d|RD_s, 0, IL3A, 0),
    instdes("campv", ['d','s'], 0x70000035, 0xfc1f07ff, WR_d|RD_s, 0, IL3A, 0),
    instdes("camwi", ['d','s','t'], 0x700000b5, 0xfc0007ff, RD_s|RD_t, RD_d, IL3A, 0),
    instdes("ramri", ['d','s'], 0x700000f5, 0xfc1f07ff, WR_d|RD_s, 0, IL3A, 0),
    instdes("gsle", ['s','t'], 0x70000026, 0xfc00ffff, RD_s|RD_t, 0, IL3A, 0),
    instdes("gsgt", ['s','t'], 0x70000027, 0xfc00ffff, RD_s|RD_t, 0, IL3A, 0),
    instdes("gslble", ['t','b','d'], 0xc8000010, 0xfc0007ff, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gslbgt", ['t','b','d'], 0xc8000011, 0xfc0007ff, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gslhle", ['t','b','d'], 0xc8000012, 0xfc0007ff, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gslhgt", ['t','b','d'], 0xc8000013, 0xfc0007ff, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gslwle", ['t','b','d'], 0xc8000014, 0xfc0007ff, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gslwgt", ['t','b','d'], 0xc8000015, 0xfc0007ff, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gsldle", ['t','b','d'], 0xc8000016, 0xfc0007ff, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gsldgt", ['t','b','d'], 0xc8000017, 0xfc0007ff, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gssble", ['t','b','d'], 0xe8000010, 0xfc0007ff, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gssbgt", ['t','b','d'], 0xe8000011, 0xfc0007ff, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gsshle", ['t','b','d'], 0xe8000012, 0xfc0007ff, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gsshgt", ['t','b','d'], 0xe8000013, 0xfc0007ff, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gsswle", ['t','b','d'], 0xe8000014, 0xfc0007ff, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gsswgt", ['t','b','d'], 0xe8000015, 0xfc0007ff, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gssdle", ['t','b','d'], 0xe8000016, 0xfc0007ff, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gssdgt", ['t','b','d'], 0xe8000017, 0xfc0007ff, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gslwlec1", ['T','b','d'], 0xc8000018, 0xfc0007ff, WR_T|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gslwgtc1", ['T','b','d'], 0xc8000019, 0xfc0007ff, WR_T|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gsldlec1", ['T','b','d'], 0xc800001a, 0xfc0007ff, WR_T|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gsldgtc1", ['T','b','d'], 0xc800001b, 0xfc0007ff, WR_T|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gsswlec1", ['T','b','d'], 0xe800001c, 0xfc0007ff, RD_T|RD_b|SM, RD_d, IL3A, 0),
    instdes("gsswgtc1", ['T','b','d'], 0xe800001d, 0xfc0007ff, RD_T|RD_b|SM, RD_d, IL3A, 0),
    instdes("gssdlec1", ['T','b','d'], 0xe800001e, 0xfc0007ff, RD_T|RD_b|SM, RD_d, IL3A, 0),
    instdes("gssdgtc1", ['T','b','d'], 0xe800001f, 0xfc0007ff, RD_T|RD_b|SM, RD_d, IL3A, 0),
    instdes("gslwlc1", ['T','+a(b)'], 0xc8000004, 0xfc00c03f, WR_T|RD_b|LDD, 0, IL3A, 0),
    instdes("gslwrc1", ['T','+a(b)'], 0xc8000005, 0xfc00c03f, WR_T|RD_b|LDD, 0, IL3A, 0),
    instdes("gsldlc1", ['T','+a(b)'], 0xc8000006, 0xfc00c03f, WR_T|RD_b|LDD, 0, IL3A, 0),
    instdes("gsldrc1", ['T','+a(b)'], 0xc8000007, 0xfc00c03f, WR_T|RD_b|LDD, 0, IL3A, 0),
    instdes("gsswlc1", ['T','+a(b)'], 0xe8000004, 0xfc00c03f, RD_T|RD_b|SM, 0, IL3A, 0),
    instdes("gsswrc1", ['T','+a(b)'], 0xe8000005, 0xfc00c03f, RD_T|RD_b|SM, 0, IL3A, 0),
    instdes("gssdlc1", ['T','+a(b)'], 0xe8000006, 0xfc00c03f, RD_T|RD_b|SM, 0, IL3A, 0),
    instdes("gssdrc1", ['T','+a(b)'], 0xe8000007, 0xfc00c03f, RD_T|RD_b|SM, 0, IL3A, 0),
    instdes("gslbx", ['t','+b(b','d)'], 0xd8000000, 0xfc000007, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gslhx", ['t','+b(b','d)'], 0xd8000001, 0xfc000007, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gslwx", ['t','+b(b','d)'], 0xd8000002, 0xfc000007, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gsldx", ['t','+b(b','d)'], 0xd8000003, 0xfc000007, WR_t|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gssbx", ['t','+b(b','d)'], 0xf8000000, 0xfc000007, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gsshx", ['t','+b(b','d)'], 0xf8000001, 0xfc000007, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gsswx", ['t','+b(b','d)'], 0xf8000002, 0xfc000007, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gssdx", ['t','+b(b','d)'], 0xf8000003, 0xfc000007, RD_t|RD_b|SM, RD_d, IL3A, 0),
    instdes("gslwxc1", ['T','+b(b','d)'], 0xd8000006, 0xfc000007, WR_T|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gsldxc1", ['T','+b(b','d)'], 0xd8000007, 0xfc000007, WR_T|RD_b|LDD, RD_d, IL3A, 0),
    instdes("gsswxc1", ['T','+b(b','d)'], 0xf8000006, 0xfc000007, RD_T|RD_b|SM, RD_d, IL3A, 0),
    instdes("gssdxc1", ['T','+b(b','d)'], 0xf8000007, 0xfc000007, RD_T|RD_b|SM, RD_d, IL3A, 0),
    instdes("gslq", ['+z','t','+c(b)'], 0xc8000020, 0xfc008020, WR_t|RD_b|LDD, WR_z, IL3A, 0),
    instdes("gssq", ['+z','t','+c(b)'], 0xe8000020, 0xfc008020, RD_t|RD_b|SM, RD_z, IL3A, 0),
    instdes("gslqc1", ['+Z','T','+c(b)'], 0xc8008020, 0xfc008020, WR_T|RD_b|LDD, WR_Z, IL3A, 0),
    instdes("gssqc1", ['+Z','T','+c(b)'], 0xe8008020, 0xfc008020, RD_T|RD_b|SM, RD_Z, IL3A, 0),
    instdes("abs", ['d','v'], 0, M_ABS, INSN_MACRO, 0, I1, 0),
    instdes("abs.s", ['D','V'], 0x46000005, 0xffff003f, WR_D|RD_S|FP_S, 0, I1, 0),
    instdes("abs.d", ['D','V'], 0x46200005, 0xffff003f, WR_D|RD_S|FP_D, 0, I1, 0),
    instdes("abs.ps", ['D','V'], 0x46c00005, 0xffff003f, WR_D|RD_S|FP_D, 0, I5_33|IL2F, 0),
    instdes("abs.ps", ['D','V'], 0x45600005, 0xffff003f, WR_D|RD_S|FP_D, 0, IL2E, 0),
    instdes("aclr", ['\\','~(b)'], 0x04070000, 0xfc1f8000, SM|RD_b|NODS, 0, MC, 0),
    instdes("aclr", ['\\','o(b)'], 0, M_ACLR_OB, INSN_MACRO, 0, MC, 0),
    instdes("aclr", ['\\','A(b)'], 0, M_ACLR_AB, INSN_MACRO, 0, MC, 0),
    instdes("add", ['d','v','t'], 0x00000020, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("add", ['t','r','I'], 0, M_ADD_I, INSN_MACRO, 0, I1, 0),
    instdes("add", ['D','S','T'], 0x45c00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2E, 0),
    instdes("add", ['D','S','T'], 0x4b40000c, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2F|IL3A, 0),
    instdes("add.s", ['D','V','T'], 0x46000000, 0xffe0003f, WR_D|RD_S|RD_T|FP_S, 0, I1, 0),
    instdes("add.d", ['D','V','T'], 0x46200000, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I1, 0),
    instdes("add.ob", ['X','Y','Q'], 0x7800000b, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("add.ob", ['D','S','T'], 0x4ac0000b, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("add.ob", ['D','S','T[e]'], 0x4800000b, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("add.ob", ['D','S','k'], 0x4bc0000b, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("add.ps", ['D','V','T'], 0x46c00000, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I5_33|IL2F, 0),
    instdes("add.ps", ['D','V','T'], 0x45600000, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, IL2E, 0),
    instdes("add.qh", ['X','Y','Q'], 0x7820000b, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("adda.ob", ['Y','Q'], 0x78000037, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("adda.qh", ['Y','Q'], 0x78200037, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("addi", ['t','r','j'], 0x20000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("addiu", ['t','r','j'], 0x24000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("addl.ob", ['Y','Q'], 0x78000437, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("addl.qh", ['Y','Q'], 0x78200437, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("addr.ps", ['D','S','T'], 0x46c00018, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, M3D, 0),
    instdes("addu", ['d','v','t'], 0x00000021, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("addu", ['t','r','I'], 0, M_ADDU_I, INSN_MACRO, 0, I1, 0),
    instdes("addu", ['D','S','T'], 0x45800000, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2E, 0),
    instdes("addu", ['D','S','T'], 0x4b00000c, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2F|IL3A, 0),
    instdes("alni.ob", ['X','Y','Z','O'], 0x78000018, 0xff00003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("alni.ob", ['D','S','T','%'], 0x48000018, 0xff00003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("alni.qh", ['X','Y','Z','O'], 0x7800001a, 0xff00003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("alnv.ps", ['D','V','T','s'], 0x4c00001e, 0xfc00003f, WR_D|RD_S|RD_T|RD_s|FP_D, 0, I5_33, 0),
    instdes("alnv.ob", ['X','Y','Z','s'], 0x78000019, 0xfc00003f, WR_D|RD_S|RD_T|RD_s|FP_D, 0, MX|SB1, 0),
    instdes("alnv.qh", ['X','Y','Z','s'], 0x7800001b, 0xfc00003f, WR_D|RD_S|RD_T|RD_s|FP_D, 0, MX, 0),
    instdes("and", ['d','v','t'], 0x00000024, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("and", ['t','r','I'], 0, M_AND_I, INSN_MACRO, 0, I1, 0),
    instdes("and", ['D','S','T'], 0x47c00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("and", ['D','S','T'], 0x4bc00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("and.ob", ['X','Y','Q'], 0x7800000c, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("and.ob", ['D','S','T'], 0x4ac0000c, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("and.ob", ['D','S','T[e]'], 0x4800000c, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("and.ob", ['D','S','k'], 0x4bc0000c, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("and.qh", ['X','Y','Q'], 0x7820000c, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("andi", ['t','r','i'], 0x30000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("aset", ['\\','~(b)'], 0x04078000, 0xfc1f8000, SM|RD_b|NODS, 0, MC, 0),
    instdes("aset", ['\\','o(b)'], 0, M_ASET_OB, INSN_MACRO, 0, MC, 0),
    instdes("aset", ['\\','A(b)'], 0, M_ASET_AB, INSN_MACRO, 0, MC, 0),
    instdes("baddu", ['d','v','t'], 0x70000028, 0xfc0007ff, WR_d|RD_s|RD_t, 0, IOCT, 0),
    instdes("bbit032", ['s','+x','p'], 0xd8000000, 0xfc000000, RD_s|CBD, 0, IOCT, 0),
    instdes("bbit0", ['s','+X','p'], 0xd8000000, 0xfc000000, RD_s|CBD, 0, IOCT, 0),
    instdes("bbit0", ['s','+x','p'], 0xc8000000, 0xfc000000, RD_s|CBD, 0, IOCT, 0),
    instdes("bbit132", ['s','+x','p'], 0xf8000000, 0xfc000000, RD_s|CBD, 0, IOCT, 0),
    instdes("bbit1", ['s','+X','p'], 0xf8000000, 0xfc000000, RD_s|CBD, 0, IOCT, 0),
    instdes("bbit1", ['s','+x','p'], 0xe8000000, 0xfc000000, RD_s|CBD, 0, IOCT, 0),
    instdes("bc1any2f", ['N','p'], 0x45200000, 0xffe30000, CBD|RD_CC|FP_S, 0, M3D, 0),
    instdes("bc1any2t", ['N','p'], 0x45210000, 0xffe30000, CBD|RD_CC|FP_S, 0, M3D, 0),
    instdes("bc1any4f", ['N','p'], 0x45400000, 0xffe30000, CBD|RD_CC|FP_S, 0, M3D, 0),
    instdes("bc1any4t", ['N','p'], 0x45410000, 0xffe30000, CBD|RD_CC|FP_S, 0, M3D, 0),
    instdes("bc1f", ['p'], 0x45000000, 0xffff0000, CBD|RD_CC|FP_S, 0, I1, 0),
    instdes("bc1f", ['N','p'], 0x45000000, 0xffe30000, CBD|RD_CC|FP_S, 0, I4_32, 0),
    instdes("bc1fl", ['p'], 0x45020000, 0xffff0000, CBL|RD_CC|FP_S, 0, I2|T3, 0),
    instdes("bc1fl", ['N','p'], 0x45020000, 0xffe30000, CBL|RD_CC|FP_S, 0, I4_32, 0),
    instdes("bc1t", ['p'], 0x45010000, 0xffff0000, CBD|RD_CC|FP_S, 0, I1, 0),
    instdes("bc1t", ['N','p'], 0x45010000, 0xffe30000, CBD|RD_CC|FP_S, 0, I4_32, 0),
    instdes("bc1tl", ['p'], 0x45030000, 0xffff0000, CBL|RD_CC|FP_S, 0, I2|T3, 0),
    instdes("bc1tl", ['N','p'], 0x45030000, 0xffe30000, CBL|RD_CC|FP_S, 0, I4_32, 0),
    instdes("beqz", ['s','p'], 0x10000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("beqzl", ['s','p'], 0x50000000, 0xfc1f0000, CBL|RD_s, 0, I2|T3, 0),
    instdes("beq", ['s','t','p'], 0x10000000, 0xfc000000, CBD|RD_s|RD_t, 0, I1, 0),
    instdes("beq", ['s','I','p'], 0, M_BEQ_I, INSN_MACRO, 0, I1, 0),
    instdes("beql", ['s','t','p'], 0x50000000, 0xfc000000, CBL|RD_s|RD_t, 0, I2|T3, 0),
    instdes("beql", ['s','I','p'], 0, M_BEQL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("bge", ['s','t','p'], 0, M_BGE, INSN_MACRO, 0, I1, 0),
    instdes("bge", ['s','I','p'], 0, M_BGE_I, INSN_MACRO, 0, I1, 0),
    instdes("bgel", ['s','t','p'], 0, M_BGEL, INSN_MACRO, 0, I2|T3, 0),
    instdes("bgel", ['s','I','p'], 0, M_BGEL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("bgeu", ['s','t','p'], 0, M_BGEU, INSN_MACRO, 0, I1, 0),
    instdes("bgeu", ['s','I','p'], 0, M_BGEU_I, INSN_MACRO, 0, I1, 0),
    instdes("bgeul", ['s','t','p'], 0, M_BGEUL, INSN_MACRO, 0, I2|T3, 0),
    instdes("bgeul", ['s','I','p'], 0, M_BGEUL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("bgez", ['s','p'], 0x04010000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bgezl", ['s','p'], 0x04030000, 0xfc1f0000, CBL|RD_s, 0, I2|T3, 0),
    instdes("bgezal", ['s','p'], 0x04110000, 0xfc1f0000, CBD|RD_s|WR_31, 0, I1, 0),
    instdes("bgezall", ['s','p'], 0x04130000, 0xfc1f0000, CBL|RD_s|WR_31, 0, I2|T3, 0),
    instdes("bgt", ['s','t','p'], 0, M_BGT, INSN_MACRO, 0, I1, 0),
    instdes("bgt", ['s','I','p'], 0, M_BGT_I, INSN_MACRO, 0, I1, 0),
    instdes("bgtl", ['s','t','p'], 0, M_BGTL, INSN_MACRO, 0, I2|T3, 0),
    instdes("bgtl", ['s','I','p'], 0, M_BGTL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("bgtu", ['s','t','p'], 0, M_BGTU, INSN_MACRO, 0, I1, 0),
    instdes("bgtu", ['s','I','p'], 0, M_BGTU_I, INSN_MACRO, 0, I1, 0),
    instdes("bgtul", ['s','t','p'], 0, M_BGTUL, INSN_MACRO, 0, I2|T3, 0),
    instdes("bgtul", ['s','I','p'], 0, M_BGTUL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("bgtz", ['s','p'], 0x1c000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bgtzl", ['s','p'], 0x5c000000, 0xfc1f0000, CBL|RD_s, 0, I2|T3, 0),
    instdes("ble", ['s','t','p'], 0, M_BLE, INSN_MACRO, 0, I1, 0),
    instdes("ble", ['s','I','p'], 0, M_BLE_I, INSN_MACRO, 0, I1, 0),
    instdes("blel", ['s','t','p'], 0, M_BLEL, INSN_MACRO, 0, I2|T3, 0),
    instdes("blel", ['s','I','p'], 0, M_BLEL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("bleu", ['s','t','p'], 0, M_BLEU, INSN_MACRO, 0, I1, 0),
    instdes("bleu", ['s','I','p'], 0, M_BLEU_I, INSN_MACRO, 0, I1, 0),
    instdes("bleul", ['s','t','p'], 0, M_BLEUL, INSN_MACRO, 0, I2|T3, 0),
    instdes("bleul", ['s','I','p'], 0, M_BLEUL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("blez", ['s','p'], 0x18000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("blezl", ['s','p'], 0x58000000, 0xfc1f0000, CBL|RD_s, 0, I2|T3, 0),
    instdes("blt", ['s','t','p'], 0, M_BLT, INSN_MACRO, 0, I1, 0),
    instdes("blt", ['s','I','p'], 0, M_BLT_I, INSN_MACRO, 0, I1, 0),
    instdes("bltl", ['s','t','p'], 0, M_BLTL, INSN_MACRO, 0, I2|T3, 0),
    instdes("bltl", ['s','I','p'], 0, M_BLTL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("bltu", ['s','t','p'], 0, M_BLTU, INSN_MACRO, 0, I1, 0),
    instdes("bltu", ['s','I','p'], 0, M_BLTU_I, INSN_MACRO, 0, I1, 0),
    instdes("bltul", ['s','t','p'], 0, M_BLTUL, INSN_MACRO, 0, I2|T3, 0),
    instdes("bltul", ['s','I','p'], 0, M_BLTUL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("bltz", ['s','p'], 0x04000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bltzl", ['s','p'], 0x04020000, 0xfc1f0000, CBL|RD_s, 0, I2|T3, 0),
    instdes("bltzal", ['s','p'], 0x04100000, 0xfc1f0000, CBD|RD_s|WR_31, 0, I1, 0),
    instdes("bltzall", ['s','p'], 0x04120000, 0xfc1f0000, CBL|RD_s|WR_31, 0, I2|T3, 0),
    instdes("bnez", ['s','p'], 0x14000000, 0xfc1f0000, CBD|RD_s, 0, I1, 0),
    instdes("bnezl", ['s','p'], 0x54000000, 0xfc1f0000, CBL|RD_s, 0, I2|T3, 0),
    instdes("bne", ['s','t','p'], 0x14000000, 0xfc000000, CBD|RD_s|RD_t, 0, I1, 0),
    instdes("bne", ['s','I','p'], 0, M_BNE_I, INSN_MACRO, 0, I1, 0),
    instdes("bnel", ['s','t','p'], 0x54000000, 0xfc000000, CBL|RD_s|RD_t, 0, I2|T3, 0),
    instdes("bnel", ['s','I','p'], 0, M_BNEL_I, INSN_MACRO, 0, I2|T3, 0),
    instdes("break", [], 0x0000000d, 0xffffffff, TRAP, 0, I1, 0),
    instdes("break", ['c'], 0x0000000d, 0xfc00ffff, TRAP, 0, I1, 0),
    instdes("break", ['c','q'], 0x0000000d, 0xfc00003f, TRAP, 0, I1, 0),
    instdes("c.f.d", ['S','T'], 0x46200030, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.f.d", ['M','S','T'], 0x46200030, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.f.s", ['S','T'], 0x46000030, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.f.s", ['M','S','T'], 0x46000030, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.f.ps", ['S','T'], 0x46c00030, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.f.ps", ['S','T'], 0x45600030, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.f.ps", ['M','S','T'], 0x46c00030, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.un.d", ['S','T'], 0x46200031, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.un.d", ['M','S','T'], 0x46200031, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.un.s", ['S','T'], 0x46000031, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.un.s", ['M','S','T'], 0x46000031, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.un.ps", ['S','T'], 0x46c00031, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.un.ps", ['S','T'], 0x45600031, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.un.ps", ['M','S','T'], 0x46c00031, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.eq.d", ['S','T'], 0x46200032, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.eq.d", ['M','S','T'], 0x46200032, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.eq.s", ['S','T'], 0x46000032, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.eq.s", ['M','S','T'], 0x46000032, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.eq.ob", ['Y','Q'], 0x78000001, 0xfc2007ff, WR_CC|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("c.eq.ob", ['S','T'], 0x4ac00001, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.eq.ob", ['S','T[e]'], 0x48000001, 0xfe2007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.eq.ob", ['S','k'], 0x4bc00001, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.eq.ps", ['S','T'], 0x46c00032, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.eq.ps", ['S','T'], 0x45600032, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.eq.ps", ['M','S','T'], 0x46c00032, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.eq.qh", ['Y','Q'], 0x78200001, 0xfc2007ff, WR_CC|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("c.ueq.d", ['S','T'], 0x46200033, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.ueq.d", ['M','S','T'], 0x46200033, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.ueq.s", ['S','T'], 0x46000033, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.ueq.s", ['M','S','T'], 0x46000033, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.ueq.ps", ['S','T'], 0x46c00033, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.ueq.ps", ['S','T'], 0x45600033, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.ueq.ps", ['M','S','T'], 0x46c00033, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.olt.d", ['S','T'], 0x46200034, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.olt.d", ['M','S','T'], 0x46200034, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.olt.s", ['S','T'], 0x46000034, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.olt.s", ['M','S','T'], 0x46000034, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.olt.ps", ['S','T'], 0x46c00034, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.olt.ps", ['S','T'], 0x45600034, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.olt.ps", ['M','S','T'], 0x46c00034, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.ult.d", ['S','T'], 0x46200035, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.ult.d", ['M','S','T'], 0x46200035, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.ult.s", ['S','T'], 0x46000035, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.ult.s", ['M','S','T'], 0x46000035, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.ult.ps", ['S','T'], 0x46c00035, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.ult.ps", ['S','T'], 0x45600035, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.ult.ps", ['M','S','T'], 0x46c00035, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.ole.d", ['S','T'], 0x46200036, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.ole.d", ['M','S','T'], 0x46200036, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.ole.s", ['S','T'], 0x46000036, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.ole.s", ['M','S','T'], 0x46000036, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.ole.ps", ['S','T'], 0x46c00036, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.ole.ps", ['S','T'], 0x45600036, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.ole.ps", ['M','S','T'], 0x46c00036, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.ule.d", ['S','T'], 0x46200037, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.ule.d", ['M','S','T'], 0x46200037, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.ule.s", ['S','T'], 0x46000037, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.ule.s", ['M','S','T'], 0x46000037, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.ule.ps", ['S','T'], 0x46c00037, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.ule.ps", ['S','T'], 0x45600037, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.ule.ps", ['M','S','T'], 0x46c00037, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.sf.d", ['S','T'], 0x46200038, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.sf.d", ['M','S','T'], 0x46200038, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.sf.s", ['S','T'], 0x46000038, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.sf.s", ['M','S','T'], 0x46000038, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.sf.ps", ['S','T'], 0x46c00038, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.sf.ps", ['S','T'], 0x45600038, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.sf.ps", ['M','S','T'], 0x46c00038, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.ngle.d", ['S','T'], 0x46200039, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.ngle.d", ['M','S','T'], 0x46200039, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.ngle.s", ['S','T'], 0x46000039, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.ngle.s", ['M','S','T'], 0x46000039, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.ngle.ps", ['S','T'], 0x46c00039, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.ngle.ps", ['S','T'], 0x45600039, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.ngle.ps", ['M','S','T'], 0x46c00039, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.seq.d", ['S','T'], 0x4620003a, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.seq.d", ['M','S','T'], 0x4620003a, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.seq.s", ['S','T'], 0x4600003a, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.seq.s", ['M','S','T'], 0x4600003a, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.seq.ps", ['S','T'], 0x46c0003a, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.seq.ps", ['S','T'], 0x4560003a, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.seq.ps", ['M','S','T'], 0x46c0003a, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.ngl.d", ['S','T'], 0x4620003b, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.ngl.d", ['M','S','T'], 0x4620003b, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.ngl.s", ['S','T'], 0x4600003b, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.ngl.s", ['M','S','T'], 0x4600003b, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.ngl.ps", ['S','T'], 0x46c0003b, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.ngl.ps", ['S','T'], 0x4560003b, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.ngl.ps", ['M','S','T'], 0x46c0003b, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.lt.d", ['S','T'], 0x4620003c, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.lt.d", ['M','S','T'], 0x4620003c, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.lt.s", ['S','T'], 0x4600003c, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.lt.s", ['M','S','T'], 0x4600003c, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.lt.ob", ['Y','Q'], 0x78000004, 0xfc2007ff, WR_CC|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("c.lt.ob", ['S','T'], 0x4ac00004, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.lt.ob", ['S','T[e]'], 0x48000004, 0xfe2007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.lt.ob", ['S','k'], 0x4bc00004, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.lt.ps", ['S','T'], 0x46c0003c, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.lt.ps", ['S','T'], 0x4560003c, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.lt.ps", ['M','S','T'], 0x46c0003c, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.lt.qh", ['Y','Q'], 0x78200004, 0xfc2007ff, WR_CC|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("c.nge.d", ['S','T'], 0x4620003d, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.nge.d", ['M','S','T'], 0x4620003d, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.nge.s", ['S','T'], 0x4600003d, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.nge.s", ['M','S','T'], 0x4600003d, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.nge.ps", ['S','T'], 0x46c0003d, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.nge.ps", ['S','T'], 0x4560003d, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.nge.ps", ['M','S','T'], 0x46c0003d, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.le.d", ['S','T'], 0x4620003e, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.le.d", ['M','S','T'], 0x4620003e, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.le.s", ['S','T'], 0x4600003e, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.le.s", ['M','S','T'], 0x4600003e, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.le.ob", ['Y','Q'], 0x78000005, 0xfc2007ff, WR_CC|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("c.le.ob", ['S','T'], 0x4ac00005, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.le.ob", ['S','T[e]'], 0x48000005, 0xfe2007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.le.ob", ['S','k'], 0x4bc00005, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("c.le.ps", ['S','T'], 0x46c0003e, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.le.ps", ['S','T'], 0x4560003e, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.le.ps", ['M','S','T'], 0x46c0003e, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("c.le.qh", ['Y','Q'], 0x78200005, 0xfc2007ff, WR_CC|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("c.ngt.d", ['S','T'], 0x4620003f, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I1, 0),
    instdes("c.ngt.d", ['M','S','T'], 0x4620003f, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I4_32, 0),
    instdes("c.ngt.s", ['S','T'], 0x4600003f, 0xffe007ff, RD_S|RD_T|WR_CC|FP_S, 0, I1, 0),
    instdes("c.ngt.s", ['M','S','T'], 0x4600003f, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, I4_32, 0),
    instdes("c.ngt.ps", ['S','T'], 0x46c0003f, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33|IL2F, 0),
    instdes("c.ngt.ps", ['S','T'], 0x4560003f, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("c.ngt.ps", ['M','S','T'], 0x46c0003f, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, I5_33, 0),
    instdes("cabs.eq.d", ['M','S','T'], 0x46200072, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.eq.ps", ['M','S','T'], 0x46c00072, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.eq.s", ['M','S','T'], 0x46000072, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.f.d", ['M','S','T'], 0x46200070, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.f.ps", ['M','S','T'], 0x46c00070, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.f.s", ['M','S','T'], 0x46000070, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.le.d", ['M','S','T'], 0x4620007e, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.le.ps", ['M','S','T'], 0x46c0007e, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.le.s", ['M','S','T'], 0x4600007e, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.lt.d", ['M','S','T'], 0x4620007c, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.lt.ps", ['M','S','T'], 0x46c0007c, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.lt.s", ['M','S','T'], 0x4600007c, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.nge.d", ['M','S','T'], 0x4620007d, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.nge.ps", ['M','S','T'], 0x46c0007d, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.nge.s", ['M','S','T'], 0x4600007d, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.ngl.d", ['M','S','T'], 0x4620007b, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ngl.ps", ['M','S','T'], 0x46c0007b, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ngl.s", ['M','S','T'], 0x4600007b, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.ngle.d", ['M','S','T'], 0x46200079, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ngle.ps", ['M','S','T'], 0x46c00079, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ngle.s", ['M','S','T'], 0x46000079, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.ngt.d", ['M','S','T'], 0x4620007f, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ngt.ps", ['M','S','T'], 0x46c0007f, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ngt.s", ['M','S','T'], 0x4600007f, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.ole.d", ['M','S','T'], 0x46200076, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ole.ps", ['M','S','T'], 0x46c00076, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ole.s", ['M','S','T'], 0x46000076, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.olt.d", ['M','S','T'], 0x46200074, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.olt.ps", ['M','S','T'], 0x46c00074, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.olt.s", ['M','S','T'], 0x46000074, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.seq.d", ['M','S','T'], 0x4620007a, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.seq.ps", ['M','S','T'], 0x46c0007a, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.seq.s", ['M','S','T'], 0x4600007a, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.sf.d", ['M','S','T'], 0x46200078, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.sf.ps", ['M','S','T'], 0x46c00078, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.sf.s", ['M','S','T'], 0x46000078, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.ueq.d", ['M','S','T'], 0x46200073, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ueq.ps", ['M','S','T'], 0x46c00073, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ueq.s", ['M','S','T'], 0x46000073, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.ule.d", ['M','S','T'], 0x46200077, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ule.ps", ['M','S','T'], 0x46c00077, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ule.s", ['M','S','T'], 0x46000077, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.ult.d", ['M','S','T'], 0x46200075, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ult.ps", ['M','S','T'], 0x46c00075, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.ult.s", ['M','S','T'], 0x46000075, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("cabs.un.d", ['M','S','T'], 0x46200071, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.un.ps", ['M','S','T'], 0x46c00071, 0xffe000ff, RD_S|RD_T|WR_CC|FP_D, 0, M3D, 0),
    instdes("cabs.un.s", ['M','S','T'], 0x46000071, 0xffe000ff, RD_S|RD_T|WR_CC|FP_S, 0, M3D, 0),
    instdes("flushi", [], 0xbc010000, 0xffffffff, 0, 0, L1, 0),
    instdes("flushd", [], 0xbc020000, 0xffffffff, 0, 0, L1, 0),
    instdes("flushid", [], 0xbc030000, 0xffffffff, 0, 0, L1, 0),
    instdes("wb", ['o(b)'], 0xbc040000, 0xfc1f0000, SM|RD_b, 0, L1, 0),
    instdes("cache", ['k','o(b)'], 0xbc000000, 0xfc000000, RD_b, 0, I3_32|T3, 0),
    instdes("cache", ['k','A(b)'], 0, M_CACHE_AB, INSN_MACRO, 0, I3_32|T3, 0),
    instdes("ceil.l.d", ['D','S'], 0x4620000a, 0xffff003f, WR_D|RD_S|FP_D, 0, I3_33, 0),
    instdes("ceil.l.s", ['D','S'], 0x4600000a, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I3_33, 0),
    instdes("ceil.w.d", ['D','S'], 0x4620000e, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I2, 0),
    instdes("ceil.w.s", ['D','S'], 0x4600000e, 0xffff003f, WR_D|RD_S|FP_S, 0, I2, 0),
    instdes("cfc0", ['t','G'], 0x40400000, 0xffe007ff, LCD|WR_t|RD_C0, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("cfc1", ['t','G'], 0x44400000, 0xffe007ff, LCD|WR_t|RD_C1|FP_S, 0, I1, 0),
    instdes("cfc1", ['t','S'], 0x44400000, 0xffe007ff, LCD|WR_t|RD_C1|FP_S, 0, I1, 0),
    instdes("cftc1", ['d','E'], 0x41000023, 0xffe007ff, TRAP|LCD|WR_d|RD_C1|FP_S, 0, MT32, 0),
    instdes("cftc1", ['d','T'], 0x41000023, 0xffe007ff, TRAP|LCD|WR_d|RD_C1|FP_S, 0, MT32, 0),
    instdes("cftc2", ['d','E'], 0x41000025, 0xffe007ff, TRAP|LCD|WR_d|RD_C2, 0, MT32, IOCT|IOCTP|IOCT2),
    instdes("cins32", ['t','r','+p','+S'], 0x70000033, 0xfc00003f, WR_t|RD_s, 0, IOCT, 0),
    instdes("cins", ['t','r','+P','+S'], 0x70000033, 0xfc00003f, WR_t|RD_s, 0, IOCT, 0),
    instdes("cins", ['t','r','+p','+s'], 0x70000032, 0xfc00003f, WR_t|RD_s, 0, IOCT, 0),
    instdes("clo", ['U','s'], 0x70000021, 0xfc0007ff, WR_d|WR_t|RD_s, 0, I32|N55, 0),
    instdes("clz", ['U','s'], 0x70000020, 0xfc0007ff, WR_d|WR_t|RD_s, 0, I32|N55, 0),
    instdes("ctc0", ['t','G'], 0x40c00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("ctc1", ['t','G'], 0x44c00000, 0xffe007ff, COD|RD_t|WR_CC|FP_S, 0, I1, 0),
    instdes("ctc1", ['t','S'], 0x44c00000, 0xffe007ff, COD|RD_t|WR_CC|FP_S, 0, I1, 0),
    instdes("cttc1", ['t','g'], 0x41800023, 0xffe007ff, TRAP|COD|RD_t|WR_CC|FP_S, 0, MT32, 0),
    instdes("cttc1", ['t','S'], 0x41800023, 0xffe007ff, TRAP|COD|RD_t|WR_CC|FP_S, 0, MT32, 0),
    instdes("cttc2", ['t','g'], 0x41800025, 0xffe007ff, TRAP|COD|RD_t|WR_CC, 0, MT32, IOCT|IOCTP|IOCT2),
    instdes("cvt.d.l", ['D','S'], 0x46a00021, 0xffff003f, WR_D|RD_S|FP_D, 0, I3_33, 0),
    instdes("cvt.d.s", ['D','S'], 0x46000021, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I1, 0),
    instdes("cvt.d.w", ['D','S'], 0x46800021, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I1, 0),
    instdes("cvt.l.d", ['D','S'], 0x46200025, 0xffff003f, WR_D|RD_S|FP_D, 0, I3_33, 0),
    instdes("cvt.l.s", ['D','S'], 0x46000025, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I3_33, 0),
    instdes("cvt.s.l", ['D','S'], 0x46a00020, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I3_33, 0),
    instdes("cvt.s.d", ['D','S'], 0x46200020, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I1, 0),
    instdes("cvt.s.w", ['D','S'], 0x46800020, 0xffff003f, WR_D|RD_S|FP_S, 0, I1, 0),
    instdes("cvt.s.pl", ['D','S'], 0x46c00028, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I5_33, 0),
    instdes("cvt.s.pu", ['D','S'], 0x46c00020, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I5_33, 0),
    instdes("cvt.w.d", ['D','S'], 0x46200024, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I1, 0),
    instdes("cvt.w.s", ['D','S'], 0x46000024, 0xffff003f, WR_D|RD_S|FP_S, 0, I1, 0),
    instdes("cvt.ps.pw", ['D','S'], 0x46800026, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, M3D, 0),
    instdes("cvt.ps.s", ['D','V','T'], 0x46000026, 0xffe0003f, WR_D|RD_S|RD_T|FP_S|FP_D, 0, I5_33, 0),
    instdes("cvt.pw.ps", ['D','S'], 0x46c00024, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, M3D, 0),
    instdes("dabs", ['d','v'], 0, M_DABS, INSN_MACRO, 0, I3, 0),
    instdes("dadd", ['d','v','t'], 0x0000002c, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I3, 0),
    instdes("dadd", ['t','r','I'], 0, M_DADD_I, INSN_MACRO, 0, I3, 0),
    instdes("dadd", ['D','S','T'], 0x45e00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("dadd", ['D','S','T'], 0x4b60000c, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("daddi", ['t','r','j'], 0x60000000, 0xfc000000, WR_t|RD_s, 0, I3, 0),
    instdes("daddiu", ['t','r','j'], 0x64000000, 0xfc000000, WR_t|RD_s, 0, I3, 0),
    instdes("daddu", ['d','v','t'], 0x0000002d, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I3, 0),
    instdes("daddu", ['t','r','I'], 0, M_DADDU_I, INSN_MACRO, 0, I3, 0),
    instdes("daddwc", ['d','s','t'], 0x70000038, 0xfc0007ff, WR_d|RD_s|RD_t|WR_C0|RD_C0, 0, XLR, 0),
    instdes("dbreak", [], 0x7000003f, 0xffffffff, 0, 0, N5, 0),
    instdes("dclo", ['U','s'], 0x70000025, 0xfc0007ff, RD_s|WR_d|WR_t, 0, I64|N55, 0),
    instdes("dclz", ['U','s'], 0x70000024, 0xfc0007ff, RD_s|WR_d|WR_t, 0, I64|N55, 0),
    instdes("dctr", ['o(b)'], 0xbc050000, 0xfc1f0000, RD_b, 0, I3, 0),
    instdes("dctw", ['o(b)'], 0xbc090000, 0xfc1f0000, RD_b, 0, I3, 0),
    instdes("deret", [], 0x4200001f, 0xffffffff, NODS, 0, I32|G2, 0),
    instdes("dext", ['t','r','I','+I'], 0, M_DEXT, INSN_MACRO, 0, I65, 0),
    instdes("dext", ['t','r','+A','+C'], 0x7c000003, 0xfc00003f, WR_t|RD_s, 0, I65, 0),
    instdes("dextm", ['t','r','+A','+G'], 0x7c000001, 0xfc00003f, WR_t|RD_s, 0, I65, 0),
    instdes("dextu", ['t','r','+E','+H'], 0x7c000002, 0xfc00003f, WR_t|RD_s, 0, I65, 0),
    instdes("ddiv", ['z','s','t'], 0x0000001e, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I3, 0),
    instdes("ddiv", ['d','v','t'], 0, M_DDIV_3, INSN_MACRO, 0, I3, 0),
    instdes("ddiv", ['d','v','I'], 0, M_DDIV_3I, INSN_MACRO, 0, I3, 0),
    instdes("ddivu", ['z','s','t'], 0x0000001f, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I3, 0),
    instdes("ddivu", ['d','v','t'], 0, M_DDIVU_3, INSN_MACRO, 0, I3, 0),
    instdes("ddivu", ['d','v','I'], 0, M_DDIVU_3I, INSN_MACRO, 0, I3, 0),
    instdes("di", [], 0x41606000, 0xffffffff, WR_t|WR_C0, 0, I33, 0),
    instdes("di", ['t'], 0x41606000, 0xffe0ffff, WR_t|WR_C0, 0, I33, 0),
    instdes("dins", ['t','r','I','+I'], 0, M_DINS, INSN_MACRO, 0, I65, 0),
    instdes("dins", ['t','r','+A','+B'], 0x7c000007, 0xfc00003f, WR_t|RD_s, 0, I65, 0),
    instdes("dinsm", ['t','r','+A','+F'], 0x7c000005, 0xfc00003f, WR_t|RD_s, 0, I65, 0),
    instdes("dinsu", ['t','r','+E','+F'], 0x7c000006, 0xfc00003f, WR_t|RD_s, 0, I65, 0),
    instdes("div", ['z','s','t'], 0x0000001a, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("div", ['z','t'], 0x0000001a, 0xffe0ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("div", ['d','v','t'], 0, M_DIV_3, INSN_MACRO, 0, I1, 0),
    instdes("div", ['d','v','I'], 0, M_DIV_3I, INSN_MACRO, 0, I1, 0),
    instdes("div.d", ['D','V','T'], 0x46200003, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I1, 0),
    instdes("div.s", ['D','V','T'], 0x46000003, 0xffe0003f, WR_D|RD_S|RD_T|FP_S, 0, I1, 0),
    instdes("div.ps", ['D','V','T'], 0x46c00003, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, SB1, 0),
    instdes("divu", ['z','s','t'], 0x0000001b, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("divu", ['z','t'], 0x0000001b, 0xffe0ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("divu", ['d','v','t'], 0, M_DIVU_3, INSN_MACRO, 0, I1, 0),
    instdes("divu", ['d','v','I'], 0, M_DIVU_3I, INSN_MACRO, 0, I1, 0),
    instdes("dla", ['t','A(b)'], 0, M_DLA_AB, INSN_MACRO, 0, I3, 0),
    instdes("dlca", ['t','A(b)'], 0, M_DLCA_AB, INSN_MACRO, 0, I3, 0),
    instdes("dli", ['t','j'], 0x24000000, 0xffe00000, WR_t, 0, I3, 0),
    instdes("dli", ['t','i'], 0x34000000, 0xffe00000, WR_t, 0, I3, 0),
    instdes("dli", ['t','I'], 0, M_DLI, INSN_MACRO, 0, I3, 0),
    instdes("dmacc", ['d','s','t'], 0x00000029, 0xfc0007ff, RD_s|RD_t|WR_LO|WR_d, 0, N412, 0),
    instdes("dmacchi", ['d','s','t'], 0x00000229, 0xfc0007ff, RD_s|RD_t|WR_LO|WR_d, 0, N412, 0),
    instdes("dmacchis", ['d','s','t'], 0x00000629, 0xfc0007ff, RD_s|RD_t|WR_LO|WR_d, 0, N412, 0),
    instdes("dmacchiu", ['d','s','t'], 0x00000269, 0xfc0007ff, RD_s|RD_t|WR_LO|WR_d, 0, N412, 0),
    instdes("dmacchius", ['d','s','t'], 0x00000669, 0xfc0007ff, RD_s|RD_t|WR_LO|WR_d, 0, N412, 0),
    instdes("dmaccs", ['d','s','t'], 0x00000429, 0xfc0007ff, RD_s|RD_t|WR_LO|WR_d, 0, N412, 0),
    instdes("dmaccu", ['d','s','t'], 0x00000069, 0xfc0007ff, RD_s|RD_t|WR_LO|WR_d, 0, N412, 0),
    instdes("dmaccus", ['d','s','t'], 0x00000469, 0xfc0007ff, RD_s|RD_t|WR_LO|WR_d, 0, N412, 0),
    instdes("dmadd16", ['s','t'], 0x00000029, 0xfc00ffff, RD_s|RD_t|MOD_LO, 0, N411, 0),
    instdes("dmfc0", ['t','G'], 0x40200000, 0xffe007ff, LCD|WR_t|RD_C0, 0, I3, 0),
    instdes("dmfc0", ['t','+D'], 0x40200000, 0xffe007f8, LCD|WR_t|RD_C0, 0, I64, 0),
    instdes("dmfc0", ['t','G','H'], 0x40200000, 0xffe007f8, LCD|WR_t|RD_C0, 0, I64, 0),
    instdes("dmt", [], 0x41600bc1, 0xffffffff, TRAP, 0, MT32, 0),
    instdes("dmt", ['t'], 0x41600bc1, 0xffe0ffff, TRAP|WR_t, 0, MT32, 0),
    instdes("dmtc0", ['t','G'], 0x40a00000, 0xffe007ff, COD|RD_t|WR_C0|WR_CC, 0, I3, 0),
    instdes("dmtc0", ['t','+D'], 0x40a00000, 0xffe007f8, COD|RD_t|WR_C0|WR_CC, 0, I64, 0),
    instdes("dmtc0", ['t','G','H'], 0x40a00000, 0xffe007f8, COD|RD_t|WR_C0|WR_CC, 0, I64, 0),
    instdes("dmfc1", ['t','S'], 0x44200000, 0xffe007ff, LCD|WR_t|RD_S|FP_D, 0, I3, 0),
    instdes("dmfc1", ['t','G'], 0x44200000, 0xffe007ff, LCD|WR_t|RD_S|FP_D, 0, I3, 0),
    instdes("dmtc1", ['t','S'], 0x44a00000, 0xffe007ff, COD|RD_t|WR_S|FP_D, 0, I3, 0),
    instdes("dmtc1", ['t','G'], 0x44a00000, 0xffe007ff, COD|RD_t|WR_S|FP_D, 0, I3, 0),
    instdes("dmul", ['d','v','t'], 0x70000003, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, IOCT, 0),
    instdes("dmul", ['d','v','t'], 0, M_DMUL, INSN_MACRO, 0, I3, 0),
    instdes("dmul", ['d','v','I'], 0, M_DMUL_I, INSN_MACRO, 0, I3, 0),
    instdes("dmulo", ['d','v','t'], 0, M_DMULO, INSN_MACRO, 0, I3, 0),
    instdes("dmulo", ['d','v','I'], 0, M_DMULO_I, INSN_MACRO, 0, I3, 0),
    instdes("dmulou", ['d','v','t'], 0, M_DMULOU, INSN_MACRO, 0, I3, 0),
    instdes("dmulou", ['d','v','I'], 0, M_DMULOU_I, INSN_MACRO, 0, I3, 0),
    instdes("dmult", ['s','t'], 0x0000001c, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I3, 0),
    instdes("dmultu", ['s','t'], 0x0000001d, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I3, 0),
    instdes("dneg", ['d','w'], 0x0000002e, 0xffe007ff, WR_d|RD_t, 0, I3, 0),
    instdes("dnegu", ['d','w'], 0x0000002f, 0xffe007ff, WR_d|RD_t, 0, I3, 0),
    instdes("dpop", ['d','v'], 0x7000002d, 0xfc1f07ff, WR_d|RD_s, 0, IOCT, 0),
    instdes("drem", ['z','s','t'], 0x0000001e, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I3, 0),
    instdes("drem", ['d','v','t'], 0, M_DREM_3, INSN_MACRO, 0, I3, 0),
    instdes("drem", ['d','v','I'], 0, M_DREM_3I, INSN_MACRO, 0, I3, 0),
    instdes("dremu", ['z','s','t'], 0x0000001f, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I3, 0),
    instdes("dremu", ['d','v','t'], 0, M_DREMU_3, INSN_MACRO, 0, I3, 0),
    instdes("dremu", ['d','v','I'], 0, M_DREMU_3I, INSN_MACRO, 0, I3, 0),
    instdes("dret", [], 0x7000003e, 0xffffffff, 0, 0, N5, 0),
    instdes("drol", ['d','v','t'], 0, M_DROL, INSN_MACRO, 0, I3, 0),
    instdes("drol", ['d','v','I'], 0, M_DROL_I, INSN_MACRO, 0, I3, 0),
    instdes("dror", ['d','v','t'], 0, M_DROR, INSN_MACRO, 0, I3, 0),
    instdes("dror", ['d','v','I'], 0, M_DROR_I, INSN_MACRO, 0, I3, 0),
    instdes("dror", ['d','w','<'], 0x0020003a, 0xffe0003f, WR_d|RD_t, 0, N5|I65, 0),
    instdes("drorv", ['d','t','s'], 0x00000056, 0xfc0007ff, RD_t|RD_s|WR_d, 0, N5|I65, 0),
    instdes("dror32", ['d','w','<'], 0x0020003e, 0xffe0003f, WR_d|RD_t, 0, N5|I65, 0),
    instdes("drotl", ['d','v','t'], 0, M_DROL, INSN_MACRO, 0, I65, 0),
    instdes("drotl", ['d','v','I'], 0, M_DROL_I, INSN_MACRO, 0, I65, 0),
    instdes("drotr", ['d','v','t'], 0, M_DROR, INSN_MACRO, 0, I65, 0),
    instdes("drotr", ['d','v','I'], 0, M_DROR_I, INSN_MACRO, 0, I65, 0),
    instdes("drotrv", ['d','t','s'], 0x00000056, 0xfc0007ff, RD_t|RD_s|WR_d, 0, I65, 0),
    instdes("drotr32", ['d','w','<'], 0x0020003e, 0xffe0003f, WR_d|RD_t, 0, I65, 0),
    instdes("dsbh", ['d','w'], 0x7c0000a4, 0xffe007ff, WR_d|RD_t, 0, I65, 0),
    instdes("dshd", ['d','w'], 0x7c000164, 0xffe007ff, WR_d|RD_t, 0, I65, 0),
    instdes("dsllv", ['d','t','s'], 0x00000014, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I3, 0),
    instdes("dsll32", ['d','w','<'], 0x0000003c, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsll", ['d','w','s'], 0x00000014, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I3, 0),
    instdes("dsll", ['d','w','>'], 0x0000003c, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsll", ['d','w','<'], 0x00000038, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsll", ['D','S','T'], 0x45a00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("dsll", ['D','S','T'], 0x4b20000e, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("dsrav", ['d','t','s'], 0x00000017, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I3, 0),
    instdes("dsra32", ['d','w','<'], 0x0000003f, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsra", ['d','w','s'], 0x00000017, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I3, 0),
    instdes("dsra", ['d','w','>'], 0x0000003f, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsra", ['d','w','<'], 0x0000003b, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsra", ['D','S','T'], 0x45e00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("dsra", ['D','S','T'], 0x4b60000f, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("dsrlv", ['d','t','s'], 0x00000016, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I3, 0),
    instdes("dsrl32", ['d','w','<'], 0x0000003e, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsrl", ['d','w','s'], 0x00000016, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I3, 0),
    instdes("dsrl", ['d','w','>'], 0x0000003e, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsrl", ['d','w','<'], 0x0000003a, 0xffe0003f, WR_d|RD_t, 0, I3, 0),
    instdes("dsrl", ['D','S','T'], 0x45a00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("dsrl", ['D','S','T'], 0x4b20000f, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("dsub", ['d','v','t'], 0x0000002e, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I3, 0),
    instdes("dsub", ['d','v','I'], 0, M_DSUB_I, INSN_MACRO, 0, I3, 0),
    instdes("dsub", ['D','S','T'], 0x45e00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("dsub", ['D','S','T'], 0x4b60000d, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("dsubu", ['d','v','t'], 0x0000002f, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I3, 0),
    instdes("dsubu", ['d','v','I'], 0, M_DSUBU_I, INSN_MACRO, 0, I3, 0),
    instdes("dvpe", [], 0x41600001, 0xffffffff, TRAP, 0, MT32, 0),
    instdes("dvpe", ['t'], 0x41600001, 0xffe0ffff, TRAP|WR_t, 0, MT32, 0),
    instdes("ei", [], 0x41606020, 0xffffffff, WR_t|WR_C0, 0, I33, 0),
    instdes("ei", ['t'], 0x41606020, 0xffe0ffff, WR_t|WR_C0, 0, I33, 0),
    instdes("emt", [], 0x41600be1, 0xffffffff, TRAP, 0, MT32, 0),
    instdes("emt", ['t'], 0x41600be1, 0xffe0ffff, TRAP|WR_t, 0, MT32, 0),
    instdes("eret", [], 0x42000018, 0xffffffff, NODS, 0, I3_32, 0),
    instdes("evpe", [], 0x41600021, 0xffffffff, TRAP, 0, MT32, 0),
    instdes("evpe", ['t'], 0x41600021, 0xffe0ffff, TRAP|WR_t, 0, MT32, 0),
    instdes("ext", ['t','r','+A','+C'], 0x7c000000, 0xfc00003f, WR_t|RD_s, 0, I33, 0),
    instdes("exts32", ['t','r','+p','+S'], 0x7000003b, 0xfc00003f, WR_t|RD_s, 0, IOCT, 0),
    instdes("exts", ['t','r','+P','+S'], 0x7000003b, 0xfc00003f, WR_t|RD_s, 0, IOCT, 0),
    instdes("exts", ['t','r','+p','+s'], 0x7000003a, 0xfc00003f, WR_t|RD_s, 0, IOCT, 0),
    instdes("floor.l.d", ['D','S'], 0x4620000b, 0xffff003f, WR_D|RD_S|FP_D, 0, I3_33, 0),
    instdes("floor.l.s", ['D','S'], 0x4600000b, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I3_33, 0),
    instdes("floor.w.d", ['D','S'], 0x4620000f, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I2, 0),
    instdes("floor.w.s", ['D','S'], 0x4600000f, 0xffff003f, WR_D|RD_S|FP_S, 0, I2, 0),
    instdes("hibernate", [], 0x42000023, 0xffffffff, 0, 0, V1, 0),
    instdes("ins", ['t','r','+A','+B'], 0x7c000004, 0xfc00003f, WR_t|RD_s, 0, I33, 0),
    instdes("iret", [], 0x42000038, 0xffffffff, NODS, 0, MC, 0),
    instdes("jr", ['s'], 0x00000008, 0xfc1fffff, UBD|RD_s, 0, I1, 0),
    instdes("jr.hb", ['s'], 0x00000408, 0xfc1fffff, UBD|RD_s, 0, I32, 0),
    instdes("j", ['s'], 0x00000008, 0xfc1fffff, UBD|RD_s, 0, I1, 0),
    instdes("j", ['a'], 0, M_J_A, INSN_MACRO, 0, I1, 0),
    instdes("j", ['a'], 0x08000000, 0xfc000000, UBD, 0, I1, 0),
    instdes("jalr", ['s'], 0x0000f809, 0xfc1fffff, UBD|RD_s|WR_d, 0, I1, 0),
    instdes("jalr", ['d','s'], 0x00000009, 0xfc1f07ff, UBD|RD_s|WR_d, 0, I1, 0),
    instdes("jalr.hb", ['s'], 0x0000fc09, 0xfc1fffff, UBD|RD_s|WR_d, 0, I32, 0),
    instdes("jalr.hb", ['d','s'], 0x00000409, 0xfc1f07ff, UBD|RD_s|WR_d, 0, I32, 0),
    instdes("jal", ['d','s'], 0, M_JAL_2, INSN_MACRO, 0, I1, 0),
    instdes("jal", ['s'], 0, M_JAL_1, INSN_MACRO, 0, I1, 0),
    instdes("jal", ['a'], 0, M_JAL_A, INSN_MACRO, 0, I1, 0),
    instdes("jal", ['a'], 0x0c000000, 0xfc000000, UBD|WR_31, 0, I1, 0),
    instdes("jalx", ['a'], 0x74000000, 0xfc000000, UBD|WR_31, 0, I1, 0),
    instdes("la", ['t','A(b)'], 0, M_LA_AB, INSN_MACRO, 0, I1, 0),
    instdes("laa", ['d','(b)','t'], 0x7000049f, 0xfc0007ff, LDD|SM|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("laad", ['d','(b)','t'], 0x700004df, 0xfc0007ff, LDD|SM|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("lac", ['d','(b)'], 0x7000039f, 0xfc1f07ff, LDD|SM|WR_d|RD_b, 0, IOCT2, 0),
    instdes("lacd", ['d','(b)'], 0x700003df, 0xfc1f07ff, LDD|SM|WR_d|RD_b, 0, IOCT2, 0),
    instdes("lad", ['d','(b)'], 0x7000019f, 0xfc1f07ff, LDD|SM|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("ladd", ['d','(b)'], 0x700001df, 0xfc1f07ff, LDD|SM|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("lai", ['d','(b)'], 0x7000009f, 0xfc1f07ff, LDD|SM|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("laid", ['d','(b)'], 0x700000df, 0xfc1f07ff, LDD|SM|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("las", ['d','(b)'], 0x7000029f, 0xfc1f07ff, LDD|SM|WR_d|RD_b, 0, IOCT2, 0),
    instdes("lasd", ['d','(b)'], 0x700002df, 0xfc1f07ff, LDD|SM|WR_d|RD_b, 0, IOCT2, 0),
    instdes("law", ['d','(b)','t'], 0x7000059f, 0xfc0007ff, LDD|SM|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("lawd", ['d','(b)','t'], 0x700005df, 0xfc0007ff, LDD|SM|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("lb", ['t','o(b)'], 0x80000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lb", ['t','A(b)'], 0, M_LB_AB, INSN_MACRO, 0, I1, 0),
    instdes("lbu", ['t','o(b)'], 0x90000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lbu", ['t','A(b)'], 0, M_LBU_AB, INSN_MACRO, 0, I1, 0),
    instdes("lbx", ['d','t(b)'], 0x7c00058a, 0xfc0007ff, LDD|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("lbux", ['d','t(b)'], 0x7c00018a, 0xfc0007ff, LDD|WR_d|RD_t|RD_b, 0, D32|IOCT2, 0),
    instdes("ldx", ['d','t(b)'], 0x7c00020a, 0xfc0007ff, LDD|WR_d|RD_t|RD_b, 0, D64|IOCT2, 0),
    instdes("lhx", ['d','t(b)'], 0x7c00010a, 0xfc0007ff, LDD|WR_d|RD_t|RD_b, 0, D32|IOCT2, 0),
    instdes("lhux", ['d','t(b)'], 0x7c00050a, 0xfc0007ff, LDD|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("lwx", ['d','t(b)'], 0x7c00000a, 0xfc0007ff, LDD|WR_d|RD_t|RD_b, 0, D32|IOCT2, 0),
    instdes("lwux", ['d','t(b)'], 0x7c00040a, 0xfc0007ff, LDD|WR_d|RD_t|RD_b, 0, IOCT2, 0),
    instdes("lca", ['t','A(b)'], 0, M_LCA_AB, INSN_MACRO, 0, I1, 0),
    instdes("ld", ['t','o(b)'], 0, M_LD_OB, INSN_MACRO, 0, I1, 0),
    instdes("ld", ['t','o(b)'], 0xdc000000, 0xfc000000, WR_t|RD_b, 0, I3, 0),
    instdes("ld", ['t','A(b)'], 0, M_LD_AB, INSN_MACRO, 0, I1, 0),
    instdes("ldaddw", ['t','b'], 0x70000010, 0xfc00ffff, SM|RD_t|WR_t|RD_b, 0, XLR, 0),
    instdes("ldaddwu", ['t','b'], 0x70000011, 0xfc00ffff, SM|RD_t|WR_t|RD_b, 0, XLR, 0),
    instdes("ldaddd", ['t','b'], 0x70000012, 0xfc00ffff, SM|RD_t|WR_t|RD_b, 0, XLR, 0),
    instdes("ldc1", ['T','o(b)'], 0xd4000000, 0xfc000000, CLD|RD_b|WR_T|FP_D, 0, I2, 0),
    instdes("ldc1", ['E','o(b)'], 0xd4000000, 0xfc000000, CLD|RD_b|WR_T|FP_D, 0, I2, 0),
    instdes("ldc1", ['T','A(b)'], 0, M_LDC1_AB, INSN_MACRO, INSN2_M_FP_D, I2, 0),
    instdes("ldc1", ['E','A(b)'], 0, M_LDC1_AB, INSN_MACRO, INSN2_M_FP_D, I2, 0),
    instdes("l.d", ['T','o(b)'], 0xd4000000, 0xfc000000, CLD|RD_b|WR_T|FP_D, 0, I2, 0),
    instdes("l.d", ['T','o(b)'], 0, M_L_DOB, INSN_MACRO, INSN2_M_FP_D, I1, 0),
    instdes("l.d", ['T','A(b)'], 0, M_L_DAB, INSN_MACRO, INSN2_M_FP_D, I1, 0),
    instdes("ldc2", ['E','o(b)'], 0xd8000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I2, IOCT|IOCTP|IOCT2),
    instdes("ldc2", ['E','A(b)'], 0, M_LDC2_AB, INSN_MACRO, 0, I2, IOCT|IOCTP|IOCT2),
    instdes("ldc3", ['E','o(b)'], 0xdc000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I2, IOCT|IOCTP|IOCT2),
    instdes("ldc3", ['E','A(b)'], 0, M_LDC3_AB, INSN_MACRO, 0, I2, IOCT|IOCTP|IOCT2),
    instdes("ldl", ['t','o(b)'], 0x68000000, 0xfc000000, LDD|WR_t|RD_b, 0, I3, 0),
    instdes("ldl", ['t','A(b)'], 0, M_LDL_AB, INSN_MACRO, 0, I3, 0),
    instdes("ldr", ['t','o(b)'], 0x6c000000, 0xfc000000, LDD|WR_t|RD_b, 0, I3, 0),
    instdes("ldr", ['t','A(b)'], 0, M_LDR_AB, INSN_MACRO, 0, I3, 0),
    instdes("ldxc1", ['D','t(b)'], 0x4c000001, 0xfc00f83f, LDD|WR_D|RD_t|RD_b|FP_D, 0, I4_33, 0),
    instdes("lh", ['t','o(b)'], 0x84000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lh", ['t','A(b)'], 0, M_LH_AB, INSN_MACRO, 0, I1, 0),
    instdes("lhu", ['t','o(b)'], 0x94000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lhu", ['t','A(b)'], 0, M_LHU_AB, INSN_MACRO, 0, I1, 0),
    instdes("li.d", ['t','F'], 0, M_LI_D, INSN_MACRO, INSN2_M_FP_D, I1, 0),
    instdes("li.d", ['T','L'], 0, M_LI_DD, INSN_MACRO, INSN2_M_FP_D, I1, 0),
    instdes("li.s", ['t','f'], 0, M_LI_S, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("li.s", ['T','l'], 0, M_LI_SS, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("ll", ['t','o(b)'], 0xc0000000, 0xfc000000, LDD|RD_b|WR_t, 0, I2, 0),
    instdes("ll", ['t','A(b)'], 0, M_LL_AB, INSN_MACRO, 0, I2, 0),
    instdes("lld", ['t','o(b)'], 0xd0000000, 0xfc000000, LDD|RD_b|WR_t, 0, I3, 0),
    instdes("lld", ['t','A(b)'], 0, M_LLD_AB, INSN_MACRO, 0, I3, 0),
    instdes("lui", ['t','u'], 0x3c000000, 0xffe00000, WR_t, 0, I1, 0),
    instdes("luxc1", ['D','t(b)'], 0x4c000005, 0xfc00f83f, LDD|WR_D|RD_t|RD_b|FP_D, 0, I5_33|N55, 0),
    instdes("lw", ['t','o(b)'], 0x8c000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lw", ['t','A(b)'], 0, M_LW_AB, INSN_MACRO, 0, I1, 0),
    instdes("lwc0", ['E','o(b)'], 0xc0000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwc0", ['E','A(b)'], 0, M_LWC0_AB, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwc1", ['T','o(b)'], 0xc4000000, 0xfc000000, CLD|RD_b|WR_T|FP_S, 0, I1, 0),
    instdes("lwc1", ['E','o(b)'], 0xc4000000, 0xfc000000, CLD|RD_b|WR_T|FP_S, 0, I1, 0),
    instdes("lwc1", ['T','A(b)'], 0, M_LWC1_AB, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("lwc1", ['E','A(b)'], 0, M_LWC1_AB, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("l.s", ['T','o(b)'], 0xc4000000, 0xfc000000, CLD|RD_b|WR_T|FP_S, 0, I1, 0),
    instdes("l.s", ['T','A(b)'], 0, M_LWC1_AB, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("lwc2", ['E','o(b)'], 0xc8000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwc2", ['E','A(b)'], 0, M_LWC2_AB, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwc3", ['E','o(b)'], 0xcc000000, 0xfc000000, CLD|RD_b|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwc3", ['E','A(b)'], 0, M_LWC3_AB, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("lwl", ['t','o(b)'], 0x88000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lwl", ['t','A(b)'], 0, M_LWL_AB, INSN_MACRO, 0, I1, 0),
    instdes("lcache", ['t','o(b)'], 0x88000000, 0xfc000000, LDD|RD_b|WR_t, 0, I2, 0),
    instdes("lcache", ['t','A(b)'], 0, M_LWL_AB, INSN_MACRO, 0, I2, 0),
    instdes("lwr", ['t','o(b)'], 0x98000000, 0xfc000000, LDD|RD_b|WR_t, 0, I1, 0),
    instdes("lwr", ['t','A(b)'], 0, M_LWR_AB, INSN_MACRO, 0, I1, 0),
    instdes("flush", ['t','o(b)'], 0x98000000, 0xfc000000, LDD|RD_b|WR_t, 0, I2, 0),
    instdes("flush", ['t','A(b)'], 0, M_LWR_AB, INSN_MACRO, 0, I2, 0),
    instdes("fork", ['d','s','t'], 0x7c000008, 0xfc0007ff, TRAP|WR_d|RD_s|RD_t, 0, MT32, 0),
    instdes("lwu", ['t','o(b)'], 0x9c000000, 0xfc000000, LDD|RD_b|WR_t, 0, I3, 0),
    instdes("lwu", ['t','A(b)'], 0, M_LWU_AB, INSN_MACRO, 0, I3, 0),
    instdes("lwxc1", ['D','t(b)'], 0x4c000000, 0xfc00f83f, LDD|WR_D|RD_t|RD_b|FP_S, 0, I4_33, 0),
    instdes("lwxs", ['d','t(b)'], 0x70000088, 0xfc0007ff, LDD|RD_b|RD_t|WR_d, 0, SMT, 0),
    instdes("macc", ['d','s','t'], 0x00000028, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N412, 0),
    instdes("macc", ['d','s','t'], 0x00000158, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("maccs", ['d','s','t'], 0x00000428, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N412, 0),
    instdes("macchi", ['d','s','t'], 0x00000228, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N412, 0),
    instdes("macchi", ['d','s','t'], 0x00000358, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("macchis", ['d','s','t'], 0x00000628, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N412, 0),
    instdes("macchiu", ['d','s','t'], 0x00000268, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N412, 0),
    instdes("macchiu", ['d','s','t'], 0x00000359, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("macchius", ['d','s','t'], 0x00000668, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N412, 0),
    instdes("maccu", ['d','s','t'], 0x00000068, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N412, 0),
    instdes("maccu", ['d','s','t'], 0x00000159, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("maccus", ['d','s','t'], 0x00000468, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N412, 0),
    instdes("mad", ['s','t'], 0x70000000, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, P3, 0),
    instdes("madu", ['s','t'], 0x70000001, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, P3, 0),
    instdes("madd.d", ['D','R','S','T'], 0x4c000021, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_D, 0, I4_33, 0),
    instdes("madd.d", ['D','S','T'], 0x46200018, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("madd.d", ['D','S','T'], 0x72200018, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F, 0),
    instdes("madd.s", ['D','R','S','T'], 0x4c000020, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_S, 0, I4_33, 0),
    instdes("madd.s", ['D','S','T'], 0x46000018, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2E, 0),
    instdes("madd.s", ['D','S','T'], 0x72000018, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2F, 0),
    instdes("madd.ps", ['D','R','S','T'], 0x4c000026, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_D, 0, I5_33, 0),
    instdes("madd.ps", ['D','S','T'], 0x45600018, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("madd.ps", ['D','S','T'], 0x71600018, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F, 0),
    instdes("madd", ['s','t'], 0x0000001c, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, L1, 0),
    instdes("madd", ['s','t'], 0x70000000, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, I32|N55, 0),
    instdes("madd", ['s','t'], 0x70000000, 0xfc00ffff, RD_s|RD_t|WR_HILO|IS_M, 0, G1, 0),
    instdes("madd", ['7','s','t'], 0x70000000, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("madd", ['d','s','t'], 0x70000000, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d|IS_M, 0, G1, 0),
    instdes("maddp", ['s','t'], 0x70000441, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, SMT, 0),
    instdes("maddu", ['s','t'], 0x0000001d, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, L1, 0),
    instdes("maddu", ['s','t'], 0x70000001, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, I32|N55, 0),
    instdes("maddu", ['s','t'], 0x70000001, 0xfc00ffff, RD_s|RD_t|WR_HILO|IS_M, 0, G1, 0),
    instdes("maddu", ['7','s','t'], 0x70000001, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("maddu", ['d','s','t'], 0x70000001, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d|IS_M, 0, G1, 0),
    instdes("madd16", ['s','t'], 0x00000028, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, N411, 0),
    instdes("max.ob", ['X','Y','Q'], 0x78000007, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("max.ob", ['D','S','T'], 0x4ac00007, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("max.ob", ['D','S','T[e]'], 0x48000007, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("max.ob", ['D','S','k'], 0x4bc00007, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("max.qh", ['X','Y','Q'], 0x78200007, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("mfpc", ['t','P'], 0x4000c801, 0xffe0ffc1, LCD|WR_t|RD_C0, 0, M1|N5, 0),
    instdes("mfps", ['t','P'], 0x4000c800, 0xffe0ffc1, LCD|WR_t|RD_C0, 0, M1|N5, 0),
    instdes("mftacx", ['d'], 0x41020021, 0xffff07ff, TRAP|WR_d|RD_a, 0, MT32, 0),
    instdes("mftacx", ['d','*'], 0x41020021, 0xfff307ff, TRAP|WR_d|RD_a, 0, MT32, 0),
    instdes("mftc0", ['d','+t'], 0x41000000, 0xffe007ff, TRAP|LCD|WR_d|RD_C0, 0, MT32, 0),
    instdes("mftc0", ['d','+T'], 0x41000000, 0xffe007f8, TRAP|LCD|WR_d|RD_C0, 0, MT32, 0),
    instdes("mftc0", ['d','E','H'], 0x41000000, 0xffe007f8, TRAP|LCD|WR_d|RD_C0, 0, MT32, 0),
    instdes("mftc1", ['d','T'], 0x41000022, 0xffe007ff, TRAP|LCD|WR_d|RD_T|FP_S, 0, MT32, 0),
    instdes("mftc1", ['d','E'], 0x41000022, 0xffe007ff, TRAP|LCD|WR_d|RD_T|FP_S, 0, MT32, 0),
    instdes("mftc2", ['d','E'], 0x41000024, 0xffe007ff, TRAP|LCD|WR_d|RD_C2, 0, MT32, IOCT|IOCTP|IOCT2),
    instdes("mftdsp", ['d'], 0x41100021, 0xffff07ff, TRAP|WR_d, 0, MT32, 0),
    instdes("mftgpr", ['d','t'], 0x41000020, 0xffe007ff, TRAP|WR_d|RD_t, 0, MT32, 0),
    instdes("mfthc1", ['d','T'], 0x41000032, 0xffe007ff, TRAP|LCD|WR_d|RD_T|FP_D, 0, MT32, 0),
    instdes("mfthc1", ['d','E'], 0x41000032, 0xffe007ff, TRAP|LCD|WR_d|RD_T|FP_D, 0, MT32, 0),
    instdes("mfthc2", ['d','E'], 0x41000034, 0xffe007ff, TRAP|LCD|WR_d|RD_C2, 0, MT32, IOCT|IOCTP|IOCT2),
    instdes("mfthi", ['d'], 0x41010021, 0xffff07ff, TRAP|WR_d|RD_a, 0, MT32, 0),
    instdes("mfthi", ['d','*'], 0x41010021, 0xfff307ff, TRAP|WR_d|RD_a, 0, MT32, 0),
    instdes("mftlo", ['d'], 0x41000021, 0xffff07ff, TRAP|WR_d|RD_a, 0, MT32, 0),
    instdes("mftlo", ['d','*'], 0x41000021, 0xfff307ff, TRAP|WR_d|RD_a, 0, MT32, 0),
    instdes("mftr", ['d','t','!','H','$'], 0x41000000, 0xffe007c8, TRAP|WR_d, 0, MT32, 0),
    instdes("mfc0", ['t','G'], 0x40000000, 0xffe007ff, LCD|WR_t|RD_C0, 0, I1, 0),
    instdes("mfc0", ['t','+D'], 0x40000000, 0xffe007f8, LCD|WR_t|RD_C0, 0, I32, 0),
    instdes("mfc0", ['t','G','H'], 0x40000000, 0xffe007f8, LCD|WR_t|RD_C0, 0, I32, 0),
    instdes("mfc1", ['t','S'], 0x44000000, 0xffe007ff, LCD|WR_t|RD_S|FP_S, 0, I1, 0),
    instdes("mfc1", ['t','G'], 0x44000000, 0xffe007ff, LCD|WR_t|RD_S|FP_S, 0, I1, 0),
    instdes("mfhc1", ['t','S'], 0x44600000, 0xffe007ff, LCD|WR_t|RD_S|FP_D, 0, I33, 0),
    instdes("mfhc1", ['t','G'], 0x44600000, 0xffe007ff, LCD|WR_t|RD_S|FP_D, 0, I33, 0),
    instdes("mfdr", ['t','G'], 0x7000003d, 0xffe007ff, LCD|WR_t|RD_C0, 0, N5, 0),
    instdes("mfhi", ['d'], 0x00000010, 0xffff07ff, WR_d|RD_HI, 0, I1, 0),
    instdes("mfhi", ['d','9'], 0x00000010, 0xff9f07ff, WR_d|RD_HI, 0, D32, 0),
    instdes("mflo", ['d'], 0x00000012, 0xffff07ff, WR_d|RD_LO, 0, I1, 0),
    instdes("mflo", ['d','9'], 0x00000012, 0xff9f07ff, WR_d|RD_LO, 0, D32, 0),
    instdes("mflhxu", ['d'], 0x00000052, 0xffff07ff, WR_d|MOD_HILO, 0, SMT, 0),
    instdes("mfcr", ['t','s'], 0x70000018, 0xfc00ffff, WR_t, 0, XLR, 0),
    instdes("min.ob", ['X','Y','Q'], 0x78000006, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("min.ob", ['D','S','T'], 0x4ac00006, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("min.ob", ['D','S','T[e]'], 0x48000006, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("min.ob", ['D','S','k'], 0x4bc00006, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("min.qh", ['X','Y','Q'], 0x78200006, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("mov.d", ['D','S'], 0x46200006, 0xffff003f, WR_D|RD_S|FP_D, 0, I1, 0),
    instdes("mov.s", ['D','S'], 0x46000006, 0xffff003f, WR_D|RD_S|FP_S, 0, I1, 0),
    instdes("mov.ps", ['D','S'], 0x46c00006, 0xffff003f, WR_D|RD_S|FP_D, 0, I5_33|IL2F, 0),
    instdes("mov.ps", ['D','S'], 0x45600006, 0xffff003f, WR_D|RD_S|FP_D, 0, IL2E, 0),
    instdes("movf", ['d','s','N'], 0x00000001, 0xfc0307ff, WR_d|RD_s|RD_CC|FP_S|FP_D, 0, I4_32, 0),
    instdes("movf.d", ['D','S','N'], 0x46200011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_D, 0, I4_32, 0),
    instdes("movf.l", ['D','S','N'], 0x46a00011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_D, 0, MX|SB1, 0),
    instdes("movf.l", ['X','Y','N'], 0x46a00011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_D, 0, MX|SB1, 0),
    instdes("movf.s", ['D','S','N'], 0x46000011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_S, 0, I4_32, 0),
    instdes("movf.ps", ['D','S','N'], 0x46c00011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_D, 0, I5_33, 0),
    instdes("movn", ['d','v','t'], 0x0000000b, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I4_32|IL2E|IL2F, 0),
    instdes("movnz", ['d','v','t'], 0x0000000b, 0xfc0007ff, WR_d|RD_s|RD_t, 0, IL2E|IL2F|IL3A, 0),
    instdes("ffc", ['d','v'], 0x0000000b, 0xfc1f07ff, WR_d|RD_s, 0, L1, 0),
    instdes("movn.d", ['D','S','t'], 0x46200013, 0xffe0003f, WR_D|RD_S|RD_t|FP_D, 0, I4_32, 0),
    instdes("movn.l", ['D','S','t'], 0x46a00013, 0xffe0003f, WR_D|RD_S|RD_t|FP_D, 0, MX|SB1, 0),
    instdes("movn.l", ['X','Y','t'], 0x46a00013, 0xffe0003f, WR_D|RD_S|RD_t|FP_D, 0, MX|SB1, 0),
    instdes("movn.s", ['D','S','t'], 0x46000013, 0xffe0003f, WR_D|RD_S|RD_t|FP_S, 0, I4_32, 0),
    instdes("movn.ps", ['D','S','t'], 0x46c00013, 0xffe0003f, WR_D|RD_S|RD_t|FP_D, 0, I5_33, 0),
    instdes("movt", ['d','s','N'], 0x00010001, 0xfc0307ff, WR_d|RD_s|RD_CC|FP_S|FP_D, 0, I4_32, 0),
    instdes("movt.d", ['D','S','N'], 0x46210011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_D, 0, I4_32, 0),
    instdes("movt.l", ['D','S','N'], 0x46a10011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_D, 0, MX|SB1, 0),
    instdes("movt.l", ['X','Y','N'], 0x46a10011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_D, 0, MX|SB1, 0),
    instdes("movt.s", ['D','S','N'], 0x46010011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_S, 0, I4_32, 0),
    instdes("movt.ps", ['D','S','N'], 0x46c10011, 0xffe3003f, WR_D|RD_S|RD_CC|FP_D, 0, I5_33, 0),
    instdes("movz", ['d','v','t'], 0x0000000a, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I4_32|IL2E|IL2F, 0),
    instdes("ffs", ['d','v'], 0x0000000a, 0xfc1f07ff, WR_d|RD_s, 0, L1, 0),
    instdes("movz.d", ['D','S','t'], 0x46200012, 0xffe0003f, WR_D|RD_S|RD_t|FP_D, 0, I4_32, 0),
    instdes("movz.l", ['D','S','t'], 0x46a00012, 0xffe0003f, WR_D|RD_S|RD_t|FP_D, 0, MX|SB1, 0),
    instdes("movz.l", ['X','Y','t'], 0x46a00012, 0xffe0003f, WR_D|RD_S|RD_t|FP_D, 0, MX|SB1, 0),
    instdes("movz.s", ['D','S','t'], 0x46000012, 0xffe0003f, WR_D|RD_S|RD_t|FP_S, 0, I4_32, 0),
    instdes("movz.ps", ['D','S','t'], 0x46c00012, 0xffe0003f, WR_D|RD_S|RD_t|FP_D, 0, I5_33, 0),
    instdes("msac", ['d','s','t'], 0x000001d8, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("msacu", ['d','s','t'], 0x000001d9, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("msachi", ['d','s','t'], 0x000003d8, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("msachiu", ['d','s','t'], 0x000003d9, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("msgn.qh", ['X','Y','Q'], 0x78200000, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("msgsnd", ['t'], 0, M_MSGSND, INSN_MACRO, 0, XLR, 0),
    instdes("msgld", [], 0, M_MSGLD, INSN_MACRO, 0, XLR, 0),
    instdes("msgld", ['t'], 0, M_MSGLD_T, INSN_MACRO, 0, XLR, 0),
    instdes("msgwait", [], 0, M_MSGWAIT, INSN_MACRO, 0, XLR, 0),
    instdes("msgwait", ['t'], 0, M_MSGWAIT_T, INSN_MACRO, 0, XLR, 0),
    instdes("msub.d", ['D','R','S','T'], 0x4c000029, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_D, 0, I4_33, 0),
    instdes("msub.d", ['D','S','T'], 0x46200019, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("msub.d", ['D','S','T'], 0x72200019, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F, 0),
    instdes("msub.s", ['D','R','S','T'], 0x4c000028, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_S, 0, I4_33, 0),
    instdes("msub.s", ['D','S','T'], 0x46000019, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2E, 0),
    instdes("msub.s", ['D','S','T'], 0x72000019, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2F, 0),
    instdes("msub.ps", ['D','R','S','T'], 0x4c00002e, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_D, 0, I5_33, 0),
    instdes("msub.ps", ['D','S','T'], 0x45600019, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("msub.ps", ['D','S','T'], 0x71600019, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F, 0),
    instdes("msub", ['s','t'], 0x0000001e, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, L1, 0),
    instdes("msub", ['s','t'], 0x70000004, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, I32|N55, 0),
    instdes("msub", ['7','s','t'], 0x70000004, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("msubu", ['s','t'], 0x0000001f, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, L1, 0),
    instdes("msubu", ['s','t'], 0x70000005, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, I32|N55, 0),
    instdes("msubu", ['7','s','t'], 0x70000005, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("mtpc", ['t','P'], 0x4080c801, 0xffe0ffc1, COD|RD_t|WR_C0, 0, M1|N5, 0),
    instdes("mtps", ['t','P'], 0x4080c800, 0xffe0ffc1, COD|RD_t|WR_C0, 0, M1|N5, 0),
    instdes("mtc0", ['t','G'], 0x40800000, 0xffe007ff, COD|RD_t|WR_C0|WR_CC, 0, I1, 0),
    instdes("mtc0", ['t','+D'], 0x40800000, 0xffe007f8, COD|RD_t|WR_C0|WR_CC, 0, I32, 0),
    instdes("mtc0", ['t','G','H'], 0x40800000, 0xffe007f8, COD|RD_t|WR_C0|WR_CC, 0, I32, 0),
    instdes("mtc1", ['t','S'], 0x44800000, 0xffe007ff, COD|RD_t|WR_S|FP_S, 0, I1, 0),
    instdes("mtc1", ['t','G'], 0x44800000, 0xffe007ff, COD|RD_t|WR_S|FP_S, 0, I1, 0),
    instdes("mthc1", ['t','S'], 0x44e00000, 0xffe007ff, COD|RD_t|WR_S|FP_D, 0, I33, 0),
    instdes("mthc1", ['t','G'], 0x44e00000, 0xffe007ff, COD|RD_t|WR_S|FP_D, 0, I33, 0),
    instdes("mtdr", ['t','G'], 0x7080003d, 0xffe007ff, COD|RD_t|WR_C0, 0, N5, 0),
    instdes("mthi", ['s'], 0x00000011, 0xfc1fffff, RD_s|WR_HI, 0, I1, 0),
    instdes("mthi", ['s','7'], 0x00000011, 0xfc1fe7ff, RD_s|WR_HI, 0, D32, 0),
    instdes("mtlo", ['s'], 0x00000013, 0xfc1fffff, RD_s|WR_LO, 0, I1, 0),
    instdes("mtlo", ['s','7'], 0x00000013, 0xfc1fe7ff, RD_s|WR_LO, 0, D32, 0),
    instdes("mtlhx", ['s'], 0x00000053, 0xfc1fffff, RD_s|MOD_HILO, 0, SMT, 0),
    instdes("mtcr", ['t','s'], 0x70000019, 0xfc00ffff, RD_t, 0, XLR, 0),
    instdes("mtm0", ['s'], 0x70000008, 0xfc1fffff, RD_s, 0, IOCT, 0),
    instdes("mtm1", ['s'], 0x7000000c, 0xfc1fffff, RD_s, 0, IOCT, 0),
    instdes("mtm2", ['s'], 0x7000000d, 0xfc1fffff, RD_s, 0, IOCT, 0),
    instdes("mtp0", ['s'], 0x70000009, 0xfc1fffff, RD_s, 0, IOCT, 0),
    instdes("mtp1", ['s'], 0x7000000a, 0xfc1fffff, RD_s, 0, IOCT, 0),
    instdes("mtp2", ['s'], 0x7000000b, 0xfc1fffff, RD_s, 0, IOCT, 0),
    instdes("mttc0", ['t','G'], 0x41800000, 0xffe007ff, TRAP|COD|RD_t|WR_C0|WR_CC, 0, MT32, 0),
    instdes("mttc0", ['t','+D'], 0x41800000, 0xffe007f8, TRAP|COD|RD_t|WR_C0|WR_CC, 0, MT32, 0),
    instdes("mttc0", ['t','G','H'], 0x41800000, 0xffe007f8, TRAP|COD|RD_t|WR_C0|WR_CC, 0, MT32, 0),
    instdes("mttc1", ['t','S'], 0x41800022, 0xffe007ff, TRAP|COD|RD_t|WR_S|FP_S, 0, MT32, 0),
    instdes("mttc1", ['t','G'], 0x41800022, 0xffe007ff, TRAP|COD|RD_t|WR_S|FP_S, 0, MT32, 0),
    instdes("mttc2", ['t','g'], 0x41800024, 0xffe007ff, TRAP|COD|RD_t|WR_C2|WR_CC, 0, MT32, IOCT|IOCTP|IOCT2),
    instdes("mttacx", ['t'], 0x41801021, 0xffe0ffff, TRAP|WR_a|RD_t, 0, MT32, 0),
    instdes("mttacx", ['t','&'], 0x41801021, 0xffe09fff, TRAP|WR_a|RD_t, 0, MT32, 0),
    instdes("mttdsp", ['t'], 0x41808021, 0xffe0ffff, TRAP|RD_t, 0, MT32, 0),
    instdes("mttgpr", ['t','d'], 0x41800020, 0xffe007ff, TRAP|WR_d|RD_t, 0, MT32, 0),
    instdes("mtthc1", ['t','S'], 0x41800032, 0xffe007ff, TRAP|COD|RD_t|WR_S|FP_D, 0, MT32, 0),
    instdes("mtthc1", ['t','G'], 0x41800032, 0xffe007ff, TRAP|COD|RD_t|WR_S|FP_D, 0, MT32, 0),
    instdes("mtthc2", ['t','g'], 0x41800034, 0xffe007ff, TRAP|COD|RD_t|WR_C2|WR_CC, 0, MT32, IOCT|IOCTP|IOCT2),
    instdes("mtthi", ['t'], 0x41800821, 0xffe0ffff, TRAP|WR_a|RD_t, 0, MT32, 0),
    instdes("mtthi", ['t','&'], 0x41800821, 0xffe09fff, TRAP|WR_a|RD_t, 0, MT32, 0),
    instdes("mttlo", ['t'], 0x41800021, 0xffe0ffff, TRAP|WR_a|RD_t, 0, MT32, 0),
    instdes("mttlo", ['t','&'], 0x41800021, 0xffe09fff, TRAP|WR_a|RD_t, 0, MT32, 0),
    instdes("mttr", ['t','d','!','H','$'], 0x41800000, 0xffe007c8, TRAP|RD_t, 0, MT32, 0),
    instdes("mul.d", ['D','V','T'], 0x46200002, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I1, 0),
    instdes("mul.s", ['D','V','T'], 0x46000002, 0xffe0003f, WR_D|RD_S|RD_T|FP_S, 0, I1, 0),
    instdes("mul.ob", ['X','Y','Q'], 0x78000030, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("mul.ob", ['D','S','T'], 0x4ac00030, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("mul.ob", ['D','S','T[e]'], 0x48000030, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("mul.ob", ['D','S','k'], 0x4bc00030, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("mul.ps", ['D','V','T'], 0x46c00002, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I5_33|IL2F, 0),
    instdes("mul.ps", ['D','V','T'], 0x45600002, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, IL2E, 0),
    instdes("mul.qh", ['X','Y','Q'], 0x78200030, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("mul", ['d','v','t'], 0x70000002, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, I32|P3|N55, 0),
    instdes("mul", ['d','s','t'], 0x00000058, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N54, 0),
    instdes("mul", ['d','v','t'], 0, M_MUL, INSN_MACRO, 0, I1, 0),
    instdes("mul", ['d','v','I'], 0, M_MUL_I, INSN_MACRO, 0, I1, 0),
    instdes("mula.ob", ['Y','Q'], 0x78000033, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("mula.ob", ['S','T'], 0x4ac00033, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mula.ob", ['S','T[e]'], 0x48000033, 0xfe2007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mula.ob", ['S','k'], 0x4bc00033, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mula.qh", ['Y','Q'], 0x78200033, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("mulhi", ['d','s','t'], 0x00000258, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("mulhiu", ['d','s','t'], 0x00000259, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("mull.ob", ['Y','Q'], 0x78000433, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("mull.ob", ['S','T'], 0x4ac00433, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mull.ob", ['S','T[e]'], 0x48000433, 0xfe2007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mull.ob", ['S','k'], 0x4bc00433, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mull.qh", ['Y','Q'], 0x78200433, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("mulo", ['d','v','t'], 0, M_MULO, INSN_MACRO, 0, I1, 0),
    instdes("mulo", ['d','v','I'], 0, M_MULO_I, INSN_MACRO, 0, I1, 0),
    instdes("mulou", ['d','v','t'], 0, M_MULOU, INSN_MACRO, 0, I1, 0),
    instdes("mulou", ['d','v','I'], 0, M_MULOU_I, INSN_MACRO, 0, I1, 0),
    instdes("mulr.ps", ['D','S','T'], 0x46c0001a, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, M3D, 0),
    instdes("muls", ['d','s','t'], 0x000000d8, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("mulsu", ['d','s','t'], 0x000000d9, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("mulshi", ['d','s','t'], 0x000002d8, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("mulshiu", ['d','s','t'], 0x000002d9, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("muls.ob", ['Y','Q'], 0x78000032, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("muls.ob", ['S','T'], 0x4ac00032, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("muls.ob", ['S','T[e]'], 0x48000032, 0xfe2007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("muls.ob", ['S','k'], 0x4bc00032, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("muls.qh", ['Y','Q'], 0x78200032, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("mulsl.ob", ['Y','Q'], 0x78000432, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("mulsl.ob", ['S','T'], 0x4ac00432, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mulsl.ob", ['S','T[e]'], 0x48000432, 0xfe2007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mulsl.ob", ['S','k'], 0x4bc00432, 0xffe007ff, WR_CC|RD_S|RD_T, 0, N54, 0),
    instdes("mulsl.qh", ['Y','Q'], 0x78200432, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("mult", ['s','t'], 0x00000018, 0xfc00ffff, RD_s|RD_t|WR_HILO|IS_M, 0, I1, 0),
    instdes("mult", ['7','s','t'], 0x00000018, 0xfc00e7ff, WR_a|RD_s|RD_t, 0, D32, 0),
    instdes("mult", ['d','s','t'], 0x00000018, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d|IS_M, 0, G1, 0),
    instdes("multp", ['s','t'], 0x00000459, 0xfc00ffff, RD_s|RD_t|MOD_HILO, 0, SMT, 0),
    instdes("multu", ['s','t'], 0x00000019, 0xfc00ffff, RD_s|RD_t|WR_HILO|IS_M, 0, I1, 0),
    instdes("multu", ['7','s','t'], 0x00000019, 0xfc00e7ff, WR_a|RD_s|RD_t, 0, D32, 0),
    instdes("multu", ['d','s','t'], 0x00000019, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d|IS_M, 0, G1, 0),
    instdes("mulu", ['d','s','t'], 0x00000059, 0xfc0007ff, RD_s|RD_t|WR_HILO|WR_d, 0, N5, 0),
    instdes("neg", ['d','w'], 0x00000022, 0xffe007ff, WR_d|RD_t, 0, I1, 0),
    instdes("negu", ['d','w'], 0x00000023, 0xffe007ff, WR_d|RD_t, 0, I1, 0),
    instdes("neg.d", ['D','V'], 0x46200007, 0xffff003f, WR_D|RD_S|FP_D, 0, I1, 0),
    instdes("neg.s", ['D','V'], 0x46000007, 0xffff003f, WR_D|RD_S|FP_S, 0, I1, 0),
    instdes("neg.ps", ['D','V'], 0x46c00007, 0xffff003f, WR_D|RD_S|FP_D, 0, I5_33|IL2F, 0),
    instdes("neg.ps", ['D','V'], 0x45600007, 0xffff003f, WR_D|RD_S|FP_D, 0, IL2E, 0),
    instdes("nmadd.d", ['D','R','S','T'], 0x4c000031, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_D, 0, I4_33, 0),
    instdes("nmadd.d", ['D','S','T'], 0x4620001a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("nmadd.d", ['D','S','T'], 0x7220001a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F, 0),
    instdes("nmadd.s", ['D','R','S','T'], 0x4c000030, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_S, 0, I4_33, 0),
    instdes("nmadd.s", ['D','S','T'], 0x4600001a, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2E, 0),
    instdes("nmadd.s", ['D','S','T'], 0x7200001a, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2F, 0),
    instdes("nmadd.ps", ['D','R','S','T'], 0x4c000036, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_D, 0, I5_33, 0),
    instdes("nmadd.ps", ['D','S','T'], 0x4560001a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("nmadd.ps", ['D','S','T'], 0x7160001a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F, 0),
    instdes("nmsub.d", ['D','R','S','T'], 0x4c000039, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_D, 0, I4_33, 0),
    instdes("nmsub.d", ['D','S','T'], 0x4620001b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("nmsub.d", ['D','S','T'], 0x7220001b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F, 0),
    instdes("nmsub.s", ['D','R','S','T'], 0x4c000038, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_S, 0, I4_33, 0),
    instdes("nmsub.s", ['D','S','T'], 0x4600001b, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2E, 0),
    instdes("nmsub.s", ['D','S','T'], 0x7200001b, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2F, 0),
    instdes("nmsub.ps", ['D','R','S','T'], 0x4c00003e, 0xfc00003f, RD_R|RD_S|RD_T|WR_D|FP_D, 0, I5_33, 0),
    instdes("nmsub.ps", ['D','S','T'], 0x4560001b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("nmsub.ps", ['D','S','T'], 0x7160001b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F, 0),
    instdes("nor", ['d','v','t'], 0x00000027, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("nor", ['t','r','I'], 0, M_NOR_I, INSN_MACRO, 0, I1, 0),
    instdes("nor", ['D','S','T'], 0x47a00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("nor", ['D','S','T'], 0x4ba00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("nor.ob", ['X','Y','Q'], 0x7800000f, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("nor.ob", ['D','S','T'], 0x4ac0000f, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("nor.ob", ['D','S','T[e]'], 0x4800000f, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("nor.ob", ['D','S','k'], 0x4bc0000f, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("nor.qh", ['X','Y','Q'], 0x7820000f, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("not", ['d','v'], 0x00000027, 0xfc1f07ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("or", ['d','v','t'], 0x00000025, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("or", ['t','r','I'], 0, M_OR_I, INSN_MACRO, 0, I1, 0),
    instdes("or", ['D','S','T'], 0x45a00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("or", ['D','S','T'], 0x4b20000c, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("or.ob", ['X','Y','Q'], 0x7800000e, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("or.ob", ['D','S','T'], 0x4ac0000e, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("or.ob", ['D','S','T[e]'], 0x4800000e, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("or.ob", ['D','S','k'], 0x4bc0000e, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("or.qh", ['X','Y','Q'], 0x7820000e, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("ori", ['t','r','i'], 0x34000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("pabsdiff.ob", ['X','Y','Q'], 0x78000009, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, SB1, 0),
    instdes("pabsdiffc.ob", ['Y','Q'], 0x78000035, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, SB1, 0),
    instdes("pause", [], 0x00000140, 0xffffffff, TRAP, 0, I33, 0),
    instdes("pavg.ob", ['X','Y','Q'], 0x78000008, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, SB1, 0),
    instdes("pickf.ob", ['X','Y','Q'], 0x78000002, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("pickf.ob", ['D','S','T'], 0x4ac00002, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("pickf.ob", ['D','S','T[e]'], 0x48000002, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("pickf.ob", ['D','S','k'], 0x4bc00002, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("pickf.qh", ['X','Y','Q'], 0x78200002, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("pickt.ob", ['X','Y','Q'], 0x78000003, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("pickt.ob", ['D','S','T'], 0x4ac00003, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("pickt.ob", ['D','S','T[e]'], 0x48000003, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("pickt.ob", ['D','S','k'], 0x4bc00003, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("pickt.qh", ['X','Y','Q'], 0x78200003, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("pll.ps", ['D','V','T'], 0x46c0002c, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I5_33, 0),
    instdes("plu.ps", ['D','V','T'], 0x46c0002d, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I5_33, 0),
    instdes("pop", ['d','v'], 0x7000002c, 0xfc1f07ff, WR_d|RD_s, 0, IOCT, 0),
    instdes("pul.ps", ['D','V','T'], 0x46c0002e, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I5_33, 0),
    instdes("puu.ps", ['D','V','T'], 0x46c0002f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I5_33, 0),
    instdes("pperm", ['s','t'], 0x70000481, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, SMT, 0),
    instdes("qmac.00", ['s','t'], 0x70000412, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, IOCT2, 0),
    instdes("qmac.01", ['s','t'], 0x70000452, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, IOCT2, 0),
    instdes("qmac.02", ['s','t'], 0x70000492, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, IOCT2, 0),
    instdes("qmac.03", ['s','t'], 0x700004d2, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, IOCT2, 0),
    instdes("qmacs.00", ['s','t'], 0x70000012, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, IOCT2, 0),
    instdes("qmacs.01", ['s','t'], 0x70000052, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, IOCT2, 0),
    instdes("qmacs.02", ['s','t'], 0x70000092, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, IOCT2, 0),
    instdes("qmacs.03", ['s','t'], 0x700000d2, 0xfc00ffff, MOD_HILO|RD_s|RD_t, 0, IOCT2, 0),
    instdes("rach.ob", ['X'], 0x7a00003f, 0xfffff83f, WR_D|FP_D, RD_MACC, MX|SB1, 0),
    instdes("rach.ob", ['D'], 0x4a00003f, 0xfffff83f, WR_D, 0, N54, 0),
    instdes("rach.qh", ['X'], 0x7a20003f, 0xfffff83f, WR_D|FP_D, RD_MACC, MX, 0),
    instdes("racl.ob", ['X'], 0x7800003f, 0xfffff83f, WR_D|FP_D, RD_MACC, MX|SB1, 0),
    instdes("racl.ob", ['D'], 0x4800003f, 0xfffff83f, WR_D, 0, N54, 0),
    instdes("racl.qh", ['X'], 0x7820003f, 0xfffff83f, WR_D|FP_D, RD_MACC, MX, 0),
    instdes("racm.ob", ['X'], 0x7900003f, 0xfffff83f, WR_D|FP_D, RD_MACC, MX|SB1, 0),
    instdes("racm.ob", ['D'], 0x4900003f, 0xfffff83f, WR_D, 0, N54, 0),
    instdes("racm.qh", ['X'], 0x7920003f, 0xfffff83f, WR_D|FP_D, RD_MACC, MX, 0),
    instdes("recip.d", ['D','S'], 0x46200015, 0xffff003f, WR_D|RD_S|FP_D, 0, I4_33, 0),
    instdes("recip.ps", ['D','S'], 0x46c00015, 0xffff003f, WR_D|RD_S|FP_D, 0, SB1, 0),
    instdes("recip.s", ['D','S'], 0x46000015, 0xffff003f, WR_D|RD_S|FP_S, 0, I4_33, 0),
    instdes("recip1.d", ['D','S'], 0x4620001d, 0xffff003f, WR_D|RD_S|FP_D, 0, M3D, 0),
    instdes("recip1.ps", ['D','S'], 0x46c0001d, 0xffff003f, WR_D|RD_S|FP_S, 0, M3D, 0),
    instdes("recip1.s", ['D','S'], 0x4600001d, 0xffff003f, WR_D|RD_S|FP_S, 0, M3D, 0),
    instdes("recip2.d", ['D','S','T'], 0x4620001c, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, M3D, 0),
    instdes("recip2.ps", ['D','S','T'], 0x46c0001c, 0xffe0003f, WR_D|RD_S|RD_T|FP_S, 0, M3D, 0),
    instdes("recip2.s", ['D','S','T'], 0x4600001c, 0xffe0003f, WR_D|RD_S|RD_T|FP_S, 0, M3D, 0),
    instdes("rem", ['z','s','t'], 0x0000001a, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("rem", ['d','v','t'], 0, M_REM_3, INSN_MACRO, 0, I1, 0),
    instdes("rem", ['d','v','I'], 0, M_REM_3I, INSN_MACRO, 0, I1, 0),
    instdes("remu", ['z','s','t'], 0x0000001b, 0xfc00ffff, RD_s|RD_t|WR_HILO, 0, I1, 0),
    instdes("remu", ['d','v','t'], 0, M_REMU_3, INSN_MACRO, 0, I1, 0),
    instdes("remu", ['d','v','I'], 0, M_REMU_3I, INSN_MACRO, 0, I1, 0),
    instdes("rdhwr", ['t','K'], 0x7c00003b, 0xffe007ff, WR_t, 0, I33, 0),
    instdes("rdpgpr", ['d','w'], 0x41400000, 0xffe007ff, WR_d, 0, I33, 0),
    instdes("rfe", [], 0x42000010, 0xffffffff, 0, 0, I1|T3, 0),
    instdes("rnas.qh", ['X','Q'], 0x78200025, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX, 0),
    instdes("rnau.ob", ['X','Q'], 0x78000021, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX|SB1, 0),
    instdes("rnau.qh", ['X','Q'], 0x78200021, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX, 0),
    instdes("rnes.qh", ['X','Q'], 0x78200026, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX, 0),
    instdes("rneu.ob", ['X','Q'], 0x78000022, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX|SB1, 0),
    instdes("rneu.qh", ['X','Q'], 0x78200022, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX, 0),
    instdes("rol", ['d','v','t'], 0, M_ROL, INSN_MACRO, 0, I1, 0),
    instdes("rol", ['d','v','I'], 0, M_ROL_I, INSN_MACRO, 0, I1, 0),
    instdes("ror", ['d','v','t'], 0, M_ROR, INSN_MACRO, 0, I1, 0),
    instdes("ror", ['d','v','I'], 0, M_ROR_I, INSN_MACRO, 0, I1, 0),
    instdes("ror", ['d','w','<'], 0x00200002, 0xffe0003f, WR_d|RD_t, 0, N5|I33|SMT, 0),
    instdes("rorv", ['d','t','s'], 0x00000046, 0xfc0007ff, RD_t|RD_s|WR_d, 0, N5|I33|SMT, 0),
    instdes("rotl", ['d','v','t'], 0, M_ROL, INSN_MACRO, 0, I33|SMT, 0),
    instdes("rotl", ['d','v','I'], 0, M_ROL_I, INSN_MACRO, 0, I33|SMT, 0),
    instdes("rotr", ['d','v','t'], 0, M_ROR, INSN_MACRO, 0, I33|SMT, 0),
    instdes("rotr", ['d','v','I'], 0, M_ROR_I, INSN_MACRO, 0, I33|SMT, 0),
    instdes("rotrv", ['d','t','s'], 0x00000046, 0xfc0007ff, RD_t|RD_s|WR_d, 0, I33|SMT, 0),
    instdes("round.l.d", ['D','S'], 0x46200008, 0xffff003f, WR_D|RD_S|FP_D, 0, I3_33, 0),
    instdes("round.l.s", ['D','S'], 0x46000008, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I3_33, 0),
    instdes("round.w.d", ['D','S'], 0x4620000c, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I2, 0),
    instdes("round.w.s", ['D','S'], 0x4600000c, 0xffff003f, WR_D|RD_S|FP_S, 0, I2, 0),
    instdes("rsqrt.d", ['D','S'], 0x46200016, 0xffff003f, WR_D|RD_S|FP_D, 0, I4_33, 0),
    instdes("rsqrt.ps", ['D','S'], 0x46c00016, 0xffff003f, WR_D|RD_S|FP_D, 0, SB1, 0),
    instdes("rsqrt.s", ['D','S'], 0x46000016, 0xffff003f, WR_D|RD_S|FP_S, 0, I4_33, 0),
    instdes("rsqrt1.d", ['D','S'], 0x4620001e, 0xffff003f, WR_D|RD_S|FP_D, 0, M3D, 0),
    instdes("rsqrt1.ps", ['D','S'], 0x46c0001e, 0xffff003f, WR_D|RD_S|FP_S, 0, M3D, 0),
    instdes("rsqrt1.s", ['D','S'], 0x4600001e, 0xffff003f, WR_D|RD_S|FP_S, 0, M3D, 0),
    instdes("rsqrt2.d", ['D','S','T'], 0x4620001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, M3D, 0),
    instdes("rsqrt2.ps", ['D','S','T'], 0x46c0001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_S, 0, M3D, 0),
    instdes("rsqrt2.s", ['D','S','T'], 0x4600001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_S, 0, M3D, 0),
    instdes("rzs.qh", ['X','Q'], 0x78200024, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX, 0),
    instdes("rzu.ob", ['X','Q'], 0x78000020, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX|SB1, 0),
    instdes("rzu.ob", ['D','k'], 0x4bc00020, 0xffe0f83f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("rzu.qh", ['X','Q'], 0x78200020, 0xfc20f83f, WR_D|RD_T|FP_D, RD_MACC, MX, 0),
    instdes("saa", ['t','o(b)'], 0, M_SAA_OB, INSN_MACRO, 0, IOCTP, 0),
    instdes("saa", ['t','A(b)'], 0, M_SAA_AB, INSN_MACRO, 0, IOCTP, 0),
    instdes("saa", ['t','(b)'], 0x70000018, 0xfc00ffff, SM|RD_t|RD_b, 0, IOCTP, 0),
    instdes("saad", ['t','o(b)'], 0, M_SAAD_OB, INSN_MACRO, 0, IOCTP, 0),
    instdes("saad", ['t','A(b)'], 0, M_SAAD_AB, INSN_MACRO, 0, IOCTP, 0),
    instdes("saad", ['t','(b)'], 0x70000019, 0xfc00ffff, SM|RD_t|RD_b, 0, IOCTP, 0),
    instdes("sb", ['t','o(b)'], 0xa0000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("sb", ['t','A(b)'], 0, M_SB_AB, INSN_MACRO, 0, I1, 0),
    instdes("sc", ['t','o(b)'], 0xe0000000, 0xfc000000, SM|RD_t|WR_t|RD_b, 0, I2, 0),
    instdes("sc", ['t','A(b)'], 0, M_SC_AB, INSN_MACRO, 0, I2, 0),
    instdes("scd", ['t','o(b)'], 0xf0000000, 0xfc000000, SM|RD_t|WR_t|RD_b, 0, I3, 0),
    instdes("scd", ['t','A(b)'], 0, M_SCD_AB, INSN_MACRO, 0, I3, 0),
    instdes("sd", ['t','o(b)'], 0, M_SD_OB, INSN_MACRO, 0, I1, 0),
    instdes("sd", ['t','o(b)'], 0xfc000000, 0xfc000000, SM|RD_t|RD_b, 0, I3, 0),
    instdes("sd", ['t','A(b)'], 0, M_SD_AB, INSN_MACRO, 0, I1, 0),
    instdes("sdbbp", [], 0x0000000e, 0xffffffff, TRAP, 0, G2, 0),
    instdes("sdbbp", ['c'], 0x0000000e, 0xfc00ffff, TRAP, 0, G2, 0),
    instdes("sdbbp", ['c','q'], 0x0000000e, 0xfc00003f, TRAP, 0, G2, 0),
    instdes("sdbbp", [], 0x7000003f, 0xffffffff, TRAP, 0, I32, 0),
    instdes("sdbbp", ['B'], 0x7000003f, 0xfc00003f, TRAP, 0, I32, 0),
    instdes("sdc1", ['T','o(b)'], 0xf4000000, 0xfc000000, SM|RD_T|RD_b|FP_D, 0, I2, 0),
    instdes("sdc1", ['E','o(b)'], 0xf4000000, 0xfc000000, SM|RD_T|RD_b|FP_D, 0, I2, 0),
    instdes("sdc1", ['T','A(b)'], 0, M_SDC1_AB, INSN_MACRO, INSN2_M_FP_D, I2, 0),
    instdes("sdc1", ['E','A(b)'], 0, M_SDC1_AB, INSN_MACRO, INSN2_M_FP_D, I2, 0),
    instdes("sdc2", ['E','o(b)'], 0xf8000000, 0xfc000000, SM|RD_C2|RD_b, 0, I2, IOCT|IOCTP|IOCT2),
    instdes("sdc2", ['E','A(b)'], 0, M_SDC2_AB, INSN_MACRO, 0, I2, IOCT|IOCTP|IOCT2),
    instdes("sdc3", ['E','o(b)'], 0xfc000000, 0xfc000000, SM|RD_C3|RD_b, 0, I2, IOCT|IOCTP|IOCT2),
    instdes("sdc3", ['E','A(b)'], 0, M_SDC3_AB, INSN_MACRO, 0, I2, IOCT|IOCTP|IOCT2),
    instdes("s.d", ['T','o(b)'], 0xf4000000, 0xfc000000, SM|RD_T|RD_b|FP_D, 0, I2, 0),
    instdes("s.d", ['T','o(b)'], 0, M_S_DOB, INSN_MACRO, INSN2_M_FP_D, I1, 0),
    instdes("s.d", ['T','A(b)'], 0, M_S_DAB, INSN_MACRO, INSN2_M_FP_D, I1, 0),
    instdes("sdl", ['t','o(b)'], 0xb0000000, 0xfc000000, SM|RD_t|RD_b, 0, I3, 0),
    instdes("sdl", ['t','A(b)'], 0, M_SDL_AB, INSN_MACRO, 0, I3, 0),
    instdes("sdr", ['t','o(b)'], 0xb4000000, 0xfc000000, SM|RD_t|RD_b, 0, I3, 0),
    instdes("sdr", ['t','A(b)'], 0, M_SDR_AB, INSN_MACRO, 0, I3, 0),
    instdes("sdxc1", ['S','t(b)'], 0x4c000009, 0xfc0007ff, SM|RD_S|RD_t|RD_b|FP_D, 0, I4_33, 0),
    instdes("seb", ['d','w'], 0x7c000420, 0xffe007ff, WR_d|RD_t, 0, I33, 0),
    instdes("seh", ['d','w'], 0x7c000620, 0xffe007ff, WR_d|RD_t, 0, I33, 0),
    instdes("selsl", ['d','v','t'], 0x00000005, 0xfc0007ff, WR_d|RD_s|RD_t, 0, L1, 0),
    instdes("selsr", ['d','v','t'], 0x00000001, 0xfc0007ff, WR_d|RD_s|RD_t, 0, L1, 0),
    instdes("seq", ['d','v','t'], 0x7000002a, 0xfc0007ff, WR_d|RD_s|RD_t, 0, IOCT, 0),
    instdes("seq", ['d','v','t'], 0, M_SEQ, INSN_MACRO, 0, I1, 0),
    instdes("seq", ['d','v','I'], 0, M_SEQ_I, INSN_MACRO, 0, I1, 0),
    instdes("seq", ['S','T'], 0x46a00032, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("seq", ['S','T'], 0x4ba0000c, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2F|IL3A, 0),
    instdes("seqi", ['t','r','+Q'], 0x7000002e, 0xfc00003f, WR_t|RD_s, 0, IOCT, 0),
    instdes("sge", ['d','v','t'], 0, M_SGE, INSN_MACRO, 0, I1, 0),
    instdes("sge", ['d','v','I'], 0, M_SGE_I, INSN_MACRO, 0, I1, 0),
    instdes("sgeu", ['d','v','t'], 0, M_SGEU, INSN_MACRO, 0, I1, 0),
    instdes("sgeu", ['d','v','I'], 0, M_SGEU_I, INSN_MACRO, 0, I1, 0),
    instdes("sgt", ['d','v','t'], 0, M_SGT, INSN_MACRO, 0, I1, 0),
    instdes("sgt", ['d','v','I'], 0, M_SGT_I, INSN_MACRO, 0, I1, 0),
    instdes("sgtu", ['d','v','t'], 0, M_SGTU, INSN_MACRO, 0, I1, 0),
    instdes("sgtu", ['d','v','I'], 0, M_SGTU_I, INSN_MACRO, 0, I1, 0),
    instdes("sh", ['t','o(b)'], 0xa4000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("sh", ['t','A(b)'], 0, M_SH_AB, INSN_MACRO, 0, I1, 0),
    instdes("shfl.bfla.qh", ['X','Y','Z'], 0x7a20001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("shfl.mixh.ob", ['X','Y','Z'], 0x7980001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("shfl.mixh.ob", ['D','S','T'], 0x4980001f, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("shfl.mixh.qh", ['X','Y','Z'], 0x7820001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("shfl.mixl.ob", ['X','Y','Z'], 0x79c0001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("shfl.mixl.ob", ['D','S','T'], 0x49c0001f, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("shfl.mixl.qh", ['X','Y','Z'], 0x78a0001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("shfl.pach.ob", ['X','Y','Z'], 0x7900001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("shfl.pach.ob", ['D','S','T'], 0x4900001f, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("shfl.pach.qh", ['X','Y','Z'], 0x7920001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("shfl.pacl.ob", ['D','S','T'], 0x4940001f, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("shfl.repa.qh", ['X','Y','Z'], 0x7b20001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("shfl.repb.qh", ['X','Y','Z'], 0x7ba0001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("shfl.upsl.ob", ['X','Y','Z'], 0x78c0001f, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("sle", ['d','v','t'], 0, M_SLE, INSN_MACRO, 0, I1, 0),
    instdes("sle", ['d','v','I'], 0, M_SLE_I, INSN_MACRO, 0, I1, 0),
    instdes("sle", ['S','T'], 0x46a0003e, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("sle", ['S','T'], 0x4ba0000e, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2F|IL3A, 0),
    instdes("sleu", ['d','v','t'], 0, M_SLEU, INSN_MACRO, 0, I1, 0),
    instdes("sleu", ['d','v','I'], 0, M_SLEU_I, INSN_MACRO, 0, I1, 0),
    instdes("sleu", ['S','T'], 0x4680003e, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("sleu", ['S','T'], 0x4b80000e, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2F|IL3A, 0),
    instdes("sllv", ['d','t','s'], 0x00000004, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sll", ['d','w','s'], 0x00000004, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sll", ['d','w','<'], 0x00000000, 0xffe0003f, WR_d|RD_t, 0, I1, 0),
    instdes("sll", ['D','S','T'], 0x45800002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("sll", ['D','S','T'], 0x4b00000e, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("sll.ob", ['X','Y','Q'], 0x78000010, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("sll.ob", ['D','S','T[e]'], 0x48000010, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("sll.ob", ['D','S','k'], 0x4bc00010, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("sll.qh", ['X','Y','Q'], 0x78200010, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("slt", ['d','v','t'], 0x0000002a, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("slt", ['d','v','I'], 0, M_SLT_I, INSN_MACRO, 0, I1, 0),
    instdes("slt", ['S','T'], 0x46a0003c, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("slt", ['S','T'], 0x4ba0000d, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2F|IL3A, 0),
    instdes("slti", ['t','r','j'], 0x28000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("sltiu", ['t','r','j'], 0x2c000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("sltu", ['d','v','t'], 0x0000002b, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("sltu", ['d','v','I'], 0, M_SLTU_I, INSN_MACRO, 0, I1, 0),
    instdes("sltu", ['S','T'], 0x4680003c, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("sltu", ['S','T'], 0x4b80000d, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2F|IL3A, 0),
    instdes("sne", ['d','v','t'], 0x7000002b, 0xfc0007ff, WR_d|RD_s|RD_t, 0, IOCT, 0),
    instdes("sne", ['d','v','t'], 0, M_SNE, INSN_MACRO, 0, I1, 0),
    instdes("sne", ['d','v','I'], 0, M_SNE_I, INSN_MACRO, 0, I1, 0),
    instdes("snei", ['t','r','+Q'], 0x7000002f, 0xfc00003f, WR_t|RD_s, 0, IOCT, 0),
    instdes("sqrt.d", ['D','S'], 0x46200004, 0xffff003f, WR_D|RD_S|FP_D, 0, I2, 0),
    instdes("sqrt.s", ['D','S'], 0x46000004, 0xffff003f, WR_D|RD_S|FP_S, 0, I2, 0),
    instdes("sqrt.ps", ['D','S'], 0x46c00004, 0xffff003f, WR_D|RD_S|FP_D, 0, SB1, 0),
    instdes("srav", ['d','t','s'], 0x00000007, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sra", ['d','w','s'], 0x00000007, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("sra", ['d','w','<'], 0x00000003, 0xffe0003f, WR_d|RD_t, 0, I1, 0),
    instdes("sra", ['D','S','T'], 0x45c00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("sra", ['D','S','T'], 0x4b40000f, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("sra.qh", ['X','Y','Q'], 0x78200013, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("srlv", ['d','t','s'], 0x00000006, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("srl", ['d','w','s'], 0x00000006, 0xfc0007ff, WR_d|RD_t|RD_s, 0, I1, 0),
    instdes("srl", ['d','w','<'], 0x00000002, 0xffe0003f, WR_d|RD_t, 0, I1, 0),
    instdes("srl", ['D','S','T'], 0x45800003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("srl", ['D','S','T'], 0x4b00000f, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("srl.ob", ['X','Y','Q'], 0x78000012, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("srl.ob", ['D','S','T[e]'], 0x48000012, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("srl.ob", ['D','S','k'], 0x4bc00012, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("srl.qh", ['X','Y','Q'], 0x78200012, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("standby", [], 0x42000021, 0xffffffff, 0, 0, V1, 0),
    instdes("sub", ['d','v','t'], 0x00000022, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("sub", ['d','v','I'], 0, M_SUB_I, INSN_MACRO, 0, I1, 0),
    instdes("sub", ['D','S','T'], 0x45c00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2E, 0),
    instdes("sub", ['D','S','T'], 0x4b40000d, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2F|IL3A, 0),
    instdes("sub.d", ['D','V','T'], 0x46200001, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I1, 0),
    instdes("sub.s", ['D','V','T'], 0x46000001, 0xffe0003f, WR_D|RD_S|RD_T|FP_S, 0, I1, 0),
    instdes("sub.ob", ['X','Y','Q'], 0x7800000a, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("sub.ob", ['D','S','T'], 0x4ac0000a, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("sub.ob", ['D','S','T[e]'], 0x4800000a, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("sub.ob", ['D','S','k'], 0x4bc0000a, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("sub.ps", ['D','V','T'], 0x46c00001, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, I5_33|IL2F, 0),
    instdes("sub.ps", ['D','V','T'], 0x45600001, 0xffe0003f, WR_D|RD_S|RD_T|FP_D, 0, IL2E, 0),
    instdes("sub.qh", ['X','Y','Q'], 0x7820000a, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("suba.ob", ['Y','Q'], 0x78000036, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("suba.qh", ['Y','Q'], 0x78200036, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("subl.ob", ['Y','Q'], 0x78000436, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("subl.qh", ['Y','Q'], 0x78200436, 0xfc2007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("subu", ['d','v','t'], 0x00000023, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("subu", ['d','v','I'], 0, M_SUBU_I, INSN_MACRO, 0, I1, 0),
    instdes("subu", ['D','S','T'], 0x45800001, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2E, 0),
    instdes("subu", ['D','S','T'], 0x4b00000d, 0xffe0003f, RD_S|RD_T|WR_D|FP_S, 0, IL2F|IL3A, 0),
    instdes("suspend", [], 0x42000022, 0xffffffff, 0, 0, V1, 0),
    instdes("suxc1", ['S','t(b)'], 0x4c00000d, 0xfc0007ff, SM|RD_S|RD_t|RD_b|FP_D, 0, I5_33|N55, 0),
    instdes("sw", ['t','o(b)'], 0xac000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("sw", ['t','A(b)'], 0, M_SW_AB, INSN_MACRO, 0, I1, 0),
    instdes("swapw", ['t','b'], 0x70000014, 0xfc00ffff, SM|RD_t|WR_t|RD_b, 0, XLR, 0),
    instdes("swapwu", ['t','b'], 0x70000015, 0xfc00ffff, SM|RD_t|WR_t|RD_b, 0, XLR, 0),
    instdes("swapd", ['t','b'], 0x70000016, 0xfc00ffff, SM|RD_t|WR_t|RD_b, 0, XLR, 0),
    instdes("swc0", ['E','o(b)'], 0xe0000000, 0xfc000000, SM|RD_C0|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swc0", ['E','A(b)'], 0, M_SWC0_AB, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swc1", ['T','o(b)'], 0xe4000000, 0xfc000000, SM|RD_T|RD_b|FP_S, 0, I1, 0),
    instdes("swc1", ['E','o(b)'], 0xe4000000, 0xfc000000, SM|RD_T|RD_b|FP_S, 0, I1, 0),
    instdes("swc1", ['T','A(b)'], 0, M_SWC1_AB, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("swc1", ['E','A(b)'], 0, M_SWC1_AB, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("s.s", ['T','o(b)'], 0xe4000000, 0xfc000000, SM|RD_T|RD_b|FP_S, 0, I1, 0),
    instdes("s.s", ['T','A(b)'], 0, M_SWC1_AB, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("swc2", ['E','o(b)'], 0xe8000000, 0xfc000000, SM|RD_C2|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swc2", ['E','A(b)'], 0, M_SWC2_AB, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swc3", ['E','o(b)'], 0xec000000, 0xfc000000, SM|RD_C3|RD_b, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swc3", ['E','A(b)'], 0, M_SWC3_AB, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("swl", ['t','o(b)'], 0xa8000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("swl", ['t','A(b)'], 0, M_SWL_AB, INSN_MACRO, 0, I1, 0),
    instdes("scache", ['t','o(b)'], 0xa8000000, 0xfc000000, RD_t|RD_b, 0, I2, 0),
    instdes("scache", ['t','A(b)'], 0, M_SWL_AB, INSN_MACRO, 0, I2, 0),
    instdes("swr", ['t','o(b)'], 0xb8000000, 0xfc000000, SM|RD_t|RD_b, 0, I1, 0),
    instdes("swr", ['t','A(b)'], 0, M_SWR_AB, INSN_MACRO, 0, I1, 0),
    instdes("invalidate", ['t','o(b)'], 0xb8000000, 0xfc000000, RD_t|RD_b, 0, I2, 0),
    instdes("invalidate", ['t','A(b)'], 0, M_SWR_AB, INSN_MACRO, 0, I2, 0),
    instdes("swxc1", ['S','t(b)'], 0x4c000008, 0xfc0007ff, SM|RD_S|RD_t|RD_b|FP_S, 0, I4_33, 0),
    instdes("synciobdma", [], 0x0000008f, 0xffffffff, NODS, 0, IOCT, 0),
    instdes("syncs", [], 0x0000018f, 0xffffffff, NODS, 0, IOCT, 0),
    instdes("syncw", [], 0x0000010f, 0xffffffff, NODS, 0, IOCT, 0),
    instdes("syncws", [], 0x0000014f, 0xffffffff, NODS, 0, IOCT, 0),
    instdes("sync_acquire", [], 0x0000044f, 0xffffffff, NODS, 0, I33, 0),
    instdes("sync_mb", [], 0x0000040f, 0xffffffff, NODS, 0, I33, 0),
    instdes("sync_release", [], 0x0000048f, 0xffffffff, NODS, 0, I33, 0),
    instdes("sync_rmb", [], 0x000004cf, 0xffffffff, NODS, 0, I33, 0),
    instdes("sync_wmb", [], 0x0000010f, 0xffffffff, NODS, 0, I33, 0),
    instdes("sync", [], 0x0000000f, 0xffffffff, NODS, 0, I2|G1, 0),
    instdes("sync", ['1'], 0x0000000f, 0xfffff83f, NODS, 0, I32, 0),
    instdes("sync.p", [], 0x0000040f, 0xffffffff, NODS, 0, I2, 0),
    instdes("sync.l", [], 0x0000000f, 0xffffffff, NODS, 0, I2, 0),
    instdes("synci", ['o(b)'], 0x041f0000, 0xfc1f0000, SM|RD_b, 0, I33, 0),
    instdes("syscall", [], 0x0000000c, 0xffffffff, TRAP, 0, I1, 0),
    instdes("syscall", ['B'], 0x0000000c, 0xfc00003f, TRAP, 0, I1, 0),
    instdes("teqi", ['s','j'], 0x040c0000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("teq", ['s','t'], 0x00000034, 0xfc00ffff, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("teq", ['s','t','q'], 0x00000034, 0xfc00003f, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("teq", ['s','j'], 0x040c0000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("teq", ['s','I'], 0, M_TEQ_I, INSN_MACRO, 0, I2, 0),
    instdes("tgei", ['s','j'], 0x04080000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tge", ['s','t'], 0x00000030, 0xfc00ffff, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tge", ['s','t','q'], 0x00000030, 0xfc00003f, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tge", ['s','j'], 0x04080000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tge", ['s','I'], 0, M_TGE_I, INSN_MACRO, 0, I2, 0),
    instdes("tgeiu", ['s','j'], 0x04090000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tgeu", ['s','t'], 0x00000031, 0xfc00ffff, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tgeu", ['s','t','q'], 0x00000031, 0xfc00003f, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tgeu", ['s','j'], 0x04090000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tgeu", ['s','I'], 0, M_TGEU_I, INSN_MACRO, 0, I2, 0),
    instdes("tlbp", [], 0x42000008, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("tlbr", [], 0x42000001, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("tlbwi", [], 0x42000002, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("tlbwr", [], 0x42000006, 0xffffffff, INSN_TLB, 0, I1, 0),
    instdes("tlti", ['s','j'], 0x040a0000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tlt", ['s','t'], 0x00000032, 0xfc00ffff, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tlt", ['s','t','q'], 0x00000032, 0xfc00003f, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tlt", ['s','j'], 0x040a0000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tlt", ['s','I'], 0, M_TLT_I, INSN_MACRO, 0, I2, 0),
    instdes("tltiu", ['s','j'], 0x040b0000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tltu", ['s','t'], 0x00000033, 0xfc00ffff, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tltu", ['s','t','q'], 0x00000033, 0xfc00003f, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tltu", ['s','j'], 0x040b0000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tltu", ['s','I'], 0, M_TLTU_I, INSN_MACRO, 0, I2, 0),
    instdes("tnei", ['s','j'], 0x040e0000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tne", ['s','t'], 0x00000036, 0xfc00ffff, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tne", ['s','t','q'], 0x00000036, 0xfc00003f, RD_s|RD_t|TRAP, 0, I2, 0),
    instdes("tne", ['s','j'], 0x040e0000, 0xfc1f0000, RD_s|TRAP, 0, I2, 0),
    instdes("tne", ['s','I'], 0, M_TNE_I, INSN_MACRO, 0, I2, 0),
    instdes("trunc.l.d", ['D','S'], 0x46200009, 0xffff003f, WR_D|RD_S|FP_D, 0, I3_33, 0),
    instdes("trunc.l.s", ['D','S'], 0x46000009, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I3_33, 0),
    instdes("trunc.w.d", ['D','S'], 0x4620000d, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I2, 0),
    instdes("trunc.w.d", ['D','S','x'], 0x4620000d, 0xffff003f, WR_D|RD_S|FP_S|FP_D, 0, I2, 0),
    instdes("trunc.w.d", ['D','S','t'], 0, M_TRUNCWD, INSN_MACRO, INSN2_M_FP_S|INSN2_M_FP_D, I1, 0),
    instdes("trunc.w.s", ['D','S'], 0x4600000d, 0xffff003f, WR_D|RD_S|FP_S, 0, I2, 0),
    instdes("trunc.w.s", ['D','S','x'], 0x4600000d, 0xffff003f, WR_D|RD_S|FP_S, 0, I2, 0),
    instdes("trunc.w.s", ['D','S','t'], 0, M_TRUNCWS, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("uld", ['t','o(b)'], 0, M_ULD, INSN_MACRO, 0, I3, 0),
    instdes("uld", ['t','A(b)'], 0, M_ULD_A, INSN_MACRO, 0, I3, 0),
    instdes("ulh", ['t','o(b)'], 0, M_ULH, INSN_MACRO, 0, I1, 0),
    instdes("ulh", ['t','A(b)'], 0, M_ULH_A, INSN_MACRO, 0, I1, 0),
    instdes("ulhu", ['t','o(b)'], 0, M_ULHU, INSN_MACRO, 0, I1, 0),
    instdes("ulhu", ['t','A(b)'], 0, M_ULHU_A, INSN_MACRO, 0, I1, 0),
    instdes("ulw", ['t','o(b)'], 0, M_ULW, INSN_MACRO, 0, I1, 0),
    instdes("ulw", ['t','A(b)'], 0, M_ULW_A, INSN_MACRO, 0, I1, 0),
    instdes("usd", ['t','o(b)'], 0, M_USD, INSN_MACRO, 0, I3, 0),
    instdes("usd", ['t','A(b)'], 0, M_USD_A, INSN_MACRO, 0, I3, 0),
    instdes("ush", ['t','o(b)'], 0, M_USH, INSN_MACRO, 0, I1, 0),
    instdes("ush", ['t','A(b)'], 0, M_USH_A, INSN_MACRO, 0, I1, 0),
    instdes("usw", ['t','o(b)'], 0, M_USW, INSN_MACRO, 0, I1, 0),
    instdes("usw", ['t','A(b)'], 0, M_USW_A, INSN_MACRO, 0, I1, 0),
    instdes("v3mulu", ['d','v','t'], 0x70000011, 0xfc0007ff, WR_d|RD_s|RD_t, 0, IOCT, 0),
    instdes("vmm0", ['d','v','t'], 0x70000010, 0xfc0007ff, WR_d|RD_s|RD_t, 0, IOCT, 0),
    instdes("vmulu", ['d','v','t'], 0x7000000f, 0xfc0007ff, WR_d|RD_s|RD_t, 0, IOCT, 0),
    instdes("wach.ob", ['Y'], 0x7a00003e, 0xffff07ff, RD_S|FP_D, WR_MACC, MX|SB1, 0),
    instdes("wach.ob", ['S'], 0x4a00003e, 0xffff07ff, RD_S, 0, N54, 0),
    instdes("wach.qh", ['Y'], 0x7a20003e, 0xffff07ff, RD_S|FP_D, WR_MACC, MX, 0),
    instdes("wacl.ob", ['Y','Z'], 0x7800003e, 0xffe007ff, RD_S|RD_T|FP_D, WR_MACC, MX|SB1, 0),
    instdes("wacl.ob", ['S','T'], 0x4800003e, 0xffe007ff, RD_S|RD_T, 0, N54, 0),
    instdes("wacl.qh", ['Y','Z'], 0x7820003e, 0xffe007ff, RD_S|RD_T|FP_D, WR_MACC, MX, 0),
    instdes("wait", [], 0x42000020, 0xffffffff, NODS, 0, I3_32, 0),
    instdes("wait", ['J'], 0x42000020, 0xfe00003f, NODS, 0, I32|N55, 0),
    instdes("waiti", [], 0x42000020, 0xffffffff, NODS, 0, L1, 0),
    instdes("wrpgpr", ['d','w'], 0x41c00000, 0xffe007ff, RD_t, 0, I33, 0),
    instdes("wsbh", ['d','w'], 0x7c0000a0, 0xffe007ff, WR_d|RD_t, 0, I33, 0),
    instdes("xor", ['d','v','t'], 0x00000026, 0xfc0007ff, WR_d|RD_s|RD_t, 0, I1, 0),
    instdes("xor", ['t','r','I'], 0, M_XOR_I, INSN_MACRO, 0, I1, 0),
    instdes("xor", ['D','S','T'], 0x47800002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("xor", ['D','S','T'], 0x4b800002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("xor.ob", ['X','Y','Q'], 0x7800000d, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX|SB1, 0),
    instdes("xor.ob", ['D','S','T'], 0x4ac0000d, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("xor.ob", ['D','S','T[e]'], 0x4800000d, 0xfe20003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("xor.ob", ['D','S','k'], 0x4bc0000d, 0xffe0003f, WR_D|RD_S|RD_T, 0, N54, 0),
    instdes("xor.qh", ['X','Y','Q'], 0x7820000d, 0xfc20003f, WR_D|RD_S|RD_T|FP_D, 0, MX, 0),
    instdes("xori", ['t','r','i'], 0x38000000, 0xfc000000, WR_t|RD_s, 0, I1, 0),
    instdes("yield", ['s'], 0x7c000009, 0xfc1fffff, NODS|RD_s, 0, MT32, 0),
    instdes("yield", ['d','s'], 0x7c000009, 0xfc1f07ff, NODS|WR_d|RD_s, 0, MT32, 0),
    instdes("zcb", ['(b)'], 0x7000071f, 0xfc1fffff, SM|RD_b, 0, IOCT2, 0),
    instdes("zcbt", ['(b)'], 0x7000075f, 0xfc1fffff, SM|RD_b, 0, IOCT2, 0),
    instdes("udi0", ['s','t','d','+1'], 0x70000010, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi0", ['s','t','+2'], 0x70000010, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi0", ['s','+3'], 0x70000010, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi0", ['+4'], 0x70000010, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi1", ['s','t','d','+1'], 0x70000011, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi1", ['s','t','+2'], 0x70000011, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi1", ['s','+3'], 0x70000011, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi1", ['+4'], 0x70000011, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi2", ['s','t','d','+1'], 0x70000012, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi2", ['s','t','+2'], 0x70000012, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi2", ['s','+3'], 0x70000012, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi2", ['+4'], 0x70000012, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi3", ['s','t','d','+1'], 0x70000013, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi3", ['s','t','+2'], 0x70000013, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi3", ['s','+3'], 0x70000013, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi3", ['+4'], 0x70000013, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi4", ['s','t','d','+1'], 0x70000014, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi4", ['s','t','+2'], 0x70000014, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi4", ['s','+3'], 0x70000014, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi4", ['+4'], 0x70000014, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi5", ['s','t','d','+1'], 0x70000015, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi5", ['s','t','+2'], 0x70000015, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi5", ['s','+3'], 0x70000015, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi5", ['+4'], 0x70000015, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi6", ['s','t','d','+1'], 0x70000016, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi6", ['s','t','+2'], 0x70000016, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi6", ['s','+3'], 0x70000016, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi6", ['+4'], 0x70000016, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi7", ['s','t','d','+1'], 0x70000017, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi7", ['s','t','+2'], 0x70000017, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi7", ['s','+3'], 0x70000017, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi7", ['+4'], 0x70000017, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi8", ['s','t','d','+1'], 0x70000018, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi8", ['s','t','+2'], 0x70000018, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi8", ['s','+3'], 0x70000018, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi8", ['+4'], 0x70000018, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi9", ['s','t','d','+1'], 0x70000019, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi9", ['s','t','+2'], 0x70000019, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi9", ['s','+3'], 0x70000019, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi9", ['+4'], 0x70000019, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi10", ['s','t','d','+1'], 0x7000001a, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi10", ['s','t','+2'], 0x7000001a, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi10", ['s','+3'], 0x7000001a, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi10", ['+4'], 0x7000001a, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi11", ['s','t','d','+1'], 0x7000001b, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi11", ['s','t','+2'], 0x7000001b, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi11", ['s','+3'], 0x7000001b, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi11", ['+4'], 0x7000001b, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi12", ['s','t','d','+1'], 0x7000001c, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi12", ['s','t','+2'], 0x7000001c, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi12", ['s','+3'], 0x7000001c, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi12", ['+4'], 0x7000001c, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi13", ['s','t','d','+1'], 0x7000001d, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi13", ['s','t','+2'], 0x7000001d, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi13", ['s','+3'], 0x7000001d, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi13", ['+4'], 0x7000001d, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi14", ['s','t','d','+1'], 0x7000001e, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi14", ['s','t','+2'], 0x7000001e, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi14", ['s','+3'], 0x7000001e, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi14", ['+4'], 0x7000001e, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi15", ['s','t','d','+1'], 0x7000001f, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi15", ['s','t','+2'], 0x7000001f, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi15", ['s','+3'], 0x7000001f, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("udi15", ['+4'], 0x7000001f, 0xfc00003f, WR_d|RD_s|RD_t, 0, I33, 0),
    instdes("bc2f", ['p'], 0x49000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc2f", ['N','p'], 0x49000000, 0xffe30000, CBD|RD_CC, 0, I32, IOCT|IOCTP|IOCT2),
    instdes("bc2fl", ['p'], 0x49020000, 0xffff0000, CBL|RD_CC, 0, I2|T3, IOCT|IOCTP|IOCT2),
    instdes("bc2fl", ['N','p'], 0x49020000, 0xffe30000, CBL|RD_CC, 0, I32, IOCT|IOCTP|IOCT2),
    instdes("bc2t", ['p'], 0x49010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc2t", ['N','p'], 0x49010000, 0xffe30000, CBD|RD_CC, 0, I32, IOCT|IOCTP|IOCT2),
    instdes("bc2tl", ['p'], 0x49030000, 0xffff0000, CBL|RD_CC, 0, I2|T3, IOCT|IOCTP|IOCT2),
    instdes("bc2tl", ['N','p'], 0x49030000, 0xffe30000, CBL|RD_CC, 0, I32, IOCT|IOCTP|IOCT2),
    instdes("cfc2", ['t','G'], 0x48400000, 0xffe007ff, LCD|WR_t|RD_C2, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("ctc2", ['t','G'], 0x48c00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("dmfc2", ['t','i'], 0x48200000, 0xffe00000, LCD|WR_t|RD_C2, 0, IOCT, 0),
    instdes("dmfc2", ['t','G'], 0x48200000, 0xffe007ff, LCD|WR_t|RD_C2, 0, I3, IOCT|IOCTP|IOCT2),
    instdes("dmfc2", ['t','G','H'], 0x48200000, 0xffe007f8, LCD|WR_t|RD_C2, 0, I64, IOCT|IOCTP|IOCT2),
    instdes("dmtc2", ['t','i'], 0x48a00000, 0xffe00000, COD|RD_t|WR_C2|WR_CC, 0, IOCT, 0),
    instdes("dmtc2", ['t','G'], 0x48a00000, 0xffe007ff, COD|RD_t|WR_C2|WR_CC, 0, I3, IOCT|IOCTP|IOCT2),
    instdes("dmtc2", ['t','G','H'], 0x48a00000, 0xffe007f8, COD|RD_t|WR_C2|WR_CC, 0, I64, IOCT|IOCTP|IOCT2),
    instdes("mfc2", ['t','G'], 0x48000000, 0xffe007ff, LCD|WR_t|RD_C2, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("mfc2", ['t','G','H'], 0x48000000, 0xffe007f8, LCD|WR_t|RD_C2, 0, I32, IOCT|IOCTP|IOCT2),
    instdes("mfhc2", ['t','G'], 0x48600000, 0xffe007ff, LCD|WR_t|RD_C2, 0, I33, IOCT|IOCTP|IOCT2),
    instdes("mfhc2", ['t','G','H'], 0x48600000, 0xffe007f8, LCD|WR_t|RD_C2, 0, I33, IOCT|IOCTP|IOCT2),
    instdes("mfhc2", ['t','i'], 0x48600000, 0xffe00000, LCD|WR_t|RD_C2, 0, I33, IOCT|IOCTP|IOCT2),
    instdes("mtc2", ['t','G'], 0x48800000, 0xffe007ff, COD|RD_t|WR_C2|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("mtc2", ['t','G','H'], 0x48800000, 0xffe007f8, COD|RD_t|WR_C2|WR_CC, 0, I32, IOCT|IOCTP|IOCT2),
    instdes("mthc2", ['t','G'], 0x48e00000, 0xffe007ff, COD|RD_t|WR_C2|WR_CC, 0, I33, IOCT|IOCTP|IOCT2),
    instdes("mthc2", ['t','G','H'], 0x48e00000, 0xffe007f8, COD|RD_t|WR_C2|WR_CC, 0, I33, IOCT|IOCTP|IOCT2),
    instdes("mthc2", ['t','i'], 0x48e00000, 0xffe00000, COD|RD_t|WR_C2|WR_CC, 0, I33, IOCT|IOCTP|IOCT2),
    instdes("bc3f", ['p'], 0x4d000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc3fl", ['p'], 0x4d020000, 0xffff0000, CBL|RD_CC, 0, I2|T3, IOCT|IOCTP|IOCT2),
    instdes("bc3t", ['p'], 0x4d010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc3tl", ['p'], 0x4d030000, 0xffff0000, CBL|RD_CC, 0, I2|T3, IOCT|IOCTP|IOCT2),
    instdes("cfc3", ['t','G'], 0x4c400000, 0xffe007ff, LCD|WR_t|RD_C3, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("ctc3", ['t','G'], 0x4cc00000, 0xffe007ff, COD|RD_t|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("dmfc3", ['t','G'], 0x4c200000, 0xffe007ff, LCD|WR_t|RD_C3, 0, I3, IOCT|IOCTP|IOCT2),
    instdes("dmtc3", ['t','G'], 0x4ca00000, 0xffe007ff, COD|RD_t|WR_C3|WR_CC, 0, I3, IOCT|IOCTP|IOCT2),
    instdes("mfc3", ['t','G'], 0x4c000000, 0xffe007ff, LCD|WR_t|RD_C3, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("mfc3", ['t','G','H'], 0x4c000000, 0xffe007f8, LCD|WR_t|RD_C3, 0, I32, IOCT|IOCTP|IOCT2),
    instdes("mtc3", ['t','G'], 0x4c800000, 0xffe007ff, COD|RD_t|WR_C3|WR_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("mtc3", ['t','G','H'], 0x4c800000, 0xffe007f8, COD|RD_t|WR_C3|WR_CC, 0, I32, IOCT|IOCTP|IOCT2),
    instdes("addciu", ['t','r','j'], 0x70000000, 0xfc000000, WR_t|RD_s, 0, L1, 0),
    instdes("absq_s.ph", ['d','t'], 0x7c000252, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("absq_s.pw", ['d','t'], 0x7c000456, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("absq_s.qh", ['d','t'], 0x7c000256, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("absq_s.w", ['d','t'], 0x7c000452, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("addq.ph", ['d','s','t'], 0x7c000290, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("addq.pw", ['d','s','t'], 0x7c000494, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("addq.qh", ['d','s','t'], 0x7c000294, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("addq_s.ph", ['d','s','t'], 0x7c000390, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("addq_s.pw", ['d','s','t'], 0x7c000594, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("addq_s.qh", ['d','s','t'], 0x7c000394, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("addq_s.w", ['d','s','t'], 0x7c000590, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("addsc", ['d','s','t'], 0x7c000410, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("addu.ob", ['d','s','t'], 0x7c000014, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("addu.qb", ['d','s','t'], 0x7c000010, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("addu_s.ob", ['d','s','t'], 0x7c000114, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("addu_s.qb", ['d','s','t'], 0x7c000110, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("addwc", ['d','s','t'], 0x7c000450, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("bitrev", ['d','t'], 0x7c0006d2, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("bposge32", ['p'], 0x041c0000, 0xffff0000, CBD, 0, D32, 0),
    instdes("bposge64", ['p'], 0x041d0000, 0xffff0000, CBD, 0, D64, 0),
    instdes("cmp.eq.ph", ['s','t'], 0x7c000211, 0xfc00ffff, RD_s|RD_t, 0, D32, 0),
    instdes("cmp.eq.pw", ['s','t'], 0x7c000415, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmp.eq.qh", ['s','t'], 0x7c000215, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmpgu.eq.ob", ['d','s','t'], 0x7c000115, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("cmpgu.eq.qb", ['d','s','t'], 0x7c000111, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("cmpgu.le.ob", ['d','s','t'], 0x7c000195, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("cmpgu.le.qb", ['d','s','t'], 0x7c000191, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("cmpgu.lt.ob", ['d','s','t'], 0x7c000155, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("cmpgu.lt.qb", ['d','s','t'], 0x7c000151, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("cmp.le.ph", ['s','t'], 0x7c000291, 0xfc00ffff, RD_s|RD_t, 0, D32, 0),
    instdes("cmp.le.pw", ['s','t'], 0x7c000495, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmp.le.qh", ['s','t'], 0x7c000295, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmp.lt.ph", ['s','t'], 0x7c000251, 0xfc00ffff, RD_s|RD_t, 0, D32, 0),
    instdes("cmp.lt.pw", ['s','t'], 0x7c000455, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmp.lt.qh", ['s','t'], 0x7c000255, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmpu.eq.ob", ['s','t'], 0x7c000015, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmpu.eq.qb", ['s','t'], 0x7c000011, 0xfc00ffff, RD_s|RD_t, 0, D32, 0),
    instdes("cmpu.le.ob", ['s','t'], 0x7c000095, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmpu.le.qb", ['s','t'], 0x7c000091, 0xfc00ffff, RD_s|RD_t, 0, D32, 0),
    instdes("cmpu.lt.ob", ['s','t'], 0x7c000055, 0xfc00ffff, RD_s|RD_t, 0, D64, 0),
    instdes("cmpu.lt.qb", ['s','t'], 0x7c000051, 0xfc00ffff, RD_s|RD_t, 0, D32, 0),
    instdes("dextpdp", ['t','7','6'], 0x7c0002bc, 0xfc00e7ff, WR_t|RD_a|DSP_VOLA, 0, D64, 0),
    instdes("dextpdpv", ['t','7','s'], 0x7c0002fc, 0xfc00e7ff, WR_t|RD_a|RD_s|DSP_VOLA, 0, D64, 0),
    instdes("dextp", ['t','7','6'], 0x7c0000bc, 0xfc00e7ff, WR_t|RD_a, 0, D64, 0),
    instdes("dextpv", ['t','7','s'], 0x7c0000fc, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D64, 0),
    instdes("dextr.l", ['t','7','6'], 0x7c00043c, 0xfc00e7ff, WR_t|RD_a, 0, D64, 0),
    instdes("dextr_r.l", ['t','7','6'], 0x7c00053c, 0xfc00e7ff, WR_t|RD_a, 0, D64, 0),
    instdes("dextr_rs.l", ['t','7','6'], 0x7c0005bc, 0xfc00e7ff, WR_t|RD_a, 0, D64, 0),
    instdes("dextr_rs.w", ['t','7','6'], 0x7c0001bc, 0xfc00e7ff, WR_t|RD_a, 0, D64, 0),
    instdes("dextr_r.w", ['t','7','6'], 0x7c00013c, 0xfc00e7ff, WR_t|RD_a, 0, D64, 0),
    instdes("dextr_s.h", ['t','7','6'], 0x7c0003bc, 0xfc00e7ff, WR_t|RD_a, 0, D64, 0),
    instdes("dextrv.l", ['t','7','s'], 0x7c00047c, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D64, 0),
    instdes("dextrv_r.l", ['t','7','s'], 0x7c00057c, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D64, 0),
    instdes("dextrv_rs.l", ['t','7','s'], 0x7c0005fc, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D64, 0),
    instdes("dextrv_rs.w", ['t','7','s'], 0x7c0001fc, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D64, 0),
    instdes("dextrv_r.w", ['t','7','s'], 0x7c00017c, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D64, 0),
    instdes("dextrv_s.h", ['t','7','s'], 0x7c0003fc, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D64, 0),
    instdes("dextrv.w", ['t','7','s'], 0x7c00007c, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D64, 0),
    instdes("dextr.w", ['t','7','6'], 0x7c00003c, 0xfc00e7ff, WR_t|RD_a, 0, D64, 0),
    instdes("dinsv", ['t','s'], 0x7c00000d, 0xfc00ffff, WR_t|RD_s, 0, D64, 0),
    instdes("dmadd", ['7','s','t'], 0x7c000674, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dmaddu", ['7','s','t'], 0x7c000774, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dmsub", ['7','s','t'], 0x7c0006f4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dmsubu", ['7','s','t'], 0x7c0007f4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dmthlip", ['s','7'], 0x7c0007fc, 0xfc1fe7ff, RD_s|MOD_a|DSP_VOLA, 0, D64, 0),
    instdes("dpaq_sa.l.pw", ['7','s','t'], 0x7c000334, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dpaq_sa.l.w", ['7','s','t'], 0x7c000330, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("dpaq_s.w.ph", ['7','s','t'], 0x7c000130, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("dpaq_s.w.qh", ['7','s','t'], 0x7c000134, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dpau.h.obl", ['7','s','t'], 0x7c0000f4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dpau.h.obr", ['7','s','t'], 0x7c0001f4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dpau.h.qbl", ['7','s','t'], 0x7c0000f0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("dpau.h.qbr", ['7','s','t'], 0x7c0001f0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("dpsq_sa.l.pw", ['7','s','t'], 0x7c000374, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dpsq_sa.l.w", ['7','s','t'], 0x7c000370, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("dpsq_s.w.ph", ['7','s','t'], 0x7c000170, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("dpsq_s.w.qh", ['7','s','t'], 0x7c000174, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dpsu.h.obl", ['7','s','t'], 0x7c0002f4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dpsu.h.obr", ['7','s','t'], 0x7c0003f4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("dpsu.h.qbl", ['7','s','t'], 0x7c0002f0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("dpsu.h.qbr", ['7','s','t'], 0x7c0003f0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("dshilo", ['7',':'], 0x7c0006bc, 0xfc07e7ff, MOD_a, 0, D64, 0),
    instdes("dshilov", ['7','s'], 0x7c0006fc, 0xfc1fe7ff, MOD_a|RD_s, 0, D64, 0),
    instdes("extpdp", ['t','7','6'], 0x7c0002b8, 0xfc00e7ff, WR_t|RD_a|DSP_VOLA, 0, D32, 0),
    instdes("extpdpv", ['t','7','s'], 0x7c0002f8, 0xfc00e7ff, WR_t|RD_a|RD_s|DSP_VOLA, 0, D32, 0),
    instdes("extp", ['t','7','6'], 0x7c0000b8, 0xfc00e7ff, WR_t|RD_a, 0, D32, 0),
    instdes("extpv", ['t','7','s'], 0x7c0000f8, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D32, 0),
    instdes("extr_rs.w", ['t','7','6'], 0x7c0001b8, 0xfc00e7ff, WR_t|RD_a, 0, D32, 0),
    instdes("extr_r.w", ['t','7','6'], 0x7c000138, 0xfc00e7ff, WR_t|RD_a, 0, D32, 0),
    instdes("extr_s.h", ['t','7','6'], 0x7c0003b8, 0xfc00e7ff, WR_t|RD_a, 0, D32, 0),
    instdes("extrv_rs.w", ['t','7','s'], 0x7c0001f8, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D32, 0),
    instdes("extrv_r.w", ['t','7','s'], 0x7c000178, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D32, 0),
    instdes("extrv_s.h", ['t','7','s'], 0x7c0003f8, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D32, 0),
    instdes("extrv.w", ['t','7','s'], 0x7c000078, 0xfc00e7ff, WR_t|RD_a|RD_s, 0, D32, 0),
    instdes("extr.w", ['t','7','6'], 0x7c000038, 0xfc00e7ff, WR_t|RD_a, 0, D32, 0),
    instdes("insv", ['t','s'], 0x7c00000c, 0xfc00ffff, WR_t|RD_s, 0, D32, 0),
    instdes("maq_sa.w.phl", ['7','s','t'], 0x7c000430, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("maq_sa.w.phr", ['7','s','t'], 0x7c0004b0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("maq_sa.w.qhll", ['7','s','t'], 0x7c000434, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_sa.w.qhlr", ['7','s','t'], 0x7c000474, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_sa.w.qhrl", ['7','s','t'], 0x7c0004b4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_sa.w.qhrr", ['7','s','t'], 0x7c0004f4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_s.l.pwl", ['7','s','t'], 0x7c000734, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_s.l.pwr", ['7','s','t'], 0x7c0007b4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_s.w.phl", ['7','s','t'], 0x7c000530, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("maq_s.w.phr", ['7','s','t'], 0x7c0005b0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("maq_s.w.qhll", ['7','s','t'], 0x7c000534, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_s.w.qhlr", ['7','s','t'], 0x7c000574, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_s.w.qhrl", ['7','s','t'], 0x7c0005b4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("maq_s.w.qhrr", ['7','s','t'], 0x7c0005f4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("modsub", ['d','s','t'], 0x7c000490, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("mthlip", ['s','7'], 0x7c0007f8, 0xfc1fe7ff, RD_s|MOD_a|DSP_VOLA, 0, D32, 0),
    instdes("muleq_s.pw.qhl", ['d','s','t'], 0x7c000714, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D64, 0),
    instdes("muleq_s.pw.qhr", ['d','s','t'], 0x7c000754, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D64, 0),
    instdes("muleq_s.w.phl", ['d','s','t'], 0x7c000710, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D32, 0),
    instdes("muleq_s.w.phr", ['d','s','t'], 0x7c000750, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D32, 0),
    instdes("muleu_s.ph.qbl", ['d','s','t'], 0x7c000190, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D32, 0),
    instdes("muleu_s.ph.qbr", ['d','s','t'], 0x7c0001d0, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D32, 0),
    instdes("muleu_s.qh.obl", ['d','s','t'], 0x7c000194, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D64, 0),
    instdes("muleu_s.qh.obr", ['d','s','t'], 0x7c0001d4, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D64, 0),
    instdes("mulq_rs.ph", ['d','s','t'], 0x7c0007d0, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D32, 0),
    instdes("mulq_rs.qh", ['d','s','t'], 0x7c0007d4, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D64, 0),
    instdes("mulsaq_s.l.pw", ['7','s','t'], 0x7c0003b4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("mulsaq_s.w.ph", ['7','s','t'], 0x7c0001b0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D32, 0),
    instdes("mulsaq_s.w.qh", ['7','s','t'], 0x7c0001b4, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D64, 0),
    instdes("packrl.ph", ['d','s','t'], 0x7c000391, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("packrl.pw", ['d','s','t'], 0x7c000395, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("pick.ob", ['d','s','t'], 0x7c0000d5, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("pick.ph", ['d','s','t'], 0x7c0002d1, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("pick.pw", ['d','s','t'], 0x7c0004d5, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("pick.qb", ['d','s','t'], 0x7c0000d1, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("pick.qh", ['d','s','t'], 0x7c0002d5, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("preceq.pw.qhla", ['d','t'], 0x7c000396, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceq.pw.qhl", ['d','t'], 0x7c000316, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceq.pw.qhra", ['d','t'], 0x7c0003d6, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceq.pw.qhr", ['d','t'], 0x7c000356, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceq.s.l.pwl", ['d','t'], 0x7c000516, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceq.s.l.pwr", ['d','t'], 0x7c000556, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("precequ.ph.qbla", ['d','t'], 0x7c000192, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("precequ.ph.qbl", ['d','t'], 0x7c000112, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("precequ.ph.qbra", ['d','t'], 0x7c0001d2, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("precequ.ph.qbr", ['d','t'], 0x7c000152, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("precequ.pw.qhla", ['d','t'], 0x7c000196, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("precequ.pw.qhl", ['d','t'], 0x7c000116, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("precequ.pw.qhra", ['d','t'], 0x7c0001d6, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("precequ.pw.qhr", ['d','t'], 0x7c000156, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceq.w.phl", ['d','t'], 0x7c000312, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("preceq.w.phr", ['d','t'], 0x7c000352, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("preceu.ph.qbla", ['d','t'], 0x7c000792, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("preceu.ph.qbl", ['d','t'], 0x7c000712, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("preceu.ph.qbra", ['d','t'], 0x7c0007d2, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("preceu.ph.qbr", ['d','t'], 0x7c000752, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("preceu.qh.obla", ['d','t'], 0x7c000796, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceu.qh.obl", ['d','t'], 0x7c000716, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceu.qh.obra", ['d','t'], 0x7c0007d6, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("preceu.qh.obr", ['d','t'], 0x7c000756, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("precrq.ob.qh", ['d','s','t'], 0x7c000315, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("precrq.ph.w", ['d','s','t'], 0x7c000511, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("precrq.pw.l", ['d','s','t'], 0x7c000715, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("precrq.qb.ph", ['d','s','t'], 0x7c000311, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("precrq.qh.pw", ['d','s','t'], 0x7c000515, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("precrq_rs.ph.w", ['d','s','t'], 0x7c000551, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("precrq_rs.qh.pw", ['d','s','t'], 0x7c000555, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("precrqu_s.ob.qh", ['d','s','t'], 0x7c0003d5, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("precrqu_s.qb.ph", ['d','s','t'], 0x7c0003d1, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("raddu.l.ob", ['d','s'], 0x7c000514, 0xfc1f07ff, WR_d|RD_s, 0, D64, 0),
    instdes("raddu.w.qb", ['d','s'], 0x7c000510, 0xfc1f07ff, WR_d|RD_s, 0, D32, 0),
    instdes("rddsp", ['d'], 0x7fff04b8, 0xffff07ff, WR_d, 0, D32, 0),
    instdes("rddsp", ['d',' '], 0x7c0004b8, 0xffc007ff, WR_d, 0, D32, 0),
    instdes("repl.ob", ['d','5'], 0x7c000096, 0xff0007ff, WR_d, 0, D64, 0),
    instdes("repl.ph", ['d','@'], 0x7c000292, 0xfc0007ff, WR_d, 0, D32, 0),
    instdes("repl.pw", ['d','@'], 0x7c000496, 0xfc0007ff, WR_d, 0, D64, 0),
    instdes("repl.qb", ['d','5'], 0x7c000092, 0xff0007ff, WR_d, 0, D32, 0),
    instdes("repl.qh", ['d','@'], 0x7c000296, 0xfc0007ff, WR_d, 0, D64, 0),
    instdes("replv.ob", ['d','t'], 0x7c0000d6, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("replv.ph", ['d','t'], 0x7c0002d2, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("replv.pw", ['d','t'], 0x7c0004d6, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("replv.qb", ['d','t'], 0x7c0000d2, 0xffe007ff, WR_d|RD_t, 0, D32, 0),
    instdes("replv.qh", ['d','t'], 0x7c0002d6, 0xffe007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shilo", ['7','0'], 0x7c0006b8, 0xfc0fe7ff, MOD_a, 0, D32, 0),
    instdes("shilov", ['7','s'], 0x7c0006f8, 0xfc1fe7ff, MOD_a|RD_s, 0, D32, 0),
    instdes("shll.ob", ['d','t','3'], 0x7c000017, 0xff0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shll.ph", ['d','t','4'], 0x7c000213, 0xfe0007ff, WR_d|RD_t, 0, D32, 0),
    instdes("shll.pw", ['d','t','6'], 0x7c000417, 0xfc0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shll.qb", ['d','t','3'], 0x7c000013, 0xff0007ff, WR_d|RD_t, 0, D32, 0),
    instdes("shll.qh", ['d','t','4'], 0x7c000217, 0xfe0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shll_s.ph", ['d','t','4'], 0x7c000313, 0xfe0007ff, WR_d|RD_t, 0, D32, 0),
    instdes("shll_s.pw", ['d','t','6'], 0x7c000517, 0xfc0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shll_s.qh", ['d','t','4'], 0x7c000317, 0xfe0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shll_s.w", ['d','t','6'], 0x7c000513, 0xfc0007ff, WR_d|RD_t, 0, D32, 0),
    instdes("shllv.ob", ['d','t','s'], 0x7c000097, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shllv.ph", ['d','t','s'], 0x7c000293, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("shllv.pw", ['d','t','s'], 0x7c000497, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shllv.qb", ['d','t','s'], 0x7c000093, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("shllv.qh", ['d','t','s'], 0x7c000297, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shllv_s.ph", ['d','t','s'], 0x7c000393, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("shllv_s.pw", ['d','t','s'], 0x7c000597, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shllv_s.qh", ['d','t','s'], 0x7c000397, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shllv_s.w", ['d','t','s'], 0x7c000593, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("shra.ph", ['d','t','4'], 0x7c000253, 0xfe0007ff, WR_d|RD_t, 0, D32, 0),
    instdes("shra.pw", ['d','t','6'], 0x7c000457, 0xfc0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shra.qh", ['d','t','4'], 0x7c000257, 0xfe0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shra_r.ph", ['d','t','4'], 0x7c000353, 0xfe0007ff, WR_d|RD_t, 0, D32, 0),
    instdes("shra_r.pw", ['d','t','6'], 0x7c000557, 0xfc0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shra_r.qh", ['d','t','4'], 0x7c000357, 0xfe0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shra_r.w", ['d','t','6'], 0x7c000553, 0xfc0007ff, WR_d|RD_t, 0, D32, 0),
    instdes("shrav.ph", ['d','t','s'], 0x7c0002d3, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("shrav.pw", ['d','t','s'], 0x7c0004d7, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shrav.qh", ['d','t','s'], 0x7c0002d7, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shrav_r.ph", ['d','t','s'], 0x7c0003d3, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("shrav_r.pw", ['d','t','s'], 0x7c0005d7, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shrav_r.qh", ['d','t','s'], 0x7c0003d7, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shrav_r.w", ['d','t','s'], 0x7c0005d3, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("shrl.ob", ['d','t','3'], 0x7c000057, 0xff0007ff, WR_d|RD_t, 0, D64, 0),
    instdes("shrl.qb", ['d','t','3'], 0x7c000053, 0xff0007ff, WR_d|RD_t, 0, D32, 0),
    instdes("shrlv.ob", ['d','t','s'], 0x7c0000d7, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("shrlv.qb", ['d','t','s'], 0x7c0000d3, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("subq.ph", ['d','s','t'], 0x7c0002d0, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("subq.pw", ['d','s','t'], 0x7c0004d4, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("subq.qh", ['d','s','t'], 0x7c0002d4, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("subq_s.ph", ['d','s','t'], 0x7c0003d0, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("subq_s.pw", ['d','s','t'], 0x7c0005d4, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("subq_s.qh", ['d','s','t'], 0x7c0003d4, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("subq_s.w", ['d','s','t'], 0x7c0005d0, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("subu.ob", ['d','s','t'], 0x7c000054, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("subu.qb", ['d','s','t'], 0x7c000050, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("subu_s.ob", ['d','s','t'], 0x7c000154, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D64, 0),
    instdes("subu_s.qb", ['d','s','t'], 0x7c000150, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D32, 0),
    instdes("wrdsp", ['s'], 0x7c1ffcf8, 0xfc1fffff, RD_s|DSP_VOLA, 0, D32, 0),
    instdes("wrdsp", ['s','8'], 0x7c0004f8, 0xfc1e07ff, RD_s|DSP_VOLA, 0, D32, 0),
    instdes("absq_s.qb", ['d','t'], 0x7c000052, 0xffe007ff, WR_d|RD_t, 0, D33, 0),
    instdes("addu.ph", ['d','s','t'], 0x7c000210, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("addu_s.ph", ['d','s','t'], 0x7c000310, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("adduh.qb", ['d','s','t'], 0x7c000018, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("adduh_r.qb", ['d','s','t'], 0x7c000098, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("append", ['t','s','h'], 0x7c000031, 0xfc0007ff, WR_t|RD_t|RD_s, 0, D33, 0),
    instdes("balign", ['t','s','I'], 0, M_BALIGN, INSN_MACRO, 0, D33, 0),
    instdes("balign", ['t','s','2'], 0x7c000431, 0xfc00e7ff, WR_t|RD_t|RD_s, 0, D33, 0),
    instdes("cmpgdu.eq.qb", ['d','s','t'], 0x7c000611, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("cmpgdu.lt.qb", ['d','s','t'], 0x7c000651, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("cmpgdu.le.qb", ['d','s','t'], 0x7c000691, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("dpa.w.ph", ['7','s','t'], 0x7c000030, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("dps.w.ph", ['7','s','t'], 0x7c000070, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("mul.ph", ['d','s','t'], 0x7c000318, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D33, 0),
    instdes("mul_s.ph", ['d','s','t'], 0x7c000398, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D33, 0),
    instdes("mulq_rs.w", ['d','s','t'], 0x7c0005d8, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D33, 0),
    instdes("mulq_s.ph", ['d','s','t'], 0x7c000790, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D33, 0),
    instdes("mulq_s.w", ['d','s','t'], 0x7c000598, 0xfc0007ff, WR_d|RD_s|RD_t|WR_HILO, 0, D33, 0),
    instdes("mulsa.w.ph", ['7','s','t'], 0x7c0000b0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("precr.qb.ph", ['d','s','t'], 0x7c000351, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("precr_sra.ph.w", ['t','s','h'], 0x7c000791, 0xfc0007ff, WR_t|RD_t|RD_s, 0, D33, 0),
    instdes("precr_sra_r.ph.w", ['t','s','h'], 0x7c0007d1, 0xfc0007ff, WR_t|RD_t|RD_s, 0, D33, 0),
    instdes("prepend", ['t','s','h'], 0x7c000071, 0xfc0007ff, WR_t|RD_t|RD_s, 0, D33, 0),
    instdes("shra.qb", ['d','t','3'], 0x7c000113, 0xff0007ff, WR_d|RD_t, 0, D33, 0),
    instdes("shra_r.qb", ['d','t','3'], 0x7c000153, 0xff0007ff, WR_d|RD_t, 0, D33, 0),
    instdes("shrav.qb", ['d','t','s'], 0x7c000193, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("shrav_r.qb", ['d','t','s'], 0x7c0001d3, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("shrl.ph", ['d','t','4'], 0x7c000653, 0xfe0007ff, WR_d|RD_t, 0, D33, 0),
    instdes("shrlv.ph", ['d','t','s'], 0x7c0006d3, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("subu.ph", ['d','s','t'], 0x7c000250, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("subu_s.ph", ['d','s','t'], 0x7c000350, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("subuh.qb", ['d','s','t'], 0x7c000058, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("subuh_r.qb", ['d','s','t'], 0x7c0000d8, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("addqh.ph", ['d','s','t'], 0x7c000218, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("addqh_r.ph", ['d','s','t'], 0x7c000298, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("addqh.w", ['d','s','t'], 0x7c000418, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("addqh_r.w", ['d','s','t'], 0x7c000498, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("subqh.ph", ['d','s','t'], 0x7c000258, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("subqh_r.ph", ['d','s','t'], 0x7c0002d8, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("subqh.w", ['d','s','t'], 0x7c000458, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("subqh_r.w", ['d','s','t'], 0x7c0004d8, 0xfc0007ff, WR_d|RD_s|RD_t, 0, D33, 0),
    instdes("dpax.w.ph", ['7','s','t'], 0x7c000230, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("dpsx.w.ph", ['7','s','t'], 0x7c000270, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("dpaqx_s.w.ph", ['7','s','t'], 0x7c000630, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("dpaqx_sa.w.ph", ['7','s','t'], 0x7c0006b0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("dpsqx_s.w.ph", ['7','s','t'], 0x7c000670, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("dpsqx_sa.w.ph", ['7','s','t'], 0x7c0006f0, 0xfc00e7ff, MOD_a|RD_s|RD_t, 0, D33, 0),
    instdes("bc0f", ['p'], 0x41000000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc0fl", ['p'], 0x41020000, 0xffff0000, CBL|RD_CC, 0, I2|T3, IOCT|IOCTP|IOCT2),
    instdes("bc0t", ['p'], 0x41010000, 0xffff0000, CBD|RD_CC, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("bc0tl", ['p'], 0x41030000, 0xffff0000, CBL|RD_CC, 0, I2|T3, IOCT|IOCTP|IOCT2),
    instdes("mult.g", ['d','s','t'], 0x7c000018, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("mult.g", ['d','s','t'], 0x70000010, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsmult", ['d','s','t'], 0x70000010, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("multu.g", ['d','s','t'], 0x7c000019, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("multu.g", ['d','s','t'], 0x70000012, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsmultu", ['d','s','t'], 0x70000012, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("dmult.g", ['d','s','t'], 0x7c00001c, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("dmult.g", ['d','s','t'], 0x70000011, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsdmult", ['d','s','t'], 0x70000011, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("dmultu.g", ['d','s','t'], 0x7c00001d, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("dmultu.g", ['d','s','t'], 0x70000013, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsdmultu", ['d','s','t'], 0x70000013, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("div.g", ['d','s','t'], 0x7c00001a, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("div.g", ['d','s','t'], 0x70000014, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsdiv", ['d','s','t'], 0x70000014, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("divu.g", ['d','s','t'], 0x7c00001b, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("divu.g", ['d','s','t'], 0x70000016, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsdivu", ['d','s','t'], 0x70000016, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("ddiv.g", ['d','s','t'], 0x7c00001e, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("ddiv.g", ['d','s','t'], 0x70000015, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsddiv", ['d','s','t'], 0x70000015, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("ddivu.g", ['d','s','t'], 0x7c00001f, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("ddivu.g", ['d','s','t'], 0x70000017, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsddivu", ['d','s','t'], 0x70000017, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("mod.g", ['d','s','t'], 0x7c000022, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("mod.g", ['d','s','t'], 0x7000001c, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsmod", ['d','s','t'], 0x7000001c, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("modu.g", ['d','s','t'], 0x7c000023, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("modu.g", ['d','s','t'], 0x7000001e, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsmodu", ['d','s','t'], 0x7000001e, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("dmod.g", ['d','s','t'], 0x7c000026, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("dmod.g", ['d','s','t'], 0x7000001d, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsdmod", ['d','s','t'], 0x7000001d, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("dmodu.g", ['d','s','t'], 0x7c000027, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2E, 0),
    instdes("dmodu.g", ['d','s','t'], 0x7000001f, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL2F, 0),
    instdes("gsdmodu", ['d','s','t'], 0x7000001f, 0xfc0007ff, RD_s|RD_t|WR_d, 0, IL3A, 0),
    instdes("packsshb", ['D','S','T'], 0x47400002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("packsshb", ['D','S','T'], 0x4b400002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("packsswh", ['D','S','T'], 0x47200002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("packsswh", ['D','S','T'], 0x4b200002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("packushb", ['D','S','T'], 0x47600002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("packushb", ['D','S','T'], 0x4b600002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("paddb", ['D','S','T'], 0x47c00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("paddb", ['D','S','T'], 0x4bc00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("paddh", ['D','S','T'], 0x47400000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("paddh", ['D','S','T'], 0x4b400000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("paddw", ['D','S','T'], 0x47600000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("paddw", ['D','S','T'], 0x4b600000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("paddd", ['D','S','T'], 0x47e00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("paddd", ['D','S','T'], 0x4be00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("paddsb", ['D','S','T'], 0x47800000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("paddsb", ['D','S','T'], 0x4b800000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("paddsh", ['D','S','T'], 0x47000000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("paddsh", ['D','S','T'], 0x4b000000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("paddusb", ['D','S','T'], 0x47a00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("paddusb", ['D','S','T'], 0x4ba00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("paddush", ['D','S','T'], 0x47200000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("paddush", ['D','S','T'], 0x4b200000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pandn", ['D','S','T'], 0x47e00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pandn", ['D','S','T'], 0x4be00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pavgb", ['D','S','T'], 0x46600000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pavgb", ['D','S','T'], 0x4b200008, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pavgh", ['D','S','T'], 0x46400000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pavgh", ['D','S','T'], 0x4b000008, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pcmpeqb", ['D','S','T'], 0x46c00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pcmpeqb", ['D','S','T'], 0x4b800009, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pcmpeqh", ['D','S','T'], 0x46800001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pcmpeqh", ['D','S','T'], 0x4b400009, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pcmpeqw", ['D','S','T'], 0x46400001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pcmpeqw", ['D','S','T'], 0x4b000009, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pcmpgtb", ['D','S','T'], 0x46e00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pcmpgtb", ['D','S','T'], 0x4ba00009, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pcmpgth", ['D','S','T'], 0x46a00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pcmpgth", ['D','S','T'], 0x4b600009, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pcmpgtw", ['D','S','T'], 0x46600001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pcmpgtw", ['D','S','T'], 0x4b200009, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pextrh", ['D','S','T'], 0x45c00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pextrh", ['D','S','T'], 0x4b40000e, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pinsrh_0", ['D','S','T'], 0x47800003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pinsrh_0", ['D','S','T'], 0x4b800003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pinsrh_1", ['D','S','T'], 0x47a00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pinsrh_1", ['D','S','T'], 0x4ba00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pinsrh_2", ['D','S','T'], 0x47c00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pinsrh_2", ['D','S','T'], 0x4bc00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pinsrh_3", ['D','S','T'], 0x47e00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pinsrh_3", ['D','S','T'], 0x4be00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pmaddhw", ['D','S','T'], 0x45e00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pmaddhw", ['D','S','T'], 0x4b60000e, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pmaxsh", ['D','S','T'], 0x46800000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pmaxsh", ['D','S','T'], 0x4b400008, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pmaxub", ['D','S','T'], 0x46c00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pmaxub", ['D','S','T'], 0x4b800008, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pminsh", ['D','S','T'], 0x46a00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pminsh", ['D','S','T'], 0x4b600008, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pminub", ['D','S','T'], 0x46e00000, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pminub", ['D','S','T'], 0x4ba00008, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pmovmskb", ['D','S'], 0x46a00005, 0xffff003f, RD_S|WR_D|FP_D, 0, IL2E, 0),
    instdes("pmovmskb", ['D','S'], 0x4ba0000f, 0xffff003f, RD_S|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pmulhuh", ['D','S','T'], 0x46e00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pmulhuh", ['D','S','T'], 0x4ba0000a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pmulhh", ['D','S','T'], 0x46a00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pmulhh", ['D','S','T'], 0x4b60000a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pmullh", ['D','S','T'], 0x46800002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pmullh", ['D','S','T'], 0x4b40000a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pmuluw", ['D','S','T'], 0x46c00002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pmuluw", ['D','S','T'], 0x4b80000a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pasubub", ['D','S','T'], 0x45a00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pasubub", ['D','S','T'], 0x4b20000d, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("biadd", ['D','S'], 0x46800005, 0xffff003f, RD_S|WR_D|FP_D, 0, IL2E, 0),
    instdes("biadd", ['D','S'], 0x4b80000f, 0xffff003f, RD_S|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("pshufh", ['D','S','T'], 0x47000002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("pshufh", ['D','S','T'], 0x4b000002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psllh", ['D','S','T'], 0x46600002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psllh", ['D','S','T'], 0x4b20000a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psllw", ['D','S','T'], 0x46400002, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psllw", ['D','S','T'], 0x4b00000a, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psrah", ['D','S','T'], 0x46a00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psrah", ['D','S','T'], 0x4b60000b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psraw", ['D','S','T'], 0x46800003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psraw", ['D','S','T'], 0x4b40000b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psrlh", ['D','S','T'], 0x46600003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psrlh", ['D','S','T'], 0x4b20000b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psrlw", ['D','S','T'], 0x46400003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psrlw", ['D','S','T'], 0x4b00000b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psubb", ['D','S','T'], 0x47c00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psubb", ['D','S','T'], 0x4bc00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psubh", ['D','S','T'], 0x47400001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psubh", ['D','S','T'], 0x4b400001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psubw", ['D','S','T'], 0x47600001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psubw", ['D','S','T'], 0x4b600001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psubd", ['D','S','T'], 0x47e00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psubd", ['D','S','T'], 0x4be00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psubsb", ['D','S','T'], 0x47800001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psubsb", ['D','S','T'], 0x4b800001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psubsh", ['D','S','T'], 0x47000001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psubsh", ['D','S','T'], 0x4b000001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psubusb", ['D','S','T'], 0x47a00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psubusb", ['D','S','T'], 0x4ba00001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("psubush", ['D','S','T'], 0x47200001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("psubush", ['D','S','T'], 0x4b200001, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("punpckhbh", ['D','S','T'], 0x47600003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("punpckhbh", ['D','S','T'], 0x4b600003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("punpckhhw", ['D','S','T'], 0x47200003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("punpckhhw", ['D','S','T'], 0x4b200003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("punpckhwd", ['D','S','T'], 0x46e00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("punpckhwd", ['D','S','T'], 0x4ba0000b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("punpcklbh", ['D','S','T'], 0x47400003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("punpcklbh", ['D','S','T'], 0x4b400003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("punpcklhw", ['D','S','T'], 0x47000003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("punpcklhw", ['D','S','T'], 0x4b000003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("punpcklwd", ['D','S','T'], 0x46c00003, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2E, 0),
    instdes("punpcklwd", ['D','S','T'], 0x4b80000b, 0xffe0003f, RD_S|RD_T|WR_D|FP_D, 0, IL2F|IL3A, 0),
    instdes("sequ", ['S','T'], 0x46800032, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2E, 0),
    instdes("sequ", ['S','T'], 0x4b80000c, 0xffe007ff, RD_S|RD_T|WR_CC|FP_D, 0, IL2F|IL3A, 0),
    instdes("c0", ['C'], 0x42000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("c1", ['C'], 0x46000000, 0xfe000000, FP_S, 0, I1, 0),
    instdes("c2", ['C'], 0x4a000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("c3", ['C'], 0x4e000000, 0xfe000000, CP, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("cop0", ['C'], 0, M_COP0, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("cop1", ['C'], 0, M_COP1, INSN_MACRO, INSN2_M_FP_S, I1, 0),
    instdes("cop2", ['C'], 0, M_COP2, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
    instdes("cop3", ['C'], 0, M_COP3, INSN_MACRO, 0, I1, IOCT|IOCTP|IOCT2),
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
    'slt':   instopdes(instop_alu, operator.lt, 's', 32),
    'slti':  instopdes(instop_alu, operator.lt, 's', 32),
    'sltiu': instopdes(instop_alu, operator.lt, 'u', 32),
    'sltu':  instopdes(instop_alu, operator.lt, 'u', 32),
    'srav':  instopdes(instop_alu, operator.rshift, 's', 32),
    'sra':   instopdes(instop_alu, operator.rshift, 's', 32),
    'srlv':  instopdes(instop_alu, operator.rshift, 'u', 32),
    'srl':   instopdes(instop_alu, operator.rshift, 'u', 32),
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
    'xori':  instopdes(instop_alu, operator.xor, 'u', 32),
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

instdesbyname = {}

for inst in instdeslist:
    if not inst.name in instdesbyname:
        instdesbyname[inst.name] = [inst]
    else:
        instdesbyname[inst.name].append(inst)

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
                if value >= value:
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

    def __init__(self, operation = None, args = [], encoding = 0, pinfo = 0):
        self.operation = operation
        self.args = args
        self.encoding = encoding
        self.pinfo = pinfo
        self.stalls = 0

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
        for rstr in cpu.regsastext():
             sys.stdout.write(' ' + rstr)
             c += 1
             if c % 6 == 0:
                 sys.stdout.write('\n')
        if c % 6 != 0:
            sys.stdout.write('\n')
