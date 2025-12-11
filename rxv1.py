import sys
import struct

from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_segment import *
from ida_name import *
from ida_netnode import *
from ida_xref import *
from ida_idaapi import *

import ida_lines
import ida_bytes
import ida_ida
import ida_frame
import ida_offset
import ida_pro
import idc
import ida_xref
import idaapi


PLFM_RXV1 = 0x8000 + 4578

MEMEX_B     = 0
MEMEX_W     = 1
MEMEX_L     = 2
MEMEX_UW    = 3
MEMEX_UB    = 4
MEMEX_S     = 5
MEMEX_A     = 6
MEMEX_NEED_SHOW  = 16

memex_names = [ ".b", ".w", ".l", ".uw", ".ub", ".s", ".a" ]
cond_names = [ "eq", "ne", "c", "nc", "gtu", "leu", "pz", "n", "ge", "lt", "gt", "le", "o", "no", "bra", "" ]

COND_EQ     = 0
COND_NE     = 1
COND_C      = 2
COND_NC     = 3
COND_GTU    = 4
COND_LEU    = 5
COND_PZ     = 6
COND_N      = 7
COND_GE     = 8
COND_LT     = 9
COND_GT     = 10
COND_LE     = 11
COND_O      = 12
COND_NO     = 13
COND_BRA    = 14
COND_NONE   = 15

FLAG_C      = 0
FLAG_Z      = 1
FLAG_S      = 2
FLAG_O      = 3
FLAG_I      = 8
FLAG_U      = 9

PHRASE_R_PLUS   = 0 # [r+]
PHRASE_R_MINUS  = 1 # [-r]
PHRASE_R_R      = 2 # [r,r]
PHRASE_R_RANGE  = 3 # r-r

CR_INTB = 12

o_flag = o_idpspec0
o_creg = o_idpspec1

# monkey patches for insn_t

def insn_get_memex(self):
    return self.auxpref & 0x1F
def insn_set_memex(self, value):
    self.auxpref = (self.auxpref & ~0x1F) | (value & 0x1F)
insn_t.memex = property(insn_get_memex, insn_set_memex)

def insn_get_cond(self):
    return self.insnpref & 0x0F
def insn_set_cond(self, value):
    self.insnpref = (self.insnpref & ~0x0F) | (value & 0x0F)
insn_t.cond = property(insn_get_cond, insn_set_cond)

# monkey patches for op_t

def op_get_cond(self):
    return self.specval & 0x0F
def op_set_cond(self, value):
    self.specval = (self.specval & ~0x0F) | (value & 0x0F)
op_t.memex = property(op_get_cond, op_set_cond) 

def op_get_phrase(self):
    return self.specflag1 & 3
def op_set_phrase(self, value):
    self.specflag1 = (self.specval & ~3) | (value & 3)
op_t.phrase = property(op_get_phrase, op_set_phrase) 

# instructions groups

RX_GROUP_ABS = 0
RX_GROUP_ADC = 1
RX_GROUP_ADD = 2
RX_GROUP_AND = 3
RX_GROUP_BCLR = 4
RX_GROUP_B = 5
RX_GROUP_BM = 6
RX_GROUP_BNOT = 7
RX_GROUP_BRA = 8
RX_GROUP_BRK = 9
RX_GROUP_BSET = 10
RX_GROUP_BSR = 11
RX_GROUP_BTST = 12
RX_GROUP_CLRPSW = 13
RX_GROUP_CMP = 14
RX_GROUP_DIV = 15
RX_GROUP_DIVU = 16
RX_GROUP_EMUL = 17
RX_GROUP_EMULU = 18
RX_GROUP_FADD = 19
RX_GROUP_FCMP = 20
RX_GROUP_FDIV = 21
RX_GROUP_FMUL = 22
RX_GROUP_FSUB = 23
RX_GROUP_FTOI = 24
RX_GROUP_INT = 25
RX_GROUP_ITOF = 26
RX_GROUP_JMP = 27
RX_GROUP_JSR = 28
RX_GROUP_MACHI = 29
RX_GROUP_MACLO = 30
RX_GROUP_MAX = 31
RX_GROUP_MIN = 32
RX_GROUP_MOV = 33
RX_GROUP_MOVU = 34
RX_GROUP_MUL = 35
RX_GROUP_MULHI = 36
RX_GROUP_MULLO = 37
RX_GROUP_MVFACHI = 38
RX_GROUP_MVFACMI = 39
RX_GROUP_MVFC = 40
RX_GROUP_MVTACHI = 41
RX_GROUP_MVTACLO = 42
RX_GROUP_MVTC = 43
RX_GROUP_MVTIPL = 44
RX_GROUP_NEG = 45
RX_GROUP_NOP = 46
RX_GROUP_NOT = 47
RX_GROUP_OR = 48
RX_GROUP_POP = 49
RX_GROUP_POPC = 50
RX_GROUP_POPM = 51
RX_GROUP_PUSH = 52
RX_GROUP_PUSHC = 53
RX_GROUP_PUSHM = 54
RX_GROUP_RACW = 55
RX_GROUP_REVL = 56
RX_GROUP_REVW = 57
RX_GROUP_RMPA = 58
RX_GROUP_ROLC = 59
RX_GROUP_RORC = 60
RX_GROUP_ROTL = 61
RX_GROUP_ROTR = 62
RX_GROUP_ROUND = 63
RX_GROUP_RTE = 64
RX_GROUP_RTFI = 65
RX_GROUP_RTS = 66
RX_GROUP_RTSD = 67
RX_GROUP_SAT = 68
RX_GROUP_SATR = 69
RX_GROUP_SBB = 70
RX_GROUP_SC = 71
RX_GROUP_SCMPU = 72
RX_GROUP_SETPSW = 73
RX_GROUP_SHAR = 74
RX_GROUP_SHLL = 75
RX_GROUP_SHLR = 76
RX_GROUP_SMOVB = 77
RX_GROUP_SMOVF = 78
RX_GROUP_SMOVU = 79
RX_GROUP_SSTR = 80
RX_GROUP_STNZ = 81
RX_GROUP_STZ = 82
RX_GROUP_SUB = 83
RX_GROUP_SUNTIL = 84
RX_GROUP_SWHILE = 85
RX_GROUP_TST = 86
RX_GROUP_WAIT = 87
RX_GROUP_XCHG = 88
RX_GROUP_XOR = 89

# our proccessor class

class rxv1_processor_t(processor_t):

    id = PLFM_RXV1

    flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_WORD_INS | PR_USE32 | PR_DEFSEG32 | PR_BINMEM

    cnbits = 8

    dnbits = 8

    psnames = [ 'RXv1' ]

    plnames = [ 'Renesas RX:RXv1 (big endian)' ]
    
    segreg_size = 0
    
    retcodes = [
        '\x02',     # rts
        '\x67',     # rtsd
        '\x4f',     # rtsd
        '\x7f\x95', # rte 
        '\x7f\x94'  # rtf
    ]

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 19)

    assembler = {
        'flag' : AS_COLON | AS_ASCIIZ | AS_ASCIIC | AS_1TEXT,
        'uflag' : 0,
        'name' : "RXv1",
        'header': [".rxv1"],
        'origin': ".org",
        'end' : ".end",
        'cmnt' : ";",
        'ascsep' : '\"',
        'accsep' : "'",
        'esccodes' : "\"'",
        'a_ascii' : ".string",
        'a_byte' : ".byte",
        'a_word' : '.word',
        'a_dword' : '.dword',
        'a_float' : '.float',
        'a_double' : '.double',
        'a_dups': "#d dup(#v)",
        'a_bss' : '.block %s',
        'a_equ': ".equ",
        'a_seg': "seg",
        'a_curip': "$",
        'a_public': ".global",
        'a_weak': "",
        'a_extrn': ".ref",
        'a_comdef': "",
        'a_align': ".align",
        'lbrace': "(",
        'rbrace': ")",
        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "!",
        'a_shl': "<<",
        'a_shr': ">>",
        'a_sizeof_fmt': "size %s"
    }

    def get_real_address(self, ea):
        val = (ea >> 2 << 2) + 3 - (ea & 3)
        return val

    def get_hl_byte(self, ea):
        val = ida_bytes.get_wide_byte(self.get_real_address(ea))
        return val
    
    def get_hl_word(self, ea):
        return ( self.get_hl_byte(ea + 1) << 8) | self.get_hl_byte(ea)

    def get_hl_bits24(self, ea):
        res = 0
        for i in range(2,-1,-1):
            res <<= 8
            res |= self.get_hl_byte(ea + i)
        return res

    def get_hl_dword(self, ea):
        res = 0
        for i in range(3,-1,-1):
            res <<= 8
            res |= self.get_hl_byte(ea + i)
        return res

    def to_signed(self, value, bits):
        sign_bit = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)

    def set_reg(self, insn, op_num, reg_offset, reg_bit_offset):
        op = insn.ops[op_num]
        op.type = o_reg
        op.dtype = dt_word
        op.reg = (self.get_hl_byte(insn.ea + reg_offset) >> reg_bit_offset) & 0x0f

    def set_imm(self, insn, op_num, li_offset, li_bit_offset, imm_offset):
        op = insn.ops[op_num]
        li = (self.get_hl_byte(insn.ea + li_offset) >> li_bit_offset) & 3
        op.type = o_imm
        size = 0
        match li:
            case 0: # imm32
                op.value = self.get_hl_dword(insn.ea + imm_offset)
                op.dtype = dt_dword
                size = 4
            case 1: # simm8
                op.value = self.get_hl_byte(insn.ea + imm_offset)
                op.dtype = dt_byte
                size = 1
            case 2: # simm16
                op.value = self.get_hl_word(insn.ea + imm_offset)
                op.dtype = dt_word
                size = 2
            case 3: # simm24
                op.value = self.get_hl_bits24(insn.ea + imm_offset)
                if (op.value & 0x800000) != 0:
                    op.value = op.value | 0xff000000
                op.dtype = dt_dword
                size = 3
        return size

    def get_memex_scale(self, memex):
        if memex & 0xf in (MEMEX_W, MEMEX_UW):
            return 2
        if memex & 0xf == MEMEX_L:
            return 4
        return 1

    def set_ld(self, insn, op_num, ld_offset, ld_bit_offset, memex, reg_offset, reg_bit_offset, dsp_offset):
        size = 0
        op = insn.ops[op_num]
        ld = (self.get_hl_byte(insn.ea + ld_offset) >> ld_bit_offset) & 3
        op.reg = (self.get_hl_byte(insn.ea + reg_offset) >> reg_bit_offset) & 0x0f
        op.dtype = dt_word
        match ld:
            case 0: # [reg]
                op.type = o_displ
                op.value = 0
                op.memex = memex
                size = 0
            case 1: # dsp:8[reg]
                op.type = o_displ
                op.value = self.get_memex_scale(memex) * self.get_hl_byte(insn.ea + dsp_offset)
                op.memex = memex
                size = 1
            case 2: # dsp:16[reg]
                op.type = o_displ
                op.value = self.get_memex_scale(memex) * self.get_hl_word(insn.ea + dsp_offset)
                op.memex = memex
                size = 2
            case 3: # reg
                op.type = o_reg
                size = 0
        return size

    def decode_b2_reg(self, insn: insn_t):
        self.set_reg(insn, 0, 1, 0)
        insn.size = 2

    def decode_b2_rs_rd(self, insn):
        self.set_reg(insn, 0, 2, 4)
        self.set_reg(insn, 1, 2, 0)
        insn.size = 3

    def decode_b3_li_rd(self, insn):
        insn.size = 3 + self.set_imm(insn, 0, 1, 2, 3)
        self.set_reg(insn, 1, 2, 0)

    def decode_b2_ld_rs_rd(self, insn):
        insn.size = 3 + self.set_ld(insn, 0, 1, 0, MEMEX_UB, 2, 4, 3)        
        self.set_reg(insn, 1, 2, 0)

    def decode_b3_mi_ld_rs_rd(self, insn):
        memex = (self.get_hl_byte(insn.ea + 1) >> 6) & 3
        insn.size = 4 + self.set_ld(insn, 0, 1, 0, memex, 3, 4, 4)        
        self.set_reg(insn, 1, 3, 0)

    def decode_b1_uimm4_rd(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte( insn.ea + 1) >> 4
        self.set_reg(insn, 1, 1, 0)
        insn.size = 2

    def decode_b1_uimm4_rd_with_memex(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte( insn.ea + 1) >> 4
        self.set_reg(insn, 1, 1, 0)
        insn.memex = MEMEX_L | MEMEX_NEED_SHOW
        insn.size = 2

    def decode_b1_ld_rs_rd(self, insn):
        insn.size = 2 + self.set_ld(insn, 0, 0, 0, MEMEX_UB, 1, 4, 2)        
        self.set_reg(insn, 1, 1, 0)

    def decode_b2_mi_ld_rs_rd(self, insn):
        memex = (self.get_hl_byte(insn.ea + 1) >> 6) & 3
        insn.size = 3 + self.set_ld(insn, 0, 1, 0, memex, 2, 4, 3)        
        self.set_reg(insn, 1, 2, 0)

    def decode_b1_li_rs2_rd(self, insn):
        insn.size = 2 + self.set_imm(insn, 0, 0, 0, 2)
        self.set_reg(insn, 1, 1, 4)
        self.set_reg(insn, 2, 1, 0)

    def decode_b2_rd_rs_rs2(self, insn):
        self.set_reg(insn, 0, 2, 4)
        self.set_reg(insn, 1, 2, 0)
        self.set_reg(insn, 2, 1, 0)
        insn.size = 3

    def decode_b1_sz2_dsp5_rd_rs(self, insn):
        val0 = self.get_hl_byte(insn.ea)
        sz = (val0 >> 4) & 3
        if sz == 3:
            return
        val1 = self.get_hl_byte(insn.ea+1)
        insn.memex = sz | MEMEX_NEED_SHOW
        insn.Op1.type = o_reg
        insn.Op1.dtype = dt_byte
        insn.Op1.reg = val1 & 7
        insn.Op2.type = o_displ
        insn.Op2.dtype = dt_byte
        insn.Op2.reg = (val1 >> 4) & 7
        insn.Op2.value = self.get_memex_scale(sz) * (((val0 & 7) << 2) | ((val1 >> 6) & 2) | ((val1 >> 3) & 1))
        insn.size = 2

    def decode_b1_sz2_dsp5_rs_rd(self, insn):
        val0 = self.get_hl_byte(insn.ea)
        sz = (val0 >> 4) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        val1 = self.get_hl_byte(insn.ea+1)
        insn.Op1.type = o_displ
        insn.Op1.dtype = dt_byte
        insn.Op1.reg = (val1 >> 4) & 7
        insn.Op1.value = self.get_memex_scale(sz) * (((val0 & 7) << 2) | ((val1 >> 6) & 2) | ((val1 >> 3) & 1))
        insn.Op2.type = o_reg
        insn.Op2.dtype = dt_byte
        insn.Op2.reg = val1 & 7
        insn.size = 2

    def decode_b1_sz2_dsp5_rd_uimm8(self, insn):
        sz = self.get_hl_byte(insn.ea) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        val1 = self.get_hl_byte(insn.ea+1)
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea + 2)
        if sz & 0xF == MEMEX_B:
            insn.Op1.value = self.to_signed(insn.Op1.value, 8)
        insn.Op2.type = o_displ
        insn.Op2.dtype = dt_byte
        insn.Op2.value = self.get_memex_scale(sz) * (((val1 & 0x80)>>3) | (val1 & 0x0F))
        insn.Op2.reg = (val1 >> 4) & 7
        insn.size = 3

    def decode_b2_rd_uimm8(self, insn):
        insn.memex = MEMEX_L | MEMEX_NEED_SHOW
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea + 2)
        self.set_reg(insn, 1, 1, 0)
        insn.size = 3

    def decode_b2_rd_li(self, insn):
        insn.size = 2 + self.set_imm(insn, 0, 1, 2, 2)
        self.set_reg(insn, 1, 1, 4)
        insn.memex = MEMEX_L | MEMEX_NEED_SHOW

    def decode_b1_sz2_rs_rd(self, insn):
        sz = (self.get_hl_byte(insn.ea) >> 4 ) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        self.set_reg(insn, 0, 1, 4)
        self.set_reg(insn, 1, 1, 0)
        insn.size = 2

    def decode_b1_ld_rd_li_sz2(self, insn):
        sz = self.get_hl_byte(insn.ea+1) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        insn.size = 2 + self.set_ld(insn, 1, 0, 0, sz, 1, 4, 2)
        insn.size += self.set_imm(insn, 0, 1, 2, insn.size) 

    def decode_b1_sz2_ld_rs_rd(self, insn):
        sz = (self.get_hl_byte(insn.ea) >> 4) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        insn.size = 2 + self.set_ld(insn, 0, 0, 0, sz, 1, 4, 2)
        self.set_reg(insn, 1, 1, 0)

    def decode_b2_sz2_ri_rb_rd(self, insn):
        val0 = self.get_hl_byte(insn.ea+1)
        sz = (val0 >> 4) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        insn.Op1.type = o_phrase
        insn.Op1.phrase = PHRASE_R_R
        insn.Op1.value = val0 & 0x0F # ri
        insn.Op1.reg = (self.get_hl_byte(insn.ea+2) >> 4) & 0x0F # rb
        self.set_reg(insn, 1, 2, 0) # rd
        insn.size = 3

    def decode_b1_sz2_ld_rd_rs(self, insn):
        sz = (self.get_hl_byte(insn.ea) >> 4) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        self.set_reg(insn, 0, 1, 0)
        insn.size = 2 + self.set_ld(insn, 1, 0, 2, sz, 1, 4, 2)

    def decode_b2_sz2_ri_rb_rs(self, insn):
        val0 = self.get_hl_byte(insn.ea+1)
        sz = (val0 >> 4) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        self.set_reg(insn, 0, 2, 0) # rs
        insn.Op2.type = o_phrase
        insn.Op2.phrase = PHRASE_R_R
        insn.Op2.value = val0 & 0x0F # ri
        insn.Op2.reg = (self.get_hl_byte(insn.ea+2) >> 4) & 0x0F # rb
        insn.size = 3

    def decode_b1_sz2_ldd_lds_rs_rd(self, insn):
        sz = (self.get_hl_byte(insn.ea) >> 4) & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        insn.size = 2 + self.set_ld(insn, 0, 0, 0, sz, 1, 4, 2)
        insn.size += self.set_ld(insn, 1, 0, 2, sz, 1, 0, insn.size)

    def decode_b2_ad_sz2_rd_rs(self, insn):
        val0 = self.get_hl_byte(insn.ea+1)
        sz = val0 & 3
        if sz == 3:
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        val1 = self.get_hl_byte(insn.ea+2)
        ad = (val0 >> 2) & 3
        if ad & 2:
            insn.Op1.type = o_phrase
            insn.Op1.phrase = PHRASE_R_PLUS if ad == 2 else PHRASE_R_MINUS
            insn.Op1.reg = val1 >> 4
            self.set_reg(insn, 1, 2, 0)
        else:
            self.set_reg(insn, 0, 2, 0)
            insn.Op2.type = o_phrase
            insn.Op2.phrase = PHRASE_R_PLUS if ad == 0 else PHRASE_R_MINUS
            insn.Op2.reg = val1 >> 4
        insn.size = 3

    def decode_b1_sz1_dsp5_rs_rd(self, insn):
        val0 = self.get_hl_byte(insn.ea)
        sz = (val0 >> 3) & 1
        insn.memex = sz | MEMEX_NEED_SHOW
        val1 = self.get_hl_byte(insn.ea+1)
        insn.Op1.type = o_displ
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_memex_scale(sz) * (((val0 & 7) << 2) | ((val1 >> 6) & 2) | ((val1 >> 3) & 1))
        insn.Op1.reg = (val1 >> 4) & 7  
        insn.Op2.type = o_reg
        insn.Op2.dtype = dt_byte
        insn.Op2.reg = val1 & 7
        insn.size = 2

    def decode_b1_sz1_ld_rs_rd(self, insn):
        sz = (self.get_hl_byte(insn.ea) >> 2) & 1
        insn.memex = sz | MEMEX_NEED_SHOW
        insn.size = 2 + self.set_ld(insn, 0, 0, 0, sz, 1, 4, 2)
        self.set_reg(insn, 1, 1, 0)

    def decode_b2_sz1_ri_rb_rd(self, insn):
        val0 = self.get_hl_byte(insn.ea+1)
        insn.memex = ((val0 >> 4) & 1) | MEMEX_NEED_SHOW
        insn.Op1.type = o_phrase
        insn.Op1.phrase = PHRASE_R_R
        insn.Op1.value = val0 & 0x0F # ri
        val1 = self.get_hl_byte(insn.ea+2)
        insn.Op1.reg = (val1 >> 4) & 0x0F # rb
        self.set_reg(insn, 1, 2, 0) # rd
        insn.size = 3

    def decode_b2_ad_sz1_rs_rd(self, insn):
        val0 = self.get_hl_byte(insn.ea+1)
        ad = (val0 >> 2) & 3
        if ad < 2:
            return
        val1 = self.get_hl_byte(insn.ea+2)
        insn.memex = (val0 & 1) | MEMEX_NEED_SHOW
        insn.Op1.type = o_phrase
        insn.Op1.phrase = PHRASE_R_PLUS if ad == 2 else PHRASE_R_MINUS
        insn.Op1.value = val1 >> 4
        self.set_reg(insn, 1, 2, 0)
        insn.size = 3

    def decode_b2_li_rd(self, insn):
        insn.size = 2 + self.set_imm(insn, 0, 0, 0, 2)
        self.set_reg(insn, 1, 1, 0)

    def decode_b2_ld_rd_imm3(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea + 1) & 7
        insn.size = 2 + self.set_ld(insn, 1, 0, 0, MEMEX_B, 1, 4, 2)

    def decode_b2_ld_rd_rs(self, insn):
        self.set_reg(insn, 0, 2, 0)
        insn.size = 3 + self.set_ld(insn, 1, 1, 0, MEMEX_B, 2, 4, 3)        

    def decode_b1_imm5_rd(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value =  ((self.get_hl_byte(insn.ea) & 1) << 4) | ((self.get_hl_byte(insn.ea + 1) >> 4) & 0x0F)
        self.set_reg(insn, 1, 1, 0)
        insn.size = 2

    def decode_b1_cd_dsp3(self, insn):
        insn.Op1.type = o_near
        insn.Op1.dtype = dt_code
        data = self.get_hl_byte(insn.ea)
        insn.cond = (COND_NE if data & 8 else COND_EQ) + 1
        disp = data & 7
        if disp < 3:
            disp += 8
        insn.Op1.addr = insn.ea + disp
        insn.memex = MEMEX_S | MEMEX_NEED_SHOW
        insn.size = 1

    def decode_b1_cd_dsp8(self, insn):
        cd = self.get_hl_byte(insn.ea) & 0xf
        # skip BRA.B and reserved
        if cd == 0x0E or cd == 0x0F:
            return
        insn.cond = cd + 1
        insn.Op1.type = o_near
        insn.Op1.dtype = dt_code
        insn.Op1.addr = insn.ea + self.to_signed(self.get_hl_byte(insn.ea+1), 8)
        insn.memex = MEMEX_B | MEMEX_NEED_SHOW
        insn.size = 2

    def decode_b1_cd_dsp16(self, insn):
        insn.Op1.type = o_near
        insn.Op1.dtype = dt_code
        insn.memex = MEMEX_W | MEMEX_NEED_SHOW
        insn.cond = (COND_NE if self.get_hl_byte(insn.ea) & 1 else COND_EQ) + 1
        insn.Op1.addr = insn.ea + self.to_signed(self.get_hl_word(insn.ea+1), 16)
        insn.size = 3

    def decode_b2_imm3_ld_rs_cd(self, insn):
        cd = self.get_hl_byte(insn.ea+2) & 0xf
        if cd == 0x0E or cd == 0x0F:
            return
        insn.cond = cd
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = (self.get_hl_byte(insn.ea+1) >> 2) & 7
        insn.size = 3 + self.set_ld(insn, 1, 1, 0, MEMEX_B, 2, 4, 3)

    def decode_b2_imm5_cd_rd(self, insn):
        cd = (self.get_hl_byte(insn.ea+2) >> 4) & 0xf
        if cd == 0x0E or cd == 0x0F:
            return
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+1) & 0x01F
        self.set_reg(insn, 1, 2, 0)
        insn.memex = cd
        insn.size = 3

    def decode_b3_imm3_ld_rd(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = (self.get_hl_byte(insn.ea) >> 2) & 7
        insn.size = 3 + self.set_ld(insn, 1, 1, 0, MEMEX_B, 2, 4, 3)

    def decode_b1_dsp3(self, insn):
        insn.Op1.type = o_near
        insn.Op1.dtype = dt_code
        data = self.get_hl_byte(insn.ea)
        disp = data & 7
        if disp < 3:
            disp += 8
        insn.Op1.addr = insn.ea + disp
        insn.memex = MEMEX_S
        insn.size = 1

    def decode_b1_dsp8(self, insn):
        insn.Op1.type = o_near
        insn.Op1.dtype = dt_code
        insn.Op1.addr = insn.ea + self.to_signed(self.get_hl_byte(insn.ea+1), 8)
        insn.memex = MEMEX_B | MEMEX_NEED_SHOW
        insn.size = 2

    def decode_b1_dsp16(self, insn):
        insn.Op1.type = o_near
        insn.Op1.dtype = dt_code
        insn.Op1.addr = insn.ea + self.to_signed(self.get_hl_word(insn.ea+1), 16)
        insn.memex = MEMEX_W | MEMEX_NEED_SHOW
        insn.size = 3

    def decode_b1_dsp24(self, insn):
        insn.Op1.type = o_near
        insn.Op1.dtype = dt_code
        insn.Op1.addr = (insn.ea + self.to_signed(self.get_hl_bits24(insn.ea+1), 24)) & 0xFFFFFFFF
        insn.memex = MEMEX_A | MEMEX_NEED_SHOW
        insn.size = 4

    def decode_b1(self, insn):
        insn.size = 1

    def decode_b2_ld_rs_imm3(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+1) & 7
        insn.size = 2 + self.set_ld(insn, 1, 0, 0, MEMEX_B, 1, 4, 2)

    def decode_b2_ld_rs_rs2(self, insn):
        self.decode_b2_ld_rd_rs(insn)

    def decode_b1_imm5_rs(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = ((self.get_hl_byte(insn.ea) & 1) << 4) | (self.get_hl_byte(insn.ea+1) >> 4)
        self.set_reg(insn, 1, 1, 0)
        insn.size = 2

    def decode_b2_cb(self, insn):
        cb = self.get_hl_byte(insn.ea+1) & 0x0F
        if cb > 3 and cb < 8 or cb > 9:
            return
        insn.Op1.type = o_flag
        insn.Op1.value = cb
        insn.size = 2

    def decode_b1_uimm4_rs2(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+1) >> 4
        self.set_reg(insn, 1, 1, 0)
        insn.size = 2

    def decode_b2_rs2_uimm8(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+2)
        self.set_reg(insn, 1, 1, 0)
        insn.size = 3

    def decode_b2_li_rs2(self, insn):
        insn.size = 2 + self.set_imm(insn, 0, 0, 0, 2)
        self.set_reg(insn, 1, 1, 0)

    def decode_b3_li_rs2(self, insn):
        insn.size = 3 + self.set_imm(insn, 0, 1, 2, 3)
        self.set_reg(insn, 1, 2, 0)

    def decode_b3_reg_imm32(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_dword
        insn.Op1.value = self.get_hl_dword(insn.ea+3)
        self.set_reg(insn, 1, 2, 0)
        insn.size = 7

    def decode_b2_imm8(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+2)
        insn.size = 3

    def decode_b3_reg(self, insn):
        self.set_reg(insn, 0, 2, 0)
        insn.size = 3

    def decode_b2_cr_rd(self, insn):
        cr = self.get_hl_byte(insn.ea+2) >> 4
        if cr > 3 and cr < 8 or cr > 12:
            return
        insn.Op1.type = o_creg
        insn.Op1.dtype = dt_byte
        insn.Op1.value = cr
        self.set_reg(insn, 1, 2, 0)
        insn.size = 3

    def decode_b3_li_cr(self, insn):
        insn.size = 3 + self.set_imm(insn, 0, 1, 2, 3)
        cr = self.get_hl_byte(insn.ea+2) & 0x0F
        if cr == 1 or cr > 3 and cr < 8 or cr > 12:
            return
        insn.Op2.type = o_creg
        insn.Op2.dtype = dt_byte
        insn.Op2.value = cr

    def decode_b2_rs_cr(self, insn):
        cr = self.get_hl_byte(insn.ea+2) & 0x0F
        if cr == 1 or cr > 3 and cr < 8 or cr > 12:
            return
        self.set_reg(insn, 0, 2, 4)
        insn.Op2.type = o_creg
        insn.Op2.dtype = dt_byte
        insn.Op2.value = cr
        insn.size = 3

    def decode_b3_imm4(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+2) & 0x0F
        insn.size = 3

    def decode_b2_cr(self, insn):
        cr = self.get_hl_byte(insn.ea+1) & 0x0F
        if cr == 1 or cr > 3 and cr < 8 or cr > 12:
            return
        insn.Op1.type = o_creg
        insn.Op1.dtype = dt_byte
        insn.Op1.value = cr
        insn.size = 2

    def decode_b1_reg_reg2(self, insn):
        val = self.get_hl_byte(insn.ea+1)
        insn.Op1.type = o_phrase
        insn.Op1.dtype = dt_byte
        insn.Op1.value = val >> 4
        insn.Op1.reg = val & 0x0F
        insn.size = 2

    def decode_b2_sz2_rs(self, insn):
        sz = (self.get_hl_byte(insn.ea+1) >> 4) & 3
        if sz == 3:
            return
        insn.memex = sz
        self.set_reg(insn, 0, 1, 0)
        insn.size = 2

    def decode_b2_ld_rs_sz2(self, insn):
        sz = self.get_hl_byte(insn.ea+1) & 3
        if sz == 3:
            return
        insn.memex = sz
        insn.size = 2 + self.set_ld(insn, 0, 0, 0, sz, 1, 4, 2)

    def decode_b3_imm1(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.Value = 1 if self.get_hl_byte(insn.ea+2) & 0x10 == 0 else 2
        insn.size = 3

    def decode_b2_sz2(self, insn):
        insn.memex = self.get_hl_byte(insn.ea+1) & 3
        if insn.memex < 3:
            insn.size = 2

    def decode_b2_imm5_rd(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = ((self.get_hl_byte(insn.ea+1) & 1) << 4) | (self.get_hl_byte(insn.ea+2) >> 4)
        self.set_reg(insn, 1, 2, 0)
        insn.size = 3

    def decode_b2(self, insn):
        insn.size = 2

    def decode_b1_uimm8(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+1)
        insn.size = 2

    def decode_b1_rd_rd2(self, insn):
        val = self.get_hl_byte(insn.ea+1)
        insn.Op1.type = o_phrase
        insn.Op1.phrase = PHRASE_R_RANGE
        insn.Op1.value = val >> 4
        insn.Op1.reg = val & 0x0F
        insn.size = 2

    def decode_b1_rd_rd2_uimm8(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+2)
        val = self.get_hl_byte(insn.ea+1)
        insn.Op2.type = o_phrase
        insn.Op2.phrase = PHRASE_R_RANGE
        insn.Op2.value = val >> 4
        insn.Op2.reg = val & 0x0F
        insn.size = 3

    def decode_b3_ld_rs_rd(self, insn):
        insn.size = 4 + self.set_ld(insn, 0, 1, 0, MEMEX_L, 3, 4, 4)
        self.set_reg(insn, 1, 3, 0)

    def decode_b2_sz2_ld_rd_cd(self, insn):
        sz = (self.get_hl_byte(insn.ea+1) >> 2) & 3
        if sz == 3: 
            return
        insn.memex = sz | MEMEX_NEED_SHOW
        insn.size = 3 + self.set_ld(insn, 0, 1, 0, sz, 2, 4, 3) 
        cd = self.get_hl_byte(insn.ea+2) & 0x0F
        if cd == 0x0E or cd == 0x0F:
            insn.size = 0
            return
        insn.cond = cd + 1

    def decode_b2_imm5_rs2_rd(self, insn):
        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_byte
        insn.Op1.value = self.get_hl_byte(insn.ea+1) & 0x1F
        self.set_reg(insn, 1, 2, 4)
        self.set_reg(insn, 2, 2, 0)
        insn.size = 3
        return

    # TODO: make gynamic instruction groups

    def get_itype_group(self, itype):
        return self.itable[itype]['group']  

    def init_instructions(self):
        self.itable = [
            { 'name': 'abs_1',      'mnem': [ 0x7e, 0xff, 0x20, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_CHG1, 'group' : RX_GROUP_ABS },
            { 'name': 'abs_2',      'mnem': [ 0xfc, 0xff, 0x0f, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_ABS },
            { 'name': 'adc_1',      'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0x20, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_ADC },
            { 'name': 'adc_2',      'mnem': [ 0xfc, 0xff, 0x0b, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_ADC  },
            { 'name': 'adc_3',      'mnem': [ 0x06, 0xff, 0xa0, 0xfc, 0x20, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_ADC  },
            { 'name': 'add_1',      'mnem': [ 0x62, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_uimm4_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_ADD  },
            { 'name': 'add_3u',     'mnem': [ 0x48, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_ADD  },
            { 'name': 'add_3n',     'mnem': [ 0x06, 0xff, 0x08, 0x3c, 0x00, 0x00 ], 'decode': self.decode_b2_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_ADD },
            { 'name': 'add_4',      'mnem': [ 0x70, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_li_rs2_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG3, 'group' : RX_GROUP_ADD },
            { 'name': 'add_5',      'mnem': [ 0xff, 0xff, 0x20, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_rd_rs_rs2, 'feature': CF_USE1 | CF_USE2 | CF_CHG3, 'group' : RX_GROUP_ADD },
            { 'name': 'and_1',      'mnem': [ 0x64, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_uimm4_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_AND },
            { 'name': 'and_2',      'mnem': [ 0x74, 0xfc, 0x20, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_AND },
            { 'name': 'and_3u',     'mnem': [ 0x50, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_AND },
            { 'name': 'and_3n',     'mnem': [ 0x06, 0xff, 0x08, 0x3c, 0x00, 0x00 ], 'decode': self.decode_b2_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_AND },
            { 'name': 'and_4',      'mnem': [ 0xff, 0xff, 0x40, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_rd_rs_rs2, 'feature': CF_USE1 | CF_USE2 | CF_CHG3, 'group' : RX_GROUP_AND },
            { 'name': 'bclr_1',     'mnem': [ 0xf0, 0xfc, 0x08, 0x08, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rd_imm3, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BCLR  },
            { 'name': 'bclr_2',     'mnem': [ 0xfc, 0xff, 0x64, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rd_rs, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BCLR  },
            { 'name': 'bclr_3',     'mnem': [ 0x7a, 0xfe, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_imm5_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BCLR  },
            { 'name': 'b_1',        'mnem': [ 0x10, 0xf0, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_cd_dsp3, 'feature': CF_USE1, 'group' : RX_GROUP_B },
            { 'name': 'b_2',        'mnem': [ 0x20, 0xf0, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_cd_dsp8, 'feature': CF_USE1, 'group' : RX_GROUP_B },
            { 'name': 'b_3',        'mnem': [ 0x3a, 0xfe, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_cd_dsp16, 'feature': CF_USE1, 'group' : RX_GROUP_B },
            { 'name': 'bm_1',       'mnem': [ 0xfc, 0xff, 0xe0, 0xe0, 0x00, 0x00 ], 'decode': self.decode_b2_imm3_ld_rs_cd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BM },
            { 'name': 'bm_2',       'mnem': [ 0xfd, 0xff, 0xe0, 0xe0, 0x00, 0x00 ], 'decode': self.decode_b2_imm5_cd_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BM },
            { 'name': 'bnot_1',     'mnem': [ 0xfc, 0xff, 0xe0, 0xe0, 0x0f, 0x0f ], 'decode': self.decode_b3_imm3_ld_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BNOT },
            { 'name': 'bnot_2',     'mnem': [ 0xfc, 0xff, 0x6c, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rd_rs, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BNOT },
            { 'name': 'bnot_3',     'mnem': [ 0xfd, 0xff, 0xe0, 0xe0, 0xf0, 0xf0 ], 'decode': self.decode_b2_ld_rd_rs, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BNOT },
            { 'name': 'bra_1',      'mnem': [ 0x08, 0xf8, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_dsp3, 'feature': CF_USE1 | CF_USE1, 'group' : RX_GROUP_BRA },
            { 'name': 'bra_2',      'mnem': [ 0x2e, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_dsp8, 'feature': CF_USE1 | CF_USE1, 'group' : RX_GROUP_BRA },
            { 'name': 'bra_3',      'mnem': [ 0x38, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_dsp16, 'feature': CF_USE1 | CF_USE1, 'group' : RX_GROUP_BRA },
            { 'name': 'bra_4',      'mnem': [ 0x04, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_dsp24, 'feature': CF_USE1 | CF_USE1, 'group' : RX_GROUP_BRA },
            { 'name': 'bra_5',      'mnem': [ 0x7f, 0xff, 0x40, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_USE1, 'group' : RX_GROUP_BRA },
            { 'name': 'brk',        'mnem': [ 0x00, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1, 'feature': CF_STOP, 'group' : RX_GROUP_BRK },
            { 'name': 'bset_1',     'mnem': [ 0xf0, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rd_imm3, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BSET },
            { 'name': 'bset_2',     'mnem': [ 0xfc, 0xff, 0x60, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rd_rs, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BSET },
            { 'name': 'bset_3',     'mnem': [ 0x78, 0xfe, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_imm5_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_BSET },
            { 'name': 'bsr_1',      'mnem': [ 0x39, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_dsp16, 'feature': CF_USE1 | CF_USE2 | CF_CALL, 'group' : RX_GROUP_BSR },
            { 'name': 'bsr_2',      'mnem': [ 0x05, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_dsp24, 'feature': CF_USE1 | CF_USE2 | CF_CALL, 'group' : RX_GROUP_BSR },
            { 'name': 'bsr.l_3',    'mnem': [ 0x7f, 0xff, 0x50, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_USE2 | CF_CALL, 'group' : RX_GROUP_BSR },
            { 'name': 'btst_1',     'mnem': [ 0xf4, 0xfc, 0x00, 0x08, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_imm3, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_BTST },
            { 'name': 'btst_2',     'mnem': [ 0xfc, 0xff, 0x68, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rs2, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_BTST },
            { 'name': 'btst_3',     'mnem': [ 0x7c, 0xfe, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_imm5_rs, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_BTST },
            { 'name': 'clrpsw',     'mnem': [ 0x7f, 0xff, 0xb0, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_cb, 'feature': CF_CHG1, 'group' : RX_GROUP_CLRPSW },
            { 'name': 'cmp_1',      'mnem': [ 0x61, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_uimm4_rs2, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_CMP },
            { 'name': 'cmp_2',      'mnem': [ 0x75, 0xff, 0x50, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_rs2_uimm8, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_CMP },
            { 'name': 'cmp_3',      'mnem': [ 0x74, 0xfc, 0x00, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_li_rs2, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_CMP },
            { 'name': 'cmp_4u',     'mnem': [ 0x44, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_ld_rs_rd, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_CMP },
            { 'name': 'cmp_4n',     'mnem': [ 0x06, 0xff, 0x04, 0x3c, 0x00, 0x00 ], 'decode': self.decode_b2_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_CMP },
            { 'name': 'div_1',      'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0x80, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_DIV},
            { 'name': 'div_2u',     'mnem': [ 0xfc, 0xff, 0x20, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_DIV },
            { 'name': 'div_2n',     'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x08, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_DIV },
            { 'name': 'divu_1',     'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0x90, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_DIVU },
            { 'name': 'divu_2u',    'mnem': [ 0xfc, 0xff, 0x24, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_DIVU },
            { 'name': 'divu_2n',    'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x80, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_DIVU },
            { 'name': 'emul_1',     'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0x60, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_EMUL },
            { 'name': 'emul_2u',    'mnem': [ 0xfc, 0xff, 0x18, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_EMUL },
            { 'name': 'emul_2n',    'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x06, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_EMUL },
            { 'name': 'emulu_1',    'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0x70, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_EMULU },
            { 'name': 'emulu_2u',   'mnem': [ 0xfc, 0xff, 0x1c, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_EMULU },
            { 'name': 'emulu_2n',   'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x07, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_EMULU },
            { 'name': 'fadd_1',     'mnem': [ 0xfd, 0xff, 0x72, 0xff, 0x20, 0xf0 ], 'decode': self.decode_b3_reg_imm32, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_FADD },
            { 'name': 'fadd_2',     'mnem': [ 0xfc, 0xff, 0x88, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_FADD },
            { 'name': 'fcmp_1',     'mnem': [ 0xfd, 0xff, 0x72, 0xff, 0x10, 0xf0 ], 'decode': self.decode_b3_reg_imm32, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_FCMP },
            { 'name': 'fcmp_2',     'mnem': [ 0xfc, 0xff, 0x84, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rs2, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_FCMP },
            { 'name': 'fdiv_1',     'mnem': [ 0xfd, 0xff, 0x72, 0xff, 0x40, 0xf0 ], 'decode': self.decode_b3_reg_imm32, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_FDIV },
            { 'name': 'fdiv_2',     'mnem': [ 0xfc, 0xff, 0x90, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_FDIV },
            { 'name': 'fmul_1',     'mnem': [ 0xfd, 0xff, 0x72, 0xff, 0x30, 0xf0 ], 'decode': self.decode_b3_reg_imm32, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_FMUL },
            { 'name': 'fmul_2',     'mnem': [ 0xfc, 0xff, 0x8c, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_FMUL },
            { 'name': 'fsub_1',     'mnem': [ 0xfd, 0xff, 0x72, 0xff, 0x00, 0xf0 ], 'decode': self.decode_b3_reg_imm32, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_FSUB },
            { 'name': 'fsub_2',     'mnem': [ 0xfc, 0xff, 0x80, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_FSUB },
            { 'name': 'ftoi',       'mnem': [ 0xfc, 0xff, 0x94, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_FTOI },
            { 'name': 'int',        'mnem': [ 0x75, 0xff, 0x60, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_imm8, 'feature': CF_USE1, 'group' : RX_GROUP_INT },
            { 'name': 'itof_1u',    'mnem': [ 0xfc, 0xff, 0x44, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_ITOF },
            { 'name': 'itof_1n',    'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x11, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_ITOF },
            { 'name': 'jmp',        'mnem': [ 0x7f, 0xff, 0x00, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_JUMP, 'group' : RX_GROUP_JMP },
            { 'name': 'jsr',        'mnem': [ 0x7f, 0xff, 0x10, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_CALL, 'group' : RX_GROUP_JSR },
            { 'name': 'machi',      'mnem': [ 0xfd, 0xff, 0x04, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_MACHI },
            { 'name': 'maclo',      'mnem': [ 0xfd, 0xff, 0x05, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_MACLO },
            { 'name': 'max_1',      'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0x40, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MAX },
            { 'name': 'max_2u',     'mnem': [ 0xfc, 0xff, 0x10, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MAX },
            { 'name': 'max_2n',     'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x04, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MAX },
            { 'name': 'min_1',      'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0x50, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MIN },
            { 'name': 'min_2u',     'mnem': [ 0xfc, 0xff, 0x14, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MIN },
            { 'name': 'min_2n',     'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x05, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MIN },
            { 'name': 'mov_1',      'mnem': [ 0x80, 0xc8, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz2_dsp5_rd_rs, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_2',      'mnem': [ 0x88, 0xc8, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz2_dsp5_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_3',      'mnem': [ 0x66, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_uimm4_rd_with_memex, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_4',      'mnem': [ 0x3c, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz2_dsp5_rd_uimm8, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_5',      'mnem': [ 0x75, 0xff, 0x40, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_rd_uimm8, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_6',      'mnem': [ 0xfb, 0xff, 0x02, 0x03, 0x00, 0x00 ], 'decode': self.decode_b2_rd_li, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_7',      'mnem': [ 0xcf, 0xcf, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz2_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_8',      'mnem': [ 0xf8, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_ld_rd_li_sz2, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_9',      'mnem': [ 0xcc, 0xcc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz2_ld_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_10',     'mnem': [ 0xfe, 0xff, 0x40, 0xc0, 0x00, 0x00 ], 'decode': self.decode_b2_sz2_ri_rb_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_11',     'mnem': [ 0xc3, 0xc3, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz2_ld_rd_rs, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_12',     'mnem': [ 0xfe, 0xff, 0x00, 0xc0, 0x00, 0x00 ], 'decode': self.decode_b2_sz2_ri_rb_rs, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_13',     'mnem': [ 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz2_ldd_lds_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV },
            { 'name': 'mov_14_15',  'mnem': [ 0xfd, 0xff, 0x20, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_ad_sz2_rd_rs, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOV }, 
            { 'name': 'movu_1',     'mnem': [ 0xb0, 0xf0, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz1_dsp5_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOVU },
            { 'name': 'movu_2',     'mnem': [ 0x58, 0xf8, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_sz1_ld_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOVU },
            { 'name': 'movu_3',     'mnem': [ 0xfe, 0xff, 0xc0, 0xe0, 0x00, 0x00 ], 'decode': self.decode_b2_sz1_ri_rb_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOVU },
            { 'name': 'movu_4',     'mnem': [ 0xfd, 0xff, 0x30, 0xf2, 0x00, 0x00 ], 'decode': self.decode_b2_ad_sz1_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MOVU },
            { 'name': 'mul_1',      'mnem': [ 0x63, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_uimm4_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MUL },
            { 'name': 'mul_2',      'mnem': [ 0x74, 0xfc, 0x10, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MUL },
            { 'name': 'mul_3u',     'mnem': [ 0x4c, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MUL },
            { 'name': 'mul_3n',     'mnem': [ 0x06, 0xff, 0x0c, 0x3c, 0x00, 0x00 ], 'decode': self.decode_b2_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_MUL },
            { 'name': 'mul_4',      'mnem': [ 0xff, 0xff, 0x30, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_rd_rs_rs2, 'feature': CF_USE1 | CF_USE2 | CF_CHG3, 'group' : RX_GROUP_MUL },
            { 'name': 'mulhi',      'mnem': [ 0xfd, 0xff, 0x00, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_MULHI },
            { 'name': 'mullo',      'mnem': [ 0xfd, 0xff, 0x01, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_MULLO },
            { 'name': 'mvfachi',    'mnem': [ 0xfd, 0xff, 0x1f, 0xff, 0x00, 0xf0 ], 'decode': self.decode_b3_reg, 'feature': CF_CHG1, 'group' : RX_GROUP_MVFACHI },
            { 'name': 'mvfacmi',    'mnem': [ 0xfd, 0xff, 0x1f, 0xff, 0x20, 0xf0 ], 'decode': self.decode_b3_reg, 'feature': CF_CHG1, 'group' : RX_GROUP_MVFACMI },
            { 'name': 'mvfc',       'mnem': [ 0xfd, 0xff, 0x6a, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_cr_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MVFC },
            { 'name': 'mvtachi',    'mnem': [ 0xfd, 0xff, 0x17, 0xff, 0x00, 0xf0 ], 'decode': self.decode_b3_reg, 'feature': CF_USE1, 'group' : RX_GROUP_MVTACHI },
            { 'name': 'mvtaclo',    'mnem': [ 0xfd, 0xff, 0x17, 0xff, 0x10, 0xf0 ], 'decode': self.decode_b3_reg, 'feature': CF_USE1, 'group' : RX_GROUP_MVTACLO },
            { 'name': 'mvtc_1',     'mnem': [ 0xfd, 0xff, 0x73, 0xf3, 0x00, 0xf0 ], 'decode': self.decode_b3_li_cr, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MVTC },
            { 'name': 'mvtc_2',     'mnem': [ 0xfd, 0xff, 0x68, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_cr, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_MVTC },
            { 'name': 'mvtipl',     'mnem': [ 0x75, 0xff, 0x70, 0xff, 0x00, 0xf0 ], 'decode': self.decode_b3_imm4, 'feature': CF_USE1, 'group' : RX_GROUP_MVTIPL },
            { 'name': 'neg_1',      'mnem': [ 0x7e, 0xff, 0x10, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_CHG1, 'group' : RX_GROUP_NEG },
            { 'name': 'neg_2',      'mnem': [ 0xfc, 0xff, 0x07, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_NEG },
            { 'name': 'nop',        'mnem': [ 0x03, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1, 'feature': 0, 'group' : RX_GROUP_NOP },
            { 'name': 'not_1',      'mnem': [ 0x7e, 0xff, 0x00, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_CHG1, 'group' : RX_GROUP_NOT },
            { 'name': 'not_2',      'mnem': [ 0xfc, 0xff, 0x3b, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_NOT },
            { 'name': 'or_1',       'mnem': [ 0x65, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_uimm4_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_OR  },
            { 'name': 'or_2',       'mnem': [ 0x74, 0xfc, 0x30, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_OR  },
            { 'name': 'or_3u',      'mnem': [ 0x54, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_OR  },
            { 'name': 'or_3n',      'mnem': [ 0x06, 0xff, 0x14, 0x3c, 0x00, 0x00 ], 'decode': self.decode_b2_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_OR  },
            { 'name': 'or_4',       'mnem': [ 0xff, 0xff, 0x50, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_rd_rs_rs2, 'feature': CF_USE1 | CF_USE2 | CF_CHG3, 'group' : RX_GROUP_OR  },
            { 'name': 'pop',        'mnem': [ 0x7e, 0xff, 0xb0, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_CHG1, 'group' : RX_GROUP_POP  },
            { 'name': 'popc',       'mnem': [ 0x7e, 0xff, 0xe0, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_cr, 'feature': CF_CHG1, 'group' : RX_GROUP_POPC },
            { 'name': 'popm',       'mnem': [ 0x6f, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_rd_rd2, 'feature': CF_CHG1 | CF_CHG2, 'group' : RX_GROUP_POPM },
            { 'name': 'push_1',     'mnem': [ 0x7e, 0xff, 0x80, 0xc0, 0x00, 0x00 ], 'decode': self.decode_b2_sz2_rs, 'feature': CF_USE1, 'group' : RX_GROUP_PUSH },
            { 'name': 'push_2',     'mnem': [ 0xf4, 0xfc, 0x08, 0x0c, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_sz2, 'feature': CF_USE1, 'group' : RX_GROUP_PUSH },
            { 'name': 'pushc',      'mnem': [ 0x7e, 0xff, 0xc0, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_cr, 'feature': CF_USE1, 'group' : RX_GROUP_PUSHC },
            { 'name': 'pushm',      'mnem': [ 0x6e, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_rd_rd2, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_PUSHM },
            { 'name': 'racw',       'mnem': [ 0xfd, 0xff, 0x48, 0xff, 0x00, 0xef ], 'decode': self.decode_b3_imm1, 'feature': CF_USE1, 'group' : RX_GROUP_RACW },
            { 'name': 'revl',       'mnem': [ 0xfd, 0xff, 0x67, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_REVL },
            { 'name': 'revw',       'mnem': [ 0xfd, 0xff, 0x65, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_REVW },
            { 'name': 'rmpa',       'mnem': [ 0x7f, 0xff, 0x8c, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_sz2, 'feature': 0, 'group' : RX_GROUP_RMPA },
            { 'name': 'rolc',       'mnem': [ 0x7e, 0xff, 0x50, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_CHG1 | CF_SHFT, 'group' : RX_GROUP_ROLC  },
            { 'name': 'rorc',       'mnem': [ 0x7e, 0xff, 0x40, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_USE1 | CF_CHG1 | CF_SHFT, 'group' : RX_GROUP_RORC  },
            { 'name': 'rotl_1',     'mnem': [ 0xfd, 0xff, 0x6e, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_imm5_rd, 'feature': CF_USE1 | CF_CHG1 | CF_SHFT, 'group' : RX_GROUP_ROTL  },
            { 'name': 'rotl_2',     'mnem': [ 0xfd, 0xff, 0x66, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_ROTL  },
            { 'name': 'rotr_1',     'mnem': [ 0xfd, 0xff, 0x6e, 0xfe, 0x00, 0x00 ], 'decode': self.decode_b2_imm5_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_ROTR  },
            { 'name': 'rotr_2',     'mnem': [ 0xfd, 0xff, 0x64, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_ROTR  },
            { 'name': 'round',      'mnem': [ 0xfc, 0xff, 0x98, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_CHG1 | CF_CHG2, 'group' : RX_GROUP_ROUND },
            { 'name': 'rte',        'mnem': [ 0x7f, 0xff, 0x95, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2, 'feature': CF_STOP, 'group' : RX_GROUP_RTE },
            { 'name': 'rtfi',       'mnem': [ 0x7f, 0xff, 0x94, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2, 'feature': CF_STOP, 'group' : RX_GROUP_RTFI },
            { 'name': 'rts',        'mnem': [ 0x02, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1, 'feature': CF_STOP, 'group' : RX_GROUP_RTS },
            { 'name': 'rtsd_1',     'mnem': [ 0x67, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_uimm8, 'feature': CF_USE1 | CF_STOP,  'group' : RX_GROUP_RTSD },
            { 'name': 'rtsd_2',     'mnem': [ 0x3f, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_rd_rd2_uimm8, 'feature': CF_USE1 | CF_CHG2 | CF_CHG3 | CF_STOP,  'group' : RX_GROUP_RTSD },
            { 'name': 'sat',        'mnem': [ 0x7e, 0xff, 0x30, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_reg, 'feature': CF_CHG1, 'group' : RX_GROUP_SAT },
            { 'name': 'satr',       'mnem': [ 0x7f, 0xff, 0x93, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2, 'feature': 0, 'group' : RX_GROUP_SATR },
            { 'name': 'sbb_1',      'mnem': [ 0xfc, 0xff, 0x00, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_SBB },
            { 'name': 'sbb_2',      'mnem': [ 0x06, 0xff, 0xa0, 0xfc, 0x00, 0xff ], 'decode': self.decode_b3_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_SBB },
            { 'name': 'sc',         'mnem': [ 0xfc, 0xff, 0xd0, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_sz2_ld_rd_cd, 'feature': CF_CHG1, 'group' : RX_GROUP_SC  },
            { 'name': 'scmpu',      'mnem': [ 0x7f, 0xff, 0x83, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2, 'feature': 0, 'group' : RX_GROUP_SCMPU },
            { 'name': 'setpsw',     'mnem': [ 0x7f, 0xff, 0xa0, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_cb, 'feature': CF_CHG1, 'group' : RX_GROUP_SETPSW },
            { 'name': 'shar_1',     'mnem': [ 0x6a, 0xfe, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_imm5_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_SHAR },
            { 'name': 'shar_2',     'mnem': [ 0xfd, 0xff, 0x61, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_SHAR },
            { 'name': 'shar_3',     'mnem': [ 0xfd, 0xff, 0xa0, 0xe0, 0x00, 0x00 ], 'decode': self.decode_b2_imm5_rs2_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG3 | CF_SHFT, 'group' : RX_GROUP_SHAR },
            { 'name': 'shll_1',     'mnem': [ 0x6c, 0xfe, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_imm5_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_SHLL },
            { 'name': 'shll_2',     'mnem': [ 0xfd, 0xff, 0x62, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_SHLL },
            { 'name': 'shll_3',     'mnem': [ 0xfd, 0xff, 0xc0, 0xe0, 0x00, 0x00 ], 'decode': self.decode_b2_imm5_rs2_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG3 | CF_SHFT, 'group' : RX_GROUP_SHLL },
            { 'name': 'shrl_1',     'mnem': [ 0x68, 0xfe, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_imm5_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_SHLR },
            { 'name': 'shrl_2',     'mnem': [ 0xfd, 0xff, 0x60, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2 | CF_SHFT, 'group' : RX_GROUP_SHLR },
            { 'name': 'shrl_3',     'mnem': [ 0xfd, 0xff, 0x80, 0xe0, 0x00, 0x00 ], 'decode': self.decode_b2_imm5_rs2_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG3 | CF_SHFT, 'group' : RX_GROUP_SHLR },
            { 'name': 'smovb',      'mnem': [ 0x7f, 0xff, 0x8b, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2, 'feature': 0, 'group' : RX_GROUP_SMOVB },
            { 'name': 'smovf',      'mnem': [ 0x7f, 0xff, 0x8f, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2, 'feature': 0, 'group' : RX_GROUP_SMOVF },
            { 'name': 'smovu',      'mnem': [ 0x7f, 0xff, 0x87, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2, 'feature': 0, 'group' : RX_GROUP_SMOVU },
            { 'name': 'sstr',       'mnem': [ 0x7f, 0xff, 0x88, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2_sz2, 'feature': 0, 'group' : RX_GROUP_SSTR },
            { 'name': 'stnz',       'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0xf0, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_STNZ },
            { 'name': 'stz',        'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0xe0, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_CHG2, 'group' : RX_GROUP_STZ },
            { 'name': 'sub_1',      'mnem': [ 0x60, 0xff, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_uimm4_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_SUB },
            { 'name': 'sub_2u',     'mnem': [ 0x40, 0xfc, 0x00, 0x00, 0x00, 0x00 ], 'decode': self.decode_b1_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_SUB },
            { 'name': 'sub_2n',     'mnem': [ 0x06, 0xff, 0x00, 0x3c, 0x00, 0x00 ], 'decode': self.decode_b2_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_SUB },
            { 'name': 'sub_3',      'mnem': [ 0xff, 0xff, 0x00, 0xf0, 0x00, 0x00 ], 'decode': self.decode_b2_rd_rs_rs2, 'feature': CF_USE1 | CF_USE2 | CF_CHG3, 'group' : RX_GROUP_SUB },
            { 'name': 'suntil',     'mnem': [ 0x7f, 0xff, 0x80, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_sz2, 'feature': 0, 'group' : RX_GROUP_SUNTIL },
            { 'name': 'swhile',     'mnem': [ 0x7f, 0xff, 0x84, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_sz2, 'feature': 0, 'group' : RX_GROUP_SWHILE },
            { 'name': 'tst_1',      'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0xc0, 0xf0 ], 'decode': self.decode_b3_li_rs2, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_TST },
            { 'name': 'tst_2u',     'mnem': [ 0xfc, 0xff, 0x30, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rs2, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_TST },
            { 'name': 'tst_2n',     'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0xc0, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2, 'group' : RX_GROUP_TST },
            { 'name': 'wait',       'mnem': [ 0x7f, 0xff, 0x96, 0xff, 0x00, 0x00 ], 'decode': self.decode_b2, 'feature': 0, 'group' : RX_GROUP_WAIT },
            { 'name': 'xchg_1u',    'mnem': [ 0xfc, 0xff, 0x40, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2, 'group' : RX_GROUP_XCHG },
            { 'name': 'xchg_1n',    'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x10, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2, 'group' : RX_GROUP_XCHG },
            { 'name': 'xor_1',      'mnem': [ 0xfd, 0xff, 0x70, 0xf3, 0xd0, 0xf0 ], 'decode': self.decode_b3_li_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_XOR },
            { 'name': 'xor_2u',     'mnem': [ 0xfc, 0xff, 0x34, 0xfc, 0x00, 0x00 ], 'decode': self.decode_b2_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_XOR },
            { 'name': 'xor_2n',     'mnem': [ 0x06, 0xff, 0x20, 0x3c, 0x0d, 0xff ], 'decode': self.decode_b3_mi_ld_rs_rd, 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'group' : RX_GROUP_XOR },
        ]

        # Now create an instruction table compatible with IDA processor module requirements
        Instructions = []
        i = 0
        for x in self.itable:
            name = x['name'].split("_")[0]
            d = dict(name=name, feature=x['feature'])
            Instructions.append(d)
            setattr(self, 'itype_' + name, i)
            i += 1

        self.instruc_start = 0
        self.instruc_end = len(Instructions)

        # Array of instructions
        self.instruc = Instructions

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_rts                    

    def ev_out_operand(self, ctx: outctx_t, op):
        optype = op.type

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif optype == o_creg:
            ctx.out_register(self.creg_names[op.value])

        elif optype == o_imm:
            ctx.out_symbol('#')
            if op.dtype == dt_byte:
                op.value &= 0xFF
            elif op.dtype == dt_word:
                op.value &= 0xFFFF
            #ctx.out_value(op, OOFW_IMM | OOFS_NOSIGN)
            ctx.out_value(op, OOFW_IMM)

        elif optype in [o_near, o_mem]:
            if not ctx.out_name_expr(op, op.addr, BADADDR):
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)                

        elif optype == o_displ:
            if op.value != 0:
                ctx.out_value(op, OOF_NUMBER | OOFS_NOSIGN | OOFW_32)

            ctx.out_symbol('[')
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(']')

            if (op.memex & MEMEX_NEED_SHOW) == MEMEX_NEED_SHOW:
                ctx.out_line(memex_names[ ctx.insn.memex & 7 ])

        elif optype == o_phrase:
            if op.phrase == PHRASE_R_MINUS:
                ctx.out_symbol('[')
                ctx.out_symbol('-')
                ctx.out_register(self.reg_names[op.reg])
                ctx.out_symbol(']')
            elif op.phrase == PHRASE_R_PLUS:
                ctx.out_symbol('[')
                ctx.out_register(self.reg_names[op.reg])
                ctx.out_symbol('+')
                ctx.out_symbol(']')
            elif op.phrase == PHRASE_R_R:
                ctx.out_symbol('[')
                ctx.out_register(self.reg_names[op.value&0xF])
                ctx.out_symbol(',')
                ctx.out_symbol(' ')
                ctx.out_register(self.reg_names[op.reg])
                ctx.out_symbol(']')
            elif op.phrase == PHRASE_R_RANGE:
                ctx.out_register(self.reg_names[op.value&0xF])
                ctx.out_symbol('-')
                ctx.out_register(self.reg_names[op.reg])
            else:
                ctx.out_register(self.reg_names[op.reg])
        
        elif optype == o_flag:
                ctx.out_register(self.flag_names[op.value&0xF])

        else:
            return False

        return True

    def handle_operand(self, insn, op, is_read):
        optype = op.type
        feats = insn.get_canon_feature()
        if optype == o_near:
            if feats & CF_CALL:
                insn.add_cref(op.addr, op.offb, fl_CN)
            elif feats & CF_JUMP:
                insn.add_cref(op.addr, op.offb, fl_JN)
            elif self.get_itype_group(insn.itype) in [RX_GROUP_BRA, RX_GROUP_B, RX_GROUP_BM]:
                insn.add_cref(op.addr, 0, fl_JN)
        elif optype == o_imm:
            if ida_bytes.op_adds_xrefs(ida_bytes.get_flags(insn.ea), op.n):
                ida_ua.insn_add_off_drefs(insn, op, dr_O, OOFW_IMM|OOF_SIGNED)

    def get_ui_value(self, value, type):
        if type == dt_byte:
            value = value & 0xff
        elif type == dt_word:
            value = value & 0xffff
        return hex(value) if value > 9 else value

    def ev_emu_insn(self, insn):
        feature = insn.get_canon_feature()
        
        if feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, 1)
        if feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, 0)
        if feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, 1)
        if feature & CF_CHG2:
            self.handle_operand(insn, insn.Op2, 0)
        if feature & CF_CHG3:
            self.handle_operand(insn, insn.Op3, 0)
        if feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        # add flow
        flow = feature & CF_STOP == 0
        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        # mov.l #imm, rX
        # jsr rX

        if insn.itype == self.itype_jsr:
            prev = insn_t()
            if decode_prev_insn(prev, insn.ea) != BADADDR:
                if self.get_itype_group(prev.itype) == RX_GROUP_MOV and \
                    prev.Op1.type == o_imm and \
                    prev.Op2.type == o_reg and \
                    prev.Op2.reg == insn.Op1.reg:
                        prev.add_cref(prev.Op1.value, prev.Op1.offb, fl_CN) # call to immediate address

        ## mov.l #imm0, reg ?
        # mov.l #imm, rX
        # mov.? #imm/reg, disp[rX] ; set 0x(imm0)

        # TODO: check, need exist segment of data

        if self.get_itype_group(insn.itype) in [RX_GROUP_MOV, RX_GROUP_BSET, RX_GROUP_BCLR, RX_GROUP_BTST] and insn.Op2.type == o_displ:
            prev = insn_t()
            if decode_prev_insn(prev, insn.ea) != BADADDR and \
                self.get_itype_group(prev.itype) == RX_GROUP_MOV and \
                prev.Op1.type == o_imm and \
                prev.Op2.type == o_reg and \
                prev.Op2.reg == insn.Op2.reg:
                    insn.add_dref(prev.Op1.value + insn.Op2.value, 0, dr_O) # data reference to immediate address
                    ida_offset.op_offset( prev.ea, 0, idc.REF_OFF32 )
                    if insn.Op1.type == o_reg:
                        prevprev = insn_t()
                        if decode_prev_insn(prevprev, prev.ea) != BADADDR and \
                            self.get_itype_group(prevprev.itype) == RX_GROUP_MOV and \
                            prevprev.Op1.type == o_imm and \
                            prevprev.Op2.type == o_reg and \
                            prevprev.Op2.reg == insn.Op1.reg:
                                idc.set_cmt(insn.ea, f"set {hex(prevprev.Op1.value) if prevprev.Op1.value > 9 else prevprev.Op1.value}", 0)
                    elif insn.Op1.type == o_imm:
                        idc.set_cmt(insn.ea, f"set {self.get_ui_value(insn.Op1.value, insn.Op1.dtype)}", 0)

        # mov.l #imm, rX
        # movu.? disp[rX], rY

        if self.get_itype_group(insn.itype) in [RX_GROUP_MOV, RX_GROUP_MOVU] and insn.Op1.type == o_displ:
            prev = insn_t()
            if decode_prev_insn(prev, insn.ea) != BADADDR:
                if self.get_itype_group(prev.itype) == RX_GROUP_MOV and \
                    prev.Op1.type == o_imm and \
                    prev.Op2.type == o_reg and \
                    prev.Op2.reg == insn.Op1.reg:
                        insn.add_dref(prev.Op1.value + insn.Op1.value, 0, dr_O) # data reference to immediate address
                        ida_offset.op_offset( prev.ea, 0, idc.REF_OFF32 )

        # mvtc #imm, intb

        if self.get_itype_group(insn.itype) == RX_GROUP_MVTC and insn.Op1.type == o_imm and insn.Op2.value == CR_INTB:
            if ida_segment.getseg(insn.ea) == ida_segment.getseg(insn.Op1.value):
                for i in range(0,256):
                    ida_offset.op_offset( insn.Op1.value + 4*i, 0, idc.REF_OFF32 )

        # and #imm, reg

        if self.get_itype_group(insn.itype) == RX_GROUP_AND and insn.Op1.type == o_imm:
            ida_bytes.op_num(insn.ea, 0)

        # float_inst #imm, ...

        if self.get_itype_group(insn.itype) in [RX_GROUP_FADD, RX_GROUP_FSUB, RX_GROUP_FMUL, RX_GROUP_FDIV, RX_GROUP_FCMP] and insn.Op1.type == o_imm:
            ida_bytes.op_flt(insn.ea, 0)

        return True


    def ev_out_insn(self, ctx : outctx_t):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        val = ""
        if ctx.insn.cond != 0:
            val = cond_names[ ctx.insn.cond-1 ]

        if (ctx.insn.memex & MEMEX_NEED_SHOW) == MEMEX_NEED_SHOW:
            val += memex_names[ ctx.insn.memex & 7 ]
        
        ctx.out_mnem(8, val)

        for i in range(0, 3):
            op = ctx.insn[i]
            if op.type == ida_ua.o_void:
                break
            if i > 0:
                ctx.out_symbol(',')
                ctx.out_char(' ')
            ctx.out_one_operand(i)

        # mov.l #imm, rX
        # mov.? #imm/reg, disp[rX] => #(imm+disp)

        xref = ida_xref.get_first_dref_from(ctx.insn.ea)
        if xref != BADADDR and ctx.insn.ops and any(op.type == o_displ for op in ctx.insn.ops):
            if ctx.insn.Op1.type != o_imm or (ctx.insn.Op1.type == o_imm and ctx.insn.Op1.value != xref):
                ctx.out_tagon(COLOR_RPTCMT)
                ctx.out_line(' => ')
                ctx.out_line(idc.get_name(xref))
                ctx.out_tagoff(COLOR_RPTCMT)

        # IDA BUG: ida_lines.get_extra_cmt -> don't work

        # prev = insn_t()
        # if decode_insn(prev, ctx.insn.ea) != BADADDR:
        #     group = self.get_itype_group(prev.itype)
        #     if group in [RX_GROUP_B, RX_GROUP_BM, RX_GROUP_BRA, RX_GROUP_JMP, RX_GROUP_JSR, RX_GROUP_BSR] \
        #         and idc.get_name(ctx.insn.ea) == '' \
        #         and ida_lines.get_extra_cmt(ctx.insn.ea, False) != "":
        #             ida_lines.add_extra_line(ctx.insn.ea, False, "")

        # if self.get_itype_group(ctx.insn.itype) in [RX_GROUP_RTS, RX_GROUP_RTE, RX_GROUP_RTFI, RX_GROUP_RTSD] \
        #     and (idc.get_name(ctx.insn.ea) == ''  or idc.get_name(ctx.insn.ea) != '_exit'):
        #         idc.set_name(ctx.insn.ea, '_exit', SN_NOWARN|SN_LOCAL)

        ctx.flush_outbuf()

    def ev_newprc(self, nproc, keep_cfg):
        """
        Before changing proccesor type
        nproc - processor number in the array of processor names
        return >=0-ok,<0-prohibit
        """
        return 0

    def ev_newfile(self, filename):
        """A new file is loaded (already)"""
        return 0

    def ev_newbinary(self, filename, fileoff, basepara, binoff, nbytes):
        """
        Before loading a binary file
         args:
          filename  - binary file name
          fileoff   - offset in the file
          basepara  - base loading paragraph
          binoff    - loader offset
          nbytes    - number of bytes to load
        """
        ida_ida.inf_set_be(True)

        ida_segment.add_segm(0, 0x00000000, 0x0001FFFF, 'IRAM', 'RAM')
        ida_segment.add_segm(0, 0x00080000, 0x000FFFFF, 'IOR0', 'RAM')
        ida_segment.add_segm(0, 0x00100000, 0x00107FFF, 'E2FLASH', 'ROM')
        ida_segment.add_segm(0, 0x007FC000, 0x007FC444, 'IOR1', 'RAM')
        ida_segment.add_segm(0, 0x08000000, 0x09FFFFFF, 'ERAM', 'RAM')

        return 0

    def notify_init(self, idp_file):
        ida_ida.inf_set_be(True)
        cfg_file = idaapi.getsysfile(f"{self.assembler['name']}.cfg", idaapi.CFG_SUBDIR)
        if cfg_file != None:
            print("Config file founded!")
        return 1

    def ev_ana_insn(self, insn: ida_ua.insn_t):
        """
        Decodes an instruction into insn
        """
        # TODO: make optimal tree search

        opcode0 = self.get_hl_byte(insn.ea)
        insn.size = 0
        i = -1
        for item in self.itable:
            mnem = item['mnem']
            decode = item['decode']
            i += 1
            if (opcode0 & mnem[1]) != mnem[0]:
                continue

            if mnem[3] == 0x00:
                insn.itype = i
                decode(insn)
                if insn.size > 0:
                    return True
                else:
                    continue

            opcode1 = self.get_hl_byte(insn.ea + 1)
            if (opcode1 & mnem[3]) != mnem[2]:
                continue

            if mnem[5] == 0x00:
                insn.itype = i
                decode(insn)
                if insn.size > 0:
                    return True
                else:
                    continue

            opcode2 = self.get_hl_byte(insn.ea + 2)
            if (opcode2 & mnem[5]) == mnem[4]:
                insn.itype = i
                decode(insn)
                if insn.size > 0:
                    return True
                else:
                    continue
        return False

    def init_registers(self):
        self.reg_names = [
            "sp", "r1", "r2", "r3", "r4", "r5", "r6","r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "isp", "usp", "intb", "pc", "psw", "bpc", "bpsw" "fintv", "fpsw", "cs", "ds"
        ]
        self.creg_names = [
            "psw", "pc", "usp", "fpsw", "", "", "", "", "bpsw", "bpc", "isp", "fintv", "intb", "", "", ""
        ]

        self.flag_names = ["c","z","s","o","","","","","i","u","","","","","",""]

        for i in range(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        self.reg_first_sreg = self.ireg_cs
        self.reg_last_sreg  = self.ireg_ds      
        self.reg_code_sreg = self.ireg_cs
        self.reg_data_sreg = self.ireg_ds

    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

def PROCESSOR_ENTRY():
    return rxv1_processor_t()