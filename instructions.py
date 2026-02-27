from ida_hexrays import *
from .cfgUtil import *
import logging
import z3

AND_TABLE = {1: 0xff, 2: 0xffff, 4: 0xffffffff, 8: 0xffffffffffffffff, 16: 0xffffffffffffffffffffffffffffffff}
JMP_OPCODE_HANDLED = [m_jnz, m_jz, m_jae, m_jb, m_ja, m_jbe, m_jge, m_jg, m_jl, m_jle]

helper_logger = logging.getLogger('gh.instrcution')
helper_logger.setLevel(logging.DEBUG)

class Instructions:
    def __init__(self, mba:mba_t):
        self.mba = mba
    def parse_mop(self, mop: mop_t):
        if mop.t == mop_d:
            return self.parse_minsn(mop.d)
        elif mop.t == mop_v:
            return z3.BitVec(f"{mop.g:X}", 64) & AND_TABLE[mop.size]
        elif mop.t == mop_r:
            return z3.BitVec(get_mreg_name(mop.r, mop.size), 64) & AND_TABLE[mop.size]
        elif mop.t == mop_S:
            return z3.BitVec(f"var_{mop.s.off:X}", 64) & AND_TABLE[mop.size]
        elif mop.t == mop_n:
            return z3.BitVecVal(mop.nnn.value, 64) & AND_TABLE[mop.size]
        else:
            raise NotImplementedError(f"Unsupported mop type: {mop.dstr()}")
        
    def parse_minsn(self, minsn: minsn_t):
        def setl(l, r):
            l = z3.Extract(minsn.l.size * 8 - 1, 0, l)
            r = z3.Extract(minsn.r.size * 8 - 1, 0, r)
            return z3.If(z3.SignExt(0, l) < z3.SignExt(0, r), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))

        def setg(l, r):
            l = z3.Extract(minsn.l.size * 8 - 1, 0, l)
            r = z3.Extract(minsn.r.size * 8 - 1, 0, r)
            return z3.If(z3.SignExt(0, l) > z3.SignExt(0, r), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        
        def setle(l, r):
            l = z3.Extract(minsn.l.size * 8 - 1, 0, l)
            r = z3.Extract(minsn.r.size * 8 - 1, 0, r)
            return z3.If(z3.SignExt(0, l) <= z3.SignExt(0, r), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))

        ops = {
            m_add   :   lambda l, r: l + r,
            m_sub   :   lambda l, r: l - r,
            m_mul   :   lambda l, r: l * r,
            m_and   :   lambda l, r: l & r,
            m_xor   :   lambda l, r: l ^ r,
            m_or    :   lambda l, r: l | r,
            m_udiv  :   lambda l, r: l // r,
            m_bnot  :   lambda l,  : ~l,
            m_shl   :   lambda l, r: l << r,
            m_shr   :   lambda l, r: l >> r,
            m_xdu   :   lambda l   : l,
            m_setl  :   setl,
            m_setle :   setle,
            m_setg  :   setg,
            m_setz  :   lambda l, r: z3.If(l == r, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64)),
            m_setnz :   lambda l, r: z3.If(l != r, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64)),
            m_lnot  :   lambda l   : z3.If(l != z3.BitVecVal(0, 64), z3.BitVecVal(0, 64), z3.BitVecVal(1, 64))
        }

        if minsn.opcode == m_ldx:
            return None

        if minsn.opcode in ops:
            bit_size = AND_TABLE[minsn.d.size]
            left = self.parse_mop(minsn.l) if minsn.l.t != mop_z else None
            right = self.parse_mop(minsn.r) if minsn.r.t != mop_z else None
            if right is None and left is not None:
                return ops[minsn.opcode](left) & bit_size
            elif left is None and right is not None:
                return ops[minsn.opcode](right) & bit_size
            elif left is not None and right is not None:
                return ops[minsn.opcode](left, right) & bit_size
            else:
                raise NotImplementedError(f"Missing operands for opcode: {minsn.dstr()}")
        else:
            raise NotImplementedError(f"Unsupported opcode: {minsn.dstr()}")
    
    def instructions_fix(self):
        for i in range(1, self.mba.qty - 1):
            mblock:mblock_t = self.mba.get_mblock(i)
            self.instructions_fix_in_mblock(mblock)
        self.mba.mark_chains_dirty()
        self.mba.optimize_local(0)
        self.mba.merge_blocks()
    
    def instructions_fix_in_mblock(self, mblock: mblock_t):
        minsn: minsn_t = mblock.head
        s = z3.Solver()
        while minsn:
            if minsn.opcode in JMP_OPCODE_HANDLED and minsn.l.t == mop_d:
                print(f"找到一个指令替换的混淆:{minsn.dstr()}")
                expr = self.parse_minsn(minsn.l.d)
                if expr is None:
                    minsn = minsn.next
                    continue
                s.push()
                s.add(expr == minsn.r.nnn.value)
                # print(s.check())
                equality = s.check().r
                s.pop()
                s.add(expr != minsn.r.nnn.value)
                # print(s.check())
                inequality = s.check().r
                # print(s.check)
                if equality != inequality:
                    if minsn.opcode == m_jz and equality == z3.Z3_L_TRUE:
                        mblock.remove_from_block(mblock.tail)
                        clear_edge(self.mba, mblock.serial)
                        insert_goto(mblock, minsn.d.b)
                        modify_edge(mblock.mba, mblock.serial, minsn.d.b)
                        mblock.mark_lists_dirty()
                    elif minsn.opcode == m_jz and equality == z3.Z3_L_FALSE:
                        mblock.remove_from_block(mblock.tail)
                        clear_edge(self.mba, mblock.serial)
                        modify_edge(mblock.mba, mblock.serial, mblock.serial + 1)
                        mblock.mark_lists_dirty()
                    elif minsn.opcode == m_jnz and inequality == z3.Z3_L_TRUE:
                        mblock.remove_from_block(mblock.tail)
                        clear_edge(self.mba, mblock.serial)
                        insert_goto(mblock, minsn.d.b)
                        modify_edge(mblock.mba, mblock.serial, minsn.d.b)
                        mblock.mark_lists_dirty()
                    elif minsn.opcode == m_jnz and inequality == z3.Z3_L_FALSE:
                        mblock.remove_from_block(mblock.tail)
                        clear_edge(self.mba, mblock.serial)
                        modify_edge(mblock.mba, mblock.serial, mblock.serial + 1)
                        mblock.mark_lists_dirty()
                    mblock.type = BLT_1WAY
                    self.mba.mark_chains_dirty()
            elif minsn.opcode == m_xdu and minsn.l.t == mop_d:
                print(f"找到一个指令替换的混淆:{minsn.dstr()}")
                if minsn.d.t == mop_r:
                    xdu_result = z3.BitVec(get_mreg_name(minsn.d.r, minsn.d.size), 64) & AND_TABLE[minsn.d.size]
                elif minsn.d.t == mop_S:
                    xdu_result = z3.BitVec(f"var_{minsn.d.s.off:X}", 64) & AND_TABLE[minsn.d.size]
                expr = self.parse_minsn(minsn.l.d)
                s.push()
                s.add(expr == 1)
                equality = s.check().r
                s.pop()
                s.push()
                s.add(expr == 0)
                inequality = s.check().r
                s.pop()
                if equality != inequality:
                    minsn.opcode = m_mov
                    minsn.l = mop_t()
                    if equality == z3.Z3_L_TRUE:
                        minsn.l.make_number(1, minsn.d.size)
                        s.add(xdu_result == 1)
                    elif inequality == z3.Z3_L_TRUE:
                        minsn.l.make_number(0, minsn.d.size)
                        s.add(xdu_result == 0)
                    helper_logger.debug(f"修改了一个指令:{minsn.dstr()}")
                else:
                    s.add(xdu_result == self.parse_minsn(minsn.l.d))
                # print(xdu_result)
            minsn = minsn.next
        try:
            self.mba.verify(True)
        except RuntimeError as e:
            helper_logger.error("Error in instructions_fix_in_mblock: {0}".format(e))
