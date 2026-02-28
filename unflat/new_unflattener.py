from ida_hexrays import *
from .cfgUtil import *
from .my_microcode_log import *
from .instructions import Instructions
from .remove_dead_code import RemoveDeadCode
import logging
from .logger_config import get_logger
from typing import TypedDict, List
from . import config

logger = get_logger(__name__)

JMP_OPCODE_HANDLED = [m_jnz, m_jz, m_jae, m_jb, m_ja, m_jbe, m_jge, m_jg, m_jl, m_jle]

hook_instance = None

class StateAssignment(TypedDict):
    mblock_id: int
    storage: str
    value: int

class PossibleState(TypedDict):
    mblock_id: int
    valrange_name: str
    valrange_value: int

class mblock_valranges_filter(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.valranges = []
        
    def get_valranges(self):
        return self.valranges
    
    def _print(self, indent, line):
        if "VALRANGES" in line or "BLOCK" in line:
            self.valranges.append("".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in line]))
        return 1

class Unflattener:

    def __init__(self, mba:mba_t, dispatcher_id = 0):
        self.mba = mba
        self.dispatcher_id = dispatcher_id
        self.dispatcher_ea = mba.get_mblock(dispatcher_id).start
        self.storage_carrier = None
        self.storage_list:list[mop_t] = [] # 存储所有可能用在ollvm分发的变量
        self.state_assignments: list[StateAssignment] = []  # 存储状态变量的赋值语句
        self.possible_states: list[PossibleState] = []  # 存储所有可能的状态值

    def find_dispatcher_id(self):
        """
        查找分发块的序号, 查找方法为找到最多入度的块, 如果OLLVM中有预处理块则会被干扰, 需要手动指定分发块序号
        """
        max_input_num = -1
        for i in range(1, self.mba.qty - 1):
            mblock: mblock_t = self.mba.get_mblock(i)
            num_input = mblock.npred()
            if num_input > max_input_num:
                max_input_num = num_input
                self.dispatcher_id = i

    def calc_entroy(self, value: int) -> bool:
        """
        计算熵值, 计算方法:判断每个字节位上是否都有值
        """
        count = 0
        for i in range(4):
            if value >> (i * 8) & 0xff != 0:
                count += 1
        return count >= 4

    def get_dispatcher_use_compare(self):
        """
        找到分发块中用于比较的存储器(寄存器或者栈上变量)
        """
        dispatcher_mblock: mblock_t = self.mba.get_mblock(self.dispatcher_id)
        minsn: minsn_t = dispatcher_mblock.tail
        logger.debug("minsn: %s", minsn.dstr())
        if minsn.opcode in JMP_OPCODE_HANDLED:
            mop_l :mop_t= minsn.l
            if mop_l.t == mop_S:
                tmp = "%0x{:X}".format(mop_l.s.off)
                logger.debug("找到栈上变量: %s", tmp)
                self.storage_carrier = tmp
            elif mop_l.t == mop_r:
                logger.debug("找到寄存器: %s", get_mreg_name(mop_l.r, mop_l.size))
                self.storage_carrier = get_mreg_name(mop_l.r, mop_l.size)
        else:
            logger.debug("不是主分发块")

    def find_use_compare(self):
        class GetOpt(minsn_visitor_t):
            def __init__(self):
                super().__init__()
                self.mop_list = {}

            def visit_minsn(self):
                if self.curins.opcode in JMP_OPCODE_HANDLED:
                    mop_l :mop_t= self.curins.l
                    if mop_l.t == mop_S:
                        tmp = "%0x{:X}".format(mop_l.s.off)
                        # logger.debug("找到栈上变量: %s", tmp)
                        if tmp not in self.mop_list.keys():
                            self.mop_list[tmp] = 1
                        else:
                            self.mop_list[tmp] += 1
                    elif mop_l.t == mop_r:
                        mreg = get_mreg_name(mop_l.r, mop_l.size)
                        if mreg not in self.mop_list.keys():
                            self.mop_list[mreg] = 1
                        else:
                            self.mop_list[mreg] += 1
                return 0
            
            def get_mop_list(self):
                return self.mop_list

        getopt = GetOpt()
        self.mba.for_all_topinsns(getopt)
        mop_list:dict = getopt.get_mop_list()
        sort_mop_list = sorted(mop_list.items(), key=lambda x: x[1], reverse=True)
        self.storage_carrier = sort_mop_list[0][0]


    def find_mblock_valranges(self):
        # 找到所有块的VALRANGES
        mba = self.mba
        vp = mblock_valranges_filter()
        mba._print(vp)
        # logger.info(vp.get_valranges())
        for line in vp.get_valranges():
            if "BLOCK" in line:
                mblock_id = int(line.split("BLOCK ")[1].split(" ")[0])
                continue
            # mblock_id = int(line.split(". ")[0])
            # logger.debug("mblock_id: %d", mblock_id)
            valranges_value = line.split("VALRANGES: ")[1]
            # logger.debug("valranges_value: %s", valranges_value)
            valranges_list = valranges_value.split(", ")
            for valrange in valranges_list:
                if ":==" in valrange:
                    valrange_name = valrange.split(":==")[0]
                    # logger.debug("valrange_name: %s", valrange_name)
                    valrange_value = valrange.split(":==")[1]
                    # logger.debug("valrange_value: 0x%x", int(valrange_value, 16))
                    if self.calc_entroy(int(valrange_value, 16)):
                        logger.info("valrange_name[%s] valrange_value[0x%x] 有足够的熵", valrange_name, int(valrange_value, 16))
                        self.possible_states.append({
                            'mblock_id': mblock_id,
                            'valrange_name': valrange_name.split(".")[0],
                            'valrange_value': int(valrange_value, 16)
                        })
        logging.debug("找到了所有块的可能性状态")
        if logger.level < logging.INFO:
            for flow_state in self.possible_states:
                logging.debug(flow_state)

    def find_next_status_in_mblock(self):
        """
        找到所有块中使用到状态赋值的语句并将内容记录
        """
        for mblock_id in range(1, self.mba.qty - 1):
            mblock :mblock_t = self.mba.get_mblock(mblock_id)
            minsn :minsn_t = mblock.head
            while minsn:
                if (minsn.opcode == m_mov and 
                    minsn.l.t == mop_n and
                    self.calc_entroy(minsn.l.nnn.value)):
                    if minsn.d.t == mop_r:
                        self.state_assignments.append({'mblock_id': mblock_id, 
                                                    'storage': get_mreg_name(minsn.d.r, minsn.d.size),
                                                    'value': minsn.l.nnn.value})
                    elif minsn.d.t == mop_S:
                        self.state_assignments.append({'mblock_id': mblock_id, 
                                                    'storage': "%0x{:X}".format(minsn.d.s.off),
                                                    'value': minsn.l.nnn.value})
                minsn = minsn.next
        logging.debug("找到了所有块中赋值的状态值")
        if logger.level < logging.INFO:
            for flow_block in self.state_assignments:
                logging.debug(flow_block)

    def find_in_possible_states(self, valrange_name=None, valrange_value=None):
        for flow_block in self.possible_states:
            if valrange_name != None and valrange_value != None:
                if flow_block['valrange_value'] == valrange_value and flow_block['valrange_name'] == valrange_name:
                    return flow_block
            elif valrange_value != None:
                 if flow_block['valrange_value'] == valrange_value:
                     return flow_block
        return None
    
    def deflat_level_1(self):
        """
        根据分发器的存储器匹配
        """
        nb_patch = 0
        for state_assignment in self.state_assignments:
            if state_assignment['storage'] == self.storage_carrier:
                flow_block = self.find_in_possible_states(valrange_value=state_assignment['value'])
                if flow_block != None:
                    next_mblock_id = flow_block['mblock_id']
                    cur_mblock_id = state_assignment['mblock_id']
                    cur_mblock = self.mba.get_mblock(cur_mblock_id)
                    change_jmp_target(cur_mblock, next_mblock_id)
                    nb_patch += 1

    def deflat_level_2(self):
        """
        暴力匹配
        """
        for state_assignment in self.state_assignments:
            flow_block = self.find_in_possible_states(valrange_value=state_assignment['value'])
            if flow_block != None:
                next_mblock_id = flow_block['mblock_id']
                cur_mblock_id = state_assignment['mblock_id']
                cur_mblock = self.mba.get_mblock(cur_mblock_id)
                change_jmp_target(cur_mblock, next_mblock_id)

    def deflat_level_3(self):
        """
        仅修改最多用于比较的分发器部分
        """
        self.find_use_compare()
        for state_assignment in self.state_assignments:
            if state_assignment['storage'] == self.storage_carrier:
                flow_block = self.find_in_possible_states(valrange_value=state_assignment['value'])
                if flow_block != None:
                    next_mblock_id = flow_block['mblock_id']
                    cur_mblock_id = state_assignment['mblock_id']
                    cur_mblock = self.mba.get_mblock(cur_mblock_id)
                    change_jmp_target(cur_mblock, next_mblock_id)

    def deflat_level_4(self):
        """
        安全模式
        """
        for state_assignment in self.state_assignments:
            flow_block = self.find_in_possible_states(valrange_name=state_assignment['storage'], valrange_value=state_assignment['value'])
            if flow_block != None:
                next_mblock_id = flow_block['mblock_id']
                cur_mblock_id = state_assignment['mblock_id']
                cur_mblock = self.mba.get_mblock(cur_mblock_id)
                change_jmp_target(cur_mblock, next_mblock_id)

    def deflat(self, level=1):
        nb_patch = 0
        if self.dispatcher_id == 0:
           self.find_dispatcher_id()
        self.get_dispatcher_use_compare()
        self.find_mblock_valranges()
        self.find_next_status_in_mblock()
        if level == 1:
            self.deflat_level_1()
        if level == 2:
            self.deflat_level_2()
        if level == 3:
            self.deflat_level_3()
        if level == 4:
            self.deflat_level_4()
        return nb_patch

class HexraysDecompilationHook(Hexrays_Hooks):
    def __init__(self):
        super().__init__()
        self.deflat_list = []
    
    def glbopt(self, mba: mbl_array_t):
        # dump_microcode_for_debug(mba, "D:\\project\\ida_split", "before_unflatten")
        # unflat.find_mlbock_valranges(mba)
        # if not config.enable_ollvm_unflatten:
        #     return MERR_OK
        if mba.entry_ea not in self.deflat_list:
            if config.enable_remove_dead_code:
                rdc = RemoveDeadCode()
                mba.for_all_topinsns(rdc)
            # struction = Instructions(mba)
            # struction.instructions_fix()
            if config.enable_ollvm_unflatten:
                unflat = Unflattener(mba)
                unflat.deflat(4)
            # mba.remove_empty_and_unreachable_blocks()
            # dump_microcode_for_debug(mba, "D:\\project\\ida_split", "after_unflatten")
            self.deflat_list.append(mba.entry_ea)
            return MERR_LOOP
        else:
            self.deflat_list.remove(mba.entry_ea)
            return MERR_OK

# testHook = HexraysDecompilationHook()
# print(testHook.hook())

def main():
    global hook_instance

    if hook_instance:
        hook_instance.unhook()

    hook_instance = HexraysDecompilationHook()
    hook_instance.hook()
    print("ollvm反混淆已加载")
