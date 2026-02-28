from ida_hexrays import *
import logging

logger = logging.getLogger(__name__)

# 条件跳转指令列表，用于识别和修改条件跳转
CONDITIONAL_JUMP_LIST = [m_ja, m_jae, m_jb, m_jbe, m_jcnd, m_jg, m_jge, m_jl, m_jle, m_jz, m_jnz]

def insert_goto(mblock:mblock_t, target_mblock_serial:int):
    """
    在微代码块中插入无条件跳转指令
    
    Args:
        mblock: 目标微代码块
        target_mblock_serial: 跳转目标块的序列号
    """
    new_goto = minsn_t(mblock.end)
    new_goto.opcode = m_goto
    new_goto.l = mop_t()
    new_goto.l.make_blkref(target_mblock_serial)
    if mblock.tail:
        mblock.insert_into_block(new_goto, mblock.tail)
    else:
        mblock.head = new_goto
        mblock.tail = new_goto

def insert_jz(mblock:mblock_t, target_mblock_serial:int, cmp_value:int, cmp_mreg:int, cmp_value_size:int, cmp_mreg_size:int):
    new_jz = minsn_t(mblock.end)
    new_jz.opcode = m_jz
    new_jz.l = mop_t()
    new_jz.l.make_reg(cmp_mreg, cmp_mreg_size)
    new_jz.r = mop_t()
    new_jz.r.make_number(cmp_value, cmp_value_size)
    new_jz.d = mop_t()
    new_jz.d.make_blkref(target_mblock_serial)
    if mblock.tail:
        mblock.insert_into_block(new_jz, mblock.tail)
    else:
        mblock.head = new_jz
        mblock.tail = new_jz

def change_jmp_target(mblock:mblock_t, target_mblock_serial:int):
    """
    修改微代码块的跳转目标
    
    Args:
        mblock: 要修改的微代码块
        target_mblock_serial: 新的跳转目标块序列号
    """
    minsn:minsn_t = mblock.tail
    ori_mblock_serial = 0
    if not minsn:
        return
    if minsn.opcode == m_goto:
        ori_mblock_serial = minsn.l.b
        minsn.l.b = target_mblock_serial
    elif minsn.opcode in CONDITIONAL_JUMP_LIST:
        ori_mblock_serial = minsn.d.b
        minsn.d.b = target_mblock_serial
    else:
        ori_mblock_serial = mblock.serial + 1
        insert_goto(mblock, target_mblock_serial)
    if ori_mblock_serial != 0 and ori_mblock_serial != target_mblock_serial:
        logger.info(f"改变块关系:{mblock.serial}->{ori_mblock_serial}, {mblock.serial}->{target_mblock_serial}")
        modify_edge(mblock.mba, mblock.serial, target_mblock_serial, ori_mblock_serial)

def create_mblock(mblock:mblock_t, mblock_serial:int) -> mblock_t:
    """
    在指定位置创建新的微代码块
    
    Args:
        mblock: 参考微代码块（用于获取MBA和地址范围）
        mblock_serial: 新块的序列号
        
    Returns:
        新创建的微代码块
    """
    mba:mba_t = mblock.mba
    new_mblock:mblock_t = mba.insert_block(mblock_serial)
    new_mblock.start = mba.alloc_fict_ea(mblock.end)
    new_mblock.end = mba.alloc_fict_ea(mblock.end + 4)
    return new_mblock

def clear_edge(mba:mba_t, mblock_id: int):
    """
    清除指定微代码块的所有后继边
    
    Args:
        mba: 微代码块数组
        mblock_id: 要清除边的微代码块ID
    """
    mblock:mblock_t = mba.get_mblock(mblock_id)
    mblock_succset = [x for x in mblock.succset]
    for succset_mblock_id in mblock_succset:
        modify_edge(mba, mblock_id, old_block_id=succset_mblock_id)

def modify_edge(mba:mba_t, cur_block_id: int, new_block_id: int = 0, old_block_id: int = 0):
    """
    修改微代码块之间的边关系（控制流边）

    Args:
        mba: 微代码块数组
        cur_block_id: 当前微代码块ID
        new_block_id: 新的后继块ID（为0表示不添加新边）
        old_block_id: 要移除的旧后继块ID（为0表示不移除）

    功能:
        - 移除从cur_block到old_block的边
        - 添加从cur_block到new_block的边
        - 更新相关块的前驱和后继集合
    """
    cur_block: mblock_t = mba.get_mblock(cur_block_id)

    # 只在需要时获取块
    new_block = mba.get_mblock(new_block_id) if new_block_id != 0 else None
    old_block = mba.get_mblock(old_block_id) if old_block_id != 0 else None

    cur_block_succset = [x for x in cur_block.succset]
    new_block_predset = [x for x in new_block.predset] if new_block else []
    old_block_predset = [x for x in old_block.predset] if old_block else []
    old_block_index = len(cur_block_succset)

    logger.debug(f"修改块关系前:cur_block_succset:{cur_block_succset}, new_block_predset:{new_block_predset}, old_block_predset:{old_block_predset}")

    # 移除旧边
    if old_block_id != 0 and old_block_id in cur_block_succset and old_block:
        old_block_index = cur_block_succset.index(old_block_id)
        cur_block_succset.remove(old_block_id)
        if cur_block_id in old_block_predset:
            old_block_predset.remove(cur_block_id)
            old_block.predset.clear()
            for i in old_block_predset:
                old_block.predset.push_back(i)

    # 添加新边
    if new_block_id != 0 and new_block_id not in cur_block_succset and new_block:
        cur_block_succset.insert(old_block_index, new_block_id)
        if cur_block_id not in new_block_predset:
            new_block_predset.append(cur_block_id)
            new_block.predset.clear()
            for i in new_block_predset:
                new_block.predset.push_back(i)

    # 更新当前块的后继集合
    cur_block.succset.clear()
    for i in cur_block_succset:
        cur_block.succset.push_back(i)

    logger.debug(f"修改块关系后:cur_block_succset:{cur_block_succset}, new_block_predset:{new_block_predset}, old_block_predset:{old_block_predset}")
    
def check_mblock_tail_opcode_is_goto(mblock:mblock_t):
    """
    检查微代码块的尾部指令是否为无条件跳转
    
    Args:
        mblock: 要检查的微代码块
        
    Returns:
        True 如果尾部是goto指令, 否则返回False
    """
    minsn:minsn_t = mblock.tail
    if minsn.opcode == m_goto:
        return True
    else:
        return False
    
def create_goto_mblock(cur_mblock:mblock_t, target_mblock_serial:int) -> mblock_t:
    """
    创建一个包含无条件跳转指令的微代码块
    
    Args:
        cur_mblock: 当前微代码块（用于确定新块的位置）
        target_mblock_serial: 跳转目标块的序列号
        
    Returns:
        新创建的包含goto指令的微代码块
    """
    mba:mba_t = cur_mblock.mba
    new_mblock = create_mblock(cur_mblock, cur_mblock.serial + 1)
    insert_goto(new_mblock, target_mblock_serial)
    new_mblock.type = BLT_1WAY
    new_mblock.flags |= MBL_GOTO
    if not check_mblock_tail_opcode_is_goto(cur_mblock):
        modify_edge(mba, cur_mblock.serial, new_mblock.serial, new_mblock.serial + 1)
    else:
        modify_edge(mba, cur_mblock.serial, new_mblock.serial)
    modify_edge(mba, new_mblock.serial, target_mblock_serial)
    new_mblock.make_lists_ready()
    new_mblock.mark_lists_dirty()
    mba.mark_chains_dirty()
    return new_mblock

def create_jz_mblock(cur_mblock:mblock_t, target_mblock_serial:int, cmp_value: int, cmp_mreg: int, cmp_value_size: int = 4, cmp_mreg_size: int = 4) -> mblock_t:
    """
    创建一个包含条件跳转指令（等于则跳转）的微代码块
    
    Args:
        cur_mblock: 当前微代码块（用于确定新块的位置）
        target_mblock_serial: 跳转目标块的序列号
        cmp_value: 比较的值
        cmp_mreg: 比较的寄存器
        cmp_value_size: 比较值的大小（字节数），默认为4
        cmp_mreg_size: 比较寄存器的大小（字节数），默认为4
        
    Returns:
        新创建的包含jz指令的微代码块
    """
    mba:mba_t = cur_mblock.mba
    new_mblock = create_mblock(cur_mblock, cur_mblock.serial + 1)
    insert_jz(new_mblock, target_mblock_serial, cmp_value, cmp_mreg, cmp_value_size, cmp_mreg_size)
    new_mblock.type = BLT_2WAY
    new_mblock.flags |= MBL_GOTO
    if not check_mblock_tail_opcode_is_goto(cur_mblock):
        modify_edge(mba, cur_mblock.serial, new_mblock.serial, new_mblock.serial + 1)
    else:
        modify_edge(mba, cur_mblock.serial, new_mblock.serial)
    modify_edge(mba, new_mblock.serial, new_mblock.serial + 1)
    modify_edge(mba, new_mblock.serial, target_mblock_serial)
    new_mblock.make_lists_ready()
    new_mblock.mark_lists_dirty()
    mba.mark_chains_dirty()
    return new_mblock

def optimize_block(mba:mba_t):
    """
    优化微代码块数组中的所有块
    
    Args:
        mba: 微代码块数组
    
    功能:
        - 对每个块的每条指令进行优化
        - 对每个块本身进行优化
    """
    for i in range(1, mba.qty - 1):
        mblock:mblock_t = mba.get_mblock(i)
        minsn:minsn_t = mblock.tail
        while minsn:
            mblock.optimize_insn(minsn)
            minsn = minsn.prev
        mblock.optimize_block()