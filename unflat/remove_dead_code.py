from ida_hexrays import *
import ida_segment

class MopOptimizer(mop_visitor_t):
    def visit_mop(self, op: mop_t, op_type: int, is_target: bool):
        if(op.t == mop_v and op.size > -1):
            # print(f"{op.dstr()}")
            seg:ida_segment.segment_t = ida_segment.getseg(op.g)
            # print(ida_segment.get_segm_name(seg))
            if ida_segment.get_segm_name(seg) == ".bss":
                op.make_number(0, op.size)
            # print(f"{op.dstr()}")
        return 0

class RemoveDeadCode(minsn_visitor_t):
    def __init__(self):
        self.minsn_line = 0
        super().__init__()

    def visit_minsn(self):
        minsn = self.curins
        self._optimizer(minsn)
        return 0

    def _optimizer(self, minsn:minsn_t):
        mopOptimizer = MopOptimizer()
        minsn.for_all_ops(mopOptimizer)
        print(f"{self.minsn_line}: {minsn.dstr()}")
        self.minsn_line += 1