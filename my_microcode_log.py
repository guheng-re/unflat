from ida_hexrays import *
import os

class mba_printer(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):
        self.mc.append("".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in line])+"\n")
        return 1

def write_mc_to_file(mba: mbl_array_t, filename: str, mba_flags: int = 0) -> bool:
    if not mba:
        return False

    vp = mba_printer()
    mba.set_mba_flags(mba_flags)
    mba._print(vp)

    with open(filename, "w") as f:
        f.writelines(vp.get_mc())
    return True

def dump_microcode_for_debug(mba: mbl_array_t, log_dir_path: str, name: str = ""):
    mc_filename = os.path.join(log_dir_path, "0x{0:x}_maturity_{1}_{2}.log".format(mba.entry_ea, mba.maturity, name))
    print("保存microcode到{0}".format(mc_filename))
    write_mc_to_file(mba, mc_filename)