import idaapi
import ida_kernwin
import ida_hexrays
import unflat.config as config

UNOLLVM_ACTION_NAME = "unflat:toggle_ollvm"
UNBCF_ACTION_NAME = "unflat:toggle_bcf"

class PopupHook(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE or idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                UNOLLVM_ACTION_NAME,
                None
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                UNBCF_ACTION_NAME,
                None
            )

class ToggleOllvmHandler(idaapi.action_handler_t):

    def activate(self, ctx):
        config.enable_ollvm_unflatten = not config.enable_ollvm_unflatten

        state = "开启" if config.enable_ollvm_unflatten else "关闭"
        print(f"[+] OLLVM 反混淆已{state}")
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vdui:
            vdui.refresh_view(True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ToggleBCFHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        config.enable_remove_dead_code = not config.enable_remove_dead_code

        state = "开启" if config.enable_remove_dead_code else "关闭"
        print(f"[+] 死代码消除已{state}")
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vdui:
            vdui.refresh_view(True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class MicroPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Hot reload microcode plugin"
    help = ""
    wanted_name = "OLLVM反混淆"
    wanted_hotkey = ""

    def init(self):
        idaapi.register_action(
                idaapi.action_desc_t(
                    UNOLLVM_ACTION_NAME,
                    "启用/关闭 OLLVM 反混淆",
                    ToggleOllvmHandler(),
                    None,
                    "Toggle OLLVM unflatten",
                    0
                )
            )
        idaapi.register_action(
                idaapi.action_desc_t(
                    UNBCF_ACTION_NAME,
                    "启用/关闭 死代码消除",
                    ToggleBCFHandler(),
                    None,
                    "Toggle BCF remove",
                    0
                )
            )
        self.menu_handler = PopupHook()
        self.menu_handler.hook()
        print("[+] Loader initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            import importlib

            import unflat.cfgUtil as cfgUtil
            importlib.reload(cfgUtil)
            print("cfgUtil重载成功")
               
            import unflat.remove_dead_code as remove_dead_code
            importlib.reload(remove_dead_code)
            print("remove_dead_code重载成功")
            
            import unflat.new_unflattener as new_unflattener
            importlib.reload(new_unflattener)
            print("new_unflattener重载成功")

            new_unflattener.main()
        except Exception as e:
            import traceback
            traceback.print_exc()

    def term(self):
        if self.menu_handler:
            self.menu_handler.unhook()
        idaapi.unregister_action(UNOLLVM_ACTION_NAME)
        idaapi.unregister_action(UNBCF_ACTION_NAME)
        print("[+] Plugin terminated")


def PLUGIN_ENTRY():
    return MicroPlugin()