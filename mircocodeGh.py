"""
IDA Microcode流程图生成器
解析microcode文本并生成可视化流程图
"""

import re
import graphviz
from typing import Dict, List, Tuple, Set

class MicrocodeBlock:
    """Microcode基本块"""
    def __init__(self, block_id: int):
        self.block_id = block_id
        self.block_type = ""
        self.start_addr = ""
        self.end_addr = ""
        self.inbounds = []  # 前驱块
        self.outbounds = []  # 后继块
        self.instructions = []  # 指令列表
        self.valranges = []  # 值范围信息
        
    def __repr__(self):
        return f"Block {self.block_id} [{self.start_addr}-{self.end_addr}]"


class MicrocodeParser:
    """Microcode文本解析器"""
    
    def __init__(self, text: str):
        self.text = text
        self.blocks: Dict[int, MicrocodeBlock] = {}
        
    def parse(self):
        """解析microcode文本"""
        lines = self.text.strip().split('\n')
        current_block = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # 解析块头: "X. Y ; TYPE-BLOCK X ..."
            block_header = re.match(r'^(\d+)\.\s+\d+\s*;\s*(\w+)-BLOCK\s+(\d+)', line)
            if block_header:
                block_id = int(block_header.group(3))
                block_type = block_header.group(2)
                
                if block_id not in self.blocks:
                    self.blocks[block_id] = MicrocodeBlock(block_id)
                current_block = self.blocks[block_id]
                current_block.block_type = block_type
                
                # 解析INBOUNDS和OUTBOUNDS
                inbounds_match = re.search(r'INBOUNDS:\s*([\d\s]+)', line)
                if inbounds_match:
                    inbounds_str = inbounds_match.group(1).strip()
                    if inbounds_str:
                        current_block.inbounds = [int(x) for x in inbounds_str.split()]
                
                outbounds_match = re.search(r'OUTBOUNDS:\s*([\d\s]+)', line)
                if outbounds_match:
                    outbounds_str = outbounds_match.group(1).strip()
                    if outbounds_str:
                        current_block.outbounds = [int(x) for x in outbounds_str.split()]
                
                # 解析地址范围
                addr_match = re.search(r'\[START=([0-9A-F]+)\s+END=([0-9A-F]+)\]', line)
                if addr_match:
                    current_block.start_addr = addr_match.group(1)
                    current_block.end_addr = addr_match.group(2)
                
                continue
            
            # 解析VALRANGES
            if current_block and 'VALRANGES:' in line:
                valrange_match = re.search(r'VALRANGES:\s*(.+)', line)
                if valrange_match:
                    current_block.valranges.append(valrange_match.group(1).strip())
                continue
            
            # 解析指令
            if current_block:
                # 匹配指令行: "X. Y instruction ..."
                insn_match = re.match(r'^\d+\.\s+\d+\s+(.+)', line)
                if insn_match:
                    insn_text = insn_match.group(1).strip()
                    # 过滤掉空行和注释
                    if insn_text and not insn_text.startswith(';'):
                        current_block.instructions.append(insn_text)
        
        return self.blocks


class MicrocodeFlowchartGenerator:
    """流程图生成器"""
    
    def __init__(self, blocks: Dict[int, MicrocodeBlock]):
        self.blocks = blocks
        self.graph = None
        
    def generate(self, output_file: str = "microcode_flowchart", 
                 format: str = "png",
                 show_instructions: bool = True,
                 max_instructions: int = 5,
                 show_valranges: bool = False,
                 highlight_dispatcher: bool = True):
        """
        生成流程图
        
        :param output_file: 输出文件名（不含扩展名）
        :param format: 输出格式 (png, pdf, svg等)
        :param show_instructions: 是否显示指令
        :param max_instructions: 最多显示的指令数
        :param show_valranges: 是否显示值范围
        :param highlight_dispatcher: 是否高亮分发器块
        """
        self.graph = graphviz.Digraph(
            name='MicrocodeFlowchart',
            format=format,
            engine='dot'
        )
        
        # 设置图的属性
        self.graph.attr(rankdir='TB', 
                       splines='ortho',
                       nodesep='0.5',
                       ranksep='0.8')
        self.graph.attr('node', shape='box', style='rounded,filled', 
                       fontname='Courier', fontsize='10')
        self.graph.attr('edge', fontname='Courier', fontsize='9')
        
        # 找到分发器块（前驱最多的块）
        dispatcher_id = self._find_dispatcher()
        
        # 添加所有块
        for block_id, block in sorted(self.blocks.items()):
            label = self._create_block_label(
                block, 
                show_instructions, 
                max_instructions,
                show_valranges
            )
            
            # 根据块类型设置颜色
            color = self._get_block_color(block, block_id == dispatcher_id and highlight_dispatcher)
            
            self.graph.node(
                str(block_id), 
                label=label,
                fillcolor=color,
                color='black',
                penwidth='1.5' if block_id == dispatcher_id and highlight_dispatcher else '1.0'
            )
        
        # 添加所有边
        for block_id, block in self.blocks.items():
            for succ_id in block.outbounds:
                if succ_id in self.blocks:
                    # 根据边的类型设置样式
                    edge_style = self._get_edge_style(block, succ_id)
                    self.graph.edge(str(block_id), str(succ_id), **edge_style)
        
        # 渲染图
        try:
            output_path = self.graph.render(output_file, cleanup=True)
            print(f"[+] 流程图已生成: {output_path}")
            return output_path
        except Exception as e:
            print(f"[!] 生成流程图失败: {e}")
            return None
    
    def _find_dispatcher(self) -> int:
        """找到分发器块（前驱数量最多的块）"""
        max_preds = -1
        dispatcher_id = -1
        
        for block_id, block in self.blocks.items():
            num_preds = len(block.inbounds)
            if num_preds > max_preds:
                max_preds = num_preds
                dispatcher_id = block_id
        
        return dispatcher_id
    
    def _create_block_label(self, block: MicrocodeBlock, 
                           show_instructions: bool,
                           max_instructions: int,
                           show_valranges: bool) -> str:
        """创建块的标签"""
        label_parts = []
        
        # 块标题
        title = f"Block {block.block_id}"
        if block.start_addr and block.start_addr != "FFFFFFFFFFFFFFFF":
            title += f"\\n0x{block.start_addr}"
        label_parts.append(f"<B>{title}</B>")
        
        # 块类型
        label_parts.append(f"<I>{block.block_type}</I>")
        
        # 前驱和后继信息
        if block.inbounds:
            label_parts.append(f"In: {', '.join(map(str, block.inbounds))}")
        if block.outbounds:
            label_parts.append(f"Out: {', '.join(map(str, block.outbounds))}")
        
        # 值范围（如果需要）
        if show_valranges and block.valranges:
            for vr in block.valranges[:2]:  # 最多显示2个
                label_parts.append(f"<FONT POINT-SIZE='8'>{vr[:50]}</FONT>")
        
        # 指令（如果需要）
        if show_instructions and block.instructions:
            label_parts.append("---")
            for i, insn in enumerate(block.instructions[:max_instructions]):
                # 截断过长的指令
                if len(insn) > 60:
                    insn = insn[:57] + "..."
                label_parts.append(f"<FONT POINT-SIZE='8'>{self._escape_html(insn)}</FONT>")
            
            if len(block.instructions) > max_instructions:
                label_parts.append(f"<FONT POINT-SIZE='8'>... ({len(block.instructions) - max_instructions} more)</FONT>")
        
        return "<" + "<BR/>".join(label_parts) + ">"
    
    def _escape_html(self, text: str) -> str:
        """转义HTML特殊字符"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;'))
    
    def _get_block_color(self, block: MicrocodeBlock, is_dispatcher: bool) -> str:
        """根据块类型获取颜色"""
        if is_dispatcher:
            return '#FF6B6B'  # 红色 - 分发器
        elif block.block_type == 'START':
            return '#51CF66'  # 绿色 - 入口
        elif block.block_type == 'STOP':
            return '#FF8787'  # 浅红 - 出口
        elif block.block_type == '1WAY':
            return '#A9E5FF'  # 浅蓝 - 单向
        elif block.block_type == '2WAY':
            return '#FFE066'  # 黄色 - 双向
        elif block.block_type == 'NWAY':
            return '#FFA94D'  # 橙色 - 多向
        else:
            return '#E0E0E0'  # 灰色 - 其他
    
    def _get_edge_style(self, block: MicrocodeBlock, succ_id: int) -> dict:
        """获取边的样式"""
        style = {}
        
        # 如果是条件跳转块，标记true/false分支
        if block.block_type == '2WAY' and len(block.outbounds) == 2:
            if succ_id == block.outbounds[0]:
                style['label'] = 'T'
                style['color'] = 'green'
            else:
                style['label'] = 'F'
                style['color'] = 'red'
        
        return style
    
    def print_statistics(self):
        """打印统计信息"""
        print("\n" + "="*60)
        print("Microcode统计信息")
        print("="*60)
        print(f"总块数: {len(self.blocks)}")
        
        # 按类型统计
        type_count = {}
        for block in self.blocks.values():
            type_count[block.block_type] = type_count.get(block.block_type, 0) + 1
        
        print("\n块类型分布:")
        for block_type, count in sorted(type_count.items()):
            print(f"  {block_type:10s}: {count:3d}")
        
        # 找到分发器
        dispatcher_id = self._find_dispatcher()
        if dispatcher_id >= 0:
            dispatcher = self.blocks[dispatcher_id]
            print(f"\n分发器块: Block {dispatcher_id}")
            print(f"  前驱数: {len(dispatcher.inbounds)}")
            print(f"  后继数: {len(dispatcher.outbounds)}")
        
        print("="*60 + "\n")


def parse_and_visualize(microcode_text: str, 
                       output_file: str = "microcode_flowchart",
                       **kwargs):
    """
    解析并可视化microcode
    
    :param microcode_text: microcode文本内容
    :param output_file: 输出文件名
    :param kwargs: 传递给generate的其他参数
    """
    # 解析
    parser = MicrocodeParser(microcode_text)
    blocks = parser.parse()
    
    print(f"[+] 解析完成，共 {len(blocks)} 个基本块")
    
    # 生成流程图
    generator = MicrocodeFlowchartGenerator(blocks)
    generator.print_statistics()
    
    output_path = generator.generate(output_file, **kwargs)
    
    return blocks, output_path


# 示例使用
if __name__ == "__main__":
    # 你的microcode文本
    microcode_text = """
    # 将你的microcode内容粘贴在这里
    """
    
    # 如果从文件读取
    try:
        with open("0x27fccc_maturity_6_after_unflatten.log", "r", encoding="utf-8") as f:
            microcode_text = f.read()
    except FileNotFoundError:
        print("[!] 请创建microcode.txt文件或直接在代码中提供文本")
        exit(1)
    
    # 生成流程图
    blocks, output_path = parse_and_visualize(
        microcode_text,
        output_file="microcode_flowchart",
        format="png",  # 可选: png, pdf, svg
        show_instructions=True,  # 显示指令
        max_instructions=5,  # 每个块最多显示5条指令
        show_valranges=False,  # 不显示值范围（太长）
        highlight_dispatcher=True  # 高亮分发器块
    )
    
    if output_path:
        print(f"\n[+] 完成！请查看: {output_path}")