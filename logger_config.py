import logging
import os
import datetime
from typing import Optional

# 日志目录
LOG_DIR = "D:\\project\\ida_split\\log"

# 日志级别
LOG_LEVEL = logging.DEBUG

# 日志格式
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# 全局日志配置标志
_logging_configured = False


def setup_logging(log_dir: str = LOG_DIR, 
                 log_level: int = LOG_LEVEL,
                 log_format: str = LOG_FORMAT,
                 force: bool = True) -> bool:
    """
    配置全局日志系统
    
    Args:
        log_dir: 日志文件目录
        log_level: 日志级别
        log_format: 日志格式
        force: 是否强制重新配置
        
    Returns:
        配置是否成功
    """
    global _logging_configured
    
    if _logging_configured and not force:
        return True
    
    try:
        # 确保日志目录存在
        os.makedirs(log_dir, exist_ok=True)
        
        # 获取当前时间用于日志文件名
        current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"unflattener_{current_time}.log"
        log_file_path = os.path.join(log_dir, log_filename)
        
        # 配置日志
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file_path, encoding='utf-8'),
                logging.StreamHandler()
            ],
            force=force
        )
        
        _logging_configured = True
        print(f"日志配置完成，日志文件路径: {log_file_path}")
        return True
        
    except Exception as e:
        print(f"日志配置失败: {e}")
        return False


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    获取日志记录器
    
    Args:
        name: 日志记录器名称，通常使用 __name__
        
    Returns:
        日志记录器实例
    """
    # 确保日志已配置
    if not _logging_configured:
        setup_logging()
    
    return logging.getLogger(name)


# 初始化日志配置
setup_logging()