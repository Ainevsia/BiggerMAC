import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
_global_logger = logging.getLogger(__name__)

class Logger:
    @staticmethod
    def info(msg: str, *args, **kwargs):
        _global_logger.info(msg, *args, **kwargs)
    
    @staticmethod
    def debug(msg: str, *args, **kwargs):
        _global_logger.debug(msg, *args, **kwargs)

    @staticmethod
    def warning(msg: str, *args, **kwargs):
        _global_logger.warning(msg, *args, **kwargs)

    @staticmethod
    def error(msg: str, *args, **kwargs):
        _global_logger.error(msg, *args, **kwargs)

    @staticmethod
    def critical(msg: str, *args, **kwargs):
        _global_logger.critical(msg, *args, **kwargs)
    
    @staticmethod
    def exception(msg: str, *args, **kwargs):
        _global_logger.exception(msg, *args, **kwargs)