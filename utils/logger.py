import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
_global_logger = logging.getLogger(__name__)

class Logger:
    @staticmethod
    def info(msg: str):
        _global_logger.info(msg)
    
    @staticmethod
    def debug(msg: str):
        _global_logger.debug(msg)

    @staticmethod
    def warning(msg: str):
        _global_logger.warning(msg)

    @staticmethod
    def error(msg: str):
        _global_logger.error(msg)

    @staticmethod
    def critical(msg: str):
        _global_logger.critical(msg)
    
    @staticmethod
    def exception(msg: str):
        _global_logger.exception(msg)