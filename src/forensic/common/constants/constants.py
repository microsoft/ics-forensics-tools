from enum import IntEnum, Enum
from pathlib import Path

class Parallelism(IntEnum):
    OFF = 0
    MULTIPROCESSING = 1


class Transport(Enum):
    TCP = 'tcp'
    UDP = 'udp'

PARALLELISM = Parallelism.OFF

APPLICATION = 'forensic'

VERBOSE = False
LOGS_DIR = 'Logs'
LOG_FILE_NAME = 'Application.log'
LOGS_FORMATTER = '%(asctime)s | %(levelname)s | %(message)s'

OUTPUT_DIR = Path('Output')
CONFIG_FILE = Path('config.json')

ARGUMENTS = ['config', 'ip', 'output_dir', 'port', 'multiprocess', 'transport', 'verbose', 'plugin', 'analyzer', 'save_config']

