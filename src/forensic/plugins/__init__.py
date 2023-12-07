from forensic.plugins.s7.s7 import S7
from forensic.plugins.CodeSysV3.CodeSysV3 import CodeSysV3
from forensic.plugins.RockwellRslogix.rockwell import Logix

__plugins__ = {
    "S7": S7,
    "CodeSysV3": CodeSysV3,
    "RockwellRslogix": Logix
}
