from forensic.analyzers.s7.block_logic import S7BlockLogic
from forensic.analyzers.s7.raw_file_parser import S7RawFileParser
from forensic.analyzers.s7.online_offline_compare import S7OnlineOfflineCompare
from forensic.analyzers.CodeSysV3.block_logic import CS3BlockLogic
from forensic.analyzers.CodeSysV3.raw_file_parser import CS3RawFileParser
from forensic.analyzers.RockwellRslogix.block_logic import RockwellRslogixBlockLogic
from forensic.analyzers.RockwellRslogix.raw_file_parser import RockwellRslogixRawFileParser
from forensic.analyzers.RockwellRslogix.online_offline_compare import RockwellRslogixOnlineOfflineCompare

__analyzers__ = {
    "S7BlockLogic": S7BlockLogic,
    "S7RawFileParser": S7RawFileParser,
    "S7OnlineOfflineCompare": S7OnlineOfflineCompare,
    "CS3BlockLogic": CS3BlockLogic,
    "CS3RawFileParser": CS3RawFileParser,
    "RockwellRslogixBlockLogic": RockwellRslogixBlockLogic,
    "RockwellRslogixRawFileParser": RockwellRslogixRawFileParser,
    "RockwellRslogixOnlineOfflineCompare": RockwellRslogixOnlineOfflineCompare
}