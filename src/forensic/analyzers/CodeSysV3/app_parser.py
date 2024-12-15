import os
import csv
import json
import networkx as nx
from pathlib import Path

from networkx import add_path

from forensic.analyzers.CodeSysV3.file_format import CodesysV3FileFormat
from forensic.analyzers.CodeSysV3.memory_dynamic_format import CodesysV3MemoryDynamicFormat
from forensic.analyzers.CodeSysV3.memory_format import CodesysV3MemoryFormat
from forensic.common.stream.stream import BinaryReader


def dump_all(output_dir, g_entry_point, symbols, all_code_blocks, taskinfos, project_info):
    call_graph_dir = os.path.join(output_dir, "call_graph")
    Path(call_graph_dir).mkdir(parents=True, exist_ok=True)

    with open(os.path.join(output_dir, 'function_addresses.csv'), 'w') as fout:
        cwriter = csv.writer(fout)
        for pointer in all_code_blocks:
            cwriter.writerow([pointer])

    with open(os.path.join(output_dir, 'symbols.csv'), 'w') as fout:
        cwriter = csv.writer(fout)
        for key, val in symbols.items():
            cwriter.writerow([key, val])

    if g_entry_point is not None:
        nx.write_gexf(g_entry_point, os.path.join(call_graph_dir, 'entry_point.gexf'))

    for taskinfo in taskinfos:
        nx.write_gexf(taskinfo['xrefs'], os.path.join(call_graph_dir, (f'{taskinfo["name"]}.gexf')))
        del taskinfo['xrefs']

    with open(os.path.join(output_dir, 'taskinfo.json'), 'w') as fout:
        fout.write(json.dumps(taskinfos))

    with open(os.path.join(output_dir, 'project_info.json'), 'w') as fout:
        fout.write(json.dumps(project_info))


def parse_app(app_fpath, output_dir):
    try:
        f = open(app_fpath, 'rb')
        file_data = f.read()
        cff = CodesysV3FileFormat()
        all_tags = cff.parse(file_data)

        cmf = CodesysV3MemoryFormat(file_data, all_tags)
        br_memory = BinaryReader(cmf.memory_file)

    # Check if we have memory symbols
        if '@table_start' in cmf.imp_addr:
            cmdf = CodesysV3MemoryDynamicFormat()
            cmf.symbols.update(cmdf.parse(br_memory, cmf.imp_addr))

        # Make sure the architecture is supported
        if cmdf.validate_supported_arch(br_memory, cmf.imp_addr):
            cmdf.simulate_to_find_taskinfos(cmf.memory_file, cmf.symbols, cmf.imp_addr, cmf.all_code_blocks)

        dump_all(output_dir, cmdf.g_entry_point, cmf.symbols, cmf.all_code_blocks, cmdf.taskinfos, cmf.project_info)
    
    except FileNotFoundError:
        print(f"Error: File {app_fpath} not found")
    except PermissionError:
        print(f"Error: Insufficient permission to read {app_fpath}.")
    except Exception as e:
        print(f"There is another Error here.")
    finally:
        f.close()
        
    
    
