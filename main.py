#!/usr/bin/env python
import os
import re
import sys
import argparse
from loguru import logger
from tqdm import tqdm
import extractor
import block_logic
from common import utils
from common import scanner
from common import on_off_compare

CURR_DIR = os.path.dirname(os.path.realpath(__file__))
OUT_DIR = os.path.join(CURR_DIR, "output")
RAW_FILES_DIR = os.path.join(OUT_DIR, 'raw-files')
OUT_FILES_DIR = os.path.join(OUT_DIR, 'out-files')
LOGIC_FILES_DIR = os.path.join(OUT_FILES_DIR, 'logic-files')
BLOCK_COMP_DIR = os.path.join(OUT_FILES_DIR, 'block-comparison')
LOG_FPATH = os.path.join(OUT_DIR, 'debug.log')


def parse_arguments():
    parser = argparse.ArgumentParser(description='Ladder Logic Forensic Tool by Section52, Microsoft')
    parser.add_argument('-fo', '--file_output', help='Store output in file', action='store_true', required=False)
    parser.add_argument('-v', '--verbose', help='Verbose logging', action='store_true', required=False)

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-if', '--ip_addresses_file', help='scan IP addresses from file, comma separated',
                       required=False)
    group.add_argument('-sc', '--scan', help='Scan for Siemens S7 PLCs in network segment (x.y.z.)', required=False)

    parser.add_argument('-ov', '--override_output_dirs', help='Override output directories', action='store_true',
                        required=False)

    parser.add_argument('-pn', '--port_number', help='Port number for connecting or scanning', required=False)

    parser.add_argument('-co', '--compare_online_vs_offline', help='Compare between online and offline projects',
                        action='store_true', required=False)
    parser.add_argument('-ci', '--compare_ip', help='PLC IP with online blocks to compare', required=False)

    parser.add_argument('-opd', '--offline_projects_directory', help='Offline projects directory (optional)',
                        required=False)
    parser.add_argument('-opdn', '--offline_project_dir_name', help='Offline project directory name (optional)',
                        required=False)

    parser.add_argument('-la', '--logic_all', help='Execute all logic options', action='store_true',
                        required=False)
    parser.add_argument('-lau', '--logic_author', help='Execute author logic', action='store_true', required=False)
    parser.add_argument('-ld', '--logic_dates', help='Execute dates logic', action='store_true', required=False)
    parser.add_argument('-ln', '--logic_network', help='Execute network logic', action='store_true', required=False)
    parser.add_argument('-lo', '--logic_ob', help='Execute organizational blocks logic', action='store_true',
                        required=False)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    return parser.parse_args()


def validate_arguments(args):
    if args.port_number and not utils.validate_port_number(args.port_number):
        logger.error('invalid port number')
        sys.exit(0)

    if args.scan and not utils.validate_network_subnet(args.scan):
        logger.error('scan argument: invalid network subnet given')
        sys.exit(0)

    if args.compare_online_vs_offline:
        if not args.compare_ip:
            logger.error('no ip was given for plc online/offline comparison')
            sys.exit(0)
        if args.compare_ip and not re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.compare_ip):
            logger.error('invalid ip given for plc online/offline comparison')
            sys.exit(0)
        if args.offline_projects_directory and not os.path.exists(args.offline_projects_directory):
            logger.error('offline projects directory argument: invalid path')
            sys.exit(0)
        if args.offline_project_dir_name and not os.path.exists(
                os.path.join(args.offline_projects_directory, args.offline_project_dir_name)):
            logger.error('offline project directory name argument: invalid project path')
            sys.exit(0)


def set_logging_config(to_file, verbose=False, log_fpath=None):
    level = 'INFO'
    if verbose:
        level = 'DEBUG'

    logger.remove()
    logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level=level)

    if to_file:
        logger.add(log_fpath, level=level)


def initiate_program(args):
    for dpath in [RAW_FILES_DIR, OUT_FILES_DIR, LOGIC_FILES_DIR, BLOCK_COMP_DIR]:
        utils.ensure_directory_exists(dpath, override=args.override_output_dirs)

    set_logging_config(to_file=args.file_output, verbose=args.verbose, log_fpath=LOG_FPATH)


def main():
    args = parse_arguments()
    validate_arguments(args)
    initiate_program(args)

    logger.info('Tool started')

    port = 102
    ip_addresses = []

    if args.port_number:
        port = args.port_number

    if args.ip_addresses_file:
        ip_addresses = utils.get_ip_addresses(args.ip_addresses_file)
    elif args.scan:
        if args.port_number:
            ip_addresses = scanner.start(subnet=args.scan, port=port)
        else:
            ip_addresses = scanner.start(subnet=args.scan)

    parsed_devices_data = []
    if args.ip_addresses_file or args.scan:
        extractor.start(ip_addresses, port, RAW_FILES_DIR)

    if args.logic_all or args.logic_author or args.logic_dates or args.logic_network or args.logic_ob:
        parsed_devices_data = utils.get_parsed_devices_data(RAW_FILES_DIR)
        block_logic.start(parsed_devices_data, LOGIC_FILES_DIR, logic_all=args.logic_all,
                          logic_author=args.logic_author, logic_dates=args.logic_dates,
                          logic_network=args.logic_network, logic_ob=args.logic_ob)

    if args.compare_online_vs_offline:
        ip_blocks = utils.get_ip_blocks(args.compare_ip, parsed_devices_data, RAW_FILES_DIR)
        on_off_compare.start(args.compare_ip, ip_blocks, BLOCK_COMP_DIR, proj_def_path=args.offline_projects_directory,
                             proj_name=args.offline_project_dir_name)

    logger.info('Finished')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.debug(e)
        sys.exit(1)
