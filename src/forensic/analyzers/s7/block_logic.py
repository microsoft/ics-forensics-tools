import os
import json
import datetime
import ipaddress
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from copy import deepcopy
from collections import Counter
from itertools import chain
from pathlib import Path
from forensic.interfaces.analyzer import AnalyzerInterface, AnalyzerCLI


class S7BlockLogicCLI(AnalyzerCLI):
    def flags(self, parser):
        parser.add_argument('--logic_all', help='Execute all logics for S7BlockLogic analyzer', action='store_true')
        parser.add_argument('--logic_author', help='Execute author logic for S7BlockLogic analyzer',
                            action='store_true')
        parser.add_argument('--logic_dates', help='Execute date logic for S7BlockLogic analyzer', action='store_true')
        parser.add_argument('--logic_network', help='Execute network logics for S7BlockLogic analyzer',
                            action='store_true')
        parser.add_argument('--logic_ob', help='Execute organizational blocks logic for S7BlockLogic analyzer',
                            action='store_true')


class S7BlockLogic(AnalyzerInterface):
    def __init__(self, config, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.plugin_name = 'S7'
        self.create_output_dir(self.plugin_name)

    def analyze(self):
        parsed_devices_data = self.get_parsed_devices_data()
        if parsed_devices_data:
            logic_all = self.config.parameters.get("logic_all")
            logic_author = self.config.parameters.get("logic_author")
            logic_dates = self.config.parameters.get("logic_dates")
            logic_network = self.config.parameters.get("logic_network")
            logic_ob = self.config.parameters.get("logic_ob")

            self.logger.info('Start executing block logics')

            df = pd.DataFrame(parsed_devices_data)
            if df.empty:
                self.logger.debug('no blocks exist for logic check')
                return
            df['block_id'] = df['type'].astype(str) + "_" + df["block_num"].astype(str)

            ip_addresses = df.ip.unique().tolist()

            if logic_all or logic_author:
                self.author_check(df, ip_addresses)
            if logic_all or logic_dates:
                self.dates_check(df, ip_addresses)
            if logic_all or logic_network:
                self.network_check(df, ip_addresses)
            if logic_all or logic_ob:
                self.ob_roles_check(df, ip_addresses)

            self.call_tree(df, ip_addresses, self.output_dir)

            self.store_df(df, os.path.join(self.output_dir, 'blocks_metadata.csv'))

    def get_parsed_devices_data(self):
        parsed_data = []
        if not self.output_dir.parent.joinpath('S7RawFileParser').is_dir():
            self.logger.error('Please run S7RawFileParser analyzer first')
            return parsed_data
        device_dir = self.output_dir.parent.joinpath('S7RawFileParser')
        for device in os.listdir(device_dir):
            self.logger.info(f'Loading file: {device}')
            with open(device_dir.joinpath(device), 'r') as f:
                device_output = json.load(f)
            for slot_rack in device_output:
                row_prefix = {'ip': Path(device.replace('_', '.')).stem,
                              'rack': slot_rack['rack'], 'slot': slot_rack['slot']}

                if slot_rack['identity']:
                    df = pd.json_normalize(slot_rack['identity'], sep='_')
                    row_prefix.update(df.to_dict(orient='records')[0])
                self.logger.info(f'loading blocks: {device}')
                for block in slot_rack['blocks']:
                    df = pd.json_normalize(block, sep='_')
                    block_row = df.to_dict(orient='records')[0]
                    block_row.update(row_prefix)
                    parsed_data.append(block_row)

        return parsed_data

    def get_called_blocks_edges(self, block_id, called_blocks):
        if (not called_blocks) or (called_blocks != called_blocks):  # nan
            return []
        return [(block_id, called_block.replace(' ', '_')) for called_block in called_blocks]

    def call_tree_layers(self, layers, edges, nodes):
        ob_calling_edges = list(filter(lambda edge: edge[0].startswith('OB'), edges))
        other_block_calling_edges = list(filter(lambda edge: not edge[0].startswith('OB'), edges))

        for node in list(filter(lambda node: node.startswith('OB'), nodes)):
            layers[node] = 1
        for calling_block, called_block in ob_calling_edges:
            layers[calling_block] = 1
            layers[called_block] = 2
        for calling_block, called_block in other_block_calling_edges:
            layers[calling_block] = 2
            layers[called_block] = 3

        layer = max(layers.values()) + 1

        layer_added_count = 1
        while True:
            prev_layer_blocks = list(filter(lambda block: layers[block] == layer - 1, layers.keys()))
            current_edges = list(filter(lambda edge: edge[0] in prev_layer_blocks, edges))
            if not current_edges:
                # set layers to the rest of the nodes
                for block_id in list(filter(lambda block_id: layers[block_id] == -1, layers.keys())):
                    layers[block_id] = layer

                    layer_added_count += 1
                    if layer_added_count % 31 == 0:
                        layer += 1
                break

            layer_added_count = 1
            for _, called_block in current_edges:
                layers[called_block] = layer
                layer_added_count += 1
                if layer_added_count % 31 == 0:
                    layer += 1
            layer += 1

    def call_tree(self, df, ip_addresses, export_dpath):
        self.logger.info('create call tree graph')
        if 'used_block' not in df.columns:
            return

        for ip in ip_addresses:
            df_ip = deepcopy(df.loc[df['ip'] == ip])
            df_ip['called_blocks_edges'] = df_ip.apply(
                lambda row: self.get_called_blocks_edges(row['block_id'], row['used_block']), axis=1)
            edges = list(chain.from_iterable(df_ip['called_blocks_edges'].tolist()))
            nodes = {block_id: block_id for block_id in set(chain.from_iterable(edges)).union(df_ip.block_id.tolist())}

            ob_node_color = '#9021a3'
            fc_node_color = '#238018'
            fb_node_color = '#0765e0'
            db_node_color = '#034499'
            other_node_color = '#72777d'
            node_colors = []
            for node in nodes.keys():
                if node.startswith('OB'):
                    node_colors.append(ob_node_color)
                elif node.startswith('FC'):
                    node_colors.append(fc_node_color)
                elif node.startswith('FB'):
                    node_colors.append(fb_node_color)
                elif node.startswith('DB'):
                    node_colors.append(db_node_color)
                else:
                    node_colors.append(other_node_color)

            # layers creation
            layers = dict.fromkeys(nodes, -1)
            self.call_tree_layers(layers, edges, nodes)

            nx_graph = nx.DiGraph()  # Made this a DiGraph (adds arrows to visual)
            plt.figure(figsize=(8, 8))  # Enlarged figure

            for key, value in nodes.items():
                nx_graph.add_node(key, name=value, layer=layers[key])

            for edge in edges:
                nx_graph.add_edge(*edge)

            layers_count = dict.fromkeys(range(1, max(layers.values()) + 1))
            for layer in layers_count.keys():
                layers_count[layer] = len(list(filter(lambda node: layers[node] == layer, layers.keys())))

            plt.figure(20, figsize=(20, 20))
            pos = nx.multipartite_layout(nx_graph, subset_key="layer", scale=20)

            for node in pos.keys():
                if layers_count[layers[node]] > 1:  # TODO: check single node y = 0
                    mul = 5
                    pos[node][1] = pos[node][1] * mul
            ip_fmt = ip.replace('.', '_')
            export_ip_dpath = os.path.join(export_dpath, ip_fmt)
            path = Path(export_ip_dpath)
            path.mkdir(parents=True, exist_ok=True)

            nx.draw(nx_graph, pos=pos, labels=nodes, node_size=1500, with_labels=True, font_color='white', font_size=8,
                    node_color=node_colors)
            # plt.show()
            plt.savefig(os.path.join(export_ip_dpath, 'call_tree_{}.svg'.format(ip_fmt)), dpi=1000)
            nx.write_gexf(nx_graph, os.path.join(export_ip_dpath, 'call_tree_{}.gexf'.format(ip_fmt)))

    def map_module_to_cpu(self, cpu_modules_mapping, module):
        module = module.replace(' ', '')
        if module in cpu_modules_mapping['300'].keys():
            return cpu_modules_mapping['300'][module]
        return ''

    def map_module_to_cpu_series(self, cpu_modules_mapping, module):
        module = module.replace(' ', '')
        if module in cpu_modules_mapping['300'].keys():
            return '300'
        return ''

    def get_block_name_by_cpu(self, func_mapping, block_id, cpu_series):
        if block_id in func_mapping.keys():
            if cpu_series:
                if func_mapping[block_id][cpu_series]:
                    return func_mapping[block_id][cpu_series]
            return func_mapping[block_id]['default']
        return []

    def parse_ob_roles_results(self, df, ip_addresses):
        result_msg = ''

        for ip in ip_addresses:
            ob_blocks = df.loc[(df['ip'] == ip) & (df['type'] == 'OB')]
            if not ob_blocks.empty:
                result_msg += '\n\tip: {}'.format(ip)
                for i, row in ob_blocks.iterrows():
                    result_msg += '\n\t\tOB {} - start event: {}, used blocks: {}'.format(row.block_num, row.ob_role,
                                                                                          row.used_block)

        if len(result_msg) > 0:
            self.logger.info('Organizational blocks found:' + result_msg)
        else:
            self.logger.info('No Organizational blocks were found.')

    def ob_roles_check(self, df, ip_addresses):
        self.logger.debug('executing organizational block check')
        with open(Path(os.path.dirname(__file__)).joinpath('mapping', 'ob_mapping.json'), 'rb') as f:
            ob_mapping = json.loads(f.read())

        df.loc[df['type'] == 'OB', 'ob_role'] = df['block_num'].apply(
            lambda block_num: ob_mapping[str(block_num)]['start_event'] if str(
                block_num) in ob_mapping.keys() else 'Unknown')

        self.parse_ob_roles_results(df, ip_addresses)

    def parse_network_results(self, df, ip_addresses, indicators_exist=True):
        result_msg = ''

        if not indicators_exist:
            self.logger.info('No network usage was found.')
            return

        for ip in ip_addresses:
            ip_anomaly_found = False
            tcon_params_msg = ''
            comm_blocks_used_msg = ''
            tcon_params = df.loc[(df['ip'] == ip) & (df['db_ext_header_tcon_params_block_length'].isnull() == False)]
            if not tcon_params.empty:
                ip_anomaly_found = True
                tcon_params_msg += '\n\t\tnetwork parameters found for:'
                for i, row in tcon_params.iterrows():
                    if row.conn_remote_address != row.conn_remote_address:  # nan
                        is_remote_addr_external = 'unknown'
                    else:
                        is_remote_addr_external = not row.conn_remote_address['is_private']
                    tcon_params_msg += '\n\t\t\t{} {} - connection type: {}, active connection: {}, local port: {}, remote ip: {}, is remote ip external: {}, remote port: {}'.format(
                        row.type, row.block_num, row.db_ext_header_tcon_params_connection_type,
                        True if row.db_ext_header_tcon_params_active_est else False,
                        row.db_ext_header_tcon_params_local_tsap_id,
                        row.db_ext_header_tcon_params_rem_staddr, is_remote_addr_external,
                        row.db_ext_header_tcon_params_rem_tsap_id)

            uses_network_blocks = df.loc[(df['ip'] == ip) & (df['uses_communication_block'] == True)]
            if not uses_network_blocks.empty:
                ip_anomaly_found = True
                block_ids = uses_network_blocks.block_id.unique().tolist()
                tcon_params_msg += '\n\t\tThe following blocks uses network functionality: {}'.format(block_ids)

            if ip_anomaly_found:
                result_msg += '\n\tip: {}{}{}'.format(ip, tcon_params_msg, comm_blocks_used_msg)

        if len(result_msg) > 0:
            self.logger.info('Network usage found:' + result_msg)
        else:
            self.logger.info('No network usage was found.')

    def is_use_communication_blocks(self, df, ip, used_block):
        if used_block != used_block:  # nan
            return False
        used_block = set(used_block)
        for block in used_block:
            if '[' in block:  # TODO: handle calling to [..]
                continue
            block_type, block_num = block.split(' ')
            row = df.loc[(df['ip'] == ip) & (df['type'] == block_type) & (df['block_num'] == int(block_num))]
            if not row.empty:
                if row.iloc[0].block_family in ('COMM', 'COM_FUNC'):
                    return True
        return False

    def address_check(self, tcon_remote_address):
        conn_remote_address = {'is_private': False}
        try:
            conn_remote_address['is_private'] = ipaddress.ip_address(tcon_remote_address).is_private
        except:
            pass

        return conn_remote_address

    def network_check(self, df, ip_addresses):
        self.logger.debug('executing block network check')
        if 'db_ext_header_tcon_params_block_length' in df.columns:
            conn_params_df = df.loc[df['db_ext_header_tcon_params_block_length'].isnull() == False]

            df.loc[df.index.isin(conn_params_df.index), 'conn_remote_address'] = df[
                'db_ext_header_tcon_params_rem_staddr'].apply(lambda tcon_params: self.address_check(tcon_params))

            df.loc[(df['used_block'].isnull() == False) & (
                    df['used_block'].str.len() > 0), 'uses_communication_block'] = df.apply(
                lambda row: self.is_use_communication_blocks(df, row['ip'], row['used_block']), axis=1)

            self.parse_network_results(df, ip_addresses)

        else:
            self.parse_network_results(df, ip_addresses, indicators_exist=False)

    def process_dates_results(self, df, ip_addresses):
        lower_bound_modified_delta = 7
        lower_bound_interface_delta = 7
        result_msg = ''

        for ip in ip_addresses:
            ip_anomaly_found = False
            modified_msg = ''
            interface_msg = ''
            modified_delta_anomaly = df.loc[(df['ip'] == ip) & (
                    df['delta_current_time_vs_last_modified'] < datetime.timedelta(days=lower_bound_modified_delta))]
            interface_delta_anomaly = df.loc[
                (df['ip'] == ip) & (df['delta_current_time_vs_last_interface_change'] < datetime.timedelta(
                    days=lower_bound_interface_delta))]
            if not modified_delta_anomaly.empty:
                ip_anomaly_found = True
                block_ids = modified_delta_anomaly.block_id.unique().tolist()
                modified_msg += '\n\t\t{} blocks modified in that last {} days: {}'.format(len(block_ids),
                                                                                           lower_bound_modified_delta,
                                                                                           block_ids)
            if not interface_delta_anomaly.empty:
                ip_anomaly_found = True
                block_ids = interface_delta_anomaly.block_id.unique().tolist()
                interface_msg += '\n\t\t{} blocks interfaces modified in that last {} days: {}'.format(len(block_ids),
                                                                                                       lower_bound_interface_delta,
                                                                                                       block_ids)

            if ip_anomaly_found:
                result_msg += '\n\tip: {}{}{}'.format(ip, modified_msg, interface_msg)

        if len(result_msg) > 0:
            self.logger.info('Date fields anomalies found:' + result_msg)
        else:
            self.logger.info('No date fields anomalies were found.')

    def dates_check(self, df, ip_addresses):
        self.logger.debug('executing block dates check')
        current_time = datetime.datetime.now()
        df['delta_current_time_vs_last_modified'] = df['last_modified'].apply(
            lambda t: (current_time - datetime.datetime.fromisoformat(t)))
        df['delta_current_time_vs_last_interface_change'] = df['last_interface_change'].apply(
            lambda t: (current_time - datetime.datetime.fromisoformat(t)))
        df['delta_last_modified_vs_interface_change'] = df.apply(lambda row: (
                datetime.datetime.fromisoformat(row['last_modified']) - datetime.datetime.fromisoformat(
            row['last_interface_change'])), axis=1)

        for ip in ip_addresses:
            min_last_modified = datetime.datetime.fromisoformat(min(df.loc[df['ip'] == ip]['last_modified']))
            max_last_modified = datetime.datetime.fromisoformat(max(df.loc[df['ip'] == ip]['last_modified']))

            df.loc[df['ip'] == ip, 'delta_to_min_last_modified'] = df['last_modified'].apply(
                lambda last_modified: datetime.datetime.fromisoformat(last_modified) - min_last_modified)
            df.loc[df['ip'] == ip, 'delta_to_max_last_modified'] = df['last_modified'].apply(
                lambda last_modified: max_last_modified - datetime.datetime.fromisoformat(last_modified))

            min_last_interface_change = datetime.datetime.fromisoformat(
                min(df.loc[df['ip'] == ip]['last_interface_change']))
            max_last_interface_change = datetime.datetime.fromisoformat(
                max(df.loc[df['ip'] == ip]['last_interface_change']))

            df.loc[df['ip'] == ip, 'delta_to_min_last_interface_change'] = df['last_interface_change'].apply(
                lambda last_interface_change: datetime.datetime.fromisoformat(
                    last_interface_change) - min_last_interface_change)
            df.loc[df['ip'] == ip, 'delta_to_max_last_interface_change'] = df['last_interface_change'].apply(
                lambda last_interface_change: max_last_interface_change - datetime.datetime.fromisoformat(
                    last_interface_change))

        self.process_dates_results(df, ip_addresses)

    def process_author_results(self, df, ip_addresses):
        lower_bound = 3
        upper_bound = 80

        result_msg = ''

        for ip in ip_addresses:
            ip_anomaly_found = False
            lower_bound_msg = ''
            upper_bound_msg = ''
            author_anomaly = df.loc[(df['ip'] == ip) & (df['author_blocks_percentage'] < lower_bound)]
            if not author_anomaly.empty:
                ip_anomaly_found = True
                author_names = author_anomaly.author_name.unique().tolist()
                lower_bound_msg += '\n\t\tless than {}% blocks presence: {} authors found: {}'.format(
                    lower_bound, len(author_names), author_names)
            author_anomaly = df.loc[(df['ip'] == ip) & (df['author_blocks_percentage'] > upper_bound)]
            if not author_anomaly.empty:
                ip_anomaly_found = True
                author_names = author_anomaly.author_name.unique().tolist()
                upper_bound_msg += '\n\t\tmore than {}% blocks presence: {} authors found: {}'.format(
                    upper_bound, len(author_names), author_names)

            if ip_anomaly_found:
                result_msg += '\n\tip: {}{}{}'.format(ip, lower_bound_msg, upper_bound_msg)

        if len(result_msg) > 0:
            self.logger.info('Author field anomalies found:' + result_msg)
        else:
            self.logger.info('No author field anomalies were found.')

    def author_check(self, df, ip_addresses):
        self.logger.debug('executing block author check')
        agg_ips = df.groupby('author_name')['ip', 'author_name'].agg(['unique'])
        author_names = list(map(lambda e: e[0], agg_ips[('author_name', 'unique')]))
        unique_ips = list(map(lambda e: e, agg_ips[('ip', 'unique')]))
        author_plcs_amount = dict.fromkeys(author_names)
        for i in range(len(author_names)):
            author_plcs_amount[author_names[i]] = unique_ips[i]

        for ip in ip_addresses:
            df_ip = df.loc[df['ip'] == ip]
            ip_blocks_amount = len(df_ip)
            authors_count = Counter(df_ip.author_name)
            # how many blocks share this author for this specific ip (percentage)
            df.loc[df['ip'] == ip, 'author_blocks_percentage'] = df['author_name'].apply(
                lambda author_name: (authors_count[author_name] / ip_blocks_amount) * 100)
            # how many plcs share this author (percentage)
            df.loc[df['ip'] == ip, 'author_plcs_percentage'] = df['author_name'].apply(
                lambda author_name: (len(author_plcs_amount[author_name]) / len(ip_addresses)) * 100)

        self.process_author_results(df, ip_addresses)

    def store_df(self, df, fpath):
        df.drop(['body', 'data', 'interface', 'seg', 'local_data', 'body_parse'], axis=1, errors='ignore', inplace=True)
        df.to_csv(fpath, escapechar='\\', index=False)
        self.logger.info('{} file was created'.format(os.path.basename(fpath)))
