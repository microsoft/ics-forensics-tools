import socket
import pandas as pd
from ipaddress import IPv4Network, IPv4Address
from pathlib import Path
from typing import List
from concurrent.futures import ThreadPoolExecutor


class Discover(object):
    def __init__(self):
        self.scans = []

    def _validate_connection(self, address: dict, port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)
        response = s.connect_ex((address["ip"], port))
        if response == 0:
            self.scans.append(address)
        s.close()

    def scan(self, addresses: List[dict], port: int) -> List[dict]:
        with ThreadPoolExecutor(30) as executor:
            for address in addresses:
                executor.submit(self._validate_connection, address, port)
        return [dict(s) for s in set(frozenset(d.items()) for d in self.scans)]

    @staticmethod
    def get_socket_addresses(addresses: List[dict]):
        extended_addresses = []
        for address in addresses:
            try:
                IPv4Address(address["ip"])
                extended_addresses.append(address)
            except ValueError:
                try:
                    for ip in IPv4Network(address["ip"]):
                        address["ip"] = str(ip)
                        extended_addresses.append(address.copy())
                except ValueError:
                    pass
        return extended_addresses

    @staticmethod
    def get_addresses_from_file(file_path: Path) -> List[dict]:
        if file_path:
            df = pd.read_csv(file_path)
            if 'ip' in df.columns:
                return df.to_dict('records')
            raise KeyError("CSV file must contain ip column")
        raise Exception("IP addresses were not provided")
