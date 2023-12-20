#!/home/ad5ian/project/BotNet/venv/bin/python3

# Author: Adrian Lujan Muñoz ( aka clhore )

# net_scan.py 192.168.169.0 255.255.255.0 2 True False

from ipaddress import ip_address, ip_network, IPv4Address, IPv4Interface, AddressValueError, NetmaskValueError
from typing import List, Any

from progress.bar import Bar, ChargingBar
from argparse import ArgumentParser
from tabulate import tabulate
from icmplib import ping
import pandas as pd
from os.path import isfile, isdir
import threading
import socket
import nmap3
import os

IP_INFO_LIST: list[Any] = list()


def client_list(net: str, mask: str) -> list:
    ip_list: list = list(
        ip_network('{red}/{mask}'.format(red=net, mask=mask))
    )
    return ip_list


def network_ip_parsec(net: str) -> str or bool:
    try:
        return format(ip_address(net))
    except ValueError:
        return False


def mask_parsec(net, mask) -> str or bool:
    try:
        return IPv4Interface('{red}/{mask}'.format(red=net, mask=mask)) \
            .with_netmask.split('/')[1]
    except AddressValueError:
        return False
    except NetmaskValueError:
        return False


def icmp_scan(ipaddress: str) -> bool:
    try:
        host: object = ping(ipaddress, count=1, privileged=False)
        return host.is_alive
    except UnicodeError:
        return False


def tcp_scan(ipaddress: str) -> bool:
    list_ports: list = [135, 137, 138, 139, 445, 548, 631, 20, 21, 22, 23, 25, 80, 111, 443, 445, 631, 993, 995]
    session: object = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )
    socket.setdefaulttimeout(1)

    for PORT in list_ports:
        res: int = session.connect_ex(
            (ipaddress, PORT)
        )
        session.close()

        if res == 111:
            return True
    return False


def udp_scan(ipaddress: str) -> bool:
    list_ports: list = [53, 123]
    session: object = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )
    socket.setdefaulttimeout(1)

    for PORT in list_ports:
        res: int = session.connect_ex((ipaddress, PORT))
        if res == 0:
            return True
    return False


def hostname_scan(ipaddress: str) -> str or bool:
    host_info: object = nmap3.NmapScanTechniques().nmap_ping_scan(ipaddress)
    hostname: object = None
    macaddress: object = None

    try:
        hostname: str = host_info[ipaddress]['hostname'][0]['name']
    except IndexError:
        hostname: bool = False
    except TypeError:
        hostname: bool = False
    except KeyError:
        hostname: bool = False

    try:
        macaddress: dict = host_info[ipaddress]['macaddress']['addr']
    except IndexError:
        macaddress: bool = False
    except TypeError:
        macaddress: bool = False
    except KeyError:
        macaddress: bool = False

    return hostname, macaddress


class Hilo(threading.Thread):
    def __init__(self, ip_list: list, icmp: bool = True, tcp: bool = None, udp: bool = None, hostname: bool = None,
                 verbose: bool = False, progress_bar: object = None):
        threading.Thread.__init__(self)
        self.IP_LIST: list = ip_list
        self.ICMP: bool = icmp
        self.TCP: bool = tcp
        self.UDP: bool = udp
        self.HOSTNAME: bool = hostname
        self.VERBOSE: bool = verbose
        self.PROGRESS_BAR: object = progress_bar

    def run(self):

        for ip in self.IP_LIST:
            err_icmp: bool = False
            err_tcp: bool = False
            err_udp: bool = False
            hostname: bool = False
            macaddress: bool = False

            if self.ICMP:
                err_icmp = icmp_scan(str(ip))

            if self.TCP:
                err_tcp = tcp_scan(str(ip))

            if self.UDP:
                err_udp = udp_scan(str(ip))

            if (err_icmp or err_tcp or err_udp) and self.HOSTNAME:
                hostname, macaddress = hostname_scan(str(ip))

            ip_info = {
                'ip': str(ip),
                'hostname': hostname,
                'macaddress': macaddress,
                'icmp': err_icmp,
                'tcp': err_tcp,
                'udp': err_udp
            }

            if err_icmp or err_tcp or err_udp:
                IP_INFO_LIST.append(ip_info)

            if (err_icmp or err_tcp or err_udp) and self.VERBOSE:
                print(
                    '{}	ONLINE'.format(ip_info['ip']),
                    end='\r'
                )

            if (err_icmp or err_tcp or err_udp) and self.PROGRESS_BAR is not None:
                self.PROGRESS_BAR.message = f'Network Scan: [ {ip} ] '

            if not self.VERBOSE and self.PROGRESS_BAR is not None:
                self.PROGRESS_BAR.next()


def net_scan(ip_list, icmp: bool = True, hostname: bool = True, tcp: bool = False, udp: bool = False,
             verbose: bool = False) -> bool:
    num_ip = len(ip_list)
    threads = 3
    num_threads = int((num_ip / threads)) + 1

    bar_scan = ChargingBar(f'Network Scan: [ -/- ] ', max=num_ip) if not verbose else None

    count = 0
    thread_list = list()
    for i in range(num_threads):
        _IP_LIST = ip_list[count:count + 3]
        thread = Hilo(_IP_LIST, icmp=icmp, tcp=tcp, udp=udp, hostname=hostname, verbose=verbose, progress_bar=bar_scan)
        thread.start()
        thread_list.append(thread)
        count += 3

    for thread in thread_list:
        thread.join()

    return True


def oui_detection(macaddress, rute_data_oui) -> str or bool:
    oui = macaddress[0:8]  # .replace(':', '-')
    with open(rute_data_oui, 'r') as file:
        while line := file.readline().rstrip():
            if oui in line:
                return line.split(',')[1]
    return False


def csv_data(data_list, filename: str = 'log.csv'):
    try:
        df = pd.json_normalize(data_list)
        df.to_csv(filename)
        return True
    except PermissionError:
        return False


def create_table(data_list: list, rute_data_oui, scan_mode: int, output_file: str = False, gui_mode: bool = False) -> object:
    data_file = {}

    if scan_mode == 0:
        data_file = {
            'ip': [i['ip'] for i in data_list],
            'status': ['ONLINE' for i in data_list]
        }

    if scan_mode in (1, 2, 3):
        data_file = {
            'ip': [i['ip'] for i in data_list],
            'hostname': [i['hostname'] for i in data_list],
            'macaddress': [i['macaddress'] for i in data_list],
            'oui': [oui_detection(i['macaddress'], rute_data_oui) if i['macaddress'] is not False else i['macaddress']
                    for i in
                    data_list],
            # 'status': ['ONLINE' for i in data_list]
        }

    present_keys = [key for key, value in data_file.items() if value]
    combined_data = list(zip(*(data_file[key] for key in present_keys)))

    sorted_data = sorted(combined_data, key=lambda x: int(x[present_keys.index('ip')].split('.')[-1]))

    # headers = [key.upper() for key in present_keys]

    # if not gui_mode:
    table = tabulate(
        sorted_data, headers=[i.upper() for i in data_file],
        showindex=True, tablefmt='fancy_grid', disable_numparse=True
    )

    if output_file:
        data_file = list()
        for i in data_list:
            i['oui'] = oui_detection(i['macaddress'], rute_data_oui) if i['macaddress'] is not False else i[
                'macaddress']
            data_file.append(i)
        # print(data_file)
        csv_data(data_file, filename=output_file)

    return table


def parser_arguments():
    parser = ArgumentParser(description='Escaner de red')

    parser.add_argument('net_ip_address', type=str, help='Ip de red')

    network_mask_description = 'Mascara de la red. Default 255.255.255.0 /24'
    parser.add_argument(
        '--mask', '--net-mask', type=str,
        help=network_mask_description, default='255.255.255.0'
    )

    scan_mode_description = 'Modo de scaneo [0,1,2,3]. Default 1'
    parser.add_argument(
        '-m', '--mode', type=int,
        help=scan_mode_description, default=1
    )

    verbose_description = 'ON verbose'
    parser.add_argument(
        '-v', '--verbose', action="store_true",
        help=verbose_description, default=False
    )

    gui_description = 'ON GUI mode'
    parser.add_argument(
        '-G', '--gui', action="store_true",
        help=gui_description, default=False
    )

    oui_description = 'ON GUI mode'
    parser.add_argument(
        '--oui', '--mac-oui', type=str,
        help=oui_description, default='/opt/hostExplorer/oui_hex.txt'
    )

    output_description = 'Save scan on csv file'
    parser.add_argument(
        '-o', '--output', type=str,
        help=output_description, default=False
    )

    return parser.parse_args()


def touch(filename, flags=os.O_CREAT | os.O_RDWR):
    os.close(os.open(filename, flags, 0o644))


def main():
    args = parser_arguments()

    net = args.net_ip_address
    mask = args.mask
    scan_mode = args.mode
    verbose = args.verbose
    gui_mode = args.gui
    rute_data_oui = args.oui
    output_file = args.output

    net = network_ip_parsec(net)
    mask = mask_parsec(net, mask)

    try:
        with open(rute_data_oui, 'r') as f:
            f.read()
    except FileNotFoundError:
        raise ValueError('ERROR: File data oui not exit')
    except IsADirectoryError:
        raise ValueError('ERROR: Path data oui is file not directory')
    except PermissionError:
        raise ValueError('ERROR: The user does not have read permission for the oui file')

    if isdir(output_file):
        raise ValueError('ERROR: Path output is file not directory')

    if not os.path.exists(output_file):
        touch(filename=output_file)
    output_file = output_file if isfile(output_file) else False

    if not net:
        raise ValueError('ERROR: Network address incorrect')
    if not mask:
        raise ValueError('ERROR: Network mask address incorrect')

    ip_list = client_list(net, mask)

    if scan_mode == 0:
        net_scan(ip_list, icmp=True, hostname=False, tcp=False, udp=False, verbose=verbose)
    elif scan_mode == 1:
        net_scan(ip_list, icmp=True, hostname=True, tcp=False, udp=False, verbose=verbose)
    elif scan_mode == 2:
        net_scan(ip_list, icmp=False, hostname=True, tcp=True, udp=False, verbose=verbose)
    elif scan_mode == 3:
        net_scan(ip_list, icmp=False, hostname=True, tcp=False, udp=True, verbose=verbose)

    table = create_table(IP_INFO_LIST, rute_data_oui, scan_mode, output_file, gui_mode)
    print(f"\r{' ' * 80}", end='\r')
    print(f'\r{table}', end='\n', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e)
