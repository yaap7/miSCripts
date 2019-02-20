#!/usr/bin/env python3

import logging
import re
import sys
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot3, Ether, Dot1Q, STP, IP, TCP, UDP, SNMP, HSRP, HSRPmd5, rdpcap


logging.basicConfig(
	level=logging.INFO,
	# level=logging.DEBUG,
	# filename='output.log'
	# format='(%(threadName)-10s)-%(levelname)s: %(message)s',
	format='%(message)s',
)


def display_proto(r):
	logging.info('{}'.format(r))


def display_item(r):
	logging.info('    {}'.format(r))


def add_result(results, item_type, data):
	if item_type in results.keys():
		if data not in results[item_type]:
			results[item_type].append(data)
	else:
		results[item_type] = [data]


def display_info_from_packet(pkt, results):
	if Dot1Q in pkt:
		logging.debug('Start dissecting Dot1Q')
		add_result(results, 'mac_addresses', pkt[Ether].src)
		add_result(results, 'mac_addresses', pkt[Ether].dst)
		add_result(results, 'vlans', pkt[Dot1Q].vlan)
		display_proto('{:<8}: {:<17} -> {:<17}'.format('Dot1Q', pkt[Ether].src, pkt[Ether].dst))
		display_item('Dot1Q vlan = {}'.format(pkt[Dot1Q].vlan))
	if STP in pkt:
		logging.debug('Start dissecting STP')
		if Ether in pkt:
			add_result(results, 'mac_addresses', pkt[Ether].src)
			add_result(results, 'mac_addresses', pkt[Ether].dst)
			display_proto('{:<8}: {:<17} -> {:<17}'.format('STP', pkt[Ether].src, pkt[Ether].dst))
		elif Dot3 in pkt:
			add_result(results, 'mac_addresses', pkt[Dot3].src)
			add_result(results, 'mac_addresses', pkt[Dot3].dst)
			display_proto('{:<8}: {:<17} -> {:<17}'.format('STP', pkt[Dot3].src, pkt[Dot3].dst))
		else:
			logging.info('---------------STP Not supported yet.')
		add_result(results, 'mac_addresses', pkt[STP].rootmac)
		add_result(results, 'mac_addresses', pkt[STP].bridgemac)
		display_item('STP version = {}'.format(pkt[STP].version))
		display_item('STP rootmac = {}'.format(pkt[STP].rootmac))
		display_item('STP bridgemac = {}'.format(pkt[STP].bridgemac))
		# TODO: rajouter un cas pour récupérer le 'orignating vlan'
		# il est visible avec wireshark mais pas scapy: le rajouter dans scapy.
		# le vlan n'est pas toujours envoyé dans une trame dot1Q, donc ça donne de l'info en plus
	if HSRP in pkt:
		logging.debug('Start dissecting HSRP')
		add_result(results, 'ip_addresses', pkt[IP].src)
		add_result(results, 'ip_addresses', pkt[IP].dst)
		add_result(results, 'ip_addresses', pkt[HSRP].virtualIP)
		display_proto('{:<8}: {:<15} -> {:<15}'.format('HSRP', pkt[IP].src, pkt[IP].dst))
		display_item('HSRP virtualIP = {}'.format(pkt[HSRP].virtualIP))
		if HSRPmd5 in pkt:
			logging.debug('Start dissecting HSRPmd5')
			add_result(results, 'ip_addresses', pkt[HSRPmd5].sourceip)
			add_result(results, 'md5sums', pkt[HSRPmd5].authdigest)
			display_item('HSRPmd5 sourceip = {}'.format(pkt[HSRPmd5].sourceip))
			display_item('HSRPmd5 authdigest = {}'.format(pkt[HSRPmd5].authdigest))
	if SNMP in pkt:
		logging.debug('Start dissecting SNMP')
		add_result(results, 'ip_addresses', pkt[IP].src)
		add_result(results, 'ip_addresses', pkt[IP].dst)
		add_result(results, 'SNMP_version', pkt[SNMP].version.val)
		add_result(results, 'SNMP_community', pkt[SNMP].community.val.decode('utf-8'))
		display_proto('{:<8}: {:<15} -> {:<15}'.format('SNMP', pkt[IP].src, pkt[IP].dst))
		display_item('SNMP version = {}'.format(pkt[SNMP].version.val))
		display_item('SNMP community = {}'.format(pkt[SNMP].community.val.decode('utf-8')))
	if IP in pkt:
		add_result(results, 'ip_addresses', pkt[IP].src)
		add_result(results, 'ip_addresses', pkt[IP].dst)
	if UDP in pkt:
		logging.debug('Start dissecting UDP')
		if 'load' not in pkt[UDP].fields.keys() or pkt[UDP].load == b'\n':
			logging.debug('Start dissecting empty UDP')
			logging.debug('empty UDP: not interessting')
		# elif pkt[UDP].load == b'\n':
		# 	logging.debug('Start dissecting empty UDP')
		# 	logging.debug('empty UDP: not interessting')
		elif re.search(b'^M-SEARCH \* HTTP/1\.1', pkt[UDP].load):
			logging.debug('Start dissecting SSDP')
			logging.debug('SSDP: not interessting')
		elif re.search(b'http://schemas.xmlsoap.org/ws/2005/04/discovery', pkt[UDP].load):
			logging.debug('Start dissecting XML shit')
			logging.debug('XML shit: not interessting')
		else:
			logging.info('---------------UDP Not supported yet.')
	if SNMP not in pkt and HSRP not in pkt and STP not in pkt and UDP not in pkt:
		logging.debug('---------------Not supported yet.')


def main():
	pkts = rdpcap(sys.argv[1])
	results = {}
	i = 0
	for pkt in pkts:
		logging.debug('Dissecting packet number {}'.format(i))
		display_info_from_packet(pkt, results)
		i += 1
	for item_type in results.keys():
		if results[item_type]:
			logging.info('List of {}:'.format(item_type))
			results[item_type].sort()
			for item_value in results[item_type]:
				logging.info('{}'.format(item_value))



if __name__ == '__main__':
	main()
