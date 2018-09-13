#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/8/8 3:44 PM
# @Author  : Jsen617
# @Site    : 
# @File    : ospf_switch_13.py
# @Software: PyCharm

"""
Usage example
1. Run this application:
$ ryu-manager  --observe-links ospf.switch_13.py


2. Switch struct

please see ryu/topology/switches.py

msg struct:
{'dpid': '0000000000000001',
'ports': [
            {'dpid': '0000000000000001',
            'hw_addr': 'b6:b8:0b:3f:e5:86',
            'name': 's1-eth1',
            'port_no': '00000001'},
            {'dpid': '0000000000000001',
            'hw_addr': '2e:fa:67:bd:f3:b2',
            'name': 's1-eth2',
            'port_no': '00000002'}
        ]
}

2. Link struct

please see ryu/topology/switches.py

note: two node will get two link.

eg: s1--s2  will get link: s1 -> s2 and link: s2->s1

msg struct

{
'dst': {'port_no': '00000001',
         'name': 's2-eth1',
         'hw_addr': '52:9c:f6:6d:d3:5f',
         'dpid': '0000000000000002'},
'src': {'port_no': '00000001',
        'name': 's1-eth1',
        'hw_addr': '22:33:5a:65:de:62',
        'dpid': '0000000000000001'}
}


3. Topology change is notified:
< {"params": [{"ports": [{"hw_addr": "56:c7:08:12:bb:36", "name": "s1-eth1", "port_no": "00000001", "dpid": "0000000000000001"}, {"hw_addr": "de:b9:49:24:74:3f", "name": "s1-eth2", "port_no": "00000002", "dpid": "0000000000000001"}], "dpid": "0000000000000001"}], "jsonrpc": "2.0", "method": "event_switch_enter", "id": 1}
> {"id": 1, "jsonrpc": "2.0", "result": ""}
< {"params": [{"ports": [{"hw_addr": "56:c7:08:12:bb:36", "name": "s1-eth1", "port_no": "00000001", "dpid": "0000000000000001"}, {"hw_addr": "de:b9:49:24:74:3f", "name": "s1-eth2", "port_no": "00000002", "dpid": "0000000000000001"}], "dpid": "0000000000000001"}], "jsonrpc": "2.0", "method": "event_switch_leave", "id": 2}
> {"id": 2, "jsonrpc": "2.0", "result": ""}
...
"""
from operator import attrgetter
import topo_Switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,DEAD_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch,get_link,get_all_host,get_host
from ryu.topology.switches import Switches
from collections import defaultdict
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4,ipv6,dhcp,udp
from ryu.lib import mac
from ryu.lib import addrconv
from ryu.lib.dpid import dpid_to_str,str_to_dpid

ARP = arp.arp.__name__
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = 'ff:ff:ff:ff:ff:ff'

class ospfswitch13(topo_Switch_13.TopoSwitch13):
    def __init__(self,*args,**kwargs):
        super(ospfswitch13,self).__init__(*args,**kwargs)

        self.sw = {}
        self.full_path = defaultdict(lambda :defaultdict(lambda :None))

        self.hw_addr = '0a:e4:1c:d1:3e:44'
        self.dhcp_server = '192.168.2.100'
        self.netmask = '255.255.255.0'
        self.dns = '8.8.8.8'
        self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)
        self.hostname = str.encode('huehuehue')
        self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)
        self.bin_server = addrconv.ipv4.text_to_bin(self.dhcp_server)
        self.ip_addr_prefix = '10.0.0.'
        self.ip_counter = 10
        self.ip_pool = {}
        self.all_macs = []

    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def _packet_int_handler(self,ev):

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len,ev.msg.total_len)
            msg = ev.msg
            datapath = msg.datapath
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            dst_mac = eth.dst
            src_mac = eth.src

            #--------process Ipv6 packet-----
            if pkt.get_protocol(ipv6.ipv6):
                #Drop the Ipv6 Packets
                match = ofp_parser.OFPMatch(eth_type = eth.ethertype)
                actions = []
                self.add_flows(datapath,1,match,actions)
                return None
            #-------

            #--------process LLDP packet---
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            #--------

            #-------process ARP--
            arp_pkt = pkt.get_protocol(arp.arp)

            if arp_pkt:
                self.arp_table[arp_pkt.src_ip] = src_mac
                self.arp_handler(msg,pkt)
                return None

            #-------process DHCP--
            dhcp_pkt = pkt.get_protocols(dhcp.dhcp)
            if dhcp_pkt:
                self.dhcp_handler(datapath,in_port,pkt)
                return None


    def arp_handler(self,msg,pkt):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocols(arp.arp)[0]

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        # Break the loop for avoiding ARP broadcast storm
        if eth_dst == mac.BROADCAST_STR:
            arp_dst_ip = arp_pkt.dst_ip
            arp_src_ip = arp_pkt.src_ip

            if (datapath.id,arp_src_ip,arp_dst_ip) in self.sw:
                #packet come back at different port
                if self.sw[(datapath.id,arp_src_ip,arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port,actions=[])
                    return True
            else:
                self.sw[(datapath.id,arp_src_ip,arp_dst_ip)] = in_port

        # Try to reply arp request
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                hwtype = arp_pkt.hwtype
                proto = arp_pkt.proto
                hlen = arp_pkt.hlen
                plen = arp_pkt.plen
                arp_src_ip = arp_pkt.src_ip
                arp_dst_ip = arp_pkt.dst_ip
                if arp_dst_ip in self.arp_table:
                    actions = [parser.OFPActionOutput(in_port)]
                    ARP_Reply = packet.Packet()

                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype = eth.ethertype,
                        dst = eth_src,
                        src = self.arp_table[arp_dst_ip]
                    ))

                    ARP_Reply.add_protocol(arp.arp(
                        opcode = arp.ARP_REPLY,
                        src_mac = self.arp_table[arp_dst_ip],
                        src_ip = arp_dst_ip,
                        dst_mac = eth_src,
                        dst_ip = arp_src_ip
                    ))

                    ARP_Reply.serialize()

                    out = parser.OFPPacketOut(
                        datapath = datapath,
                        buffer_id = ofproto.OFP_NO_BUFFER,
                        in_port = ofproto.OFPP_CONTROLLER,
                        actions = actions,
                        data = ARP_Reply.data
                    )
                    datapath.send_msg(out)
                    return True
        return False

    def dhcp_handler(self,datapath,in_port,pkt):
        dhcp_pkt = pkt.get_protocols(dhcp.dhcp)[0]
        chaddr = dhcp_pkt.chaddr
        dhcp_state = self.get_state(dhcp_pkt)
        self.logger.debug("New DHCP -->%s<-- Packet Received"%(dhcp_state))
        if dhcp_state == 'DHCPDISCOVER':
            self._send_packetOut(datapath,in_port,self.assemble_offer(pkt,chaddr))
        elif dhcp_state == 'DHCPREQUEST':
            self._send_packetOut()
        else:
            return

    def _send_packetOut(self,datapath,port,pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.debug("packet-out DHCP")
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def assemble_offer(self,pkt,chaddr):
        chaddr_yiaddr = self.get_ip(chaddr)
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc_udp = pkt.get_protocol(udp.udp)
        disc = pkt.get_protocol(dhcp.dhcp)
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 55)
        )
        
    def get_ip(self,mac):
        if mac not in self.ip_pool:
            ip = self.ip_addr_prefix + str(self.ip_counter)
            self.ip_counter += 1
            self.ip_pool[mac] = ip
        else:
            ip = self.ip_pool[mac]
        return ip








if __name__ == "__main__":
    pass