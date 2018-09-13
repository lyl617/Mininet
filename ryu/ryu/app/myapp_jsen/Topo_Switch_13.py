#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/8/6 8:54 PM
# @Author  : Jsen617
# @Site    : 
# @File    : topo_Switch_13.py
# @Software: PyCharm
from operator import attrgetter

"""
Usage example
1. Run this application:
$ ryu-manager  --observe-links topo_Switch_13.py


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
import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from collections import defaultdict
from ryu.topology import event
from ryu.topology.switches import *
from ryu.lib.dpid import dpid_to_str,str_to_dpid
import threading

mutex = threading.Lock()
class TopoSwitch13(simple_switch_13.simpleswitch13):
    def __init__(self,*args,**kwargs):
        super(TopoSwitch13,self).__init__(*args,**kwargs)
        self.monitor_thread = hub.spawn(self._monitor)

        self.switches = {}
        self.port_state = {}
        self.links = defaultdict(lambda : None)
        self.hosts = HostState()
        self.switch_macs = set()
        self.net_topo = defaultdict(lambda :defaultdict(lambda :None))

        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER,DEAD_DISPATCHER])
    def _state_change_handler(self,ev):

        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x',datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x',datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self,ev):
        msg = ev.switch
        # msg struct:
        # {'dpid': '0000000000000001',
        #  'ports': [
        #      {'dpid': '0000000000000001',
        #       'hw_addr': 'b6:b8:0b:3f:e5:86',
        #       'name': 's1-eth1',
        #       'port_no': '00000001'},
        #      {'dpid': '0000000000000001',
        #       'hw_addr': '2e:fa:67:bd:f3:b2',
        #       'name': 's1-eth2',
        #       'port_no': '00000002'}
        #  ]
        #  }
        self._register(msg.dp)
        self.logger.info('Switch enter:%s',dpid_to_str(msg.dp.id))

    def _register(self,dp):
        assert dp.id is not None
        self.switches[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = PortState()
            print("register ports:%s",self.port_state)
            for port in dp.ports.values():
                self.switch_macs.add(port.hw_addr)
                self.port_state[dp.id].add(port.port_no,port)

    def _unregister(self,dp):
        if dp.id in self.switches:
            if (self.switches[dp.id] == dp):
                del self.switches[dp.id]
                del self.port_state[dp.id]

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self,ev):

        msg = ev.host
        in_port = msg.port
        mac = msg.mac

        if self._is_edge_port(mac):
            if mutex.acquire():
                self.hosts.add(msg)
                mutex.release()
            src_dpid = msg.mac
            for ip4 in msg.ipv4:
                self.arp_table[ip4] = src_dpid
            self.logger.info("event_host_add %s",src_dpid)

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self,ev):
        msg = ev.link
        if self.links[msg] is not None:
            return
        self.links[msg] = 1
        self.logger.info('event_link_add')
    def _is_edge_port(self,mac):
        if mac in self.switch_macs:
            return False
        return True

    def _monitor(self):
        while True:
            self._update_host_list()
            self._update_net_topo()
            self.logger.info("all hosts %s",[host for host in self.hosts])
            hub.sleep(50)

    def _update_host_list(self):
        if mutex.acquire():
            for host_mac in self.hosts:
                host = self.hosts[host_mac]
                port = host.port
                if not self._is_edge_port(host.mac):
                    del(self.hosts[host_mac])
                    mutex.release()
                    return
            mutex.release()

    def _update_net_topo(self):
        for link in self.links:
            src_port = link.src.to_dict()
            dst_port = link.dst.to_dict()
            src_mac = src_port['dpid']
            dst_mac = dst_port['dpid']

            self.net_topo[src_mac][dst_mac] = link.to_dict()
            # link struct
            # {'src': self.src.to_dict(),
            #  'dst': self.dst.to_dict()}

        for host_mac in self.hosts:
            host = self.hosts[host_mac].to_dict()
            # host struct
            # {'mac': self.mac,
            #  'ipv4': self.ipv4,
            #  'ipv6': self.ipv6,
            #  'port': self.port.to_dict()}

            switch_port = host['port']
            dpid = switch_port['dpid']
            # port struct
            # {'dpid': dpid_to_str(self.dpid),
            #  'port_no': port_no_to_str(self.port_no),
            #  'hw_addr': self.hw_addr,
            #  'name': self.name.decode('utf-8')}
            host_port = {
                'hw_addr':host['mac'],
                'dpid':host['mac'],
                'port_no':'00000001',
                'name':'host'
            }
            host_id = host['mac']

            link_info_1 = {'src':host_port,'dst':switch_port}
            link_info_2 = {'src':switch_port,'dst':host_port}

            self.net_topo[host_id][dpid] = link_info_1
            self.net_topo[dpid][host_id] = link_info_2
    def print_topo(self):
        self.logger.info("------------")
        for node in self.net_topo:
            self.logger.info("node-->%s",node)
            for sub in self.net_topo[node]:
                if self.net_topo[node][sub] is not None:
                    self.logger.info("         sub:%s",sub)
        self.logger.info("------------")


if __name__ == "__main__":
    pass