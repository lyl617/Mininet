#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 03/08/2018 9:21 AM
# @Author  : Jsen617
# @Site    : 
# @File    : Traffic_Monitor.py
# @Software: PyCharm
from operator import attrgetter
import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

class TrafficMonitor(simple_switch_13.simpleswitch13):
    def __init__(self,*args,**kwargs):
        super(TrafficMonitor,self).__init__(*args,**kwargs)
        self.datapaths={}
        self.monitor_thread = hub.spawn(self._monitor)
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER,DEAD_DISPATCHER])
    def _state_change_handler(self,ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x',datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x',datapath.id)
                del self.datapaths[datapath.id]
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
    def _request_stats(self,datapath):
        self.logger.debug('send stats request: %016x',datapath.id)
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = ofp_parser.OFPPortStatsRequest(datapath,0,ofp.OFPP_ANY)
        datapath.send_msg(req)
    @set_ev_cls(ofp_event.EventOFPPortStatsReply,MAIN_DISPATCHER)
    def port_stats_reply_handler(self,ev):
        ports=[]
        for stat in ev.msg.body:
            ports.append('port_no=%d,rx_packets,tx_packets=%d,'
                         'rx_bytes=%d,tx_bytes=%d,'
                         'rx_dropped=%d，tx_dropped=%d,'
                         'rx_errors=%d,tx_errors=%d,'
                         'rx_frame_err=%d,rx_over_err=%d,rx_crc_err=%d,'
                         'collisions=%d,duration_sec=%d,duration_nsec=%d'%
                         (stat.port_no,stat.tx_packets,stat.tx_packets,
                          stat.rx_bytes,stat.tx_bytes,
                          stat.rx_dropped,stat.tx_dropped,
                          stat.rx_errors,stat.tx_errors,
                          stat.rx_frame_err,stat.rx_over_err,stat.rx_crc_err,
                          stat.collisions,stat.duration_sec,stat.duration_nsec))
        self.logger.debug('PortStats: %s',ports)
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply,MAIN_DISPATCHER)
    def flow_stats_reply_handler(self,ev):
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s'
                     'duration_sec=%d duration_nsec=%d '
                     'priority=%d '
                     'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                     'cookie=%d packet_count=%d byte_count=%d '
                     'match=%s instructions=%s' %
                     (stat.table_id,
                      stat.duration_sec, stat.duration_nsec,
                      stat.priority,
                      stat.idle_timeout, stat.hard_timeout, stat.flags,
                      stat.cookie, stat.packet_count, stat.byte_count,
                      stat.match, stat.instructions))
        self.logger.debug('FlowsStats: %s',flows)


if __name__ == "__main__":
    pass