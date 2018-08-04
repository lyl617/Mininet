#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 02/08/2018 3:15 PM
# @Author  : Jsen617
# @Site    : 
# @File    : simple_switch_13.py
# @Software: PyCharm
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

class simpleswitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self,*args,**kwargs):
        super(simpleswitch13,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

    def add_flows(self,datapath,priority,match,actions,buffer_id=None):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        if buffer_id:
            mod = ofp_parser.OFPFlowMod(datapath,command=ofproto.OFPFC_ADD,priority=priority,
                                        buffer_id=buffer_id,match=match,instructions=inst)
        else:
            mod = ofp_parser.OFPFlowMod(datapath,command=ofproto.OFPFC_ADD,priority=priority,
                                        match=match,instructions=inst)
        datapath.sendmsg(mod)
    @set_ev_cls(ofp_event.EventOFPSwitchFeature,CONFIG_DISPATCHER)
    def switch_feature_handler(self,ev):
        msg = ev.msg
        dp = msg.datapth
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        match = ofp_parser.OFPMatch()

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]

        self.add_flows(datapath=dp,priority=0,match=match,actions=actions)
    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        msg = ev.msg
        dp = msg.datapth
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        in_port = msg.match["in_port"]
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        out = ofp_parser.OFPPacketOut(dp,in_port=in_port,actions=actions)
        
        dp.sendmsg(out)




if __name__ == "__main__":
    pass