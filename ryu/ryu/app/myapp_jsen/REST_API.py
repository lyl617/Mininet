#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/8/3 8:31 PM
# @Author  : Jsen617
# @Site    : 
# @File    : REST_API.py
# @Software: PyCharm
import json
import logging

import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase,WSGIApplication,route
from ryu.lib import dpid as dpid_lib

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/mactable/{dpid}'

class RestApi(simple_switch_13.simpleswitch13):
    def __init__(self):
        super(RestApi,self).__init__()


if __name__ == "__main__":
    pass