################################################################################
#
# Copyright (c) 2020-2021 Correct Networks, Intel Corporation
# All Rights Reserved.
# Authors:
# Dragos Dumitrescu (dragos@correctnetworks.io)
# Adrian Popa (adrian.popa@correctnetworks.io)
#
# NOTICE: TBD
#
###############################################################################

import sys

from collections import namedtuple, OrderedDict
import json
import logging
import time
import unittest
import struct
import math

import argparse

import os

from csv import reader, writer

import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

from thriftutils import *
from res_pd_rpc.ttypes import *
from devport_mgr_pd_rpc import devport_mgr
from devport_mgr_pd_rpc.ttypes import *
from pal_rpc import pal
from pal_rpc.ttypes import *
from tm_api_rpc import tm
from tm_api_rpc.ttypes import *
from mc_pd_rpc import mc
from mc_pd_rpc.ttypes import *
from mirror_pd_rpc import mirror
from mirror_pd_rpc.ttypes import *
from conn_mgr_pd_rpc import conn_mgr
from conn_mgr_pd_rpc.ttypes import *

from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol

SWITCH_METER_COLOR_GREEN = 0
SWITCH_METER_COLOR_YELLOW = 1
SWITCH_METER_COLOR_RED = 2

NDP_MCAST_GRP = 0x1000

speed = pal_port_speed_t.BF_SPEED_10G
fec = pal_fec_type_t.BF_FEC_TYP_NONE
speed_10g = 2
speed_25g = 4
speed_40g = 8
speed_40g_nb = 16
speed_50g = 32
speed_100g = 64

SPEEDSTR2NR = {
    '10g' : pal_port_speed_t.BF_SPEED_10G,
    '25g' : pal_port_speed_t.BF_SPEED_25G,
    '40g' : pal_port_speed_t.BF_SPEED_40G,
    '40g_nb' : pal_port_speed_t.BF_SPEED_40G_NB,
    '50g' : pal_port_speed_t.BF_SPEED_50G,
    '100g' : pal_port_speed_t.BF_SPEED_100G
}

def speed_string_to_number(port_speed):
    global SPEEDSTR2NR
    return SPEEDSTR2NR[port_speed.lower()]


FEC2NR = {'NONE': pal_fec_type_t.BF_FEC_TYP_NONE, 'RS': pal_fec_type_t.BF_FEC_TYP_REED_SOLOMON}
def fec_string_to_number(fec):
    global FEC2NR
    return FEC2NR[fec.upper()]


logger = logging.getLogger('Test')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

def mirror_session(mir_type, mir_dir, sid, egr_port=0, egr_port_v=False,
                   egr_port_queue=0, packet_color=0, mcast_grp_a=0,
                   mcast_grp_a_v=False, mcast_grp_b=0, mcast_grp_b_v=False,
                   max_pkt_len=0, level1_mcast_hash=0, level2_mcast_hash=0,
                   cos=0, c2c=0, extract_len=0, timeout=0, int_hdr=[]):
  return MirrorSessionInfo_t(mir_type,
                             mir_dir,
                             sid,
                             egr_port,
                             egr_port_v,
                             egr_port_queue,
                             packet_color,
                             mcast_grp_a,
                             mcast_grp_a_v,
                             mcast_grp_b,
                             mcast_grp_b_v,
                             max_pkt_len,
                             level1_mcast_hash,
                             level2_mcast_hash,
                             cos,
                             c2c,
                             extract_len,
                             timeout,
                             int_hdr,
                             len(int_hdr))


PRIORITY_LOW = 0
PRIORITY_LOW_QID = 0
PRIORITY_HIGH = 7
PRIORITY_HIGH_QID = 1

OTHERS_QID = 2

TRUNCATION_LENGTH=64

Entry = namedtuple('Entry', ['dip', 'pLen', 'smac', 'eg_port', 'nhop'])
Rate = namedtuple('Rate', ['rate_kbps', 'burst_kbits'])

def get_bufsize(rate):
    return rate.burst_kbits * 125

class PortProperties(object):
    # meter_rate is of type rate and refers to ingress meter
    # shaper_rate is of type rate and refers to q shaper
    # bufsize is an int (in bytes) and refers to size of buffer
    def __init__(self, meter_rate, shaper_rate = None, bufsize = None):
        self.meter_rate = meter_rate
        self.shaper_rate = shaper_rate if shaper_rate is not None else meter_rate
        if bufsize is not None:
            self.bufsize = bufsize
        else:
            self.bufsize = get_bufsize(self.shaper_rate)
        self.other_properties = {}

class LooksLikeFixedObjectTrait:
    def __init__(self, fixedObject):
        self.pal = fixedObject.pal
        self.tm = fixedObject.tm
        self.mirror = fixedObject.mirror
        self.mc = fixedObject.mc
        self.devport_mgr = fixedObject.devport_mgr
        self.conn_mgr = fixedObject.conn_mgr

class QueryGRPCTrait:
    def __init__(self, interface, p4name, bfrt_info = None):
        self.interface = interface
        self.p4name = p4name
        if bfrt_info is not None:
            self.bfrt_info = bfrt_info
        else:
            self.bfrt_info = self.interface.bfrt_info_get(self.p4name)
    def insert_table_entry(self, target, table, keys, action, data):
        table_obj = self.bfrt_info.table_get(table)
        key_list = table_obj.make_key(keys)
        if action is None:
            data_list = table_obj.make_data(data)
        else:
            data_list = [table_obj.make_data(data, action)]
        table_obj.entry_add(target, [key_list], [data_list])
    def delete_table_entry(self, target, table, keys):
        table_obj = self.bfrt_info.table_get(table)
        key_list = table_obj.make_key(keys)
        table_obj.entry_del(target, [key_list])
    def insert_or_update_entry(self, target, table, keys, action, data):
        table_obj = self.bfrt_info.table_get(table)
        key_list = table_obj.make_key(keys)
        try:
            table_obj.entry_del(target, [key_list])
        except:
            pass
        if data is not None:
            if action is None:
                data_list=[table_obj.make_data(data)]
            else:
                data_list = [table_obj.make_data(data, action)]
        else:
            data_list = None
        table_obj.entry_add(target, [key_list], data_list)
    def get_table_entry(self, target, table, keys, props):
        table_obj = self.bfrt_info.table_get(table)
        if keys is not None:
            key_list = [table_obj.make_key(keys)]
        else:
            key_list = None
        return table_obj.entry_get(target, key_list, props)
    def modify_table_default_entry(self, target, table, action, data):
        table_obj = self.bfrt_info.table_get(table)
        data_list = table_obj.make_data(data, action)
        table_obj.default_entry_set(target, data_list)

# for each pipe have this state object.
# it can also setup and teardown itself
class PerPipeConfig(QueryGRPCTrait, LooksLikeFixedObjectTrait):
    def __init__(self, parent, pipe_id, config_json):
        QueryGRPCTrait.__init__(self, parent.interface, parent.p4_name, bfrt_info = parent.bfrt_info)
        LooksLikeFixedObjectTrait.__init__(self, parent)
        self.parent = parent
        self.pipe = pipe_id
        self.shdl = self.parent.shdl
        self.nr_pipes = self.parent.nr_pipes

        self.device_id = self.parent.device_id
        self.config_json = config_json
        self.target = gc.Target(device_id=self.device_id, pipe_id=self.pipe)
        self.all_pipes_target = gc.Target(device_id=self.device_id, pipe_id=0xffff)
        self.dev_target = DevTarget_t(self.device_id, hex_to_i16(self.pipe))
        self.entries = []
        self.ports = set()
        self.rates = {}
        self.port_properties = {}
        self.arp = {}
        self.importConfig(self.config_json)

    def is_my_port(self, port):
        pipe = portToPipe(port)
        if pipe >= self.nr_pipes:
            return False
        if self.pipe == 0xffff:
            return True
        return pipe == self.pipe

    def is_my_pipe(self, pipe):
        if self.pipe == 0xffff:
            return True
        return self.pipe == pipe

    def cleanup_ecmp(self):
        # step 1: get stuff to be erased from the table
        nh_entries = self.get_table_entry(
            self.target, 'SwitchIngress.nexthop_resolve', None, {"from_hw": False})
        for (data, keys) in nh_entries:
            key_dict = keys.to_dict()
            val = key_dict['ig_md.nhop_idx']['value']
            self.delete_table_entry(self.target, 'SwitchIngress.nexthop_resolve',
                [gc.KeyTuple('ig_md.nhop_idx', gc.to_bytes(val, 4))])
        sel_entries = self.get_table_entry(
            self.target, 'SwitchIngress.ecmp_selector_sel', None, {'from_hw': True})
        i = 0
        for (data, key) in sel_entries:
            key_dict = key.to_dict()
            gid = key_dict['$SELECTOR_GROUP_ID']['value']
            if self.pipe == 0xffff or (gid & 7 == self.pipe):
                try:
                    self.delete_table_entry(self.target, 'SwitchIngress.ecmp_selector_sel',
                                            [gc.KeyTuple('$SELECTOR_GROUP_ID', gc.to_bytes(gid, 4))])
                except:
                    logger.warning('failed to delete group id {}'.format(gid))
                    pass
        ap_entries = self.get_table_entry(
            self.target, 'SwitchIngress.ecmp_selector', None, {"from_hw": False})
        i = 0
        for (data, key) in ap_entries:
            key_dict = key.to_dict()
            mid=key_dict['$ACTION_MEMBER_ID']['value']
            if self.pipe == 0xffff or (mid & 7 == self.pipe):
                try:
                    self.delete_table_entry(self.target, 'SwitchIngress.ecmp_selector',
                                            [gc.KeyTuple('$ACTION_MEMBER_ID', gc.to_bytes(mid, 4))])
                except Exception as ex:
                    logger.warning('failed to delete mid {} because {}'.format(mid, ex))
                    pass

    def importConfig(self, config_json):
        shaper_rates = {}
        port_speeds = {}
        port_fecs = {}
        bufsize = {}
        for e in config_json["entries"]:
            port=e["eg_port"]
            if not self.is_my_port(port):
                continue
            prefix, length = e["dip"].split('/')
            length = int(length)
            self.entries.append(Entry(prefix, length, e["smac"], port, e['nhop']))
        for r in config_json["rates"]:
            port = r["eg_port"]
            if not self.is_my_port(port):
                continue
            self.ports.add(port)
            if 'rate_kbps' in r and 'burst_kbits' in r:
                self.rates[port] = Rate(int(r["rate_kbps"]), int(r["burst_kbits"]))
            else:
                logger.warning('WARNING! Port {} has no rate_kbps or burst_kbits attribute'.format(port))
                continue
            if 'shaper_rate_kbps' in r and 'shaper_burst_kbits' in r:
                shaper_rates[port] = Rate(int(r['shaper_rate_kbps']), int(r['shaper_burst_kbits']))
            if 'port_bufsize' in r:
                bufsize[port] = int(r['port_bufsize'])
            if 'port_speed' in r:
                try:
                    port_speeds[port] = speed_string_to_number(r['port_speed'])
                except:
                    logger.warning('invalid speed string {} for port {}'.format(r['port_speed'], port))
            if 'fec' in r:
                try:
                    port_fecs[port] = fec_string_to_number(r['fec'])
                except:
                    logger.warning('invalid fec {} for port {}'.format(r['fec'], port))
        if 'arp' in config_json:
            for ip in config_json['arp']:
                mac=config_json['arp'][ip]
                self.arp[ip]=mac
        if 'force_trim' in config_json:
            self.force_trim = bool(config_json['force_trim'])
        else:
            self.force_trim = False
        if 'allow_pessimism' in config_json:
            self.allow_pessimism = bool(config_json['allow_pessimism'])
        else:
            self.allow_pessimism = True
        for port in self.ports:
            if self.is_my_port(port):
                self.port_properties[port] = PortProperties(self.rates[port],
                                                            shaper_rates.get(
                                                                port, None),
                                                            bufsize.get(port, None))
                if port in port_speeds:
                    self.port_properties[port].other_properties['port_speed'] = port_speeds[port]
                else:
                    self.port_properties[port].other_properties['port_speed'] = pal_port_speed_t.BF_SPEED_100G
                if port in port_fecs:
                    self.port_properties[port].other_properties['fec'] = port_fecs[port]
                else:
                    self.port_properties[port].other_properties['fec'] = pal_fec_type_t.BF_FEC_TYP_NONE

    def global_id_from_local_id(self, local_id):
        if self.pipe == 0xffff:
            nr = 4
        else:
            nr = self.pipe
        return local_id << 3 | nr

    def handle_entries(self):
        lst = []
        revindex = {}
        self.ip2acts = {}
        for e in self.entries:
            tu = (e.smac, e.eg_port, e.nhop)
            if tu not in revindex:
                lst.append(tu)
                revindex[tu] = len(revindex)
        for e in self.entries:
            tu = (e.smac, e.eg_port, e.nhop)
            dst = (e.dip, e.pLen)
            if dst not in self.ip2acts:
                self.ip2acts[dst] = [revindex[tu]]
            else:
                self.ip2acts[dst].append(revindex[tu])
        #TODO: CLEANUP: for the current pipeline, find all entries in table
        # nexthop_resolve
        # for each e:
        #   if e is Member => mark e.action_member_id for deletion
        #   if e is Group  => mark e.group_id for deletion
        # for each group_id marked for deletion:
        #    for each action_member_id in members: => mark action_member_id for deletion
        # for each next hop - i.e. unique combination of fwd/nhop/srcmac
        # create an ACTION_MEMBER - index + 1 (because we map drop to 0)
        self.insert_or_update_entry(self.target,
                                    'SwitchIngress.ecmp_selector',
                                    [gc.KeyTuple('$ACTION_MEMBER_ID',
                                                 gc.to_bytes(self.global_id_from_local_id(0), 4))],
                                    'SwitchIngress.drop', [])
        groups = self.get_table_entry(
            self.target, 'SwitchIngress.ecmp_selector_sel', None, {'from_hw': True})
        groups = list([(x[0].to_dict(), x[1].to_dict()) for x in groups])
        for idx, e in enumerate(lst):
            action = 'SwitchIngress.ipv4_forward'
            aparms = []
            if isinstance(e[2], int):
                action = 'SwitchIngress.ipv4_forward_direct_connect'
                aparms = [gc.DataTuple('srcAddr', bytearray(gc.mac_to_bytes(e[0]))),
                          gc.DataTuple('port', gc.to_bytes(e[1], 2))]
            else:
                aparms = [gc.DataTuple('srcAddr', bytearray(gc.mac_to_bytes(e[0]))),
                          gc.DataTuple('nhop', bytearray(gc.ipv4_to_bytes(e[2]))),
                          gc.DataTuple('port', gc.to_bytes(e[1], 2))]
            global_index = self.global_id_from_local_id(idx+1)
            matching = [g for g in groups if global_index in g[0]['$ACTION_MEMBER_ID']]
            if len(matching) > 0:
                selgrid = matching[0][1]['$SELECTOR_GROUP_ID']['value']
                self.delete_table_entry(self.target, 'SwitchIngress.ecmp_selector_sel', [gc.KeyTuple('$SELECTOR_GROUP_ID',
                                                                                                     gc.to_bytes(selgrid, 4))])
            self.insert_or_update_entry(
                self.target,
                'SwitchIngress.ecmp_selector',
                [gc.KeyTuple('$ACTION_MEMBER_ID',
                             gc.to_bytes(global_index, 4))],
                action, aparms)
        groupindex = [0]
        r_groupindex = {0: 0}

        nhidx = 1
        for ip in self.ip2acts:
            (dip, plen) = ip
            gnhidx = self.global_id_from_local_id(nhidx)
            self.insert_or_update_entry(
                        self.target,
                        'SwitchIngress.ipv4_lpm',
                        [gc.KeyTuple('hdr.ipv4.dst_addr', bytearray(gc.ipv4_to_bytes(dip)), prefix_len=plen)],
                        'SwitchIngress.set_nhop_idx',
                        [gc.DataTuple('nhop_idx', gc.to_bytes(gnhidx, 4))])
            nhidx=nhidx+1
        nhidx = 1
        for ip, actions in self.ip2acts.items():
            gnhidx = self.global_id_from_local_id(nhidx)
            (dip, plen) = ip
            datafield = None
            if len(actions) > 1:
                groupmembers = tuple(actions)
                if groupmembers not in r_groupindex:
                    gid = len(r_groupindex)
                    r_groupindex[groupmembers] = gid
                    groupindex.append(groupmembers)
                    # create group made up of all actions which correspond
                    # to this ip - this is the first time we perceive this
                    # group
                    self.insert_or_update_entry(
                        self.target,
                        'SwitchIngress.ecmp_selector_sel',
                        [gc.KeyTuple('$SELECTOR_GROUP_ID', gc.to_bytes(self.global_id_from_local_id(gid), 4))],
                        None,
                        [gc.DataTuple('$MAX_GROUP_SIZE', gc.to_bytes(8, 4)),
                         gc.DataTuple('$ACTION_MEMBER_STATUS',
                            bool_arr_val=[True]*len(groupmembers)),
                         gc.DataTuple('$ACTION_MEMBER_ID',
                            int_arr_val=list([self.global_id_from_local_id(x+1) for x in groupmembers]))])
                else:
                    gid=r_groupindex[groupmembers]
                datafield=[gc.DataTuple('$SELECTOR_GROUP_ID',
                    gc.to_bytes(self.global_id_from_local_id(gid), 4))]
            else:
                datafield=[gc.DataTuple('$ACTION_MEMBER_ID',
                    gc.to_bytes(self.global_id_from_local_id(actions[0]+1), 4))]
            self.insert_or_update_entry(
                    self.target,
                    'SwitchIngress.nexthop_resolve',
                    [gc.KeyTuple('ig_md.nhop_idx', gc.to_bytes(gnhidx, 4))],
                    None,
                    datafield)
            nhidx=nhidx+1
        self.insert_or_update_entry(
                    self.target,
                    'SwitchIngress.nexthop_resolve',
                    [gc.KeyTuple('ig_md.nhop_idx', gc.to_bytes(0, 4))],
                    None,
                    [gc.DataTuple('$ACTION_MEMBER_ID',
                        gc.to_bytes(self.global_id_from_local_id(0), 4))])

    def set_meter_rate(self, port, rate, meter='SwitchIngress.meter'):
        self.insert_table_entry(
            self.all_pipes_target,
            meter,
            [gc.KeyTuple('$METER_INDEX', gc.to_bytes(port, 4))],
            None,
            [gc.DataTuple('$METER_SPEC_CIR_KBPS', gc.to_bytes(rate.rate_kbps, 8)),
             gc.DataTuple('$METER_SPEC_PIR_KBPS', gc.to_bytes(rate.rate_kbps, 8)),
             gc.DataTuple('$METER_SPEC_CBS_KBITS', gc.to_bytes(rate.burst_kbits, 8)),
             gc.DataTuple('$METER_SPEC_PBS_KBITS', gc.to_bytes(rate.burst_kbits, 8))])

    def reset_meter_rate(self, port, meter):
        self.insert_table_entry(
            self.all_pipes_target,
            meter,
            [gc.KeyTuple('$METER_INDEX', gc.to_bytes(port, 4))],
            None,
            [gc.DataTuple('$METER_SPEC_CIR_KBPS', bytearray(b"\xff" * 8)),
             gc.DataTuple('$METER_SPEC_PIR_KBPS', bytearray(b"\xff" * 8)),
             gc.DataTuple('$METER_SPEC_CBS_KBITS', bytearray(b"\xff" * 8)),
             gc.DataTuple('$METER_SPEC_PBS_KBITS', bytearray(b"\xff" * 8))])

    def setUp(self):
        # - configure the TM with 2 priority queues for each port, one high priority
        #   queue for trimmed headers and control packets, and one lower priority
        #   queue for data packets. This can be done with the tm_set_q_sched_priority
        for port in self.ports:
            # each config state handles its own ports
            # if config is per-pipe => only configure ports in this pipe
            # if config is global => configure all ports
            if not self.is_my_port(port):
                continue
            #   """
            #  tm_pool_usage_t
            #   Attributes:
            #    - pool
            #    - base_use_limit
            #    - dynamic_baf
            #    - hysteresis
            #   """
            props = self.port_properties.get(port, None)
            if props is None:
                logger.warning('no port props for {}'.format(port))
                continue
            if 'port_speed' in props.other_properties:
                speed = props.other_properties['port_speed']
            else:
                logger.warning('no speed provided, ignoring port {}'.format(port))
                continue
            if 'fec' in props.other_properties:
                fec = props.other_properties['fec']
            else:
                logger.warning('no fec provided, ignoring port {}'.format(port))
                continue
            try:
                self.pal.pal_port_add(self.device_id, port,
                                             speed, fec)
                self.pal.pal_port_an_set(
                    self.device_id, port, pal_autoneg_policy_t.BF_AN_FORCE_DISABLE)
                try:
                    #HACK: somehow the port doesn't start off if not carrying out this line
                    mu = self.pal.pal_port_mtu_get(self.device_id, port)
                    logger.info('port {} has mtu tx:{},rx:{}'.format(mu.tx_mtu, mu.rx_mtu))
                    self.pal.pal_port_mtu_set(self.device_id, port, mu.tx_mtu, mu.rx_mtu)
                except:
                    pass
            except:
                logger.warning('failed to set speed/fec ({}/{}) for port {}'.format(speed, fec, port))
            self.tm.tm_get_q_sched_priority(self.device_id, port, PRIORITY_LOW_QID)
            try:
                # ndp data should be serviced with lower prio than ndp control
                self.tm.tm_set_q_sched_priority(
                    self.device_id, port, PRIORITY_LOW_QID, PRIORITY_LOW)
                # others should be serviced with low prio wrt ndp control
                self.tm.tm_set_q_sched_priority(
                    self.device_id, port, OTHERS_QID, PRIORITY_LOW)
                # highest prio goes to ndp control
                self.tm.tm_set_q_sched_priority(
                    self.device_id, port, PRIORITY_HIGH_QID, PRIORITY_HIGH)
                high_usage=self.tm.tm_get_q_app_pool_usage(self.device_id, port, PRIORITY_HIGH_QID)
                low_usage=self.tm.tm_get_q_app_pool_usage(self.device_id, port, PRIORITY_LOW_QID)
                others_usage=self.tm.tm_get_q_app_pool_usage(self.device_id, port, OTHERS_QID)
                # set up q for port low priority
                # hold on to N = 32 (#packets) * 9000 (MTU)
                # this means #cels: N / 80 (cell size) == 3600
                # magic number: 9 == no BAF i.e. static queue
                rate = self.rates[port]
                qsize = props.bufsize
                qsize_in_cells = int(math.ceil(qsize / 80 + 3))
                self.tm.tm_set_q_app_pool_usage(self.device_id, port, PRIORITY_LOW_QID,
                                                            low_usage.pool, qsize_in_cells, 9, low_usage.hysteresis)
                self.tm.tm_set_q_app_pool_usage(self.device_id, port, OTHERS_QID,
                                                            others_usage.pool, qsize_in_cells, 9, others_usage.hysteresis)
                self.tm.tm_set_q_guaranteed_min_limit(self.device_id, port, PRIORITY_HIGH_QID,
                                                                400)
                high_usage=self.tm.tm_get_q_app_pool_usage(self.device_id, port, PRIORITY_HIGH_QID)
                low_usage=self.tm.tm_get_q_app_pool_usage(self.device_id, port, PRIORITY_LOW_QID)
                others_usage=self.tm.tm_get_q_app_pool_usage(self.device_id, port, OTHERS_QID)
                port_shaper_msg = ''
                if props.shaper_rate.rate_kbps != 0:
                    port_shaper_msg = 'shaping buffer:{}kB, speed:{}Gbps'.format(get_bufsize(props.shaper_rate) / 8.0,
                        props.shaper_rate.rate_kbps / 1e6)
                    self.tm.tm_set_port_shaping_rate(self.device_id, port, False,
                        get_bufsize(props.shaper_rate), props.shaper_rate.rate_kbps)
                    self.tm.tm_enable_port_shaping(self.device_id, port)
                else:
                    port_shaper_msg = 'shaping disabled'
                    self.tm.tm_disable_port_shaping(self.device_id, port)
                logger.info('port {} speed {} fec {} {}'.format(
                    port, speed, fec, port_shaper_msg))
                logger.info('port {} high prio ({}) queue size:{}kB'.format(
                    port, PRIORITY_HIGH_QID, high_usage.base_use_limit * 80 / 1000))
                logger.info('port {} low prio ({}) queue size:{}kB'.format(
                    port, PRIORITY_LOW_QID, low_usage.base_use_limit * 80 / 1000))
                logger.info('port {} others prio ({}) queue size:{}kB'.format(
                    port, OTHERS_QID, others_usage.base_use_limit * 80 / 1000))
            except Exception as ex:
                logger.info('failed to do tm stuff with {}, because {}'.format(port, ex))
        self.pal.pal_port_enable_all(self.device_id)
        for pipe_id in range(0, self.nr_pipes):
            if self.is_my_pipe(pipe_id):
                dod_port = (pipe_id << 7) | 68
                self.tm.tm_set_negative_mirror_dest(
                    self.device_id, pipe_id, dod_port, 1)
                print('eg mirror {} -> {}'.format(pipe_id, dod_port))
                info = mirror_session(MirrorType_e.PD_MIRROR_TYPE_NORM,
                                  Direction_e.PD_DIR_EGRESS,
                                  2 * dod_port + 2,
                                  egr_port_v=True,
                                  egr_port=dod_port,
                                  max_pkt_len=TRUNCATION_LENGTH + 3)
                try:
                    self.mirror.mirror_session_delete(self.shdl, self.dev_target, sid)
                except:
                    pass
                self.mirror.mirror_session_create(self.shdl, self.dev_target, info)
        # configure one mirroring session per egress port (i2e). This can be done
        # with the mirror_session_create PDFixed Thrift API
        logger.info("Configuring mirroring sessions")
        for port in self.ports:
            if not self.is_my_port(port):
                continue
            # session id 0 is reserved on Tofino (not Tofino2)
            sid = 2*port + 1
            self.insert_or_update_entry(
                self.target,
                'SwitchIngress.truncate',
                [gc.KeyTuple('ig_intr_tm_md.ucast_egress_port', gc.to_bytes(port, 2))],
                'SwitchIngress.mirror_and_drop',
                [gc.DataTuple('session_id', gc.to_bytes(sid, 2))])
            info = mirror_session(MirrorType_e.PD_MIRROR_TYPE_NORM,
                                  Direction_e.PD_DIR_INGRESS,
                                  sid,
                                  egr_port=port,
                                  egr_port_v=True,
                                  egr_port_queue=PRIORITY_HIGH_QID,
                                  max_pkt_len=TRUNCATION_LENGTH + 3)
            self.mirror.mirror_session_create(self.shdl, self.dev_target, info)


        NDP_MCAST_GRP = 0x1000
        info = mirror_session(MirrorType_e.PD_MIRROR_TYPE_NORM,
                                Direction_e.PD_DIR_INGRESS,
                                2,
                                mcast_grp_a=NDP_MCAST_GRP,
                                mcast_grp_a_v = True,
                                egr_port_queue = PRIORITY_HIGH_QID)
        self.mirror.mirror_session_create(self.shdl, self.dev_target, info)
        for port in self.ports:
            pipe = portToPipe(port)
            dod_port = (pipe << 7) | 68
            self.insert_or_update_entry(
                self.all_pipes_target,
                'SwitchEgress.eg_port2_egmirror',
                [gc.KeyTuple('hdr.normal_meta.egress_port', gc.to_bytes(port, 2))],
                'SwitchEgress.set_eg_mirror',
                [gc.DataTuple('session_id', gc.to_bytes(2 * dod_port + 2, 2))])
        self.devport_mgr.devport_mgr_set_copy_to_cpu(self.device_id, 1, 192)
        self.conn_mgr.complete_operations(self.shdl)
        logger.info('Populating multicast tables')
        repl_port = 68
        ports = [192]
        try:
            self.set_entry_scope_table_attribute(self.target, 'SwitchIngressParser.is_recirc_port',
                                             config_gress_scope=True,
                                             predefined_gress_scope_val=bfruntime_pb2.Mode.ALL,
                                             config_pipe_scope=True,
                                             predefined_pipe_scope=True,
                                             predefined_pipe_scope_val=bfruntime_pb2.Mode.SINGLE,
                                             pipe_scope_args=0xff,
                                             config_prsr_scope=True, predefined_prsr_scope_val=bfruntime_pb2.Mode.ALL,
                                             prsr_scope_args=0xff)
        except:
            pass
        for pipe_id in range(0, self.nr_pipes):
            if not self.is_my_pipe(pipe_id):
                continue
            pipe_repl_port = (pipe_id << 7) | repl_port
            ports.append(pipe_repl_port)
            # program value set SwitchIngressParser.is_recirc_port to be (pipe_id << 7) | repl_port
            try:
                self.delete_table_entry(
                    self.all_pipes_target, 'SwitchIngressParser.is_recirc_port',
                    [gc.KeyTuple('f1', gc.to_bytes(pipe_repl_port, 2), mask=gc.to_bytes(0xffff, 2))])
            except:
                pass
            self.insert_or_update_entry(
                self.all_pipes_target, 'SwitchIngressParser.is_recirc_port',
                [gc.KeyTuple('f1', gc.to_bytes(pipe_repl_port, 2),
                             mask=gc.to_bytes(0xffff, 2))],
                None, None)
            try:
                self.insert_or_update_entry(
                    self.all_pipes_target,
                    'SwitchEgress.act_on_egress',
                    [gc.KeyTuple('eg_intr_md.egress_port', gc.to_bytes(pipe_repl_port, 2))],
                    'SwitchEgress.invalidate_trim_and_set_update',
                    [gc.DataTuple('also_add', gc.to_bytes((1<<4)|(1<<7), 1))])
            except:
                pass
        self.mc.mc_init()
        mcsession = self.mc.mc_create_session()
        cnt = self.mc.mc_mgrp_get_count(mcsession, self.device_id)
        mcgrps = {}
        if cnt > 0:
            batch = 4
            at = self.mc.mc_mgrp_get_first(mcsession, self.device_id)
            mgid = self.mc.mc_mgrp_get_attr(mcsession, self.device_id, at).mgid
            mcgrps[mgid] = at
            cnt = cnt - 1
            while cnt > 0:
                crtbat = batch if cnt >= batch else cnt
                bat = self.mc.mc_mgrp_get_next_i(mcsession, self.device_id, at, crtbat)
                at = bat[len(bat)-1]
                for x in bat:
                    mgid = self.mc.mc_mgrp_get_attr(mcsession, self.device_id, x).mgid
                    mcgrps[mgid] = x
                cnt = cnt - crtbat
        try:
            if not NDP_MCAST_GRP in mcgrps:
                mc_hdl = self.mc.mc_mgrp_create(mcsession, self.device_id, NDP_MCAST_GRP)
            else:
                mc_hdl = mcgrps[NDP_MCAST_GRP]
            node_hdl = self.mc.mc_node_create(
                mcsession, self.device_id, 0, set_port_map(ports), set_lag_map([]))
            self.mc.mc_associate_node(mcsession, self.device_id, mc_hdl, node_hdl, 0, False)
            self.mc.mc_complete_operations(mcsession)
        finally:
            self.mc.mc_destroy_session(mcsession)
    def postRun(self):
        self.cleanup_ecmp()
        for e in self.ip2acts:
            (dip, plen) = e
            self.delete_table_entry(
                self.target,
                'SwitchIngress.ipv4_lpm',
                [gc.KeyTuple('hdr.ipv4.dst_addr', bytearray(gc.ipv4_to_bytes(dip)), prefix_len=plen)])
        for ip in self.arp:
            self.delete_table_entry(
                self.target,
                'SwitchIngress.arp',
                [gc.KeyTuple('ig_md.nhop', bytearray(gc.ipv4_to_bytes(ip)))])
        for port in self.ports:
            self.reset_meter_rate(port,meter='SwitchIngress.meter_optimistic')
            self.reset_meter_rate(port,meter='SwitchIngress.meter_pessimistic')
    def runTest(self):
        print('cleanup {}'.format(self.pipe))
        self.cleanup_ecmp()
        print('handle_entries {}'.format(self.pipe))
        self.handle_entries()
        print('arp {}'.format(self.pipe))
        for ip in self.arp:
            mac=self.arp[ip]
            self.insert_or_update_entry(
                self.target,
                'SwitchIngress.arp',
                [gc.KeyTuple('ig_md.nhop', bytearray(gc.ipv4_to_bytes(ip)))],
                'SwitchIngress.set_dst',
                [gc.DataTuple('dst_addr', bytearray(gc.mac_to_bytes(mac)))])
        self.modify_table_default_entry(self.target, 'SwitchIngress.configure_ndp',
            'SwitchIngress.set_config',
            [gc.DataTuple('p_allow_pessimism', gc.to_bytes(1, 1)),
             gc.DataTuple('always_truncate', gc.to_bytes(self.force_trim, 1)),
             gc.DataTuple('drop_ndp', gc.to_bytes(0, 1))]
        )
        for meter_name in ['SwitchIngress.meter_optimistic', 'SwitchIngress.meter_pessimistic', 'SwitchIngress.meter_halftimistic']:
            meter_obj = self.bfrt_info.table_get(meter_name)
            # normal_header, IPG + preamble + CRC
            meter_obj.attribute_meter_bytecount_adjust_set(
                self.all_pipes_target, 1 + 12 + 8 + 4)
        logger.info('Setting up meter entries')
        for port in self.ports:
            rate = self.rates[port]
            logger.info("port {} meter rate={}Gbps, buffer={}kB".format(
                port, rate.rate_kbps / 1e6, rate.burst_kbits * 125 / 1000))
            self.set_meter_rate(port, rate, meter='SwitchIngress.meter_optimistic')
            self.set_meter_rate(port, Rate(int(math.floor(rate.rate_kbps / 4.0)), rate.burst_kbits),
                                meter='SwitchIngress.meter_pessimistic')
            self.set_meter_rate(port, Rate(int(math.floor(rate.rate_kbps / 2.0)), rate.burst_kbits),
                                meter='SwitchIngress.meter_halftimistic')

    def tearDown(self):
        for port in self.ports:
            self.delete_table_entry(
                self.target,
                'SwitchIngress.truncate',
                [gc.KeyTuple('ig_intr_tm_md.ucast_egress_port', gc.to_bytes(port, 2))])
            sid = 2*port + 1
            self.mirror.mirror_session_delete(self.shdl, self.dev_target, sid)
            props = self.port_properties.get(port, None)
            if props is not None:
                self.tm.tm_disable_port_shaping(self.device_id, port)

def portToPipe(port):
    return port >> 7
def portToPipeLocalId(port):
    return port & 0x7F
def portToBitIdx(port):
    pipe = portToPipe(port)
    index = portToPipeLocalId(port)
    return 72 * pipe + index
def set_port_map(indicies):
    bit_map = [0] * ((288 + 7) // 8)
    for i in indicies:
        index = portToBitIdx(i)
        bit_map[index / 8] = (bit_map[index / 8] | (1 << (index % 8))) & 0xFF
    return bytes_to_string(bit_map)

def set_lag_map(indicies):
    bit_map = [0] * ((256 + 7) / 8)
    for i in indicies:
        bit_map[i / 8] = (bit_map[i / 8] | (1 << (i % 8))) & 0xFF
    return bytes_to_string(bit_map)

class FixedInterface:
    def __init__(self, addr):
        self.pd_transport = TSocket.TSocket(addr, 9090)
        self.pd_transport = TTransport.TBufferedTransport(self.pd_transport)
        self.pd_transport.open()
        self.binary_protocol = TBinaryProtocol.TBinaryProtocol(
            self.pd_transport)
        self.conn_mgr = conn_mgr.Client(TMultiplexedProtocol.TMultiplexedProtocol(
            self.binary_protocol, "conn_mgr"))
        self.devport_mgr = devport_mgr.Client(TMultiplexedProtocol.TMultiplexedProtocol(
            self.binary_protocol, "devport_mgr"))
        self.pal = pal.Client(TMultiplexedProtocol.TMultiplexedProtocol(
            self.binary_protocol, "pal"))
        self.tm = tm.Client(TMultiplexedProtocol.TMultiplexedProtocol(
            self.binary_protocol, "tm"))
        self.mirror = mirror.Client(TMultiplexedProtocol.TMultiplexedProtocol(
            self.binary_protocol, "mirror"))
        self.mc = mc.Client(TMultiplexedProtocol.TMultiplexedProtocol(
            self.binary_protocol, "mc"))
    def __del__(self):
        self.pd_transport.close()

class NDPLive(QueryGRPCTrait, LooksLikeFixedObjectTrait):
    def __init__(self, p4_name, interface, fixedObject, config_file, multi_pipe):
        QueryGRPCTrait.__init__(self, interface, p4_name)
        LooksLikeFixedObjectTrait.__init__(self, fixedObject)
        self.p4_name = p4_name
        self.device_id = 0
        self.pipe_cfgs = {}
        self.target=gc.Target(device_id=self.device_id, pipe_id=0xffff)
        self.config_file = config_file
        self.multi_pipe = multi_pipe

    def __enter__(self):
        self.setUp(self.config_file, self.multi_pipe)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.tearDown()

    def tearDown(self):
        logger.info('Tearing down...')
        self.pal.pal_port_del_all(self.device_id)
        try:
            for cfg in self.pipe_cfgs.values():
                cfg.tearDown()
        except:
            pass
        self.conn_mgr.complete_operations(self.shdl)
        self.conn_mgr.client_cleanup(self.shdl)

    def scope_setup(self):
        pipe_scope = bfruntime_pb2.Mode.SINGLE if len(self.pipe_cfgs) != 1 else bfruntime_pb2.Mode.ALL
        single_pipe = (len(self.pipe_cfgs) == 1)
        for t in ['SwitchIngress.truncate',
                  'SwitchIngress.ipv4_lpm',
                  'SwitchIngress.arp',
                  'SwitchIngress.configure_ndp',
                  'SwitchIngress.nexthop_resolve']:
            t_obj = self.bfrt_info.table_get(t)
            if next(t_obj.attribute_get(self.target, 'EntryScope'))['pipe_scope']['predef'] != pipe_scope:
                t_obj.default_entry_reset(self.target)
            t_obj.attribute_entry_scope_set(self.target,
                                            config_gress_scope=True,
                                            predefined_gress_scope_val=bfruntime_pb2.Mode.ALL,
                                            config_pipe_scope=True,
                                            predefined_pipe_scope=True,
                                            predefined_pipe_scope_val=pipe_scope,
                                            pipe_scope_args=0xff,
                                            config_prsr_scope=True,
                                            predefined_prsr_scope_val=bfruntime_pb2.Mode.ALL,
                                            prsr_scope_args=0xff)
    def setup_lkp(self):
        self.insert_or_update_entry(
            self.target, 'SwitchIngress.populate_lkp',
            [gc.KeyTuple('hdr.ipv4.$valid', gc.to_bytes(1, 1)),
             gc.KeyTuple('hdr.udp.$valid', gc.to_bytes(0, 1)),
             gc.KeyTuple('hdr.tcp.$valid', gc.to_bytes(1, 1)),
             gc.KeyTuple('hdr.ndp_s_data.$valid', gc.to_bytes(0, 1), mask=gc.to_bytes(0, 1)),
             gc.KeyTuple('$MATCH_PRIORITY', gc.to_bytes(100, 1))],
             'SwitchIngress.set_lkp_tcp',
            []
        )
        self.insert_or_update_entry(self.target, 'SwitchIngress.populate_lkp',
            [gc.KeyTuple('hdr.ipv4.$valid', gc.to_bytes(1, 1)),
             gc.KeyTuple('hdr.udp.$valid', gc.to_bytes(1, 1)),
             gc.KeyTuple('hdr.tcp.$valid', gc.to_bytes(0, 1)),
             gc.KeyTuple('hdr.ndp_s_data.$valid', gc.to_bytes(0, 1), mask=gc.to_bytes(1, 1)),
             gc.KeyTuple('$MATCH_PRIORITY', gc.to_bytes(50, 1))],
             'SwitchIngress.set_lkp_udp',
            []
        )
        self.insert_or_update_entry(self.target, 'SwitchIngress.populate_lkp',
            [gc.KeyTuple('hdr.ipv4.$valid', gc.to_bytes(1, 1)),
             gc.KeyTuple('hdr.udp.$valid', gc.to_bytes(1, 1)),
             gc.KeyTuple('hdr.tcp.$valid', gc.to_bytes(0, 1)),
             gc.KeyTuple('hdr.ndp_s_data.$valid', gc.to_bytes(1, 1), mask=gc.to_bytes(1, 1)),
             gc.KeyTuple('$MATCH_PRIORITY', gc.to_bytes(50, 1))],
             'SwitchIngress.set_lkp_ndp',
            []
        )
        self.insert_or_update_entry(self.target, 'SwitchIngress.populate_lkp',
            [gc.KeyTuple('hdr.ipv4.$valid', gc.to_bytes(0, 1)),
             gc.KeyTuple('hdr.udp.$valid', gc.to_bytes(0, 1)),
             gc.KeyTuple('hdr.tcp.$valid', gc.to_bytes(0, 1)),
             gc.KeyTuple('hdr.ndp_s_data.$valid', gc.to_bytes(0, 1), mask=gc.to_bytes(0, 1)),
             gc.KeyTuple('$MATCH_PRIORITY', gc.to_bytes(100, 1))],
             'SwitchIngress.set_lkp_ip_unknown',
            []
        )

        self.modify_table_default_entry(self.target, 'SwitchIngress.populate_lkp',
            'NoAction', [])

    def setUp(self, config_file, multi_pipe):
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

        self.nr_pipes = self.pal.pal_num_pipes_get(self.device_id)
        self.pal.pal_port_del_all(self.device_id)
        # Get bfrt_info and set it as part of the test
        self.shdl = self.conn_mgr.client_init()
        # config file should have a single top-level dictionary
        # mapping pipe -> config
        with open(config_file, 'r') as fconfig:
            job = json.load(fconfig)
            if multi_pipe:
                for pipe, config in job.items():
                    if int(pipe) >= self.nr_pipes:
                        logger.warning('WARNING! requested pipe {} >= #nr pipes: {}'.format(pipe, self.nr_pipes))
                        continue
                    pipe_config_obj = config
                    if 'file' in config:
                        actual_file = config['file']
                        if not os.path.isabs(config['file']):
                            actual_file = os.path.join(os.path.dirname(config_file), actual_file)
                        logger.info('configuring {} from {}'.format(pipe, actual_file))
                        with open(actual_file, 'r') as fcfg:
                            pipe_config_obj = json.load(fcfg)
                    self.pipe_cfgs[pipe] = PerPipeConfig(self, int(pipe), pipe_config_obj)
            else:
                self.pipe_cfgs[0xffff] = PerPipeConfig(self, 0xffff, job)

        # global configs
        self.scope_setup()
        self.setup_lkp()
        for pipe, cfg in self.pipe_cfgs.items():
            logger.info('setting up pipe {}'.format(pipe))
            cfg.setUp()

    def runTest(self):
        for cfg in self.pipe_cfgs.values():
            cfg.runTest()
        raw_input("Configuration done. Press Enter to cleanup...")
        for cfg in self.pipe_cfgs.values():
            cfg.postRun()

class ConnectionManager:
    def __init__(self, addr):
        self.interface = gc.ClientInterface(addr + ':50052', client_id=0,
                                            device_id=0, is_master=True)
        self.fixedObject = FixedInterface(addr)
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.interface._tear_down_stream()
        self.fixedObject.pd_transport.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', dest='grpc_addr',
                        default='localhost', required=False, help='ip of grpc')
    parser.add_argument('-multi-pipe', dest='multi_pipe',
                        action='store_true', help='set to use one instance per pipeline')
    parser.add_argument(
        'input_json', help='input json file to read configs from')
    args = parser.parse_args()
    with ConnectionManager(args.grpc_addr) as conn_mgr:
        conn_mgr.interface.bind_pipeline_config('ndp')
        with NDPLive('ndp', conn_mgr.interface, conn_mgr.fixedObject, args.input_json, args.multi_pipe) as ndplive:
            ndplive.runTest()

if __name__ == '__main__':
    main()
