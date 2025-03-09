# -*- coding: UTF-8 -*-
import sys
import pickle
import signal
import numpy as np
import os
import time

# Update for Python 3 SDE path
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.10/site-packages/tofino/'))

from bfrt_grpc import client

#GRPC_CLIENT = client.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0, is_master=True)
GRPC_CLIENT = client.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0)

bfrt_info = GRPC_CLIENT.bfrt_info_get(p4_name=None)
GRPC_CLIENT.bind_pipeline_config(p4_name=bfrt_info.p4_name)

def reset():
    GRPC_CLIENT.clear_all_tables()
    sys.stderr.write("#** Cleared all tables!\n")

def quit_handler(signum, frame):
    print("Stopping digest reception")
    GRPC_CLIENT.__del__()
    sys.exit()

if bfrt_info.p4_name != 'switch':
    sys.stderr.write(f"P4 program mismatch: driver reports currently running '{bfrt_info.p4_name}'\n")
    GRPC_CLIENT.__del__()
    sys.exit(-1)

target = client.Target()

learn_filter = bfrt_info.learn_get("digest_a")

Register_Table_Size = 3000
flow_info = {}
"""
def add_tb_entry_flow_result(data_dict):
    table_name = 'SwitchIngress.Flow_result'
    flow_index_table = bfrt_info.table_get(table_name)
    flow_index_table.info.key_field_annotation_add("hdr.ipv4.src_addr", "ipv4")
    flow_index_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    key1 = f"{data_dict['src_addr']}-{data_dict['dst_addr']}-{data_dict['src_port']}-{data_dict['dst_port']}-{data_dict['protocol']}"
    key2 = f"{data_dict['dst_addr']}-{data_dict['src_addr']}-{data_dict['dst_port']}-{data_dict['src_port']}-{data_dict['protocol']}"

    if key1 in flow_info or key2 in flow_info:
        print("Flow already exists.")
        return

    if len(flow_info) >= Register_Table_Size // 2:
        delete_keys = []
        for _ in range(10):
            del_key = next(iter(flow_info))
            del_data_dict = flow_info.pop(del_key)

            for src, dst, src_port, dst_port in [
                (del_data_dict['src_addr'], del_data_dict['dst_addr'], del_data_dict['src_port'], del_data_dict['dst_port']),
                (del_data_dict['dst_addr'], del_data_dict['src_addr'], del_data_dict['dst_port'], del_data_dict['src_port'])
            ]:
                delete_keys.append(flow_index_table.make_key([
                    client.KeyTuple('hdr.ipv4.src_addr', src),
                    client.KeyTuple('hdr.ipv4.dst_addr', dst),
                    client.KeyTuple('ig_md.src_port', src_port),
                    client.KeyTuple('ig_md.dst_port', dst_port),
                    client.KeyTuple('hdr.ipv4.protocol', del_data_dict['protocol'])
                ]))

        flow_index_table.entry_del(target, delete_keys)
        print(f"Deleted flow_result entries, remaining: {len(flow_info)}")

    entry_keys = []
    entry_data = []
    for src, dst, src_port, dst_port in [
        (data_dict['src_addr'], data_dict['dst_addr'], data_dict['src_port'], data_dict['dst_port']),
        (data_dict['dst_addr'], data_dict['src_addr'], data_dict['dst_port'], data_dict['src_port'])
    ]:
        entry_keys.append(flow_index_table.make_key([
            client.KeyTuple('hdr.ipv4.src_addr', src),
            client.KeyTuple('hdr.ipv4.dst_addr', dst),
            client.KeyTuple('ig_md.src_port', src_port),
            client.KeyTuple('ig_md.dst_port', dst_port),
            client.KeyTuple('hdr.ipv4.protocol', data_dict['protocol'])
        ]))
        entry_data.append(flow_index_table.make_data(
            [client.DataTuple('result', data_dict['result'])], "SwitchIngress.Set_flow_result"))

    flow_index_table.entry_add(target, entry_keys, entry_data)
    flow_info[key1] = data_dict
    print(f"Added flow_result entry. Current flow count: {len(flow_info)}")
"""

def add_tb_entry_flow_result(data_dict):
    table_name = 'SwitchIngress.Flow_result'
    flow_index_table = bfrt_info.table_get(table_name)

    key1 = f"{data_dict['src_addr']}-{data_dict['dst_addr']}-{data_dict['src_port']}-{data_dict['dst_port']}-{data_dict['protocol']}"
    key2 = f"{data_dict['dst_addr']}-{data_dict['src_addr']}-{data_dict['dst_port']}-{data_dict['src_port']}-{data_dict['protocol']}"

    print(f"📝 Trying to add Flow_result entry: {key1}")  # ✅ 添加 debug 打印

    if key1 in flow_info or key2 in flow_info:
        print(f"⚠️ Flow already exists: {key1} or {key2}")
        return

    entry_keys = []
    entry_data = []
    for src, dst, src_port, dst_port in [
        (data_dict['src_addr'], data_dict['dst_addr'], data_dict['src_port'], data_dict['dst_port']),
        (data_dict['dst_addr'], data_dict['src_addr'], data_dict['dst_port'], data_dict['src_port'])
    ]:
        entry_keys.append(flow_index_table.make_key([
            client.KeyTuple('hdr.ipv4.src_addr', src),
            client.KeyTuple('hdr.ipv4.dst_addr', dst),
            client.KeyTuple('ig_md.src_port', src_port),
            client.KeyTuple('ig_md.dst_port', dst_port),
            client.KeyTuple('hdr.ipv4.protocol', data_dict['protocol'])
        ]))

    print(f"✅ Writing to Flow_result: {entry_keys}")  # ✅ 添加 debug 打印

    flow_index_table.entry_add(target, entry_keys, [
        flow_index_table.make_data(
            [client.DataTuple('result', data_dict['result'])], "SwitchIngress.Set_flow_result"
        )
    ])

    flow_info[key1] = data_dict
    print(f"✅ Flow_result entry added! Current flow count: {len(flow_info)}")

def receive_digest():
    print("Receiving digests...")
    signal.signal(signal.SIGINT, quit_handler)
    signal.signal(signal.SIGTERM, quit_handler)

    while True:
        try:
            digest = GRPC_CLIENT.digest_get()
            if not digest:
                print("❌ No digest received!")  # ✅ Debug
                continue

            data_list = learn_filter.make_data_list(digest)
            
            print(f"📥 Received {len(data_list)} digest messages.")  # ✅ Debug

            for data_item in data_list:
                print(f"🔍 Digest content: {data_item.to_dict()}")  # ✅ Debug
                add_tb_entry_flow_result(data_item.to_dict())

        except KeyboardInterrupt:
            break
        except Exception as e:
            if "Digest list not received" not in str(e):
                print(f"Unexpected error receiving digest: {e}")


"""
def receive_digest():
    print("Receiving digests...")
    signal.signal(signal.SIGINT, quit_handler)
    signal.signal(signal.SIGTERM, quit_handler)

    while True:
        try:
            digest = GRPC_CLIENT.digest_get()
            if not digest:
                continue

            data_list = learn_filter.make_data_list(digest)
            
            print(f"📥 Received {len(data_list)} digest messages.")  # ✅ 添加打印调试信息
            
            for data_item in data_list:
                print(f"🔍 Digest content: {data_item.to_dict()}")  # ✅ 打印 digest 数据
                add_tb_entry_flow_result(data_item.to_dict())

        except KeyboardInterrupt:
            break
        except Exception as e:
            if "Digest list not received" not in str(e):
                print(f"Unexpected error receiving digest: {e}")



def receive_digest():
    print("Receiving digests...")
    signal.signal(signal.SIGINT, quit_handler)
    signal.signal(signal.SIGTERM, quit_handler)

    while True:
        try:
            digest = GRPC_CLIENT.digest_get()
            if not digest:
                continue

            data_list = learn_filter.make_data_list(digest)
            for data_item in data_list:
                add_tb_entry_flow_result(data_item.to_dict())

        except KeyboardInterrupt:
            break
        except Exception as e:
            if "Digest list not received" not in str(e):
                print(f"Unexpected error receiving digest: {e}")

def load_tb_bin(table_data):
    print("Loading bin table...")
    for i, entry in enumerate(table_data):
        table_name = f"pkt_bin{i+1}"
        update_action = f"Update_bin{i+1}"
        read_action = f"Read_bin{i+1}"

        tcam_table = bfrt_info.table_get(table_name)

        keys = [
            tcam_table.make_key([
                client.KeyTuple('$MATCH_PRIORITY', 1),
                client.KeyTuple('hdr.ipv4.total_len', entry[0], entry[1])
            ]),
            tcam_table.make_key([
                client.KeyTuple('$MATCH_PRIORITY', 2),
                client.KeyTuple('hdr.ipv4.total_len', 0, 0)
            ])
        ]
        data = [
            tcam_table.make_data([], update_action),
            tcam_table.make_data([], read_action)
        ]
        tcam_table.entry_add(target, keys, data)

        init_table_name = f"Init_bin{i+1}_table"
        init_update_action = f"Init1_bin{i+1}"
        init_read_action = f"Init0_bin{i+1}"

        init_table = bfrt_info.table_get(init_table_name)
        init_table.entry_add(target, keys, [
            init_table.make_data([], init_update_action),
            init_table.make_data([], init_read_action)
        ])
    print("Loaded bin table.")
"""

def load_tb_bin(table_data):
    print("Loading bin table...")

    for i, entry in enumerate(table_data):
        table_name = f"pkt_bin{i+1}"
        update_action = f"Update_bin{i+1}"
        read_action = f"Read_bin{i+1}"

        tcam_table = bfrt_info.table_get(table_name)

        keys = [
            tcam_table.make_key([
                client.KeyTuple('$MATCH_PRIORITY', 1),
                client.KeyTuple('hdr.ipv4.total_len', entry[0], entry[1])
            ]),
            tcam_table.make_key([
                client.KeyTuple('$MATCH_PRIORITY', 2),
                client.KeyTuple('hdr.ipv4.total_len', 0, 0)
            ])
        ]
        data = [
            tcam_table.make_data([], update_action),
            tcam_table.make_data([], read_action)
        ]
        
        print(f"Writing to {table_name}: {entry[0]} - {entry[1]}")  # ✅ 打印调试信息
        
        try:
            tcam_table.entry_add(target, keys, data)
            print(f"✅ Successfully added entry to {table_name}: {entry[0]} - {entry[1]}")
        except Exception as e:
            print(f"❌ Error adding entry to {table_name}: {e}")

    print("Loaded bin table.")


def load_tb_feat(table_data, table_name, feat_name, action_name, is_total_pkts=True):
    print(f"Loading feature table: {table_name}")

    tcam_table = bfrt_info.table_get(table_name)
    keys = []
    data = []

    for entry in table_data:
        match_priority = int(entry[0])
        lower = int(entry[1])
        upper = int(entry[2])
        index = int(entry[3])

        key_fields = [client.KeyTuple('$MATCH_PRIORITY', match_priority)]
        if is_total_pkts:
            key_fields.append(client.KeyTuple('ig_md.total_pkts', int(entry[4])))
        key_fields.append(client.KeyTuple(feat_name, lower, upper))

        keys.append(tcam_table.make_key(key_fields))
        data.append(tcam_table.make_data([client.DataTuple('ind', index)], action_name))

    tcam_table.entry_add(target, keys, data)
    print(f"Loaded table {table_name}.")


pkt_feat = ['proto', 'total_len', 'diffserv', 'ttl', 'tcp_dataOffset', 'tcp_window', 'udp_length']
pkt_flow_feat = ['pkt_size_max', 'flow_iat_min', 'bin_5', 'bin_3', 'pkt_size_var_approx', 'pkt_size_avg', 'pkt_size_min']

with open("./bin_table_and_class_flow.pkl", "rb") as f:
    bin_table, feat_table_datas_flow, tree_data_p2p_flow = pickle.load(f)

with open("./flow_size_and_class_pkt.pkl", "rb") as f:
    feat_table_datas_pkt, tree_data_flow_size, tree_data_p2p_pkt = pickle.load(f)

load_tb_bin(bin_table[::-1])

for feat, table, feat_name, action in [
    ('tcp_window', "SwitchIngress.Feat3", "ig_md.tcp_window", 'SwitchIngress.feat3_hit'),
    ('tcp_dataOffset', "SwitchIngress.Feat4", "ig_md.tcp_data_offset", 'SwitchIngress.feat4_hit')
]:
    load_tb_feat(feat_table_datas_pkt[feat], table, feat_name, action, is_total_pkts=False)

receive_digest()
