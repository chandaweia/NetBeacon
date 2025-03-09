import os
import pickle
from tree_to_table.rf import get_rf_feature_thres, get_rf_trees_table_entries
from tree_to_table.xgb import get_xgb_feature_thres, get_xgb_trees_table_entries
from tree_to_table.utils import get_feature_table_entries, get_bin_table

current_path = os.getcwd()
dir_path = os.path.abspath(os.path.dirname(os.getcwd()))

def get_flow_size_and_class_pkt():
    pkt_feat = ['proto', 'total_len', 'diffserv', 'ttl', 'tcp_dataOffset', 'tcp_window', 'udp_length']
    pkt_feat_bits = [8, 16, 8, 8, 4, 16, 16]
    key_bits = {pkt_feat[i]: pkt_feat_bits[i] for i in range(len(pkt_feat))}

    flow_size_model_file = current_path + '/models/flow_size_predict_1xgb.txt'
    class_pkt_model_file = current_path + '/models/class_pkt_1rf'

    feat_dict_flow_size = get_xgb_feature_thres(flow_size_model_file, pkt_feat)
    feat_dict_class_pkt = get_rf_feature_thres(class_pkt_model_file, pkt_feat, 1)

    feat_dict = {}
    for key in pkt_feat:
        feat_dict[key] = sorted(set(feat_dict_flow_size[key]) | set(feat_dict_class_pkt[key]))
        print(f"{key}: flow_size {len(feat_dict_flow_size[key])}, class_pkt {len(feat_dict_class_pkt[key])}, merged {len(feat_dict[key])}")

    pkt_feat_mark_bit = [8, 144, 24, 64, 8, 48, 72]
    range_mark_bits = {pkt_feat[i]: pkt_feat_mark_bit[i] for i in range(len(pkt_feat))}

    feat_table_datas = get_feature_table_entries(feat_dict, key_bits, range_mark_bits)
    print(f"Total feature table entries: {sum(len(v) for v in feat_table_datas.values())}")

    tree_data_flow_size = get_xgb_trees_table_entries(flow_size_model_file, pkt_feat, feat_dict, range_mark_bits)
    print(f"Flow size tree table entries: {len(tree_data_flow_size)}")

    tree_data_class_pkt = get_rf_trees_table_entries(class_pkt_model_file, pkt_feat, feat_dict, range_mark_bits, 1)
    print(f"Class pkt tree table entries: {len(tree_data_class_pkt)}")

    with open(dir_path + '/switch/control_plane/flow_size_and_class_pkt.pkl', 'wb') as f:
        pickle.dump([feat_table_datas, tree_data_flow_size, tree_data_class_pkt], f, protocol=4)

def get_class_flow():
    pkt_flow_feat = ['pkt_size_max', 'flow_iat_min', 'bin_5', 'bin_3', 'pkt_size_var_approx', 'pkt_size_avg', 'pkt_size_min']
    pkt_flow_feat_bit = [16, 32, 8, 16, 32, 32, 16]

    bin_table = get_bin_table(pkt_flow_feat, 16)

    class_flow_model_files = [
        current_path + '/models/class_flow_phase_2pkt_1rf',
        current_path + '/models/class_flow_phase_4pkt_1rf',
        current_path + '/models/class_flow_phase_8pkt_1rf',
        current_path + '/models/class_flow_phase_32pkt_1rf',
        current_path + '/models/class_flow_phase_256pkt_1rf',
        current_path + '/models/class_flow_phase_512pkt_1rf',
        current_path + '/models/class_flow_phase_2048pkt_1rf'
    ]
    class_flow_tree_nums = [1] * len(class_flow_model_files)

    feat_dicts = []
    for idx, model_file in enumerate(class_flow_model_files):
        feat_dict = get_rf_feature_thres(model_file, pkt_flow_feat, class_flow_tree_nums[idx])
        feat_dicts.append(feat_dict)

    pkt_flow_mark_bit = [80, 72, 24, 32, 80, 72, 48]
    feat_key_bits = {pkt_flow_feat[i]: pkt_flow_feat_bit[i] for i in range(len(pkt_flow_feat))}
    range_mark_bits = {pkt_flow_feat[i]: pkt_flow_mark_bit[i] for i in range(len(pkt_flow_feat))}

    pkt_flow_model_pkts = [2, 4, 8, 32, 256, 512, 2048]
    feat_table_data_all = {k: [] for k in pkt_flow_feat}
    tree_data_all = []

    for i, model_file in enumerate(class_flow_model_files):
        pkts = pkt_flow_model_pkts[i]
        feat_dict = feat_dicts[i]
        feat_table_datas = get_feature_table_entries(feat_dict, feat_key_bits, range_mark_bits, pkts=pkts)

        print(f"Phase {pkts} packets - feature table entries: {sum(len(v) for v in feat_table_datas.values())}")

        tree_data = get_rf_trees_table_entries(model_file, pkt_flow_feat, feat_dict, range_mark_bits, class_flow_tree_nums[i], pkts=pkts)

        print(f"Phase {pkts} packets - tree table entries: {len(tree_data)}")
        print(f"Phase {pkts} packets - all table entries: {sum(len(v) for v in feat_table_datas.values()) + len(tree_data)}")

        for key in pkt_flow_feat:
            feat_table_data_all[key].extend(feat_table_datas[key])
        tree_data_all.extend(tree_data)

    for key in pkt_flow_feat:
        print(f"{key} entries: {len(feat_table_data_all[key])}")
    print(f"Total tree data entries: {len(tree_data_all)}")

    with open(dir_path + '/switch/control_plane/bin_table_and_class_flow.pkl', 'wb') as f:
        pickle.dump([bin_table, feat_table_data_all, tree_data_all], f, protocol=4)

if __name__ == '__main__':
    get_flow_size_and_class_pkt()
    get_class_flow()
