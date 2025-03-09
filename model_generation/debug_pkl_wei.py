import pickle

# 你的 pkl 文件路径
pkl_file_path = "/home/cuidi/NetBeacon/switch/control_plane/bin_table_and_class_flow.pkl"

# 读取 pkl 文件
with open(pkl_file_path, "rb") as f:
    bin_table, feat_table_data_all, tree_data_all = pickle.load(f)

# 打印 bin_table 里的规则
print("Bin Table Entries:")
for entry in bin_table:
    print(entry)

# 如果 `bin_table` 是字典，查找 `hdr.ipv4.total_len`
if isinstance(bin_table, dict):
    total_len_bins = bin_table.get("total_len", [])
    print("\nTotal Length Bins:")
    print(total_len_bins)
