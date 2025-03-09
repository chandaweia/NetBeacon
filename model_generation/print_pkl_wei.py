import pickle

# Load the pickle file to inspect its contents
pkl_file_path = "/home/cuidi/NetBeacon/switch/control_plane/bin_table_and_class_flow.pkl"

try:
    with open(pkl_file_path, 'rb') as f:
        data = pickle.load(f)

    # Check the structure of the loaded data
    if not isinstance(data, list) or len(data) != 3:
        raise ValueError("Unexpected data format in the pickle file.")

    bin_table, feat_table_data_all, tree_data_all = data

    # Handle bin_table (since it's a list, we show its length)
    bin_table_summary = f"bin_table contains {len(bin_table)} entries (expected a dict?)"

    # Feature table summary
    feat_table_summary = {k: len(v) for k, v in feat_table_data_all.items()}

    # Tree data summary
    tree_data_summary = len(tree_data_all)

    result_summary = {
        "bin_table_summary": bin_table_summary,
        "feat_table_summary": feat_table_summary,
        "tree_data_summary": tree_data_summary
    }

except Exception as e:
    result_summary = {"error": str(e)}

print(result_summary)
