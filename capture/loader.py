import pyshark


def load_wireshark_file(file_path):
    try:
        print(f"FILE IS LOADING: {file_path}")
        capture = pyshark.FileCapture(file_path, use_json=True)

        packets = list(capture)
        print(f"LOADED: {len(packets)} packets")
        capture.close()
        return packets

    except Exception as ex:
        print("[ERROR] Error at loading!")
        return
