#!/usr/bin/python
import os
from p4.tmp import p4config_pb2

build_dir = '../p4c-out/bmv2'
device_bin = 'switch.bin'
out_json = 'switch.json'

def main():
    with open(os.path.join(build_dir, device_bin), 'wf') as f_out:
        with open(os.path.join(build_dir, out_json), 'r') as f_json:
            device_config = p4config_pb2.P4DeviceConfig()
            device_config.device_data = f_json.read()
            f_out.write(device_config.SerializeToString())

if __name__ == '__main__':
    main()
