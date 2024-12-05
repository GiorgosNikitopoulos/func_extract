import argparse
import os
import subprocess
import base64
import glob
import json
from pathlib import Path
import pdb
import r2pipe

def main(args):
    #Iterate over all directories in input_path
    if True:
        #Iterate over all binary files
        for binary in glob.glob(f"{args.input_path}/*"):
            print(f"Found binary {binary}")
            #radare analyse the app and enumerate all functions
            r2 = r2pipe.open(binary)
            r2.cmd('aa')
            functions = r2.cmd('afl').splitlines()
            print(f"Found {len(functions)} functions")

            func_info = {}
            disasses = {}

            #For each function
            #Extract disassembly and write file in output path
            for each_function in functions:
                parts = each_function.split()  # Split function details
                
                name = parts[3]
                size = int(parts[2])
                start_addr = int(parts[0], 16)

                # skip import stubs
                if ".imp." in name: 
                    continue

                print(f"Processing {name}")
                
                raw_bytes = r2.cmd(f"p8 {size} @ {start_addr}").strip()
                if not raw_bytes:
                    print(f"No raw bytes retrieved for {name}")
                    continue
                
                raw_bytes = bytes.fromhex(raw_bytes)
                raw_bytes = base64.b64encode(raw_bytes).decode('utf-8')
            
                each_function = each_function.split()[-1]
                disass = r2.cmd(f'pdf @ {each_function}').strip()
                disass = bytes(disass.encode())
                disass = base64.b64encode(disass).decode('utf-8')

                func_info[start_addr] = { \
                    'name': name,
                    'start': start_addr,
                    'end': start_addr + size,
                    'bytes': raw_bytes,
                    'disassembly': disass
                }
                    
            if len(func_info) != 0:
                output_dir = binary.replace(args.input_path, args.output_path)
                dir_path = Path(output_dir)
                dir_path.mkdir(parents=True, exist_ok=True)

            for func_addr, values in func_info.items():
                try:
                    name = values['name']
                    with open(os.path.join(dir_path, f"{name}.json"), 'w') as fh:
                        obj = {func_addr: values}
                        json.dump(obj, fh, indent=4)
                except Exception as e:
                    print(e)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find executable ELFs')
    parser.add_argument("--input_path", type=str, default = "/input_data", help="Input path")
    parser.add_argument("--output_path", type=str, default = "/output_data", help="Output path")
    parser.add_argument("--temp_dir", type=str, default = "/temp", help="Output path")

    args = parser.parse_args()
    main(args)

