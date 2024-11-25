import argparse
import os
import subprocess
import glob
from pathlib import Path
import pdb
import r2pipe

def main(args):
    #Iterate over all directories in input_path
    for directory in glob.glob(f"{args.input_path}/*"):

        #Iterate over all binary files
        for binary in glob.glob(f"{directory}/*"):
            #radare analyse the app and enumerate all functions
            r2 = r2pipe.open(binary)
            r2.cmd('aa')
            functions = r2.cmd('afl')
            functions = functions.splitlines()
            disasses = {}

            #For each function
            #Extract disassembly and write file in output path
            for each_function in functions:
                each_function = each_function.split()[-1]
                disass = r2.cmd(f'pdf @ {each_function}')
                disasses[each_function] = disass


            if len(disasses) > 0:
                output_dir = binary.replace(args.input_path, args.output_path)
                dir_path = Path(output_dir)
                dir_path.mkdir(parents=True, exist_ok=True)

            for func in disasses:
                try:
                    with open(os.path.join(dir_path, func), 'w') as fi_le:
                        fi_le.write(disasses[func])
                except Exception as e:
                    print(e)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find executable ELFs')
    parser.add_argument("--input_path", type=str, default = "/input_data", help="Input path")
    parser.add_argument("--output_path", type=str, default = "/output_data", help="Output path")
    parser.add_argument("--temp_dir", type=str, default = "/temp", help="Output path")

    args = parser.parse_args()
    main(args)

