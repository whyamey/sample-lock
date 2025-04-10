import struct
import sys
import numpy as np

def convert_bincode_to_sample_bin(bincode_path: str, output_bin_path: str):
    with open(bincode_path, "rb") as f:
        num_positions = struct.unpack("<Q", f.read(8))[0]
        
        all_samples = []
        num_samples = None
        
        for pos_idx in range(num_positions):
            array_len = struct.unpack("<Q", f.read(8))[0]
            
            if pos_idx == 0:
                num_samples = array_len
                print(f"Detected {num_samples} samples per position")
            elif array_len != num_samples:
                print(f"Warning: Position {pos_idx} has {array_len} samples, expected {num_samples}")
            
            for _ in range(array_len):
                val = struct.unpack("<Q", f.read(8))[0]
                val = val & 0xFFFFFFFF
                all_samples.append(val)
    
    with open(output_bin_path, "wb") as f:
        for val in all_samples:
            f.write(struct.pack("<I", val))
    
    print(f"Converted {num_positions} positions with {num_samples} samples each")
    print(f"Total samples written: {len(all_samples)}")
    print(f"Output file: {output_bin_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert_to_sample_bin.py input.bin output.bin")
        sys.exit(1)
    
    convert_bincode_to_sample_bin(sys.argv[1], sys.argv[2])
