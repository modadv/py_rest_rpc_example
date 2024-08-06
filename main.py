import msgpack
import struct
import hashlib

def md5_top_4_bytes(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    hash_bytes = md5_hash.digest()
    top_4_bytes = hash_bytes[:4]
    return top_4_bytes[::-1]  # match c++ unsigned int storage

def bytes_to_hex(byte_data):
    # 将每个字节转换为 16 进制形式
    return [f"{byte:02x}" for byte in byte_data]

def pack_rpc_header(magic_num, req_type, body_len, req_id, func_name):
    rpc_header_bytes = bytes([magic_num, req_type, 0xFF, 0xFF]) + struct.pack('I', body_len) + struct.pack('Q', req_id) + md5_top_4_bytes(func_name)
    return rpc_header_bytes


    
if __name__ == "__main__":
    print(bytes_to_hex(pack_rpc_header(39, 0, 6, 1, "echo")))