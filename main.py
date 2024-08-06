import msgpack
import struct
import hashlib
import socket

def md5_top_4_bytes(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    hash_bytes = md5_hash.digest()
    top_4_bytes = hash_bytes[:4]
    return top_4_bytes[::-1]

def bytes_to_hex(byte_data):
    return [f"{byte:02x}" for byte in byte_data]

def pack_rpc_header(magic_num, req_type, body_len, req_id, func_name):
    rpc_header_bytes = bytes([magic_num, req_type, 0xFF, 0xFF]) + struct.pack('I', body_len) + struct.pack('Q', req_id) + md5_top_4_bytes(func_name)
    return rpc_header_bytes

def pack_data(raw_data):
    packed_data = msgpack.packb(raw_data)
    return packed_data

def pack_rpc_req(func_name, req_type,  req_id, req_data):
    MAGIC_NUM = 39
    if req_data is None or len(req_data) == 0:
        print("Empty data")
        return None
    msg_bytes = bytes([0x91]) + pack_data(req_data)
    header_bytes = pack_rpc_header(MAGIC_NUM, req_type, len(msg_bytes), req_id, func_name)
    send_data = header_bytes + msg_bytes
    return send_data

if __name__ == "__main__":
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_addr_info = ("127.0.0.1", 9000)
    serv.connect(serv_addr_info)
    
    try:
        send_message = pack_rpc_req("echo", 0, 1, "test")
        print(bytes_to_hex(send_message))
        serv.sendall(send_message)
        
        recv_message = serv.recv(1024)
        print('Received data: ', bytes_to_hex(recv_message))  # need to unpack
    finally:
        serv.close();
    
    
    