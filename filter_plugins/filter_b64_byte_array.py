import base64

# Custom filter to decode Base64 string into a byte array
def decode_base64_to_bytearray(encoded_value):
    decoded_bytes = base64.b64decode(encoded_value)
    return list(decoded_bytes)

# Custom filter to encode a byte array into a Base64 string
def encode_bytearray_to_base64(byte_array):
    # Convert the list of bytes back to bytes and then encode it into a Base64 string
    byte_data = bytes(byte_array)
    encoded_value = base64.b64encode(byte_data).decode('utf-8')
    return encoded_value

# Register the filters in Ansible
class FilterModule(object):
    def filters(self):
        return {
            'decode_base64_to_bytearray': decode_base64_to_bytearray,
            'encode_bytearray_to_base64': encode_bytearray_to_base64
        }
