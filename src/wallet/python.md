hex_string = "483045022100acbd419b87d579ebaab4e5762ecd764118557455e547871e03eebcc0e1f3c2e402201fbfb2dd7da7e5c5742ac7872f15b025994fb01f553543d954364475bba7da5e012102141c8e67f406b5827e328c0184bc323b4390682be36199ce69010c2fbdad80ac"

byte_array = bytes.fromhex(hex_string)
byte_list = list(byte_array)
print(byte_list)

byte_array = [137, 85, 169, 121, 99, 223, 138, 234, 189, 76, 239, 70, 217, 238, 236, 133, 13, 246, 181, 56, 30, 176, 253, 102, 55, 78, 134, 49, 5, 56, 149, 31]

print(''.join(format(byte, '02x') for byte in byte_array))
