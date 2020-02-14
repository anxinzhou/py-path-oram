from random import randint
from Crypto.Cipher import AES
from bisect import bisect_left
from oram_tree import BlockCipher, BlockPlaintext, Bucket, OramTree


class PathOramServer:

    # block_size default to 2048 bytes
    # block_id_size 32 bytes
    #
    # a simple construction of a block
    # a block composed of two part = (cipher, nonce)
    # cipher = block_id + data   block_id = 256 bit = 32 bytes
    # nonce = AES nonce , used for decryption
    # A file could be stored in multiple block,  a mapping between file and block_id could be stored in client
    #
    # block dummy symbol used to pad a file to the maximum size which is (block_size - block_id_size)
    #

    def __init__(self, buckets, level):
        self.level = level

        # init with random blocks
        total_bucket_number = pow(2, level + 1) - 1
        if len(buckets) != total_bucket_number:
            raise Exception("number of blocks should equal to total_bucket_number")
        self.oram_tree = OramTree(buckets)

    def read(self, position):
        self.check_position_length(position)
        return self.oram_tree.read(position)

    def write_bucket(self, position, blocks, level):
        self.check_position_length(position)
        return self.oram_tree.write(position, blocks, level)

    def check_position_length(self, position):
        if len(position) < self.level:
            raise Exception("level should be less or equal than length of position")


class PathOramClient:
    key_size = 256

    # block_size default to 2048 bytes
    # block_id_size 32 bytes
    #
    # a simple construction of a block
    # a block composed of two part = (cipher, nonce)
    # cipher = block_id + data   block_id = 256 bit = 32 bytes
    # nonce = AES nonce , used for decryption
    # A file could be stored in multiple block,  a mapping between file and block_id could be stored in client
    #
    # block dummy symbol used to pad a file to the maximum size which is (block_size - block_id_size)
    def __init__(self, level, Z=5, block_size=8192, block_id_size=32):
        self.Z = Z
        self.level = level
        self.block_size = block_size
        self.block_id_size = block_id_size
        self.total_bucket_number = pow(2, level + 1) - 1
        self.block_dummy_symbol = b'\xff'
        self.dummy_block_id = int.from_bytes(self.block_dummy_symbol * self.block_id_size, byteorder='little')

        self.stash = dict()  # {block_id: block plaintext)}
        self.position_map = dict()  # {block_id:  position}

        leaf_nodes = pow(2, level)
        for i in range(leaf_nodes):
            position = self.integer_to_position(randint(0, leaf_nodes))
            self.position_map[i] = position
        # use AES for encryption
        self.key = str.encode('1' * (self.key_size // 8))

    def find_intersection_block(self, position, level):
        intersect_block = dict()
        for block_id in self.stash:
            block_position = self.position_map[block_id]
            if block_position[:level] == position[:level]:
                intersect_block[block_id] = self.stash[block_id]
        return intersect_block

    def access(self, op, block_id, block_data, oram_server):
        block_position = self.position_map[block_id]
        total_real_block = pow(2, self.level)
        self.position_map[block_id] = self.integer_to_position(randint(0, total_real_block))

        # read bucket along path block_position from server
        blocks_cipher = oram_server.read(block_position)
        to_append_stash = dict()
        for block_cipher in blocks_cipher:
            block_plaintext = self.decrypt_block(block_cipher)
            # skip dummy block
            if block_plaintext.block_id == self.dummy_block_id:
                continue
            to_append_stash[block_plaintext.block_id] = block_plaintext

        # update stash
        self.stash.update(to_append_stash)

        if block_id not in self.stash:
            # not write before
            data_to_read = None
        else:
            block_plaintext_to_read = self.stash[block_id]  # read from stash a
            data_to_read = self.remove_dummy_in_block(block_plaintext_to_read.data)
        if op == 'write':
            # pad block data to maximum block_size
            if len(block_data) > self.block_size:
                raise Exception("length of block data should be less than block size", "length of block data:",
                                len(block_data), "block size:", self.block_size)
            block_data = block_data + (self.block_size - len(block_data)) * self.block_dummy_symbol
            self.stash[block_id] = BlockPlaintext(block_id, block_data)

        for l in reversed(range(self.level + 1)):
            intersect_block = self.find_intersection_block(block_position, l)
            # select S'= min(len(intersect_block),Z) blocks to write
            select_block_num = min(len(intersect_block), self.Z)
            count = 0
            select_block_id = dict()
            for k in intersect_block:
                if count == select_block_num:
                    break
                select_block_id[k] = intersect_block[k]
                count += 1

            # remove select block from stash
            for block_id in select_block_id:
                del self.stash[block_id]

            select_blocks = [select_block_id[k] for k in select_block_id]

            select_blocks_cipher = []
            for select_block in select_blocks:
                block_cipher = self.encrypt_block(select_block)
                select_blocks_cipher.append(block_cipher)

            # padded S' with dummy blocks to size of Z, block id should be selected from stash
            if len(select_blocks_cipher) < self.Z:
                dummy_blocks_cipher = []
                for i in range(0, self.Z - len(select_blocks_cipher)):
                    dummy_block_cipher = self.generate_dummy_block_cipher()
                    dummy_blocks_cipher.append(dummy_block_cipher)
                select_blocks_cipher.extend(dummy_blocks_cipher)
            oram_server.write_bucket(block_position, select_blocks_cipher, l)

        return data_to_read

    def remove_dummy_in_block(self, data):
        dummy_symbol = self.block_dummy_symbol
        dummy_symbol_value = dummy_symbol[0]
        first_dummy_index = bisect_left(data, dummy_symbol_value)
        return data[:first_dummy_index]

    def read(self, block_id, oram_server):
        return self.access(op='read', block_data=None, block_id=block_id, oram_server=oram_server)

    def write(self, block_id, block_data, oram_server):
        return self.access(op='write', block_id=block_id, block_data=block_data, oram_server=oram_server)

    def encrypt_block(self, block_plaintext):
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        padded_block_id = block_plaintext.block_id.to_bytes(self.block_id_size, byteorder='little')
        data = padded_block_id + block_plaintext.data
        ciphertext = cipher.encrypt(data)
        return BlockCipher(ciphertext, nonce)

    def decrypt_block(self, block_cipher):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=block_cipher.nonce)
        plain_text = cipher.decrypt(block_cipher.cipher)
        block_id = int.from_bytes(plain_text[:self.block_id_size], byteorder='little')
        data = plain_text[self.block_id_size:]
        return BlockPlaintext(block_id, data)

    def generate_initialize_block(self):
        blocks = [[self.generate_dummy_block_cipher()] * self.Z for i in range(self.total_bucket_number)]
        buckets = []
        for i in range(len(blocks)):
            bucket = Bucket(blocks[i])
            buckets.append(bucket)
        return buckets

    def generate_dummy_block_cipher(self):
        dummy_block = self.block_dummy_symbol * self.block_size
        dummy_block_id = int.from_bytes(dummy_block[:self.block_id_size], byteorder='little')
        dummy_data = dummy_block[self.block_id_size: self.block_size]
        block_cipher = self.encrypt_block(
            BlockPlaintext(dummy_block_id, dummy_data))
        return block_cipher

    # change loc from 0 - 2^ level - 1 to a binary position representation in a tree (e.g. '00101')
    def integer_to_position(self, loc):
        binary_loc = bin(loc)[2:]  # remove '0b' in binary
        position_length = self.level
        position = ('0' * position_length + binary_loc)[-position_length:]
        return position
