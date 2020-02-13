from random import randint, shuffle, sample
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import util


# currently files are stored in memory of server
class BlockCipher:
    def __init__(self, cipher, nonce):
        self.cipher = cipher
        self.nonce = nonce


class BlockPlaintext:
    def __init__(self, block_id, data):
        self.block_id = block_id
        self.data = data

    def all(self):
        return self.block_id + self.data


class Bucket:
    def __init__(self, blocks):
        if blocks is None:
            self.data = []
        else:
            self.check_blocks_type(blocks)
            self.data = blocks

    def get(self):
        data = self.data
        # clear
        return data

    def put(self, blocks):
        self.check_blocks_type(blocks)
        self.data = blocks

    def check_blocks_type(cls, blocks):
        if type(blocks) is not list:
            raise Exception("wrong type of blocks passed to bucket")


class OramTree:
    def __init__(self, buckets):  # store tree in an array
        self.buckets = buckets
        self.root = None if not buckets or len(buckets) == 0 else buckets[0]

    # assume position is 0,1 string
    def read(self, position):
        blocks = []
        if not self.root:
            return blocks

        blocks.extend(self.buckets[0].get())

        target_index = 0
        for i in range(len(position)):
            if position[i] == '0':  # turn left
                target_index = 2 * i + 1
            elif position[i] == '1':  # turn right
                target_index = 2 * i + 2
            else:
                raise Exception("position should only be 0,1 string")
            target_bucket = self.buckets[target_index]
            blocks.extend(target_bucket.get())
        return blocks

    def write(self, position, blocks, level):
        if self.root == None:
            raise Exception("write to empty oram tree")
        if level > len(self.buckets):
            raise Exception("level greater than tree depth")
            # check validity of level
        if level > len(position):
            raise Exception("the length of level is greater than position map")

        target_index = 0
        for i in range(level - 1):
            if position[i] == '0':  # turn left
                target_index = 2 * i + 1
            elif position[i] == '1':  # turn rightddasd
                target_index = 2 * i + 2
            else:
                raise Exception("position should only be 0,1 string")
        target_bucket = self.buckets[target_index]
        target_bucket.put(blocks)


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

    def __init__(self, buckets, level, Z=5, block_size=2048, block_id_size=32, block_dummy_symbol='#'):
        self.Z = Z
        self.level = level
        self.block_size = block_size
        self.block_id_size = block_id_size
        self.total_bucket_number = pow(2, level - 1)
        self.block_dummy_symbol = block_dummy_symbol

        # init with random blocks
        if len(buckets) != self.total_bucket_number:
            raise Exception("number of blocks should equal to total_bucket_number")
        self.oram_tree = OramTree(buckets)

    def read(self, position):
        self.check_position_length(position)
        return self.oram_tree.read(position)

    def write_bucket(self, position, blocks, level):
        self.check_position_length(position)
        return self.oram_tree.write(position, blocks, level)

    def check_position_length(self, position):
        if len(position) != self.level - 1:
            raise Exception("wrong length of position", "length of position", len(position), "should be",
                            self.level - 1)


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
    def __init__(self, level, Z=5, block_size=2048, block_id_size=32, block_dummy_symbol='#'):
        self.Z = Z
        self.level = level
        self.block_size = block_size
        self.block_id_size = block_id_size
        self.total_bucket_number = pow(2, level - 1)
        self.block_dummy_symbol = block_dummy_symbol

        self.stash = dict()  # {block_id: block plaintext)}
        self.position_map = dict()  # {block_id:  position}

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
        self.position_map[block_id] = self.integer_to_position(randint(0, self.total_bucket_number - 1))

        # read bucket along path block_position from server
        blocks_cipher = oram_server.read(block_position)
        to_append_stash = dict()
        for block_cipher in blocks_cipher:
            block_plaintext = self.decrypt_block(block_cipher)
            to_append_stash[block_plaintext.block_id] = block_plaintext

        # update stash
        self.stash.update(to_append_stash)
        block_plaintext_to_read = self.stash[block_id]  # read from stash a
        data_to_read = self.remove_dummy_in_block(block_plaintext_to_read.data)
        if op == 'write':
            # pad block data to maximum block_size
            util.suffix_pad_dummy(block_data, self.block_size, dummy_symbol=self.block_dummy_symbol)
            self.stash[block_id] = BlockPlaintext(block_id, block_data)

        for l in reversed(range(self.level)):
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
                print("length of stash",len(self.stash.keys()),"length of to pad block", self.Z - len(select_blocks_cipher))
                dummy_blocks_id = sample(self.stash.keys(), self.Z - len(select_blocks_cipher))
                dummy_blocks_cipher = []
                for i in range(0, self.Z - len(select_blocks_cipher)):
                    dummy_block_id = dummy_blocks_id[i]
                    dummy_block_cipher = self.generate_dummy_block_cipher(dummy_block_id)
                    dummy_blocks_cipher.append(dummy_block_cipher)
                select_blocks_cipher.extend(dummy_blocks_cipher)
            oram_server.write_bucket(block_position, select_blocks_cipher, l)

        return data_to_read

    def remove_dummy_in_block(self, data):
        dummy_symbol = self.block_dummy_symbol
        last_index = len(data) - 1
        for i in reversed(range(len(data))):
            if data[i] != dummy_symbol:
                last_index = i
        return data[:last_index + 1]

    def read(self, block_id, oram_server):
        return self.access(op='read', block_id=block_id, oram_server=oram_server)

    def write(self, block_id, block_data, oram_server):
        return self.access(op='write', block_id=block_id, block_data=block_data, oram_server=oram_server)

    def encrypt_block(self, block_plaintext):
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        padded_block_id = util.prefix_pad_dummy(str(block_plaintext.block_id), self.block_id_size, dummy_symbol='0')
        data = padded_block_id + block_plaintext.data
        ciphertext = cipher.encrypt(str.encode(data))
        return BlockCipher(ciphertext, nonce)

    def decrypt_block(self, block_cipher):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=block_cipher.nonce)
        plain_text = cipher.decrypt(block_cipher.cipher).decode()
        block_id = plain_text[:self.block_id_size]
        data = plain_text[self.block_id_size:]
        return BlockPlaintext(int(block_id), data)

    def generate_initialize_block(self):
        blocks = [[0] * self.Z for i in range(self.total_bucket_number)]
        blocks_id = list(range(self.total_bucket_number * self.Z))
        shuffle(blocks_id)
        for i in range(self.total_bucket_number):
            for j in range(self.Z):
                block_id_index = i * self.Z + j
                block_id = blocks_id[block_id_index]
                position = self.integer_to_position(block_id // self.Z)
                self.position_map[block_id] = position
                block = self.generate_dummy_block_cipher(block_id)
                blocks[block_id // self.Z][block_id % self.Z] = block
        buckets = []
        for i in range(len(blocks)):
            bucket = Bucket(blocks[i])
            buckets.append(bucket)
        return buckets

    def generate_dummy_block_cipher(self, block_id):
        dummy_data = '#' * (self.block_size - self.block_id_size)
        block_cipher = self.encrypt_block(BlockPlaintext(block_id, dummy_data))
        return block_cipher

    # change loc from 0 - 2^ level - 1 to a binary position representation in a tree (e.g. '00101')
    def integer_to_position(self, loc):
        binary_loc = bin(loc)[2:]  # remove '0b' in binary
        position_length = self.level - 1
        position = ('0' * position_length + binary_loc)[-position_length:]
        return position
