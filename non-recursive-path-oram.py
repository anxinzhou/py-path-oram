from random import randint
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import util


class BLOCK_CIPHER:
    def __init__(self, cipher, nonce):
        self.cipher = cipher
        self.nonce = nonce


class BLOCK_PLAINTEXT:
    def __init__(self, block_id, data):
        self.block_id = block_id
        self.data = data
    def all(self):
        return self.block_id + self.data

class BUCKET:
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


class ORAM_TREE:
    def __init__(self, buckets):  # store tree in an array
        self.buckets = buckets
        self.root = None if not buckets or len(buckets) == 0 else buckets[0]

    # assume position is 0,1 string
    def read(self, position):
        blocks = []
        if not self.root:
            return blocks

        blocks.extend(self.buckets[0].read())

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


class PATH_ORAM_SETTING:
    # only store some public parameter
    Z = 5  # number of blocks in a bucket
    level = 10
    security_parameter = 80
    # a simple construction of a block
    # a block composed of two part = (cipher, nonce)
    #   cipher = block_id + data   block_id = 256 bit = 32 bytes
    # nonce = AES nonce , used for decryption
    #   A file could be stored in multiple block,  a mapping between file and block_id could be stored in client
    block_size = 2048  # 2048 bytes
    block_id_size = 32 # 32 bytes
    total_bucket_number = pow(2, level) - 1


class PATH_ORAM_SERVER(PATH_ORAM_SETTING):

    def __init__(self, buckets):
        # init with random blocks
        if len(buckets) != self.total_bucket_number:
            raise Exception("number of blocks should equal to total_bucket_number")
        self.oram_tree = ORAM_TREE(buckets)

    def read(self, position):
        self.check_position_length(position)
        return self.oram_tree.read(position)

    def write_bucket(self, position, blocks, level):
        self.check_position_length(position)
        return self.oram_tree.write(position, blocks, level)

    def check_position_length(self, position):
        if len(position) != self.level - 1:
            raise Exception("wrong length of position")


class PATH_ORAM_CLIENT(PATH_ORAM_SETTING):
    key_size = 256

    def __init__(self, blocks):
        self.stash = dict()
        self.position_map = dict()
        # init poistion map with random number from 0 - total_bucket_number - 1
        for block_id in range(self.total_bucket_number):
            self.position_map[block_id] = randint(0, self.total_bucket_number - 1)
        # use AES for encryption
        self.key = str.encode('1' * (self.key_size // 8))

    def find_intersection_block(self, position, level):
        intersect_block = dict()
        for block_id in self.stash:
            block_position = self.stash[block_id]
            if block_position[level] == position[level]:
                intersect_block[block_id] = self.stash[block_id]
        return intersect_block


    def access(self, op, block_id, block_data, oram_server):
        block_position = self.position_map[block_id]
        self.position_map[block_id] = randint(0, self.total_bucket_number - 1)

        # read bucket along path block_position from server
        blocks_cipher = oram_server.read(block_position)
        to_append_stash = dict()
        for block_cipher in blocks_cipher:
            block_plaintext = self.decrypt_block(block_cipher)
            to_append_stash[block_plaintext.block_id] = block_plaintext.data

        # update stash
        for l in range(self.level):
            self.stash.update(oram_server.read(to_append_stash))
        block_plaintext_to_read = self.stash[block_id]  # read from stash a
        if op == 'write':
            self.stash[block_id] = BLOCK_PLAINTEXT(block_id, block_data)

        for l in reversed(range(self.level)):
            intersect_block = self.find_intersection_block(block_position, l)
            select_block_num = min(len(intersect_block), self.Z)
            count = 0
            select_block_id = dict()
            for k in intersect_block:
                if count == select_block_num:
                    break
                select_block_id[k] = intersect_block[k]
                count += 1
            select_block_position = [self.position_map[k][:l] for k in select_block_id]
            select_blocks = [select_block_id[k] for k in select_block_id]

            select_blocks_cipher = []
            for select_block in select_blocks_cipher:
                block_cipher = self.encrypt_block(select_block)
                select_blocks_cipher.append(block_cipher)

            if len(select_blocks_cipher) < self.Z:
                # padded with dummy block
                dummy_blocks_cipher = [self.generate_dummy_block_cipher() for i in range(self.Z - len(select_blocks))]
                select_blocks.extend(dummy_blocks_cipher)
            oram_server.write_bucket(select_block_position, select_blocks, l)

        return block_plaintext_to_read.data

    def read(self, block_id, oram_server):
        return self.access(op='read', block_id=block_id, oram_server=oram_server)

    def write(self, block_id, block_data, oram_server):
        return self.access(op='write', block_id=block_id, block_data=block_data, oram_server=oram_server)

    def encrypt_block(self, block_plaintext):
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        data = util.prefix_pad_zero(block_plaintext.block_id, self.block_id_size)
        return BLOCK_CIPHER(data, nonce)

    def decrypt_block(self, block_cipher):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=block_cipher.nonce)
        plain_text = cipher.decrypt(block_cipher.cipher)
        block_id = plain_text[:self.block_id_size]
        data = plain_text[self.block_id_size:]
        return BLOCK_PLAINTEXT(eval(block_id), data)

    def generate_initialize_block(self):
        buckets = []
        for i in range(self.total_bucket_number):
            blocks_cipher = []
            for j in range(self.Z):
                block = self.generate_dummy_block_cipher()
                blocks_cipher.append(block)
            bucket = BUCKET(blocks_cipher)
            buckets.append(bucket)
        return buckets

    def generate_dummy_block_cipher(self):
        dummy_data = get_random_bytes(self.block_size).decode()
        block_id = eval(dummy_data[:self.block_id_size])
        data = dummy_data[self.block_id_size:]
        block_cipher = self.encrypt_block(BLOCK_PLAINTEXT(block_id, data))
        return block_cipher

