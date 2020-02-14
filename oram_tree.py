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
            # check validity of level

        target_index = 0
        for i in range(level):
            if position[i] == '0':  # turn left
                target_index = 2 * i + 1
            elif position[i] == '1':  # turn rightddasd
                target_index = 2 * i + 2
            else:
                raise Exception("position should only be 0,1 string")
        target_bucket = self.buckets[target_index]
        target_bucket.put(blocks)


class PositionMap:
    def __init__(self):
        self.map = dict()

    def put(self, key, value):
        self.map[key] = value

    def get(self, key):
        return self.map[key]
