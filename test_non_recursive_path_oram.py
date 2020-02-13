from non_recursive_path_oram import PathOramClient, PathOramServer
import os
import util
from math import log
import time

test_dataset = 'imdb/neg'
# test initialize
# load content in dataset
files_list = os.listdir(test_dataset)
contents = []
file_block_map = dict()
for i, file_name in enumerate(files_list):
    f = open(os.path.join(test_dataset, file_name), 'r')
    data = f.read()
    contents.append((i, data))
    file_block_map[files_list[i]] = i
    f.close()

    if i == 1000:
        break

# initialize oram

# decide level of oram
total_file_number = len(contents)
level = log(total_file_number, 2)
if level != int(level):
    level += 1
level = int(level)

print("total files", total_file_number)
print("level of oram", level)

start = time.time()
client = PathOramClient(level)
# generate dummy block
dummy_buckets = client.generate_initialize_block()
server = PathOramServer(dummy_buckets, level)
end = time.time()
print("time of initialize with dummy", end - start, 's')

start = time.time()
# write content to oram and record map between file and block_id
for i, content in enumerate(contents):
    print("write",i,"th file")
    block_id = content[0]
    data = content[1]
    client.write(block_id, data, server)
end = time.time()
print("time of write all content", end - start, "s")

# # test read
# start = time.time()
# # write content to oram
# for content in contents:
#     block_id = content[0]
#     data = content[1]
#     client.write(block_id, data, server)
# end = time.time()
