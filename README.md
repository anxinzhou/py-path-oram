# A demonstration of python implementation of path oram use python 

I assume you have read the paper of path oram, you have basic understanding of path oram, 
but not sure how it exactly works. I use this program to simulate the interaction between client and server with oram.

## For Non-Recursive Path oram

### Storage Explanation 
#### Composition of ORAM TREE on server
For n file, the level of tree is decided as 2^ level -1> = n, where level start from 0.
The tree contains 2^(level+1) - 1 buckets. A bucket contains Z block. In the implementation, I use Z = 5. 
A block is set to 8192 bytes. (also I 
store a nonce along the block, which is used for symmetric decryption, if you use asymmetric encryption, there is no 
need to store nonce).

The oram tree is initialized with dummy blocks. If you use asymmetric decryption, the server could 
generate dummy blocks with the public key of client. If you use symmetric encryption, the client generate the dummy blocks
and send to the server. The number of dummy blocks in initialization is Z * (2^(level+1) -1 ) (Blocks in a bucket * buckets in the tree)
 

#### Block

In the computer system, data is actually stored as block. So a file is actually composed of one or more block.

Here, I used 0,1,2....,n-1 as block_id (random block id is also fine). Notice that we only need set block id for the real block. 

#### Mapping between file and block

For simplicity, I assume a one to one mapping between a file and a block.
 One to many mapping (one file to many blocks) could be used for larger file. For small file, I pad the file with dummy (b'\xff') to the size of a block (For oram security). Although it's not efficient. 
A complex mapping may be further explored. 

The linux file system use one to many mapping, of course there is no need for padding.


### Position map

A position map is the key value map <block id, position>. Position is the location of a leaf node in the tree. 
(e.g. "001" means from root node, turn left, turn left, turn right) 

Position map is initialized with random position for each block id.

### Encryption tools

For speed, I use symmetric encryption AES. So a nonce need to stored along a block. There is no need for nonce for asymmetric encryption.


### Stash

The stash is a key value map <block id, block>, which is used to store blocks read from server.
Every "write" or "read" will read all blocks from a path from server. You need to remove the dummy blocks. Then
put the real blocks in stash. 

### Performance

As an proof-concept implementation, it's quite not efficient.

For 1000 files.  (1000 files from imdb dataset)
The initialization time (Need a full binary tree with level 10)  is 3.05 s.
The average write time is 0.033s.
The average read time is 0.034s.
