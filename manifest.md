## Simple encrypted block storage


### Database table

Database schema
```
|_____|_______|_______|____________|
 Nonce DB Meta DB Body Poly1305 MAC
```

- Database nonce: nonce for decryption DB meta using xchacha20 alg.
- DB Meta: metadata for the database
- DB Body: Unlimited database 
- Poly1305 MAC: Poly1305 sign

#### DB Meta
Decrypted structure:
- meta_size (u32): size of all meta fields, first field which will be parsed.
- bsize (u32, 256 - 2147483648): block size, all blocks are the same size
- bcount (u32): count of all blocks
- blocks table: list of all blocks in format [id -> block position]
    Every line in the blocks table takes 8 bytes (4 for id and 4 for the pointer shift).

Block table structure:
- id (u32): id of the block (block must be inited!)
- block position (u32): pointer shift, 0 for the first block, 
    N x ( size of full block + size of block nonce) fot the N one etc.

#### Block
All blocks in the database have the same size, from 256 bytes to 2GB (max for fat16).
Each block may has unique user's password.

Block schema:
```
|_____|_____________________|____________|
 Nonce      Ciphertext       Poly1305 MAC
      |__________|__________|
       Block meta Block body
```

Decrypted structures:
**Block meta**:
- id (u32): id of the current block. Block id is a random value
- counter (u192): xchacha20 counter
- isinited (u8): flag, if block is inited or deleted (11111111 if inited, 00000000 if not)

**Block body**:
Data field with size of 256 bytes till 2GB. May has filesystem (fat16), or useful data only.

### Database tree
```
├── db_nonce
├── db_meta
│   └── blocks_table
├── db_body
│   └── block
│       ├── nonce
│       ├── block_meta
│       ├── block_body
│       └── block_mac
└── db_mac
```
