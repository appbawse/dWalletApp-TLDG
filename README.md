# Bitcoin2

The code includes various functions to create, update, and verify different components of a blockchain system such as users, addresses, transactions, blocks, Merkle trees, proofs, and balances.
It also includes functions for encrypting and decrypting data, generating and verifying ECDSA-based JWT signatures, and handling communication between peers in a peer-to-peer network.
The code uses the MySQL database for storing blockchain-related data.
Example Usage for Transactions:
To use this code for transactions, you would typically follow these steps:

Create a user:
Call the createUser function with the necessary user information such as username, password hash, salt, and public key.
This function inserts the user data into the User table in the MySQL database.
Create an address for the user:
Call the createAddress function with the userId and the address to associate with the user.
This function inserts the address data into the Address table in the MySQL database.
Create a transaction:
Call the createTransaction function with the necessary transaction details such as the sender's address ID (fromAddressId), recipient's address ID (toAddressId), balance, and transaction hash.
This function inserts the transaction data into the Transaction table in the MySQL database.
Create a block:
Before creating a block, you need to generate the Merkle root hash for the transactions in the block.
Call the generateMerkleRootHash function with an array of transaction hashes (treeHashes) to get the Merkle root hash.
Call the createBlock function with the necessary block details, including the Merkle root hash, version, timestamp, and previous block hash (previousHash).
This function inserts the block data into the Block table in the MySQL database.
Add the transaction to the block:
Call the addTransactionToBlock function with the blockId and the transactionId to associate the transaction with the block.
This function inserts the association data into the BlockTransaction table in the MySQL database.
Process the latest Merkle tree data:
After creating the block, call the processMerkleTree function with the Merkle tree root hash (merkleTree) to perform any necessary processing or calculations.
