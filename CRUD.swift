import Vapor
import Fluent

final class User: Model, Content {
    static let schema = "User"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "username")
    var username: String
    
    @Field(key: "password_hash")
    var passwordHash: String
    
    @Field(key: "salt")
    var salt: String
    
    @Field(key: "public_key")
    var publicKey: String
    
    init() {}
    
    init(id: Int? = nil, username: String, passwordHash: String, salt: String, publicKey: String) {
        self.id = id
        self.username = username
        self.passwordHash = passwordHash
        self.salt = salt
        self.publicKey = publicKey
    }
}

func routes(_ app: Application) throws {
    // Create User
    app.post("users") { req -> EventLoopFuture<User> in
        let user = try req.content.decode(User.self)
        return user.save(on: req.db).map { user }
    }
    
    // Read all Users
    app.get("users") { req -> EventLoopFuture<[User]> in
        return User.query(on: req.db).all()
    }
    
    // Read User by ID
    app.get("users", ":userID") { req -> EventLoopFuture<User> in
        guard let userID = req.parameters.get("userID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return User.find(userID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update User
    app.put("users", ":userID") { req -> EventLoopFuture<User> in
        guard let userID = req.parameters.get("userID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedUser = try req.content.decode(User.self)
        return User.find(userID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { user in
                user.username = updatedUser.username
                user.passwordHash = updatedUser.passwordHash
                user.salt = updatedUser.salt
                user.publicKey = updatedUser.publicKey
                return user.save(on: req.db).map { user }
            }
    }
    
    // Delete User
    app.delete("users", ":userID") { req -> EventLoopFuture<HTTPStatus> in
        guard let userID = req.parameters.get("userID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return User.find(userID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { user in
                return user.delete(on: req.db).transform(to: .noContent)
            }
    }

final class Address: Model, Content {
    static let schema = "Address"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "user_id")
    var userId: Int
    
    @Field(key: "address")
    var address: String
    
    init() {}
    
    init(id: Int? = nil, userId: Int, address: String) {
        self.id = id
        self.userId = userId
        self.address = address
    }
}

func routes(_ app: Application) throws {
    // Create Address
    app.post("addresses") { req -> EventLoopFuture<Address> in
        let address = try req.content.decode(Address.self)
        return address.save(on: req.db).map { address }
    }
    
    // Read all Addresses
    app.get("addresses") { req -> EventLoopFuture<[Address]> in
        return Address.query(on: req.db).all()
    }
    
    // Read Address by ID
    app.get("addresses", ":addressID") { req -> EventLoopFuture<Address> in
        guard let addressID = req.parameters.get("addressID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Address.find(addressID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update Address
    app.put("addresses", ":addressID") { req -> EventLoopFuture<Address> in
        guard let addressID = req.parameters.get("addressID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedAddress = try req.content.decode(Address.self)
        return Address.find(addressID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { address in
                address.userId = updatedAddress.userId
                address.address = updatedAddress.address
                return address.save(on: req.db).map { address }
            }
    }
    
    // Delete Address
    app.delete("addresses", ":addressID") { req -> EventLoopFuture<HTTPStatus> in
        guard let addressID = req.parameters.get("addressID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Address.find(addressID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { address in
                return address.delete(on: req.db).transform(to: .noContent)
            }
    }

    final class Transaction: Model, Content {
    static let schema = "Transaction"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "from_address_id")
    var fromAddressID: Int
    
    @Field(key: "to_address_id")
    var toAddressID: Int
    
    @Field(key: "balance")
    var balance: Decimal
    
    @Field(key: "timestamp")
    var timestamp: Date
    
    @Field(key: "hash")
    var hash: String
    
    init() {}
    
    init(id: Int? = nil, fromAddressID: Int, toAddressID: Int, balance: Decimal, timestamp: Date, hash: String) {
        self.id = id
        self.fromAddressID = fromAddressID
        self.toAddressID = toAddressID
        self.balance = balance
        self.timestamp = timestamp
        self.hash = hash
    }
}

func routes(_ app: Application) throws {
    // Create Transaction
    app.post("transactions") { req -> EventLoopFuture<Transaction> in
        let transaction = try req.content.decode(Transaction.self)
        return transaction.save(on: req.db).map { transaction }
    }
    
    // Read all Transactions
    app.get("transactions") { req -> EventLoopFuture<[Transaction]> in
        return Transaction.query(on: req.db).all()
    }
    
    // Read Transaction by ID
    app.get("transactions", ":transactionID") { req -> EventLoopFuture<Transaction> in
        guard let transactionID = req.parameters.get("transactionID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Transaction.find(transactionID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update Transaction
    app.put("transactions", ":transactionID") { req -> EventLoopFuture<Transaction> in
        guard let transactionID = req.parameters.get("transactionID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedTransaction = try req.content.decode(Transaction.self)
        return Transaction.find(transactionID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { transaction in
                transaction.fromAddressID = updatedTransaction.fromAddressID
                transaction.toAddressID = updatedTransaction.toAddressID
                transaction.amount = updatedTransaction.amount
                transaction.timestamp = updatedTransaction.timestamp
                transaction.hash = updatedTransaction.hash
                return transaction.save(on: req.db).map { transaction }
            }
    }
    
    // Delete Transaction
    app.delete("transactions", ":transactionID") { req -> EventLoopFuture<HTTPStatus> in
        guard let transactionID = req.parameters.get("transactionID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Transaction.find(transactionID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { transaction in
                return transaction.delete(on: req.db).transform(to: .noContent)
            }
    }

    final class Block: Model, Content {
    static let schema = "Block"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "version")
    var version: Int
    
    @Field(key: "timestamp")
    var timestamp: Date
    
    @Field(key: "previous_hash")
    var previousHash: String
    
    @Field(key: "merkle_root")
    var merkleRoot: String
    
    @Field(key: "nonce")
    var nonce: Int
    
    @Field(key: "hash")
    var hash: String
    
    init() {}
    
    init(id: Int? = nil, version: Int, timestamp: Date, previousHash: String, merkleRoot: String, difficulty: Int, nonce: Int, hash: String) {
        self.id = id
        self.version = version
        self.timestamp = timestamp
        self.previousHash = previousHash
        self.merkleRoot = merkleRoot
        self.nonce = nonce
        self.hash = hash
    }
}

func routes(_ app: Application) throws {
    // Create Block
    app.post("blocks") { req -> EventLoopFuture<Block> in
        let block = try req.content.decode(Block.self)
        return block.save(on: req.db).map { block }
    }
    
    // Read all Blocks
    app.get("blocks") { req -> EventLoopFuture<[Block]> in
        return Block.query(on: req.db).all()
    }
    
    // Read Block by ID
    app.get("blocks", ":blockID") { req -> EventLoopFuture<Block> in
        guard let blockID = req.parameters.get("blockID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Block.find(blockID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update Block
    app.put("blocks", ":blockID") { req -> EventLoopFuture<Block> in
        guard let blockID = req.parameters.get("blockID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedBlock = try req.content.decode(Block.self)
        return Block.find(blockID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { block in
                block.version = updatedBlock.version
                block.timestamp = updatedBlock.timestamp
                block.previousHash = updatedBlock.previousHash
                block.merkleRoot = updatedBlock.merkleRoot
                block.nonce = updatedBlock.nonce
                block.hash = updatedBlock.hash
                return block.save(on: req.db).map { block }
            }
    }
    
    // Delete Block
    app.delete("blocks", ":blockID") { req -> EventLoopFuture<HTTPStatus> in
        guard let blockID = req.parameters.get("blockID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Block.find(blockID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { block in
                return block.delete(on: req.db).transform(to: .noContent)
            }
    }
  
final class BlockTransaction: Model, Content {
    static let schema = "BlockTransaction"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "block_id")
    var blockID: Int
    
    @Field(key: "transaction_id")
    var transactionID: Int
    
    init() {}
    
    init(id: Int? = nil, blockID: Int, transactionID: Int) {
        self.id = id
        self.blockID = blockID
        self.transactionID = transactionID
    }
}

func routes(_ app: Application) throws {
    // Create BlockTransaction
    app.post("blocktransactions") { req -> EventLoopFuture<BlockTransaction> in
        let blockTransaction = try req.content.decode(BlockTransaction.self)
        return blockTransaction.save(on: req.db).map { blockTransaction }
    }
    
    // Read all BlockTransactions
    app.get("blocktransactions") { req -> EventLoopFuture<[BlockTransaction]> in
        return BlockTransaction.query(on: req.db).all()
    }
    
    // Read BlockTransaction by ID
    app.get("blocktransactions", ":blockTransactionID") { req -> EventLoopFuture<BlockTransaction> in
        guard let blockTransactionID = req.parameters.get("blockTransactionID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return BlockTransaction.find(blockTransactionID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update BlockTransaction
    app.put("blocktransactions", ":blockTransactionID") { req -> EventLoopFuture<BlockTransaction> in
        guard let blockTransactionID = req.parameters.get("blockTransactionID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedBlockTransaction = try req.content.decode(BlockTransaction.self)
        return BlockTransaction.find(blockTransactionID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { blockTransaction in
                blockTransaction.blockID = updatedBlockTransaction.blockID
                blockTransaction.transactionID = updatedBlockTransaction.transactionID
                return blockTransaction.save(on: req.db).map { blockTransaction }
            }
    }
    
    // Delete BlockTransaction
    app.delete("blocktransactions", ":blockTransactionID") { req -> EventLoopFuture<HTTPStatus> in
        guard let blockTransactionID = req.parameters.get("blockTransactionID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return BlockTransaction.find(blockTransactionID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { blockTransaction in
                return blockTransaction.delete(on: req.db).transform(to: .noContent)
            }
    }

final class MerkleTree: Model, Content {
    static let schema = "MerkleTree"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "sharding_id")
    var shardingID: Int
    
    @Field(key: "root_hash")
    var rootHash: String
    
    init() {}
    
    init(id: Int? = nil, shardingID: Int, rootHash: String) {
        self.id = id
        self.shardingID = shardingID
        self.rootHash = rootHash
    }
}

func routes(_ app: Application)
        // Create MerkleTree
        app.post("merkletrees") { req -> EventLoopFuture<MerkleTree> in
        let merkleTree = try req.content.decode(MerkleTree.self)
        
        // Get the necessary tree hashes from the database or other source
        let treeHashes: [String] = [
            "tree_hash_1",
            "tree_hash_2",
            // Include more tree hashes as needed
        ]
        
        // Generate the Merkle root hash
        let merkleRootHash = generateMerkleRootHash(treeHashes)
        
        // Set the generated Merkle root hash on the MerkleTree model
        merkleTree.rootHash = merkleRootHash
        
        return merkleTree.save(on: req.db).map { merkleTree }
    }
    
    // Read all MerkleTrees
    app.get("merkletrees") { req -> EventLoopFuture<[MerkleTree]> in
        return MerkleTree.query(on: req.db).all()
    }
    
    // Read MerkleTree by ID
    app.get("merkletrees", ":merkleTreeID") { req -> EventLoopFuture<MerkleTree> in
        guard let merkleTreeID = req.parameters.get("merkleTreeID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTree.find(merkleTreeID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update MerkleTree
    app.put("merkletrees", ":merkleTreeID") { req -> EventLoopFuture<MerkleTree> in
        guard let merkleTreeID = req.parameters.get("merkleTreeID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedMerkleTree = try req.content.decode(MerkleTree.self)
        return MerkleTree.find(merkleTreeID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTree in
                merkleTree.shardingID = updatedMerkleTree.shardingID
                merkleTree.rootHash = updatedMerkleTree.rootHash
                return merkleTree.save(on: req.db).map { merkleTree }
            }
    }
    
    // Delete MerkleTree
    app.delete("merkletrees", ":merkleTreeID") { req -> EventLoopFuture<HTTPStatus> in
        guard let merkleTreeID = req.parameters.get("merkleTreeID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTree.find(merkleTreeID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTree in
                return merkleTree.delete(on: req.db).transform(to: .noContent)
            }
    }

  final class MerkleTreeHash: Model, Content {
    static let schema = "MerkleTreeHash"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "merkle_tree_id")
    var merkleTreeID: Int
    
    @Field(key: "index_in_tree")
    var indexInTree: Int
    
    @Field(key: "hash")
    var hash: String
    
    init() {}
    
    init(id: Int? = nil, merkleTreeID: Int, indexInTree: Int, hash: String) {
        self.id = id
        self.merkleTreeID = merkleTreeID
        self.indexInTree = indexInTree
        self.hash = hash
    }
}

func routes(_ app: Application) throws {
    // Create MerkleTreeHash
    app.post("merkletreehashes") { req -> EventLoopFuture<MerkleTreeHash> in
        let merkleTreeHash = try req.content.decode(MerkleTreeHash.self)
        return merkleTreeHash.save(on: req.db).map { merkleTreeHash }
    }
    
    // Read all MerkleTreeHashes
    app.get("merkletreehashes") { req -> EventLoopFuture<[MerkleTreeHash]> in
        return MerkleTreeHash.query(on: req.db).all()
    }
    
    // Read MerkleTreeHash by ID
    app.get("merkletreehashes", ":merkleTreeHashID") { req -> EventLoopFuture<MerkleTreeHash> in
        guard let merkleTreeHashID = req.parameters.get("merkleTreeHashID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeHash.find(merkleTreeHashID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update MerkleTreeHash
    app.put("merkletreehashes", ":merkleTreeHashID") { req -> EventLoopFuture<MerkleTreeHash> in
        guard let merkleTreeHashID = req.parameters.get("merkleTreeHashID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedMerkleTreeHash = try req.content.decode(MerkleTreeHash.self)
        return MerkleTreeHash.find(merkleTreeHashID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeHash in
                merkleTreeHash.merkleTreeID = updatedMerkleTreeHash.merkleTreeID
                merkleTreeHash.indexInTree = updatedMerkleTreeHash.indexInTree
                merkleTreeHash.hash = updatedMerkleTreeHash.hash
                return merkleTreeHash.save(on: req.db).map { merkleTreeHash }
            }
    }
    
    // Delete MerkleTreeHash
    app.delete("merkletreehashes", ":merkleTreeHashID") { req -> EventLoopFuture<HTTPStatus> in
        guard let merkleTreeHashID = req.parameters.get("merkleTreeHashID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeHash.find(merkleTreeHashID, on: req.db)
            . unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeHash in
                return merkleTreeHash.delete(on: req.db).transform(to: .noContent)
            }
    }
 
    final class MerkleTreeProofItem: Model, Content {
    static let schema = "MerkleTreeProofItem"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "merkle_tree_proof_id")
    var merkleTreeProofID: Int
    
    @Field(key: "index_in_proof")
    var indexInProof: Int
    
    @Field(key: "is_right")
    var isRight: Bool
    
    @Field(key: "hash")
    var hash: String
    
    init() {}
    
    init(id: Int? = nil, merkleTreeProofID: Int, indexInProof: Int, isRight: Bool, hash: String) {
        self.id = id
        self.merkleTreeProofID = merkleTreeProofID
        self.indexInProof = indexInProof
        self.isRight = isRight
        self.hash = hash
    }
}

func routes(_ app: Application) throws {
    // Create MerkleTreeProofItem
    app.post("merkletreeproofitems") { req -> EventLoopFuture<MerkleTreeProofItem> in
        let merkleTreeProofItem = try req.content.decode(MerkleTreeProofItem.self)
        return merkleTreeProofItem.save(on: req.db).map { merkleTreeProofItem }
    }
    
    // Read all MerkleTreeProofItems
    app.get("merkletreeproofitems") { req -> EventLoopFuture<[MerkleTreeProofItem]> in
        return MerkleTreeProofItem.query(on: req.db).all()
    }
    
    // Read MerkleTreeProofItem by ID
    app.get("merkletreeproofitems", ":merkleTreeProofItemID") { req -> EventLoopFuture<MerkleTreeProofItem> in
        guard let merkleTreeProofItemID = req.parameters.get("merkleTreeProofItemID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeProofItem.find(merkleTreeProofItemID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update MerkleTreeProofItem
    app.put("merkletreeproofitems", ":merkleTreeProofItemID") { req -> EventLoopFuture<MerkleTreeProofItem> in
        guard let merkleTreeProofItemID = req.parameters.get("merkleTreeProofItemID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedMerkleTreeProofItem = try req.content.decode(MerkleTreeProofItem.self)
        return MerkleTreeProofItem.find(merkleTreeProofItemID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeProofItem in
                merkleTreeProofItem.merkleTreeProofID = updatedMerkleTreeProofItem.merkleTreeProofID
                merkleTreeProofItem.indexInProof = updatedMerkleTreeProofItem.indexInProof
                merkleTreeProofItem.isRight = updatedMerkleTreeProofItem.isRight
                merkleTreeProofItem.hash = updatedMerkleTreeProofItem.hash
                return merkleTreeProofItem.save(on: req.db).map { merkleTreeProofItem }
            }
    }
    
      // Delete MerkleTreeProofItem
    app.delete("merkletreeproofitems", ":merkleTreeProofItemID") { req -> EventLoopFuture<HTTPStatus> in
        guard let merkleTreeProofItemID = req.parameters.get("merkleTreeProofItemID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeProofItem.find(merkleTreeProofItemID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeProofItem in
                return merkleTreeProofItem.delete(on: req.db).transform(to: .noContent)
            }
    }

  final class MerkleTreeProof: Model, Content {
    static let schema = "MerkleTreeProof"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "merkle_tree_id")
    var merkleTreeID: Int
    
    @Field(key: "merkle_tree_hash_id")
    var merkleTreeHashID: Int
    
    @Field(key: "merkle_tree_proof_item_id")
    var merkleTreeProofItemID: Int
    
    init() {}
    
    init(id: Int? = nil, merkleTreeID: Int, merkleTreeHashID: Int, merkleTreeProofItemID: Int) {
        self.id = id
        self.merkleTreeID = merkleTreeID
        self.merkleTreeHashID = merkleTreeHashID
        self.merkleTreeProofItemID = merkleTreeProofItemID
    }
}

func routes(_ app: Application) throws {
    // Create MerkleTreeProof
    app.post("merkletreeproofs") { req -> EventLoopFuture<MerkleTreeProof> in
        let merkleTreeProof = try req.content.decode(MerkleTreeProof.self)
        return merkleTreeProof.save(on: req.db).map { merkleTreeProof }
    }
    
    // Read all MerkleTreeProofs
    app.get("merkletreeproofs") { req -> EventLoopFuture<[MerkleTreeProof]> in
        return MerkleTreeProof.query(on: req.db).all()
    }
    
    // Read MerkleTreeProof by ID
    app.get("merkletreeproofs", ":merkleTreeProofID") { req -> EventLoopFuture<MerkleTreeProof> in
        guard let merkleTreeProofID = req.parameters.get("merkleTreeProofID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeProof.find(merkleTreeProofID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update MerkleTreeProof
    app.put("merkletreeproofs", ":merkleTreeProofID") { req -> EventLoopFuture<MerkleTreeProof> in
        guard let merkleTreeProofID = req.parameters.get("merkleTreeProofID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedMerkleTreeProof = try req.content.decode(MerkleTreeProof.self)
        return MerkleTreeProof.find(merkleTreeProofID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeProof in
                merkleTreeProof.merkleTreeID = updatedMerkleTreeProof.merkleTreeID
                merkleTreeProof.merkleTreeHashID = updatedMerkleTreeProof.merkleTreeHashID
                merkleTreeProof.merkleTreeProofItemID = updatedMerkleTreeProof.merkleTreeProofItemID
                return merkleTreeProof.save(on: req.db).map { merkleTreeProof }
            }
    }
    
    // Delete MerkleTreeProof
    app.delete("merkletreeproofs", ":merkleTreeProofID") { req -> EventLoopFuture<HTTPStatus> in
        guard let merkleTreeProofID = req.parameters.get("merkleTreeProofID ", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeProof.find(merkleTreeProofID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeProof in
                return merkleTreeProof.delete(on: req.db)
                    .transform(to: .noContent)
            }
    }

final class Balance: Model, Content {
    static let schema = "Balance"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "user_id")
    var userID: Int
    
    @Field(key: "token_id")
    var tokenID: Int
    
    @Field(key: "balance")
    var balance: Decimal
    
    @Field(key: "merkle_tree_id")
    var merkleTreeID: Int
    
    init() {}
    
    init(id: Int? = nil, userID: Int, tokenID: Int, balance: Decimal, merkleTreeID: Int) {
        self.id = id
        self.userID = userID
        self.tokenID = tokenID
        self.balance = balance
        self.merkleTreeID = merkleTreeID
    }
}

func routes(_ app: Application) throws {
    // Create Balance
    app.post("balances") { req -> EventLoopFuture<Balance> in
        let balance = try req.content.decode(Balance.self)
        return balance.save(on: req.db).map { balance }
    }
    
    // Read all Balances
    app.get("balances") { req -> EventLoopFuture<[Balance]> in
        return Balance.query(on: req.db).all()
    }
    
    // Read Balance by ID
    app.get("balances", ":balanceID") { req -> EventLoopFuture<Balance> in
        guard let balanceID = req.parameters.get("balanceID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Balance.find(balanceID, on: req.db).unwrap(or: Abort(.notFound))
    }
    
    // Update Balance
    app.put("balances", ":balanceID") { req -> EventLoopFuture<Balance> in
        guard let balanceID = req.parameters.get("balanceID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedBalance = try req.content.decode(Balance.self)
        return Balance.find(balanceID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { balance in
                balance.userID = updatedBalance.userID
                balance.tokenID = updatedBalance.tokenID
                balance.balance = updatedBalance.balance
                balance.merkleTreeID = updatedBalance.merkleTreeID
                return balance.save(on: req.db).map { balance }
            }
    }
    
    // Delete Balance
    app.delete("balances", ":balanceID") { req -> EventLoopFuture<HTTPStatus> in
        guard let balanceID = req.parameters.get("balanceID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Balance.find(balanceID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { balance in
                return balance.delete(on: req.db)
                    .transform(to: .noContent)
            }
    }
}

// Register your routes...
try app.routes.register(collection: routes)

 
