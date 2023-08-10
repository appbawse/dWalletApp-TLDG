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

func userRoutes(_ app: Application) throws {
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
}

final class Address: Model, Content {
    static let schema = "Address"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "street")
    var street: String
    
    @Field(key: "city")
    var city: String
    
    @Field(key: "state")
    var state: String
    
    @Field(key: "zip")
    var zip: String
    
    @Parent(key: "user_id")
    var user: User
    
    init() {}
    
    init(id: Int? = nil, street: String, city: String, state: String, zip: String, userID: User.IDValue) {
        self.id = id
        self.street = street
        self.city = city
        self.state = state
        self.zip = zip
        self.$user.id = userID
    }
}

func addressRoutes(_ app: Application) throws {
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
                address.street = updatedAddress.street
                address.city = updatedAddress.city
                address.state = updatedAddress.state
                address.zip = updatedAddress.zip
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
}

final class Block: Model, Content {
    static let schema = "Block"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "name")
    var name: String
    
    @Field(key: "size")
    var size: Int
    
    @Children(for: \.$block)
    var transactions: [Transaction]
    
    init() {}
    
    init(id: Int? = nil, name: String, size: Int) {
        self.id = id
        self.name = name
        self.size = size
    }
}

func blockRoutes(_ app: Application) throws {
    // Create Block
    app.post("blocks") { req -> EventLoopFuture<Block> in
        let block = try req.content.decode(Block.self)
        return block.save(on: req.db).map { block }
    }
    
    // Read all Blocks
    app.get("blocks") { req -> EventLoopFuture<[Block]> in
        return Block.query(on: req.db).with(\.$transactions).all()
    }
    
    // Read Block by ID
    app.get("blocks", ":blockID") { req -> EventLoopFuture<Block> in
        guard let blockID = req.parameters.get("blockID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Block.find(blockID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { block in
                block.$transactions.load(on: req.db).map { block }
            }
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
                block.name = updatedBlock.name
                block.size = updatedBlock.size
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
}

final class MerkleTree: Model, Content {
    static let schema = "MerkleTree"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "rootHash")
    var rootHash: String
    
    @Children(for: \.$merkleTree)
    var transactions: [Transaction]
    
    init() {}
    
    init(id: Int? = nil, rootHash: String) {
        self.id = id
        self.rootHash = rootHash
    }
}

func merkleTreeRoutes(_ app: Application) throws {
    // Create MerkleTree
    app.post("merkleTrees") { req -> EventLoopFuture<MerkleTree> in
        let merkleTree = try req.content.decode(MerkleTree.self)
        return merkleTree.save(on: req.db).map { merkleTree }
    }
    
    // Read all MerkleTrees
    app.get("merkleTrees") { req -> EventLoopFuture<[MerkleTree]> in
        return MerkleTree.query(on: req.db).with(\.$transactions).all()
    }
    
    // Read MerkleTree by ID
    app.get("merkleTrees", ":merkleTreeID") { req -> EventLoopFuture<MerkleTree> in
        guard let merkleTreeID = req.parameters.get("merkleTreeID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTree.find(merkleTreeID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTree in
                merkleTree.$transactions.load(on: req.db).map { merkleTree }
            }
    }
    
    // Update MerkleTree
    app.put("merkleTrees", ":merkleTreeID") { req -> EventLoopFuture<MerkleTree> in
        guard let merkleTreeID = req.parameters.get("merkleTreeID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedMerkleTree = try req.content.decode(MerkleTree.self)
        return MerkleTree.find(merkleTreeID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTree in
                merkleTree.rootHash = updatedMerkleTree.rootHash
                return merkleTree.save(on: req.db).map { merkleTree }
            }
    }
    
    // Delete MerkleTree
    app.delete("merkleTrees", ":merkleTreeID") { req -> EventLoopFuture<HTTPStatus> in
        guard let merkleTreeID = req.parameters.get("merkleTreeID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTree.find(merkleTreeID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTree in
                return merkleTree.delete(on: req.db).transform(to: .noContent)
            }
    }
}

final class MerkleTreeHash: Model, Content {
    static let schema = "MerkleTreeHash"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "hashValue")
    var hashValue: String
    
    @Parent(key: "merkleTreeID")
    var merkleTree: MerkleTree
    
    init() {}
    
    init(id: Int? = nil, hashValue: String, merkleTreeID: Int) {
        self.id = id
        self.hashValue = hashValue
        self.$merkleTree.id = merkleTreeID
    }
}

func merkleTreeHashRoutes(_ app: Application) throws {
    // Create MerkleTreeHash
    app.post("merkleTreeHashes") { req -> EventLoopFuture<MerkleTreeHash> in
        let merkleTreeHash = try req.content.decode(MerkleTreeHash.self)
        return merkleTreeHash.save(on: req.db).map { merkleTreeHash }
    }
    
    // Read all MerkleTreeHashes for a specific MerkleTree
    app.get("merkleTrees", ":merkleTreeID", "merkleTreeHashes") { req -> EventLoopFuture<[MerkleTreeHash]> in
        guard let merkleTreeID = req.parameters.get("merkleTreeID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTree.find(merkleTreeID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTree in
                merkleTree.$hashes.query(on: req.db).all()
            }
    }
    
    // Update MerkleTreeHash
    app.put("merkleTreeHashes", ":merkleTreeHashID") { req -> EventLoopFuture<MerkleTreeHash> in
        guard let merkleTreeHashID = req.parameters.get("merkleTreeHashID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedMerkleTreeHash = try req.content.decode(MerkleTreeHash.self)
        return MerkleTreeHash.find(merkleTreeHashID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeHash in
                merkleTreeHash.hashValue = updatedMerkleTreeHash.hashValue
                return merkleTreeHash.save(on: req.db).map { merkleTreeHash }
            }
    }
    
    // Delete MerkleTreeHash
    app.delete("merkleTreeHashes", ":merkleTreeHashID") { req -> EventLoopFuture<HTTPStatus> in
        guard let merkleTreeHashID = req.parameters.get("merkleTreeHashID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeHash.find(merkleTreeHashID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeHash in
                return merkleTreeHash.delete(on: req.db).transform(to: .noContent)
            }
    }
}

final class MerkleTreeProofItem: Model, Content {
    static let schema = "MerkleTreeProofItem"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "position")
    var position: Int
    
    @Field(key: "hashValue")
    var hashValue: String
    
    @Parent(key: "merkleTreeID")
    var merkleTree: MerkleTree
    
    init() {}
    
    init(id: Int? = nil, position: Int, hashValue: String, merkleTreeID: Int) {
        self.id = id
        self.position = position
        self.hashValue = hashValue
        self.$merkleTree.id = merkleTreeID
    }
}

func merkleTreeProofItemRoutes(_ app: Application) throws {
    // Create MerkleTreeProofItem
    app.post("merkleTreeProofItems") { req -> EventLoopFuture<MerkleTreeProofItem> in
        let merkleTreeProofItem = try req.content.decode(MerkleTreeProofItem.self)
        return merkleTreeProofItem.save(on: req.db).map { merkleTreeProofItem }
    }
    
    // Read all MerkleTreeProofItems for a specific MerkleTree
    app.get("merkleTrees", ":merkleTreeID", "merkleTreeProofItems") { req -> EventLoopFuture<[MerkleTreeProofItem]> in
        guard let merkleTreeID = req.parameters.get("merkleTreeID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTree.find(merkleTreeID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTree in
                merkleTree.$proof.query(on: req.db).all()
            }
    }
    
    // Update MerkleTreeProofItem
    app.put("merkleTreeProofItems", ":merkleTreeProofItemID") { req -> EventLoopFuture<MerkleTreeProofItem> in
        guard let merkleTreeProofItemID = req.parameters.get("merkleTreeProofItemID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedMerkleTreeProofItem = try req.content.decode(MerkleTreeProofItem.self)
        return MerkleTreeProofItem.find(merkleTreeProofItemID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeProofItem in
                merkleTreeProofItem.position = updatedMerkleTreeProofItem.position
                merkleTreeProofItem.hashValue = updatedMerkleTreeProofItem.hashValue
                return merkleTreeProofItem.save(on: req.db).map { merkleTreeProofItem }
            }
    }
    
    // Delete MerkleTreeProofItem
    app.delete("merkleTreeProofItems", ":merkleTreeProofItemID") { req -> EventLoopFuture<HTTPStatus> in
        guard let merkleTreeProofItemID = req.parameters.get("merkleTreeProofItemID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeProofItem.find(merkleTreeProofItemID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeProofItem in
                return merkleTreeProofItem.delete(on: req.db).transform(to: .noContent)
            }
    }
}

final class MerkleTreeProof: Model, Content {
    static let schema = "MerkleTreeProof"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "proofHash")
    var proofHash: String
    
    @Children(for: \.$merkleTreeProof)
    var proofItems: [MerkleTreeProofItem]
    
    init() {}
    
    init(id: Int? = nil, proofHash: String) {
        self.id = id
        self.proofHash = proofHash
    }
}

func merkleTreeProofRoutes(_ app: Application) throws {
    // Create MerkleTreeProof
    app.post("merkleTreeProofs") { req -> EventLoopFuture<MerkleTreeProof> in
        let merkleTreeProof = try req.content.decode(MerkleTreeProof.self)
        return merkleTreeProof.save(on: req.db).map { merkleTreeProof }
    }
    
    // Read MerkleTreeProof by ID
    app.get("merkleTreeProofs", ":merkleTreeProofID") { req -> EventLoopFuture<MerkleTreeProof> in
        guard let merkleTreeProofID = req.parameters.get("merkleTreeProofID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeProof.find(merkleTreeProofID, on: req.db)
            .unwrap(or: Abort(.notFound))
    }
    
    // Update MerkleTreeProof
    app.put("merkleTreeProofs", ":merkleTreeProofID") { req -> EventLoopFuture<MerkleTreeProof> in
        guard let merkleTreeProofID = req.parameters.get("merkleTreeProofID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        let updatedMerkleTreeProof = try req.content.decode(MerkleTreeProof.self)
        return MerkleTreeProof.find(merkleTreeProofID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeProof in
                merkleTreeProof.proofHash = updatedMerkleTreeProof.proofHash
                return merkleTreeProof.save(on: req.db).map { merkleTreeProof }
            }
    }
    
    // Delete MerkleTreeProof
    app.delete("merkleTreeProofs", ":merkleTreeProofID") { req -> EventLoopFuture<HTTPStatus> in
        guard let merkleTreeProofID = req.parameters.get("merkleTreeProofID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return MerkleTreeProof.find(merkleTreeProofID, on: req.db)
            .unwrap(or: Abort(.notFound))
            .flatMap { merkleTreeProof in
                return merkleTreeProof.delete(on: req.db).transform(to: .noContent)
            }
    }
}

final class Balance: Model, Content {
    static let schema = "Balance"
    
    @ID(custom: "id")
    var id: Int?
    
    @Field(key: "amount")
    var amount: Double
    
    @Parent(key: "userID")
    var user: User
    
    init() {}
    
    init(id: Int? = nil, amount: Double, userID: User.IDValue) {
        self.id = id
        self.amount = amount
        self.$user.id = userID
    }
}

func balanceRoutes(_ app: Application) throws {
    // Create Balance
    app.post("balances") { req -> EventLoopFuture<Balance> in
        let balance = try req.content.decode(Balance.self)
        return balance.save(on: req.db).map { balance }
    }
    
    // Read Balance by ID
    app.get("balances", ":balanceID") { req -> EventLoopFuture<Balance> in
        guard let balanceID = req.parameters.get("balanceID", as: Int.self) else {
            throw Abort(.badRequest)
        }
        return Balance.find(balanceID, on: req.db)
            .unwrap(or: Abort(.notFound))
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
                balance.amount = updatedBalance.amount
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
                return balance.delete(on: req.db).transform(to: .noContent)
            }
    }
}

// Register routes

func routes(_ app: Application) throws {
    try userRoutes(app)
    try addressRoutes(app)
    try transactionRoutes(app)
    try blockRoutes(app)
    try blockTransactionRoutes(app)
    try merkleTreeRoutes(app)
    try merkleTreeHashRoutes(app)
    try merkleTreeProofItemRoutes(app)
    try merkleTreeProofRoutes(app)
    try balanceRoutes(app)
}

// Register your routes...
try app.routes.register(collection: routes)





