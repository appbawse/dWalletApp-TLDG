import Foundation
import SwiftRedis
import UIKit
import MultipeerConnectivity
import CryptoKit
import CryptoKitRSA
import SwiftJWT
import MerkleTools
import SwiftMySQL
import MySQLDriver

class ViewController: UIViewController, MCSessionDelegate, MCNearbyServiceBrowserDelegate, MCNearbyServiceAdvertiserDelegate {
    // Declare and initialize the mysqlConnection variable
    var mysqlConnection = MySQL.Connection()

    // Connect to the MySQL server
    let connected = mysqlConnection.connect(host: "localhost", user: "your_username", password: "your_password", database: "your_database_name")

    deinit {
        // Close the MySQL connection when the view controller is deallocated
        mysqlConnection.close()
    }

    // Connect these outlets to the corresponding UI elements in your storyboard
    @IBOutlet private weak var fromAddressIdTextField: UITextField!
    @IBOutlet private weak var toAddressIdTextField: UITextField!
    @IBOutlet private weak var balanceTextField: UITextField!
    @IBOutlet private weak var createAndSaveTransactionButton: UIButton!
    
    struct User {
    let id: Int
    let username: String
    let passwordHash: String
    let salt: String
    let publicKey: String
}

struct Address {
    let id: Int
    let userId: Int
    let address: String
}

struct Transaction {
    let id: Int
    let fromAddressId: Int
    let toAddressId: Int
    let balance: Decimal
    let timestamp: Date
    let hash: String
}

struct Block {
    let id: Int
    let version: Int
    let timestamp: Date
    let previousHash: String
    let merkleRoot: String
    let hash: String
}

struct BlockTransaction {
    let id: Int
    let blockId: Int
    let transactionId: Int
}

struct MerkleTree {
    let id: Int
    let shardingId: Int
    let rootHash: String
}

struct MerkleTreeHash {
    let id: Int
    let merkleTreeId: Int
    let indexInTree: Int
    let hash: String
}

struct MerkleTreeProofItem {
    let id: Int
    let merkleTreeProofId: Int
    let indexInProof: Int
    let isRight: Bool
    let hash: String
}

struct MerkleTreeProof {
    let id: Int
    let merkleTreeId: Int
    let merkleTreeHashId: Int
    let merkleTreeProofItemId: Int
}

struct Balance {
    let id: Int
    let userId: Int
    let tokenId: Int
    let balance: Decimal
    let merkleTreeId: Int
}

    struct MerkleTreeData {
        let rootHash: String
        let treeHashes: [String]
    }
    
func generateRandomJWTSecret() -> String {
    // Generate a random 256-bit key
    let key = SymmetricKey(size: .bits256)
    
    // Get the raw data representation of the key
    let keyData = key.withUnsafeBytes { Data($0) }
    
    // Encode the key data as a base64 string
    let jwtSecret = keyData.base64EncodedString()
    
    return jwtSecret
}

// Other properties
var peerID: MCPeerID!
var session: MCSession!
var browser: MCNearbyServiceBrowser!
var advertiser: MCNearbyServiceAdvertiser!
let privateKey = P256.KeyAgreement.PrivateKey()
let publicKey = privateKey.publicKey
let jwtSecret = generateRandomJWTSecret() // Use the function to generate a random JWT secret
let merkleTools = MerkleTools()

    override func viewDidLoad() {
        super.viewDidLoad()

        // Initialize peerID and session
        peerID = MCPeerID(displayName: UIDevice.current.name)
        session = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
        session.delegate = self

        // Initialize browser and advertiser
        browser = MCNearbyServiceBrowser(peer: peerID, serviceType: "my-service")
        browser.delegate = self
        advertiser = MCNearbyServiceAdvertiser(peer: peerID, discoveryInfo: nil, serviceType: "my-service")
        advertiser.delegate = self

        // Start browsing and advertising for peers
        browser.startBrowsingForPeers()
        advertiser.startAdvertisingPeer()

        connectToRedisAndGenerateProofs()
    }

// Function to connect to Redis, retrieve Merkle tree data, and generate proofs
func connectToRedisAndGenerateProofs() {
    // Create Redis connection
    let redis = RedisConnection.make()

    redis.connect(host: "localhost", port: 6379) { redisError in
        guard redisError == nil else {
            print("Error connecting to Redis: \(redisError!)")
            return
        }

        // Retrieve Merkle tree data from Redis
        redis.get("merkle_tree_data") { redisResponse, redisError in
            guard redisError == nil, let redisMerkleTree = redisResponse?.string else {
                print("Error retrieving Merkle tree data from Redis: \(redisError!)")
                return
            }

            // MySQL connection details for two databases
            let mysqlConfig1 = MySQLDatabaseConfig(hostname: "localhost", username: "user1", password: "password1", database: "db1", privateKey: "privateKey1")
            let mysqlConfig2 = MySQLDatabaseConfig(hostname: "localhost", username: "user2", password: "password2", database: "db2", privateKey: "privateKey2")

            // Create MySQL connections
            let mysql1 = MySQLConnectionSource(config: mysqlConfig1)
            let mysql2 = MySQLConnectionSource(config: mysqlConfig2)

            // Retrieve Merkle tree data from MySQL databases
            let latestMerkleTreeQuery = "SELECT tree_data FROM merkle_tree ORDER BY timestamp DESC LIMIT 1"
            let mysqlConnections = [mysql1, mysql2]

            for mysqlConnection in mysqlConnections {
                mysqlConnection.withMySQLConnection { connection, error in
                    guard error == nil else {
                        print("Error connecting to MySQL: \(error!)")
                        return
                    }

                    do {
                        let mysqlResult = try connection.query(latestMerkleTreeQuery)
                        if let mysqlMerkleTree = mysqlResult.first?["tree_data"] as? String {
                            // Compare and process Merkle tree data
                            compareAndProcessMerkleTree(redisMerkleTree, mysqlMerkleTree)
                        } else {
                            print("No Merkle tree data found in MySQL")
                        }
                    } catch {
                        print("Error retrieving Merkle tree data from MySQL: \(error)")
                    }
                }
            }
        }
    }
}

// Compare and process Merkle tree data and generate proofs
func compareAndProcessMerkleTree(_ redisMerkleTree: String, _ mysqlMerkleTree: String) {
    // Parse and process the Merkle tree data from Redis and MySQL
    let redisMerkleRoot = calculateMerkleRoot(from: redisMerkleTree)
    let mysqlMerkleRoot = calculateMerkleRoot(from: mysqlMerkleTree)

    if redisMerkleRoot == mysqlMerkleRoot {
        print("Merkle roots match. Data integrity is preserved.")
        // Additional processing or actions when the Merkle roots match
    } else {
        print("Merkle roots do not match. Data integrity may be compromised.")
        // Additional processing or actions when the Merkle roots do not match
    }

    // Generate Merkle tree proofs for the specified items
    generateProofExample()
}

// Calculate the Merkle root hash from a given Merkle tree data
func calculateMerkleRoot(from merkleTreeData: String) -> String {
    // Split the Merkle tree data into individual leaves or nodes
    let nodes = merkleTreeData.components(separatedBy: ",")

    // Create an array to store hashed values
    var hashedValues: [Data] = nodes.map { Data($0.utf8) }

    // Iterate and hash pairs of values until a single root hash remains
    while hashedValues.count > 1 {
        var nextLevel: [Data] = []

        for i in stride(from: 0, to: hashedValues.count, by: 2) {
            var combinedData = hashedValues[i]
            if i + 1 < hashedValues.count {
                combinedData.append(hashedValues[i + 1])
            }
            
            let hash = SHA256.hash(data: combinedData)
            nextLevel.append(Data(hash))
        }

        hashedValues = nextLevel
    }

    // Convert the root hash to a hexadecimal string
    return hashedValues.first?.hexEncodedString() ?? ""
}

// Generate Merkle tree proofs for the specified items
func generateProofExample() {
    // Assuming you have the leaf index for which you want to generate the proof
    let targetLeafIndex = 2  // Replace with the actual leaf index

    // Sample Merkle tree data
    let merkleTreeData = ["leaf1", "leaf2", "leaf3", "leaf4"]
    
    // Calculate the Merkle root hash
    let merkleRoot = calculateMerkleRoot(from: merkleTreeData.joined(separator: ","))

    // Generate the Merkle proof path
    let proofPath = generateProofPath(for: targetLeafIndex, in: merkleTreeData)

    // Verify the proof
    let isProofValid = verifyProof(targetLeafIndex: targetLeafIndex, proofPath: proofPath, rootHash: merkleRoot)
    
    if isProofValid {
        print("Merkle proof is valid for leaf at index \(targetLeafIndex)")
    } else {
        print("Merkle proof is not valid for leaf at index \(targetLeafIndex)")
    }
}

// Generate a Merkle proof path for a specific leaf index
func generateProofPath(for leafIndex: Int, in merkleTreeData: [String]) -> [String] {
    var proofPath: [String] = []
    var currentIndex = leafIndex
    
    while currentIndex > 0 {
        let siblingIndex = (currentIndex % 2 == 0) ? (currentIndex - 1) : (currentIndex + 1)
        let siblingNode = merkleTreeData[siblingIndex]
        proofPath.append(siblingNode)
        
        currentIndex = (currentIndex - 1) / 2
    }
    
    return proofPath
}

// Verify a Merkle proof
func verifyProof(targetLeafIndex: Int, proofPath: [String], rootHash: String) -> Bool {
    var computedHash = Data(proofPath[0].utf8)

    for i in 1..<proofPath.count {
        let siblingData = Data(proofPath[i].utf8)
        if targetLeafIndex % 2 == 0 {
            computedHash = CryptoKit.SHA256.hash(data: computedHash + siblingData)
        } else {
            computedHash = CryptoKit.SHA256.hash(data: siblingData + computedHash)
        }
        targetLeafIndex /= 2
    }

    let computedHashHex = computedHash.map { String(format: "%02hhx", $0) }.joined()
    return computedHashHex == rootHash
}

// Helper extension to convert Data to hexadecimal string
extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

    func createUser(username: String, passwordHash: String, salt: String, publicKey: String, address: String, fromAddressId: Int, toAddressId: Int, balance: Decimal, hash: String, merkleTree: String, treeHashes: [String], indexInProof: Int, isRight: Bool, proofItemHash: String) throws {
    // Create a user
    let userQuery = "INSERT INTO User (username, password_hash, salt, public_key) VALUES ('\(username)', '\(passwordHash)', '\(salt)', '\(publicKey)')"
    guard connection.query(statement: userQuery) else {
        throw connection.errorMessage()
    }

    // Verify the created user entry
    let userQuery = "SELECT * FROM User WHERE user_id = \(userId)"
    guard let userResult = connection.query(statement: userQuery), let userRow = userResult.next() else {
        throw connection.errorMessage()
    }
    let fetchedUsername = userRow["username"] as? String
    let fetchedPasswordHash = userRow["password_hash"] as? String
    let fetchedSalt = userRow["salt"] as? String
    let fetchedPublicKey = userRow["public_key"] as? String

    if fetchedUsername == username && fetchedPasswordHash == passwordHash && fetchedSalt == salt && fetchedPublicKey == publicKey {
        print("User entry verified successfully.")
    } else {
        print("User entry verification failed.")
    }
        
    // Get the user ID of the created user
    let userResult = connection.query(statement: "SELECT LAST_INSERT_ID()")
    guard let userRow = userResult?.next(), let userId = userRow["LAST_INSERT_ID()"] as? Int else {
        throw connection.errorMessage()
    }
    
    // Create an address for the user
    let addressQuery = "INSERT INTO Address (user_id, address) VALUES (\(userId), '\(address)')"
    guard connection.query(statement: addressQuery) else {
        throw connection.errorMessage()
    }
    
    // Create a transaction
    let transactionQuery = """
        INSERT INTO Transaction (from_address_id, to_address_id, balance, timestamp, hash)
        VALUES (\(fromAddressId), \(toAddressId), \(balance), NOW(), '\(hash)')
    """
    guard connection.query(statement: transactionQuery) else {
        throw connection.errorMessage()
    }
    
    // Get the transaction ID of the created transaction
    let transactionResult = connection.query(statement: "SELECT LAST_INSERT_ID()")
    guard let transactionRow = transactionResult?.next(), let transactionId = transactionRow["LAST_INSERT_ID()"] as? Int else {
        throw connection.errorMessage()
    }
    
    // Create a block
    let version = 1 // Replace with the actual version
    let previousHash = "previous_hash" // Replace with the actual previous hash
    let merkleRoot = generateMerkleRootHash(treeHashes) // Generate the Merkle root hash
    let blockQuery = """
        INSERT INTO Block (version, timestamp, previous_hash, merkle_root, hash)
        VALUES (\(version), NOW(), '\(previousHash)', '\(merkleRoot)', '\(merkleTree)')
    """
    guard connection.query(statement: blockQuery) else {
        throw connection.errorMessage()
    }
    
    // Get the block ID of the created block
    let blockResult = connection.query(statement: "SELECT LAST_INSERT_ID()")
    guard let blockRow = blockResult?.next(), let blockId = blockRow["LAST_INSERT_ID()"] as? Int else {
        throw connection.errorMessage()
    }
    
    // Add the transaction to the block
    let blockTransactionQuery = "INSERT INTO BlockTransaction (block_id, transaction_id) VALUES (\(blockId), \(transactionId))"
    guard connection.query(statement: blockTransactionQuery) else {
        throw connection.errorMessage()
    }
    
    // Create a Merkle tree entry
    let shardingId = 1 // Replace with the actual sharding ID
    let merkleTreeQuery = "INSERT INTO MerkleTree (sharding_id, root_hash) VALUES (\(shardingId), '\(merkleTree)')"
    guard connection.query(statement: merkleTreeQuery) else {
        throw connection.errorMessage()
    }
    
    // Get the Merkle tree ID of the created Merkle tree
    let merkleTreeResult = connection.query(statement: "SELECT LAST_INSERT_ID()")
    guard let merkleTreeRow = merkleTreeResult?.next(), let merkleTreeId = merkleTreeRow["LAST_INSERT_ID()"] as? Int else {
        throw connection.errorMessage()
    }
    
    // Create a Merkle tree hash entry
    let indexInTree = 1 // Replace with the actual index in the tree
    let merkleTreeHashQuery = "INSERT INTO MerkleTreeHash (merkle_tree_id, index_in_tree, hash) VALUES (\(merkleTreeId), \(indexInTree), '\(merkleTree)')"
    guard connection.query(statement: merkleTreeHashQuery) else {
        throw connection.errorMessage()
    }
    
    // Get the Merkle tree hash ID of the created Merkle tree hash
    let merkleTreeHashResult = connection.query(statement: "SELECT LAST_INSERT_ID()")
    guard let merkleTreeHashRow = merkleTreeHashResult?.next(), let merkleTreeHashId = merkleTreeHashRow["LAST_INSERT_ID()"] as? Int else {
        throw connection.errorMessage()
    }
    
    // Create a Merkle tree proof item entry
    let isRightValue = isRight ? 1 : 0
    let merkleTreeProofItemQuery = """
        INSERT INTO MerkleTreeProofItem (merkle_tree_proof_id, index_in_proof, is_right, hash)
        VALUES (\(merkleTreeId), \(indexInProof), \(isRightValue), '\(proofItemHash)')
    """
    guard connection.query(statement: merkleTreeProofItemQuery) else {
        throw connection.errorMessage()
    }
    
    // Get the Merkle tree proof item ID of the created Merkle tree proof item
    let merkleTreeProofItemResult = connection.query(statement: "SELECT LAST_INSERT_ID()")
    guard let merkleTreeProofItemRow = merkleTreeProofItemResult?.next(), let merkleTreeProofItemId = merkleTreeProofItemRow["LAST_INSERT_ID()"] as? Int else {
        throw connection.errorMessage()
    }
    
    // Create a Merkle tree proof entry
    let merkleTreeProofQuery = """
        INSERT INTO MerkleTreeProof (merkle_tree_id, merkle_tree_hash_id, merkle_tree_proof_item_id)
        VALUES (\(merkleTreeId), \(merkleTreeHashId), \(merkleTreeProofItemId))
    """
    guard connection.query(statement: merkleTreeProofQuery) else {
        throw connection.errorMessage()
    }
    
    // Create a balance entry
    let tokenId = 1 // Replace with the actual token ID
    let balanceQuery = """
        INSERT INTO Balance (user_id, token_id, balance, merkle_tree_id)
        VALUES (\(userId), \(tokenId), \(balance), \(merkleTreeId))
    """
    guard connection.query(statement: balanceQuery) else {
        throw connection.errorMessage()
    }
    
    // Process the latest Merkle tree data
    processMerkleTree(merkleTree)
}

    func getUserIdByUsername(_ username: String) -> Int? {
    let query = "SELECT user_id FROM User WHERE username = '\(username)'"
    
    guard let result = connection.query(statement: query), let row = result.nextResult(), let userId = row["user_id"] as? Int else {
        return nil
    }
    
    return userId
}

    // Function to get a user by user ID
func getUserById(_ userId: Int) -> User? {
    let query = "SELECT * FROM User WHERE user_id = \(userId)"
    
    guard let result = connection.query(statement: query), let row = result.nextResult(),
          let username = row["username"] as? String,
          let passwordHash = row["password_hash"] as? String,
          let salt = row["salt"] as? String,
          let publicKey = row["public_key"] as? String
    else {
        return nil
    }
    
    return User(id: userId, username: username, passwordHash: passwordHash, salt: salt, publicKey: publicKey)
}

// Function to create a new address and save it to the database
func createAddress(address: Address) {
    do {
        let addressQuery = "INSERT INTO Address (user_id, address) VALUES (\(address.userId), '\(address.address)')"
        guard mysqlConnection.query(statement: addressQuery) else {
            throw mysqlConnection.errorMessage()
        }
        print("Address created and saved to the database.")
        
        // Verify the address entry
        if let addressId = getAddressIdByAddress(address.address, userId: address.userId) {
            let fetchedAddress = getAddressById(addressId)
            if fetchedAddress == address {
                print("Address entry verified successfully.")
            } else {
                print("Address entry verification failed.")
            }
        }
    } catch {
        print("Failed to create the address: \(error)")
    }
}

// Function to get the address ID by address and user ID
func getAddressIdByAddress(_ address: String, userId: Int) -> Int? {
    let query = "SELECT address_id FROM Address WHERE user_id = \(userId) AND address = '\(address)'"
    
    guard let result = mysqlConnection.query(statement: query), let row = result.nextResult(), let addressId = row["address_id"] as? Int else {
        return nil
    }
    
    return addressId
}

// Function to get an address by address ID
func getAddressById(_ addressId: Int) -> Address? {
    let query = "SELECT * FROM Address WHERE address_id = \(addressId)"
    
    guard let result = mysqlConnection.query(statement: query), let row = result.nextResult(),
          let userId = row["user_id"] as? Int,
          let address = row["address"] as? String
    else {
        return nil
    }
    
    return Address(id: addressId, userId: userId, address: address)
}

    func getAddressByUserId(_ userId: Int) -> Address? {
    let query = "SELECT * FROM Address WHERE user_id = \(userId)"
    
    guard let result = mysqlConnection.query(statement: query), let row = result.nextResult(),
          let addressId = row["address_id"] as? Int,
          let address = row["address"] as? String
    else {
        return nil
    }
    
    return Address(id: addressId, userId: userId, address: address)
}

    // Create a transaction
    func createTransaction(fromAddressId: Int, toAddressId: Int, balance: Decimal, hash: String) throws {
        let transactionQuery = """
            INSERT INTO Transaction (from_address_id, to_address_id, balance, timestamp, hash)
            VALUES (\(fromAddressId), \(toAddressId), \(balance), NOW(), '\(hash)')
        """
        guard mysqlConnection.query(statement: transactionQuery) else {
            throw mysqlConnection.errorMessage()
        }
    }
    
    // Function to create a new transaction and save it to the database
func createAndSaveTransaction(fromAddressId: Int, toAddressId: Int, balance: Decimal) {
    // Get the current timestamp
    let timestamp = getCurrentTimestamp()

    func verifyMerkleProof(transactionHash: String, merkleProofData: [[String: String]], merkleRoot: String) -> Bool {
    merkleTools.resetTree()

    // Add the transaction hash as a target for proof verification
    merkleTools.addLeaves([transactionHash])

    // Add the Merkle proof data to the MerkleTools instance
    for proofItem in merkleProofData {
        let hash = proofItem["hash"] ?? ""
        let position = Int(proofItem["position"] ?? "0") ?? 0
        let isRight = proofItem["isRight"] == "1" ? true : false
        merkleTools.addProof(position, hash: hash, isRight: isRight)
    }

    // Verify the proof for the transaction hash against the given Merkle root
    return merkleTools.validate()
}

    func verifyTransactionWithMerkleProof(transactionHashToVerify: String, merkleRoot: String) {
    let merkleProofData = fetchMerkleProofData(transactionHash: transactionHashToVerify)
    let isProofValid = verifyMerkleProof(transactionHash: transactionHashToVerify, merkleProofData: merkleProofData, merkleRoot: merkleRoot)

    if isProofValid {
        print("Merkle proof is valid for the transaction.")
    } else {
        print("Merkle proof is invalid for the transaction.")
    }
}

    let transactionHashToVerify = "transaction_hash_to_verify" // Replace this with the actual transaction hash you want to verify.
    let merkleRoot = "merkle_root" // Replace this with the actual Merkle root.
verifyTransactionWithMerkleProof(transactionHashToVerify: transactionHashToVerify, merkleRoot: merkleRoot)

    // Generate a random nonce
    let nonce = generateNonce()

    // Create the transaction data dictionary
    let transactionData: [String: Any] = [
        "from_address_id": fromAddressId,
        "to_address_id": toAddressId,
        "balance": balance,
        "timestamp": timestamp,
        "nonce": nonce
    ]

    // Generate the transaction hash
    let transactionHash = generateTransactionHash(transactionData: transactionData)

    // Create the Transaction instance
    let transaction = Transaction(
        fromAddressId: fromAddressId,
        toAddressId: toAddressId,
        balance: balance,
        timestamp: timestamp,
        nonce: nonce,
        hash: transactionHash
    )

    // Save the transaction to the database
    do {
        try createTransaction(
            fromAddressId: transaction.fromAddressId,
            toAddressId: transaction.toAddressId,
            balance: transaction.balance,
            hash: transaction.hash
        )
        print("Transaction created and saved to the database.")
    } catch {
        print("Failed to save the transaction to the database: \(error)")
    }
}

    func getTransactionsByUserIDAndAddress(userID: String, address: String) -> [Transaction] {
    var userTransactions: [Transaction] = []

    // Step 1: Get User Information (Addresses)
    let userAddresses = getUserAddresses(userID: userID) // Replace with your logic

    // Step 2: Query Transactions by Address
    for addr in userAddresses {
        if addr == address {
            let transactions = getTransactionsByAddress(address: addr) // Replace with blockchain API
            userTransactions.append(contentsOf: transactions)
        }
    }

    // Step 3: Filter and Step 4: Process Transactions
    let filteredTransactions = userTransactions.filter { transaction in
        return transaction.sender == userID || transaction.recipient == userID
    }

    return filteredTransactions
}

// Function to create a new block and save it to the database
func createBlock(version: Int, previousHash: String, merkleRoot: String, hash: String) throws {
    let query = """
        INSERT INTO Block (version, timestamp, previous_hash, merkle_root, hash)
        VALUES (\(version), NOW(), '\(previousHash)', '\(merkleRoot)', '\(hash)')
    """
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
    }
}

// Function to add a transaction to the block and save it to the database
func addTransactionToBlock(blockId: Int, transactionId: Int) throws {
    let query = "INSERT INTO BlockTransaction (block_id, transaction_id) VALUES (\(blockId), \(transactionId))"
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
    }
}

// Function to create a new block and add a transaction to it
func createBlockAndAddTransaction(block: Block, blockTransaction: BlockTransaction) {
    do {
        try createBlock(
            version: block.version,
            previousHash: block.previousHash,
            merkleRoot: block.merkleRoot,
            hash: block.hash
        )
        print("Block created and saved to the database.")

        try addTransactionToBlock(
            blockId: blockTransaction.blockId,
            transactionId: blockTransaction.transactionId
        )
        print("Transaction added to the block.")
    } catch {
        print("Error: \(error)")
    }
}
    
func createMerkleTree(shardingId: Int, rootHash: String, treeHashes: [String]) throws -> String {
    // Insert the root hash and sharding ID into the database
    let query = "INSERT INTO MerkleTree (sharding_id, root_hash) VALUES (\(shardingId), '\(rootHash)')"
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
    }

    // Now, create the Merkle tree using the provided tree hashes
    // Create MerkleTools instance
    let merkleTools = MerkleTools()

    // Add the tree hashes as leaf nodes
    for hash in treeHashes {
        merkleTools.addLeaf(hash.data(using: .utf8)!)
    }

    // Generate the Merkle root
    let root = merkleTools.makeTree()

    // Return the Merkle root hash
    return root.hash
}

func createMerkleTreeHash(merkleTreeId: Int, indexInTree: Int, hash: String) throws {
    let query = """
        INSERT INTO MerkleTreeHash (merkle_tree_id, index_in_tree, hash)
        VALUES (\(merkleTreeId), \(indexInTree), '\(hash)')
    """
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
    }
}

func createMerkleTreeProofItem(merkleTreeProofId: Int, indexInProof: Int, isRight: Bool, hash: String) throws {
    let isRightValue = isRight ? 1 : 0
    let query = """
        INSERT INTO MerkleTreeProofItem (merkle_tree_proof_id, index_in_proof, is_right, hash)
        VALUES (\(merkleTreeProofId), \(indexInProof), \(isRightValue), '\(hash)')
    """
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
    }
}

func createMerkleTreeProof(merkleTreeId: Int, merkleTreeHashId: Int, merkleTreeProofItemId: Int) throws {
    let query = """
        INSERT INTO MerkleTreeProof (merkle_tree_id, merkle_tree_hash_id, merkle_tree_proof_item_id)
        VALUES (\(merkleTreeId), \(merkleTreeHashId), \(merkleTreeProofItemId))
    """
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
    }
}

func createBalance(userId: Int, tokenId: Int, balance: Decimal, merkleTreeId: Int) throws {
    let query = """
        INSERT INTO Balance (user_id, token_id, balance, merkle_tree_id)
        VALUES (\(userId), \(tokenId), \(balance), \(merkleTreeId))
    """
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
    }
}

func processMerkleTree(jsonString: String) {
    guard let jsonData = jsonString.data(using: .utf8) else {
        print("Error: Invalid JSON data for Merkle tree.")
        return
    }
    
    do {
        let treeData = try JSONDecoder().decode(MerkleTreeData.self, from: jsonData)
        print("Merkle Root Hash: \(treeData.rootHash)")
        print("Tree Hashes: \(treeData.treeHashes)")
        
        // Perform additional processing as needed
    } catch {
        print("Error decoding JSON data for Merkle tree: \(error)")
    }
}

    func processTransaction() throws {
    // Fetch previous data and generate transaction details
    guard let previousData = fetchPreviousData() else {
        print("Failed to fetch previous data.")
        return
    }

    let previousHash = generateTransactionHash(previousData)
    let nonce = generateNonce()

    let transactionData = """
    {
        "from_address_id": 456,
        "to_address_id": 789,
        "previous_hash": "\(previousHash)",
        "balance": 10.0,
        "timestamp": "2023-06-11T12:34:56Z",
        "nonce": \(nonce),
        "hash": "transaction_hash"
    }
    """

    let transactionHash = generateTransactionHash(transactionData)
    let merkleTreeHashes = ["tree_hash_1", "tree_hash_2"] // Add more tree hashes as needed
    let merkleRootHash = generateMerkleRootHash(merkleTreeHashes)

    let payload: [String: Any] = [
        "user_id": 123, // Replace with the actual user ID
        "transaction": [
            "from_address_id": 456, // Replace with the actual from address ID
            "to_address_id": 789, // Replace with the actual to address ID
            "previous_hash": previousHash, // Use the generated previous hash
            "balance": 10.0, // Replace with the actual transaction amount
            "timestamp": "2023-06-11T12:34:56Z", // Replace with the actual transaction timestamp
            "nonce": nonce,
            "hash": transactionHash // Replace with the actual transaction hash
        ],
        "merkle_tree": [
            "root_hash": merkleRootHash,
            "tree_hash_1": "tree_hash_1",
            "tree_hash_2": "tree_hash_2"
            // Include more tree hashes as needed
        ]
    ]

    // Generate the JWT using the payload and secret
    guard let payloadData = try? JSONSerialization.data(withJSONObject: payload, options: []),
          let privateKey = P256.Signing.PrivateKey(),
          let jwtData = try? JWT(payload: payloadData).sign(using: .ecdsa(privateKey: privateKey))
    else {
        print("Error generating JWT.")
        return
    }

    // Encrypt the Merkle root data using RSA
    guard let encryptedData = encrypt(data: merkleRootHash.data(using: .utf8)!) else {
        print("Error encrypting Merkle root.")
        return
    }

    // Encode the encrypted Merkle root data as a base64 string
    let encryptedRootString = encryptedData.base64EncodedString()

    // Send the encrypted JWT and Merkle root to all connected peers
    let message = ["encryptedJWT": jwtData, "encryptedMerkleRoot": encryptedRootString]
    guard let data = try? JSONSerialization.data(withJSONObject: message, options: []),
          let session = createMCSession() // Create the MCSession as needed
    else {
        print("Error preparing data or session.")
        return
    }

    do {
        try session.send(data, toPeers: session.connectedPeers, with: .reliable)
    } catch {
        print("Error sending data: \(error)")
    }

    // Store transaction details and Merkle tree data in the database
    let transaction = Transaction(
        fromAddressID: 456,
        toAddressID: 789,
        previousHash: previousHash,
        balance: 10.0,
        timestamp: "2023-06-11T12:34:56Z",
        nonce: nonce,
        hash: transactionHash
    )

    let merkleTreeData = MerkleTreeData(
        rootHash: merkleRootHash,
        treeHashes: merkleTreeHashes
    )

    try createUser(username: "user123", passwordHash: "hash123", salt: "salt123", publicKey: "public123")
    try createAddress(userId: 123, address: "address123")
    try createTransaction(fromAddressId: transaction.fromAddressID, toAddressId: transaction.toAddressID, balance: transaction.balance, hash: transaction.hash)
    try createBlock(version: 1, previousHash: previousHash, merkleRoot: merkleRootHash, hash: "block_hash")
    try addTransactionToBlock(blockId: 1, transactionId: 1)
    try createMerkleTree(shardingId: 1, rootHash: merkleRootHash)
    try createMerkleTreeHash(merkleTreeId: 1, indexInTree: 1, hash: "tree_hash_1")
    try createMerkleTreeHash(merkleTreeId: 1, indexInTree: 2, hash: "tree_hash_2")

    // Store Merkle tree proof data in the database
    let merkleTreeProofItems = ["proof_item_1", "proof_item_2"] // Add more proof items as needed

    for (index, item) in merkleTreeProofItems.enumerated() {
        try createMerkleTreeProof(merkleTreeId: 1, merkleTreeHashId: index + 1, merkleTreeProofItemId: 1)
    }

    // Store balance data in the database
    let userId = 123 // Replace with the actual user ID
    let tokenId = 456 // Replace with the actual token ID
    let balanceAmount: Decimal = 10.0 // Replace with the actual balance amount
    try createBalance(userId: userId, tokenId: tokenId, balance: balanceAmount, merkleTreeId: 1)
}
    
    // MARK: - MCNearbyServiceBrowserDelegate

    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        // Invite the peer to join the session
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        // Handle lost peer
    }

    // MARK: - MCNearbyServiceAdvertiserDelegate

    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        // Accept the invitation and join the session
        invitationHandler(true, session)
    }

    // MARK: - MCSessionDelegate methods

    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        // Handle session state changes
        switch state {
        case .connected:
            print("Connected to peer: \(peerID.displayName)")
        case .connecting:
            print("Connecting to peer: \(peerID.displayName)")
        case .notConnected:
            print("Disconnected from peer: \(peerID.displayName)")
        @unknown default:
            break
        }
    }

    func session(_ session: MCSession, didReceiveCertificate certificate: [Any]?, fromPeer peerID: MCPeerID, certificateHandler: @escaping (Bool) -> Void) {
        // Handle received certificate
        certificateHandler(true)
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        // Handle received data
        handleReceivedData(data)
    }

    func session(_ session: MCSession, didReceiveStream stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {
        // Handle receiving a stream from other peers
    }

    // MARK: - MCBrowserViewControllerDelegate methods

    func browserViewControllerDidFinish(_ browserViewController: MCBrowserViewController) {
        // Handle user finishing browsing for other peers
        dismiss(animated: true, completion: nil)
    }

    func browserViewControllerWasCancelled(_ browserViewController: MCBrowserViewController) {
        // Handle user cancelling browsing for other peers
        dismiss(animated: true, completion: nil)
    }

    func createMCSession() -> MCSession {
    // Set the display name for the local peer (you can use any string to identify the device)
    let localPeerID = MCPeerID(displayName: UIDevice.current.name)

    // Set the securityIdentity and encryptionPreference for secure communication
    // Note: You need to set the appropriate security identity and encryption preference based on your use case.
    // In this example, we are not using any specific security identity or encryption preference.
    let securityIdentity: [Any]? = nil // Set to the identity of the user or device if needed
    let encryptionPreference: MCEncryptionPreference = .optional

    // Create the MCSession instance
    let session = MCSession(peer: localPeerID, securityIdentity: securityIdentity, encryptionPreference: encryptionPreference)

    // Set the delegate for handling session-related events
    session.delegate = self // Assuming that the current class conforms to the MCSessionDelegate protocol

    return session
}

    // MARK: - IBActions

    @IBAction func startHosting(_ sender: UIButton) {
        // Start advertising to other peers
        advertiser.startAdvertisingPeer()
    }

    @IBAction func joinSession(_ sender: UIButton) {
        // Show browser view controller to allow the user to browse for other peers
        let mcBrowser = MCBrowserViewController(serviceType: "my-service", session: session)
        mcBrowser.delegate = self
        present(mcBrowser, animated: true, completion: nil)
    }

  @IBAction func createAndSaveTransactionButtonTapped(_ sender: UIButton) {
        // Get the input values from the text fields
        guard let fromAddressIdText = fromAddressIdTextField.text,
              let toAddressIdText = toAddressIdTextField.text,
              let balanceText = balanceTextField.text,
              let fromAddressId = Int(fromAddressIdText),
              let toAddressId = Int(toAddressIdText),
              let balance = Decimal(string: balanceText)
        else {
            print("Invalid input values.")
            return
        }

        // Create and save the transaction
        createAndSaveTransaction(fromAddressId: fromAddressId, toAddressId: toAddressId, balance: balance)

        // Optionally, you can display a success message or perform other actions after creating and saving the transaction.
        // For example, show an alert:
        let alertController = UIAlertController(title: "Transaction Saved", message: "Transaction created and saved successfully!", preferredStyle: .alert)
        let okAction = UIAlertAction(title: "OK", style: .default, handler: nil)
        alertController.addAction(okAction)
        present(alertController, animated: true, completion: nil)

        // Clear the text fields after creating and saving the transaction
        fromAddressIdTextField.text = ""
        toAddressIdTextField.text = ""
        balanceTextField.text = ""
    }

    @IBAction func sendBlockMined(_ sender: UIButton) {
        // Generate the encrypted JWT
        guard let encryptedJWT = generateEncryptedJWT() else {
            print("Error generating encrypted JWT")
            return
        }

        // Send the encrypted JWT to all connected peers
        let message = ["encryptedJWT": encryptedJWT]
        guard let data = try? JSONSerialization.data(withJSONObject: message, options: []) else {
            print("Error serializing message")
            return
        }

        do {
            try session.send(data, toPeers: session.connectedPeers, with: .reliable)
        } catch {
            print("Error sending data: \(error)")
        }
    }

    // MARK: - Encryption and Decryption

    func encrypt(data: Data) -> Data? {
        do {
            let ciphertext = try CryptoKitRSA.encrypt(data, with: publicKey)
            return ciphertext
        } catch {
            print("Encryption error: \(error)")
            return nil
        }
    }

    func decrypt(data: Data) -> Data? {
        do {
            let plaintext = try CryptoKitRSA.decrypt(data, with: privateKey)
            return plaintext
        } catch {
            print("Decryption error: \(error)")
            return nil
        }
    }
    
    // MARK: - JWT Generation

func generateEncryptedJWT() -> String? {
    let payload: [String: Any] = [
           "user_id": 123, // Replace with the actual user ID
            "transaction": [
                "from_address_id": 456, // Replace with the actual from address ID
                "to_address_id": 789, // Replace with the actual to address ID
                "previous_hash": "previous_hash",
                "balance": 10.0, // Replace with the actual transaction amount
                "timestamp": "2023-06-11T12:34:56Z", // Replace with the actual transaction timestamp
                "nonce": 12345,
                "hash": "transaction_hash" // Replace with the actual transaction hash
            ],
            "merkle_tree": [
                "root_hash": "merkle_root_hash", // Replace with the actual merkle root hash
                "tree_hash_1": "tree_hash_1", // Replace with the actual tree hash 1
                "tree_hash_2": "tree_hash_2", // Replace with the actual tree hash 2
                // Include more tree hashes as needed
            ]
    ]

    // Convert the payload to JSON data
    guard let payloadData = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
        return nil
    }

    // Generate the JWT using the payload and secret
    let jwt = JWT(payload: payloadData)
    guard let jwtData = try? jwt.sign(using: .rs256(privateKey: privateKey)) else {
        return nil
    }

    // Create MerkleTools instance
    let merkleTools = MerkleTools()

    // Add the JWT data as a leaf node
    merkleTools.addLeaf(jwtData)

    // Add the tree hashes from the "merkle_tree" section
    if let merkleTree = payload["merkle_tree"] as? [String: String] {
        for (_, value) in merkleTree {
            merkleTools.addLeaf(value.data(using: .utf8)!)
        }
    }

    // Generate the Merkle root
    let root = merkleTools.makeTree()

    // Encrypt the Merkle root data using RSA
    guard let encryptedData = encrypt(data: root.data) else {
        return nil
    }

    // Encode the encrypted Merkle root data as a base64 string and directly return it
    return encryptedData.base64EncodedString()
}

    // Simulate fetching transactions for a specific user
func fetchUserTransactions(forUserID userID: Int) -> [Transaction]? {
    var transactions: [Transaction] = []

    // Replace "your_table_name" and column names accordingly
    let query = "SELECT * FROM Transaction WHERE user_id = \(userID)"

    guard let result = connection.query(statement: query) else {
        return nil
    }

    while let row = result.nextResult() {
        guard let fromAddressId = row["from_address_id"] as? Int,
              let toAddressId = row["to_address_id"] as? Int,
              let balance = row["balance"] as? Decimal,
              let timestamp = row["timestamp"] as? String,
              let hash = row["hash"] as? String
        else {
            continue
        }

        let transaction = Transaction(fromAddressId: fromAddressId, toAddressId: toAddressId, balance: balance, timestamp: timestamp, hash: hash)
        transactions.append(transaction)
    }

    return transactions
}

// Simulate fetching the balance for a specific user
func fetchUserBalance(forUserID userID: Int) -> Decimal? {
    // Replace "your_table_name" and column names accordingly
    let query = "SELECT balance FROM User WHERE user_id = \(userID)"

    guard let result = connection.query(statement: query), let row = result.nextResult() else {
        print("Failed to fetch user balance.")
        return nil
    }

    guard let balance = row["balance"] as? Decimal else {
        print("Balance not found.")
        return nil
    }

    return balance
}

import Foundation
import CryptoKit
import MySQLDriver

struct MyClaims: Codable {
    let sub: String // Subject
    let exp: Int // Expiration time
    let payload: [String: Any] // Payload data
}

    func generateEd25519Signature(header: Data, claims: Data, privateKey: Ed25519.Signing.PrivateKey) throws -> Data {
    let unsignedJWT = "\(header.base64EncodedString()).\(claims.base64EncodedString())"
    guard let unsignedData = unsignedJWT.data(using: .utf8) else {
        throw CryptoError.failedToEncodeData
    }
    
    let signature = try privateKey.signature(for: unsignedData)
    return signature.rawRepresentation
}

    func verifyEd25519Signature(header: Data, claims: Data, signature: Data, publicKey: Ed25519.Signing.PublicKey) -> Bool {
    let unsignedJWT = "\(header.base64EncodedString()).\(claims.base64EncodedString())"
    guard let unsignedData = unsignedJWT.data(using: .utf8) else {
        return false
    }
    
    let derSignature = Ed25519.Signing.ECDSASignature(rawRepresentation: signature)
    return publicKey.isValidSignature(derSignature, for: unsignedData)
}

func generateTransactionHash(transactionData: [String: Any]) -> String {
    // Convert the transactionData dictionary to JSON data
    guard let jsonData = try? JSONSerialization.data(withJSONObject: transactionData, options: []),
          let jsonString = String(data: jsonData, encoding: .utf8)
    else {
        fatalError("Failed to serialize transaction data to JSON.")
    }

    // Calculate the hash of the JSON string using SHA-256
    let hash = SHA256.hash(data: jsonString.data(using: .utf8)!)
    let transactionHash = hash.compactMap { String(format: "%02x", $0) }.joined()
    return transactionHash
}


func generateMerkleRootHash(_ treeHashes: [String]) -> String {
    var concatenatedHashes = treeHashes.joined()
    let hash = SHA256.hash(data: concatenatedHashes.data(using: .utf8)!)
    let merkleRootHash = hash.compactMap { String(format: "%02x", $0) }.joined()
    return merkleRootHash
}

func fetchPreviousData() -> String? {
   let query = "SELECT previous_data FROM your_table_name WHERE transaction_id = 'your_transaction_id'"

    guard let result = connection.query(statement: query), let row = result.nextResult() else {
        print("Failed to fetch the previous data.")
        return nil
    }

    guard let previousData = row[0] else {
        print("Previous data not found.")
        return nil
    }

    return previousData
}

func fetchTransactionsForCurrentBlock(_ blockId: Int) -> [Transaction]? {
    var transactions: [Transaction] = []
    
    let query = "SELECT * FROM Transaction WHERE block_id = \(blockId)"
    
    guard let result = connection.query(statement: query) else {
        return nil
    }
    
    while let row = result.nextResult() {
        guard let fromAddressId = row["from_address_id"] as? Int,
              let toAddressId = row["to_address_id"] as? Int,
              let balance = row["balance"] as? Decimal,
              let timestamp = row["timestamp"] as? String,
              let hash = row["hash"] as? String
        else {
            continue
        }
        
        let transaction = Transaction(fromAddressId: fromAddressId, toAddressId: toAddressId, balance: balance, timestamp: timestamp, hash: hash)
        transactions.append(transaction)
    }
    
    return transactions
}

    func fetchBlockByTransactionID(_ transactionID: String) -> Block? {
    // Step 1: Retrieve Transaction Information
    guard let transaction = getTransactionByID(transactionID) else {
        return nil
    }

    // Step 2: Get Block ID or Hash from Transaction
    let blockID = transaction.blockID // Or use transaction.blockHash

    // Step 3: Fetch Block by ID or Hash
    guard let block = getBlockByID(blockID) else {
        return nil
    }

    return block
}

func generateNonce() -> Int {
    return Int.random(in: 1...100000)
}

func handleReceivedData(_ data: Data) {
    // Decode the received data from JSON format
    guard let message = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
          let encryptedJWTString = message["encryptedJWT"] as? String,
          let encryptedMerkleRootString = message["encryptedMerkleRoot"] as? String
    else {
        print("Invalid data format.")
        return
    }

    // Convert base64 strings back to Data
    guard let encryptedJWTData = Data(base64Encoded: encryptedJWTString),
          let encryptedMerkleRootData = Data(base64Encoded: encryptedMerkleRootString)
    else {
        print("Error decoding base64 data.")
        return
    }

    // Decrypt the encrypted JWT using the private key
    guard let decryptedJWTData = decrypt(data: encryptedJWTData),
          let jwt = String(data: decryptedJWTData, encoding: .utf8)
    else {
        print("Error decrypting JWT.")
        return
    }

    // Parse the decrypted JWT payload
    guard let jwtData = jwt.data(using: .utf8),
          let jwtPayload = try? JSONDecoder().decode(MyClaims.self, from: jwtData)
    else {
        print("Error parsing JWT payload.")
        return
    }

    // Verify the JWT signature using the public key
    let headerData = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9".data(using: .utf8)!
    do {
        if try verifyEd25519Signature(header: headerData, claims: jwtData, signature: jwtPayload.signature, publicKey: publicKey) {
            print("JWT signature verified.")
        } else {
            print("Invalid JWT signature.")
            return
        }
    } catch {
        print("Error verifying JWT signature: \(error)")
        return
    }

    // Decrypt the encrypted Merkle root using the private key
    guard let decryptedMerkleRootData = decrypt(data: encryptedMerkleRootData),
          let merkleRoot = String(data: decryptedMerkleRootData, encoding: .utf8)
    else {
        print("Error decrypting Merkle root.")
        return
    }

    // Process the received Merkle root data
    processMerkleTree(merkleRoot)
}

