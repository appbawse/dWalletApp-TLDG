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
    
    struct Transaction {
        let fromAddressID: Int
        let toAddressID: Int
        let previousHash: String
        let balance: Decimal
        let timestamp: String
        let nonce: Int
        let hash: String
    }

    struct MerkleTreeData {
        let rootHash: String
        let treeHashes: [String]
    }
    
    // Other properties
    var peerID: MCPeerID!
    var session: MCSession!
    var browser: MCNearbyServiceBrowser!
    var advertiser: MCNearbyServiceAdvertiser!
    let privateKey = P256.KeyAgreement.PrivateKey()
    let publicKey = privateKey.publicKey
    let jwtSecret = "your_jwt_secret"
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

        connectToRedis()
    }

    func connectToRedis() {
        let redis = Redis()

        redis.connect(host: "localhost", port: 6379) { (redisError: NSError?) in
            guard redisError == nil else {
                print("Error connecting to Redis: \(redisError!)")
                return
            }

            redis.get("merkle_tree_data") { (redisResponse: RedisResponse?, redisError: NSError?) in
                guard redisError == nil, let redisMerkleTree = redisResponse?.asString() else {
                    print("Error retrieving Merkle tree data from Redis: \(redisError!)")
                    return
                }

                // Retrieve the latest Merkle tree data from MySQL
                let latestMerkleTreeQuery = "SELECT tree_data FROM merkle_tree ORDER BY timestamp DESC LIMIT 1"
                mysqlConnection.query(latestMerkleTreeQuery) { (mysqlResult: MySQLResult?) in
                    guard let mysqlResult = mysqlResult else {
                        print("Error retrieving Merkle tree data from MySQL: \(mysqlConnection.errorCode()) \(mysqlConnection.errorMessage())")
                        return
                    }

                    if let mysqlMerkleTree = mysqlResult.next()?[0]?.asString() {
                        // Compare the Merkle tree data from Redis and MySQL
                        let redisTimestampQuery = "GET merkle_tree_timestamp"
                        let mysqlTimestampQuery = "SELECT timestamp FROM merkle_tree ORDER BY timestamp DESC LIMIT 1"
                        let multi = redis.multi()
                        multi.sendCommand("GET", params: ["merkle_tree_timestamp"])
                        multi.sendCommand("SELECT", params: ["timestamp FROM merkle_tree ORDER BY timestamp DESC LIMIT 1"])

                        multi.exec { (redisResponses: [RedisResponse]?, redisError: NSError?) in
                            guard redisError == nil, let redisResponses = redisResponses else {
                                print("Error retrieving timestamps from Redis: \(redisError!)")
                                return
                            }

                            let redisTimestamp = redisResponses[0].asString()
                            let mysqlTimestamp = redisResponses[1].asString()

                            if let redisTimestamp = redisTimestamp, let mysqlTimestamp = mysqlTimestamp {
                                if let redisTimestampInt = Int(redisTimestamp), let mysqlTimestampInt = Int(mysqlTimestamp) {
                                    if redisTimestampInt >= mysqlTimestampInt {
                                        processMerkleTree(redisMerkleTree)
                                    } else {
                                        processMerkleTree(mysqlMerkleTree)
                                    }
                                }
                            } else if let redisTimestamp = redisTimestamp {
                                processMerkleTree(redisMerkleTree)
                            } else if let mysqlTimestamp = mysqlTimestamp {
                                processMerkleTree(mysqlMerkleTree)
                            } else {
                                print("No Merkle tree data found")
                            }
                        }
                    } else {
                        print("No Merkle tree data found in MySQL")
                    }
                }
            }
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

        // Create an address for the user
    func createAddress(userId: Int, address: String) throws {
        let addressQuery = "INSERT INTO Address (user_id, address) VALUES (\(userId), '\(address)')"
        guard mysqlConnection.query(statement: addressQuery) else {
            throw mysqlConnection.errorMessage()
        }
    }

    func getAddressIdByAddress(_ address: String, userId: Int) -> Int? {
    let query = "SELECT address_id FROM Address WHERE user_id = \(userId) AND address = '\(address)'"
    
    guard let result = connection.query(statement: query), let row = result.nextResult(), let addressId = row["address_id"] as? Int else {
        return nil
    }
    
    return addressId
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
    
    func createBlock(version: Int, previousHash: String, merkleRoot: String, hash: String) throws {
    let query = """
        INSERT INTO Block (version, timestamp, previous_hash, merkle_root, hash)
        VALUES (\(version), NOW(), '\(previousHash)', '\(merkleRoot)', '\(hash)')
    """
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
    }
}

func addTransactionToBlock(blockId: Int, transactionId: Int) throws {
    let query = "INSERT INTO BlockTransaction (block_id, transaction_id) VALUES (\(blockId), \(transactionId))"
    guard connection.query(statement: query) else {
        throw connection.errorMessage()
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

    func generateMerkleTree(treeHashes: [String]) -> String {
    // Base case: If there's only one hash, return it as the Merkle root
    if treeHashes.count == 1 {
        return treeHashes[0]
    }

    // Recursive case: Divide the treeHashes into left and right halves
    let midIndex = treeHashes.count / 2
    let leftTreeHashes = Array(treeHashes.prefix(upTo: midIndex))
    let rightTreeHashes = Array(treeHashes.suffix(from: midIndex))

    // Recursively compute the Merkle roots of left and right subtrees
    let leftMerkleRoot = generateMerkleTree(treeHashes: leftTreeHashes)
    let rightMerkleRoot = generateMerkleTree(treeHashes: rightTreeHashes)

    // Concatenate and hash the left and right Merkle roots to get the parent node
    let combinedHashes = leftMerkleRoot + rightMerkleRoot
    let parentHash = SHA256.hash(data: combinedHashes.data(using: .utf8)!).compactMap { String(format: "%02x", $0) }.joined()

    return parentHash
}

    func processMerkleTree(_ merkleTree: String) {
        // Perform necessary processing or calculations on the latest Merkle tree data
        print("Latest Merkle tree data: \(merkleTree)")
    }

    // Generate the Merkle root hash
    func generateMerkleRootHash(_ treeHashes: [String]) -> String {
        let merkleTools = MerkleTools()

        // Add the tree hashes as leaf nodes
        for hash in treeHashes {
            merkleTools.addLeaf(hash.data(using: .utf8)!)
        }

        // Generate the Merkle root
        let root = merkleTools.makeTree()

        return root.hash
    }

    // Generate the Merkle tree proof item for the given index
    func generateProofItem(itemHash: String, merkleRootHash: String) -> [String]? {
    // Create MerkleTools instance
    let merkleTools = MerkleTools()

    // Set the Merkle root hash
    merkleTools.merkleRoot = merkleRootHash

    // Add the item hash as a target to generate the proof
    merkleTools.addLeaf(itemHash.data(using: .utf8)!)

    // Generate the proof for the item hash
    return merkleTools.makeProof()
}

func generateProof(itemHashes: [String], merkleRootHash: String) -> [[String]] {
    // Create MerkleTools instance
    let merkleTools = MerkleTools()

    // Set the Merkle root hash
    merkleTools.merkleRoot = merkleRootHash

    // Add the item hashes as targets to generate proofs
    for hash in itemHashes {
        merkleTools.addLeaf(hash.data(using: .utf8)!)
    }

    // Generate the proofs for the item hashes
    return itemHashes.map { merkleTools.makeProof(targetIndex: $0) }
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

        // Encode the encrypted Merkle root data as a base64 string
        let encryptedRootString = encryptedData.base64EncodedString()

        return encryptedRootString
    }
}

import Foundation
import CryptoKit
import MySQLDriver

struct MyClaims: Codable {
    let sub: String // Subject
    let exp: Int // Expiration time
    let payload: [String: Any] // Payload data
}

// Function to generate ECDSA-based JWT signature
func generateECDSASignature(header: Data, claims: Data, privateKey: P256.Signing.PrivateKey) throws -> Data {
    let unsignedJWT = "\(header.base64EncodedString()).\(claims.base64EncodedString())"
    guard let unsignedData = unsignedJWT.data(using: .utf8) else {
        throw CryptoError.failedToEncodeData
    }
    
    let signature = try privateKey.signature(for: unsignedData)
    return signature.derRepresentation
}

// Function to verify ECDSA-based JWT signature
func verifyECDSASignature(header: Data, claims: Data, signature: Data, publicKey: P256.Signing.PublicKey) -> Bool {
    let unsignedJWT = "\(header.base64EncodedString()).\(claims.base64EncodedString())"
    guard let unsignedData = unsignedJWT.data(using: .utf8) else {
        return false
    }
    
    let derSignature = P256.Signing.ECDSASignature(derRepresentation: signature)
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
    if verifyECDSASignature(header: headerData, claims: jwtData, signature: jwtPayload.signature, publicKey: publicKey) {
        print("JWT signature verified.")
    } else {
        print("Invalid JWT signature.")
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
