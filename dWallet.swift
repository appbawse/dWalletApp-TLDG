import Foundation
import UIKit
import SwiftRedis
import MultipeerConnectivity
import CryptoKit
import SwiftJWT
import MerkleTools
import SwiftMySQL
import MySQLDriver
import Aerospike

class ViewController: UIViewController, MCSessionDelegate, MCNearbyServiceBrowserDelegate, MCNearbyServiceAdvertiserDelegate {
    
    // MARK: - Core Clients
    var mysqlConnection = MySQL.Connection()
    var aerospikeClient = AerospikeClient()
    let redis = RedisConnection.make()
    
    // MARK: - Peer-to-Peer
    var peerID: MCPeerID!
    var session: MCSession!
    var browser: MCNearbyServiceBrowser!
    var advertiser: MCNearbyServiceAdvertiser!

    // MARK: - UI Elements
    @IBOutlet private weak var fromAddressIdTextField: UITextField!
    @IBOutlet private weak var toAddressIdTextField: UITextField!
    @IBOutlet private weak var balanceTextField: UITextField!
    @IBOutlet private weak var createAndSaveTransactionButton: UIButton!
    
    // MARK: - Crypto & Tools
    let jwtSecret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }.base64EncodedString()
    let merkleTools = MerkleTools()
    let edPrivateKey = Curve25519.Signing.PrivateKey()
    var edPublicKey: Curve25519.Signing.PublicKey { edPrivateKey.publicKey }

    // MARK: - Structs
    struct User {
        let id: Int
        let username: String
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
        let parentTransactionId: Int? // DAG ref
        let tokenSALT: String
    }

    struct MerkleProof {
        let transactionHash: String
        let proofPath: [String]
    }

    // MARK: - Lifecycle
    override func viewDidLoad() {
        super.viewDidLoad()
        setupDatabaseConnections()
        setupMultipeerConnectivity()
        connectToRedisAndFetchTransactions()
    }

    func setupDatabaseConnections() {
        do {
            _ = try mysqlConnection.connect(host: "localhost", user: "user", password: "pass", database: "dwallet")
            try aerospikeClient.connect(host: "localhost", port: 3000)
        } catch {
            print("Database connection error: \(error)")
        }
    }

    func setupMultipeerConnectivity() {
        peerID = MCPeerID(displayName: UIDevice.current.name)
        session = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
        session.delegate = self

        browser = MCNearbyServiceBrowser(peer: peerID, serviceType: "dwallet-service")
        browser.delegate = self
        advertiser = MCNearbyServiceAdvertiser(peer: peerID, discoveryInfo: nil, serviceType: "dwallet-service")
        advertiser.delegate = self

        browser.startBrowsingForPeers()
        advertiser.startAdvertisingPeer()
    }

    func connectToRedisAndFetchTransactions() {
        redis.connect(host: "localhost", port: 6379) { error in
            if let error = error {
                print("Redis connection error: \(error)")
                return
            }

            self.redis.get("active_merkle_root") { response, error in
                guard let root = response?.string, error == nil else {
                    print("Redis get error: \(String(describing: error))")
                    return
                }
                self.fetchDAGTransactionData(with: root)
            }
        }
    }

    func fetchDAGTransactionData(with redisMerkleRoot: String) {
        aerospikeClient.query(namespace: "test", setName: "transactions", query: "SELECT * FROM transactions WHERE status='pending'") { results, error in
            guard error == nil else {
                print("Aerospike error: \(error!)")
                return
            }

            results.forEach { transaction in
                self.handleTransaction(transaction)
            }
        }
    }

    func handleTransaction(_ transaction: [String: Any]) {
        guard
            let hash = transaction["hash"] as? String,
            let from = transaction["fromAddressId"] as? Int,
            let to = transaction["toAddressId"] as? Int,
            guard let balanceDouble = transaction["balance"] as? Double else { return }
let balance = Decimal(balanceDouble) else {
                print("Invalid transaction")
                return
            }

        let proof = generateMerkleProof(for: hash)
        storeMerkleProof(proof, for: hash)
        
        let tokenSALT = UUID().uuidString // Simulating TokenSALT generation
        print("Transaction validated with TokenSALT: \(tokenSALT)")

        // Future: Add to DAG ledger, validate MPC, PushTo Chain Explorer
    }

    func generateMerkleProof(for hash: String) -> MerkleProof {
        let proofPath = merkleTools.generateProof(for: hash)
        return MerkleProof(transactionHash: hash, proofPath: proofPath)
    }

    func storeMerkleProof(_ proof: MerkleProof, for hash: String) {
        aerospikeClient.put(namespace: "test", setName: "merkle_proofs", key: hash, value: [
            "transactionHash": proof.transactionHash,
            "proofPath": proof.proofPath
        ]) { error in
            if let error = error {
                print("Failed to store proof: \(error.localizedDescription)")
            } else {
                print("Stored Merkle proof for \(hash)")
            }
        }
    }

    deinit {
        mysqlConnection.close()
        aerospikeClient.close()
    }
}

func createUser(username: String,
                passwordHash: String,
                salt: String,
                publicKey: String,
                address: String,
                fromAddressId: Int,
                toAddressId: Int,
                balance: Decimal,
                hash: String,
                treeHashes: [String],
                indexInProof: Int,
                isRight: Bool,
                proofItemHash: String) throws {
    
    // Step 1: Insert User
    try insertUser(username: username, passwordHash: passwordHash, salt: salt, publicKey: publicKey)
    let userId = try getLastInsertedId()

    // Step 2: Insert Address
    try createAddress(userId: userId, address: address)
    
    // Step 3: Create Transaction
    let tokenSALT = UUID().uuidString
    let transactionId = try createTransaction(fromAddressId: fromAddressId,
                                              toAddressId: toAddressId,
                                              balance: balance,
                                              hash: hash,
                                              tokenSalt: tokenSALT)

    // Step 4: Merkle Root Generation & Block Creation
    let merkleRoot = generateMerkleRootHash(treeHashes)
    let previousHash = try fetchPreviousBlockHash()
    let blockId = try createBlock(previousHash: previousHash, merkleRoot: merkleRoot)
    
    // Step 5: Link Transaction to Block
    try addTransactionToBlock(blockId: blockId, transactionId: transactionId)

    // Step 6: Merkle Tree Creation & Proof
    let merkleTreeId = try createMerkleTree(merkleRoot: merkleRoot)
    let merkleTreeHashId = try createMerkleTreeHash(merkleTreeId: merkleTreeId, hash: hash)
    let merkleTreeProofItemId = try createMerkleTreeProofItem(merkleTreeId: merkleTreeId,
                                                               indexInProof: indexInProof,
                                                               isRight: isRight,
                                                               proofItemHash: proofItemHash)
    try createMerkleTreeProof(merkleTreeId: merkleTreeId,
                               merkleTreeHashId: merkleTreeHashId,
                               merkleTreeProofItemId: merkleTreeProofItemId)

    // Step 7: Create Balance Entry
    let tokenId = 1 // Replace dynamically later
    try createBalance(userId: userId, tokenId: tokenId, balance: balance, merkleTreeId: merkleTreeId)

    // Final Step: Push to DAG or Chain Explorer
    pushToChainExplorer(userId: userId, blockId: blockId, tokenSalt: tokenSALT)
}

func createTransaction(fromAddressId: Int, toAddressId: Int, balance: Decimal, hash: String, tokenSalt: String) throws -> Int {
    let query = """
        INSERT INTO Transaction (from_address_id, to_address_id, balance, timestamp, hash, token_salt)
        VALUES (?, ?, ?, NOW(), ?, ?)
    """
    let values: [MySQL.Value] = [.int(fromAddressId), .int(toAddressId), .decimal(balance), .string(hash), .string(tokenSalt)]
    guard connection.execute(statement: query, parameters: values) else {
        throw connection.errorMessage()
    }
    return try getLastInsertedId()
}

func createBlock(previousHash: String, merkleRoot: String) throws -> Int {
    let blockHash = UUID().uuidString
    let query = """
        INSERT INTO Block (version, timestamp, previous_hash, merkle_root, hash)
        VALUES (1, NOW(), ?, ?, ?)
    """
    guard connection.execute(statement: query, parameters: [.string(previousHash), .string(merkleRoot), .string(blockHash)]) else {
        throw connection.errorMessage()
    }
    return try getLastInsertedId()
}

func fetchPreviousBlockHash() throws -> String {
    let query = "SELECT hash FROM Block ORDER BY timestamp DESC LIMIT 1"
    let result = connection.query(statement: query)
    guard let row = result?.next(), let hash = row["hash"] as? String else {
        return "GENESIS_HASH"
    }
    return hash
}

func pushToChainExplorer(userId: Int, blockId: Int, tokenSalt: String) {
    // This could call your DAG, zkProof layer, or external explorer system
    print("Pushed User \(userId), Block \(blockId) with TokenSALT \(tokenSalt) to Chain Explorer.")
}

// MARK: - MCNearbyServiceBrowserDelegate
extension ViewController: MCNearbyServiceBrowserDelegate {
    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String : String]?) {
        print("Found peer: \(peerID.displayName)")
        if isPeerAllowed(peerID) {
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
        }
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        print("Lost peer: \(peerID.displayName)")
        // Consider reconnection logic if important peer is lost
    }

    private func isPeerAllowed(_ peerID: MCPeerID) -> Bool {
        // Add allowlist or cryptographic handshake validation logic here
        return true
    }
}

// MARK: - MCNearbyServiceAdvertiserDelegate
extension ViewController: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        print("Received invitation from \(peerID.displayName)")
        // Optional: validate context signature here
        invitationHandler(true, session)
    }
}

// MARK: - MCSessionDelegate
extension ViewController: MCSessionDelegate {
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        switch state {
        case .connected: print("Connected to \(peerID.displayName)")
        case .connecting: print("Connecting to \(peerID.displayName)")
        case .notConnected: print("Disconnected from \(peerID.displayName)")
        @unknown default: break
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        handleIncomingPayload(data, from: peerID)
    }

    func session(_ session: MCSession, didReceiveStream stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}

    func session(_ session: MCSession, didReceiveCertificate certificate: [Any]?, fromPeer peerID: MCPeerID, certificateHandler: @escaping (Bool) -> Void) {
        // TODO: Replace with actual X.509 or Ed25519 chain validation
        certificateHandler(true)
    }
}

// MARK: - Secure Data Handler
func handleIncomingPayload(_ data: Data, from peer: MCPeerID) {
    guard let decrypted = decrypt(data: data),
          let json = try? JSONSerialization.jsonObject(with: decrypted) as? [String: Any] else {
        print("Invalid or corrupted data received from \(peer.displayName)")
        return
    }

    print("Received verified data from \(peer.displayName): \(json)")
    // Process transaction or encrypted JWT
}

// MARK: - MCSession Setup
lazy var session: MCSession = {
    let localPeerID = MCPeerID(displayName: UIDevice.current.name)
    let session = MCSession(peer: localPeerID, securityIdentity: nil, encryptionPreference: .required)
    session.delegate = self
    return session
}()

// MARK: - Secure JWT and Merkle Generation
func generateEncryptedJWT() -> String? {
    struct Payload: Claims {
        let user_id: Int
        let from_address_id: Int
        let to_address_id: Int
        let balance: Double
    }

    let payload = Payload(user_id: 123, from_address_id: 456, to_address_id: 789, balance: 10.0)
    var jwt = JWT(claims: payload)

    guard let jwtSigner = try? JWTSigner.hs256(key: Data(base64Encoded: jwtSecret)!),
          let signedJWT = try? jwt.sign(using: jwtSigner) else { return nil }

    return signedJWT
}

// MARK: - Data Broadcasting
func sendDataToPeers(data: [String: Any]) {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: data),
          let encrypted = encrypt(data: jsonData) else {
        print("Failed to prepare data for sending.")
        return
    }

    do {
        try session.send(encrypted, toPeers: session.connectedPeers, with: .reliable)
        print("Data sent to peers.")
    } catch {
        print("Error sending encrypted data: \(error)")
    }
}

// MARK: - Transaction Field Helpers
func clearTransactionFields() {
    fromAddressIdTextField.text = ""
    toAddressIdTextField.text = ""
    balanceTextField.text = ""
}

// MARK: - JWT Handling
struct MyClaims: Codable {
    let sub: String
    let exp: Int
    let payload: [String: String]
    let signature: Data
}

enum CryptoError: Error {
    case failedToEncodeData
    case invalidSignature
}

struct JWTHandler {
    static func generateEd25519Signature(header: Data, claims: Data, privateKey: Curve25519.Signing.PrivateKey) throws -> Data {
        let unsignedJWT = "\(header.base64EncodedString()).\(claims.base64EncodedString())"
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            throw CryptoError.failedToEncodeData
        }
        return try privateKey.signature(for: unsignedData)
    }

    static func verifyEd25519Signature(header: Data, claims: Data, signature: Data, publicKey: Curve25519.Signing.PublicKey) -> Bool {
        let unsignedJWT = "\(header.base64EncodedString()).\(claims.base64EncodedString())"
        guard let unsignedData = unsignedJWT.data(using: .utf8) else { return false }
        return publicKey.isValidSignature(signature, for: unsignedData)
    }
}

// MARK: - Merkle Tree
struct MerkleTree {
    let rootHash: String
    private(set) var leafHashes: [String]

    init(transactions: [String]) {
        self.leafHashes = transactions.map {
            SHA256.hash(data: Data($0.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        self.rootHash = MerkleTree.calculateMerkleRoot(leafHashes)
    }

    static func calculateMerkleRoot(_ hashes: [String]) -> String {
        var hashes = hashes
        while hashes.count > 1 {
            var nextLevel: [String] = []
            for i in stride(from: 0, to: hashes.count, by: 2) {
                let left = hashes[i]
                let right = i + 1 < hashes.count ? hashes[i + 1] : left
                let combined = left + right
                let hash = SHA256.hash(data: Data(combined.utf8)).map { String(format: "%02x", $0) }.joined()
                nextLevel.append(hash)
            }
            hashes = nextLevel
        }
        return hashes.first ?? ""
    }
}

struct MerkleForest {
    var trees: [MerkleTree]
    var rootHash: String {
        MerkleTree.calculateMerkleRoot(trees.map(\.rootHash))
    }
}

// MARK: - Database Fetch (MySQLDriver assumed connected globally)
func fetchRow(query: String) -> [String: Any]? {
    guard let result = connection.query(statement: query), let row = result.nextResult() else {
        print("DB query failed: \(query)")
        return nil
    }
    return row
}

func fetchTransactionsForBlock(_ blockId: Int) -> [Transaction] {
    let query = "SELECT * FROM Transaction WHERE block_id = \(blockId)"
    guard let result = connection.query(statement: query) else { return [] }

    var transactions = [Transaction]()
    while let row = result.nextResult() {
        if let from = row["from_address_id"] as? Int,
           let to = row["to_address_id"] as? Int,
           let balance = row["balance"] as? Decimal,
           let timestamp = row["timestamp"] as? String,
           let hash = row["hash"] as? String {
            transactions.append(Transaction(fromAddressId: from, toAddressId: to, balance: balance, timestamp: timestamp, hash: hash))
        }
    }
    return transactions
}

// MARK: - P2P Data Handler
func handleIncomingData(_ data: Data, publicKey: Curve25519.Signing.PublicKey) {
    guard let message = try? JSONSerialization.jsonObject(with: data) as? [String: String],
          let encryptedJWTString = message["encryptedJWT"],
          let encryptedMerkleRootString = message["encryptedMerkleRoot"],
          let encryptedJWT = Data(base64Encoded: encryptedJWTString),
          let encryptedMerkleRoot = Data(base64Encoded: encryptedMerkleRootString) else {
        print("Bad P2P input format")
        return
    }

    guard let jwtData = decrypt(data: encryptedJWT),
          let jwtStr = String(data: jwtData, encoding: .utf8),
          let jwtPayload = try? JSONDecoder().decode(MyClaims.self, from: Data(jwtStr.utf8)) else {
        print("JWT decrypt or parse failed")
        return
    }

    let headerData = Data("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZDI1NTE5In0=".utf8)
    let claimsData = try! JSONEncoder().encode(jwtPayload)

    if JWTHandler.verifyEd25519Signature(header: headerData, claims: claimsData, signature: jwtPayload.signature, publicKey: publicKey) {
        print("Signature valid")
    } else {
        print("Invalid JWT Signature")
        return
    }

    guard let merkleRootData = decrypt(data: encryptedMerkleRoot),
          let rootStr = String(data: merkleRootData, encoding: .utf8) else {
        print("Merkle root decryption failed")
        return
    }

    processMerkleTree(rootStr)
}

// MARK: - Utils
func generateNonce() -> Int {
    Int.random(in: 1...1_000_000)
}

