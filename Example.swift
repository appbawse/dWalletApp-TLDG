import Foundation
import MultipeerConnectivity
import CryptoKitRSA

// Simulate a user creating a transaction
func simulateTransaction() {
    let fromAddressId = 123
    let toAddressId = 456
    let balance: Decimal = 10.0
    let transactionHash = "transaction_hash"

    do {
        try createTransaction(fromAddressId: fromAddressId, toAddressId: toAddressId, balance: balance, hash: transactionHash)
        print("Transaction created and saved.")
    } catch {
        print("Error creating and saving the transaction: \(error)")
    }
}

// Simulate verifying a transaction with Merkle proof
func simulateTransactionVerification() {
    let transactionHashToVerify = "transaction_hash_to_verify"
    let merkleRoot = "merkle_root"

    verifyTransactionWithMerkleProof(transactionHashToVerify: transactionHashToVerify, merkleRoot: merkleRoot)
}

// Simulate creating a Merkle tree
func simulateMerkleTreeCreation() {
    let shardingId = 1
    let rootHash = "root_hash"
    let treeHashes = ["tree_hash_1", "tree_hash_2"]

    do {
        let createdRootHash = try createMerkleTree(shardingId: shardingId, rootHash: rootHash, treeHashes: treeHashes)
        print("Merkle Tree created with root hash: \(createdRootHash)")
    } catch {
        print("Error creating the Merkle Tree: \(error)")
    }
}

// Simulate creating a Merkle tree proof
func simulateMerkleTreeProofCreation() {
    let merkleTreeId = 1
    let indexInProof = 1
    let isRight = true
    let proofItemHash = "proof_item_hash"

    do {
        try createMerkleTreeProofItem(merkleTreeProofId: merkleTreeId, indexInProof: indexInProof, isRight: isRight, hash: proofItemHash)
        print("Merkle Tree Proof Item created.")
    } catch {
        print("Error creating Merkle Tree Proof Item: \(error)")
    }
}

// Simulate creating a block and adding a transaction to it
func simulateBlockAndTransactionCreation() {
    let block = Block(version: 1, previousHash: "previous_hash", merkleRoot: "merkle_root", hash: "block_hash")
    let blockTransaction = BlockTransaction(blockId: 1, transactionId: 1)

    createBlockAndAddTransaction(block: block, blockTransaction: blockTransaction)
}

// Simulate processing Merkle tree data
func simulateMerkleTreeProcessing() {
    let jsonString = "{\"rootHash\":\"root_hash\",\"treeHashes\":[\"tree_hash_1\",\"tree_hash_2\"]}"
    processMerkleTree(jsonString: jsonString)
}

// Simulate creating a user, address, and transaction
func simulateUserAddressTransaction() {
    do {
        try createUser(username: "user123", passwordHash: "hash123", salt: "salt123", publicKey: "public123")
        try createAddress(address: Address(userId: 123, address: "address123"))
        simulateTransaction()
    } catch {
        print("Error: \(error)")
    }
}

// Simulate getting transactions by user ID and address
func simulateGettingTransactions() {
    let userID = "123"
    let address = "address123"
    let transactions = getTransactionsByUserIDAndAddress(userID: userID, address: address)
    print("Transactions for user \(userID) and address \(address):")
    for transaction in transactions {
        print(transaction)
    }
}

// Simulate verifying a Merkle proof for a transaction
func simulateMerkleProofVerification() {
    let transactionHashToVerify = "transaction_hash_to_verify"
    let merkleRoot = "merkle_root"
    verifyTransactionWithMerkleProof(transactionHashToVerify: transactionHashToVerify, merkleRoot: merkleRoot)
}

func processReceivedData(receivedEncryptedJWTString: String, receivedEncryptedMerkleRootString: String) {
    // Convert base64 strings back to Data
    guard let receivedEncryptedJWTData = Data(base64Encoded: receivedEncryptedJWTString),
          let receivedEncryptedMerkleRootData = Data(base64Encoded: receivedEncryptedMerkleRootString)
    else {
        print("Error decoding base64 data.")
        return
    }

    // Decrypt the encrypted JWT using the private key
    guard let decryptedJWTData = decrypt(data: receivedEncryptedJWTData),
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
        
        // Decrypt the encrypted Merkle root using the private key
        guard let decryptedMerkleRootData = decrypt(data: receivedEncryptedMerkleRootData),
              let merkleRoot = String(data: decryptedMerkleRootData, encoding: .utf8)
        else {
            print("Error decrypting Merkle root.")
            return
        }
        
        // Process the received Merkle root data
        processMerkleTree(merkleRoot)
    } else {
        print("Invalid JWT signature.")
        return
    }
}

// Call the simulation functions
simulateTransaction()
simulateTransactionVerification()
simulateMerkleTreeCreation()
simulateMerkleTreeProofCreation()
simulateBlockAndTransactionCreation()
simulateMerkleTreeProcessing()
simulateUserAddressTransaction()
simulateGettingTransactions()
simulateMerkleProofVerification()
processReceivedData()

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
