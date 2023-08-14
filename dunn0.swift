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
