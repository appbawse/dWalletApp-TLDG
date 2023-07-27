// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "YourPackageName",
    platforms: [
        .iOS(.v13)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.34.0"),
        .package(url: "https://github.com/RedisSwift/SwiftRedis.git", from: "5.0.3"),
        .package(url: "https://github.com/IBM-Swift/CryptoKitRSA.git", from: "1.0.4"),
        .package(url: "https://github.com/IBM-Swift/BlueSocket.git", from: "1.0.55"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.6"),
        .package(url: "https://github.com/vapor/jwt.git", from: "4.0.0"),
        .package(url: "https://github.com/tinynumbers/SwiftMerkleTools.git", from: "0.2.0"),
        .package(url: "https://github.com/vapor/mysql-nio.git", from: "1.0.2"),
        .package(url: "https://github.com/vapor/mysql-kit.git", from: "4.0.1"),
    ],
    targets: [
        .target(
            name: "YourTargetName",
            dependencies: [
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "SwiftRedis", package: "SwiftRedis"),
                .product(name: "CryptoKitRSA", package: "CryptoKitRSA"),
                .product(name: "UIKit", package: "UIKit"),
                .product(name: "MultipeerConnectivity", package: "MultipeerConnectivity"),
                .product(name: "CryptoKit", package: "swift-crypto"),
                .product(name: "JWT", package: "jwt"),
                .product(name: "SwiftMerkleTools", package: "SwiftMerkleTools"),
                .product(name: "NIO", package: "mysql-nio"),
                .product(name: "AsyncKit", package: "mysql-nio"),
                .product(name: "Logging", package: "mysql-nio"),
                .product(name: "NIOTLS", package: "mysql-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "mysql-nio"),
                .product(name: "SQLKit", package: "mysql-kit"),
                .product(name: "SQLKitBenchmark", package: "mysql-kit"),
                .product(name: "SQLKitBenchmarkUtilities", package: "mysql-kit"),
                .product(name: "SQLKitBenchmarker", package: "mysql-kit"),
            ]
        ),
    ]
)
