// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "fltrBIP38",
    platforms: [.iOS(.v13), .macOS(.v10_15)],
    products: [
        .library(
            name: "fltrBIP38",
            targets: ["fltrBIP38"]),
    ],
    dependencies: [
        .package(url: "https://github.com/fltrWallet/fltrECC", branch: "main"),
        .package(url: "https://github.com/fltrWallet/fltrScrypt", branch: "main"),
        .package(url: "https://github.com/fltrWallet/fltrTx", branch: "main"),
        .package(url: "https://github.com/fltrWallet/HaByLo", branch: "main"),
    ],
    targets: [
        .target(
            name: "fltrBIP38",
            dependencies: [ "fltrECC",
                            "fltrScrypt",
                            "fltrTx",
                            "HaByLo", ]),
        .testTarget(
            name: "fltrBIP38Tests",
            dependencies: [ "fltrBIP38",
                            "fltrECC",
                            "fltrTx", ]),
    ]
)
