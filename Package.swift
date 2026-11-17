// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Visor",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "VisorProtocol", targets: ["VisorProtocol"]),
        .library(name: "VisorSession", targets: ["VisorSession"]),
        .library(name: "VisorIdentity", targets: ["VisorIdentity"]),
    ],
    targets: [
        .target(name: "VisorProtocol"),
        .target(name: "VisorSession", dependencies: ["VisorProtocol"]),
        .target(name: "VisorIdentity", dependencies: ["VisorProtocol", "VisorSession"]),
        .testTarget(name: "VisorProtocolTests", dependencies: ["VisorProtocol"]),
        .testTarget(name: "VisorSessionTests", dependencies: ["VisorProtocol", "VisorSession", "VisorIdentity"]),
    ]
)
