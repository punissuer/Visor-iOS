// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Visor",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "VisorProtocol", targets: ["VisorProtocol"])],
    targets: [
        .target(name: "VisorProtocol"),
        .testTarget(name: "VisorProtocolTests", dependencies: ["VisorProtocol"]),
    ]
)
