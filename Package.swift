// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DexGate",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "DexGate", targets: ["DexGate"])
    ],
    targets: [
        .executableTarget(
            name: "DexGate",
            path: "Sources/DexGate"
        )
    ]
)
