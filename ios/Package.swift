// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Keyhole",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "KeyholeCore", targets: ["KeyholeCore"]),
    ],
    targets: [
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            exclude: ["LICENSE"],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("."),
                .headerSearchPath("include"),
                .headerSearchPath("blake2"),
                .define("ARGON2_NO_THREADS"),
            ]
        ),
        .target(
            name: "KeyholeCore",
            dependencies: ["CArgon2"],
            path: "Sources/KeyholeCore",
            resources: [
                .copy("Resources/bip39-english.txt"),
            ]
        ),
        .testTarget(
            name: "KeyholeCoreTests",
            dependencies: ["KeyholeCore"],
            path: "Tests/KeyholeCoreTests",
            resources: [
                .copy("Fixtures"),
            ]
        ),
    ]
)
