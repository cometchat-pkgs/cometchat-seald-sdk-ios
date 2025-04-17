// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CometChatSealdSDK",
    platforms: [
        .iOS(.v14) // Specify iOS 13+ support
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "CometChatSealdSDK",
            targets: ["CometChatSealdSDK"]),
    ],
    dependencies: [
        .package(url: "https://github.com/seald/seald-sdk-ios", from: "0.9.0"),
        .package(url: "https://github.com/cometchat/chat-sdk-ios", from: "4.0.55")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "CometChatSealdSDK",
            dependencies: [
                .productItem(name: "SealdSdk", package: "seald-sdk-ios", moduleAliases: nil, condition: nil),
                .productItem(name: "CometChatSDK", package: "chat-sdk-ios", moduleAliases: nil, condition: nil)
            ]
        ),

    ]
)
