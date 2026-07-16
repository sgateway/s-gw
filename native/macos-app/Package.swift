// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "SgwMac",
  platforms: [
    .macOS(.v14)
  ],
  products: [
    .executable(name: "s-gw", targets: ["SgwMac"])
  ],
  dependencies: [
    .package(path: "../update-state")
  ],
  targets: [
    .executableTarget(
      name: "SgwMac",
      dependencies: [
        .product(name: "SgwUpdateState", package: "update-state")
      ],
      path: "Sources/SgwMac"
    )
  ]
)
