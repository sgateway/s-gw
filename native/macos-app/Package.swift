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
  targets: [
    .executableTarget(
      name: "SgwMac",
      path: "Sources/SgwMac"
    )
  ]
)
