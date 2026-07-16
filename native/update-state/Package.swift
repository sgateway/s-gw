// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "SgwUpdateState",
  platforms: [
    .macOS(.v13)
  ],
  products: [
    .library(name: "SgwUpdateState", targets: ["SgwUpdateState"])
  ],
  targets: [
    .target(name: "SgwUpdateState")
  ]
)
