// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "SgwMenuBar",
  platforms: [
    .macOS(.v13)
  ],
  products: [
    .executable(name: "s-gw-menu-bar-helper", targets: ["SgwMenuBar"])
  ],
  targets: [
    .executableTarget(
      name: "SgwMenuBar",
      path: "Sources"
    )
  ]
)
