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
  dependencies: [
    .package(path: "../update-state")
  ],
  targets: [
    .executableTarget(
      name: "SgwMenuBar",
      dependencies: [
        .product(name: "SgwUpdateState", package: "update-state")
      ],
      path: "Sources"
    )
  ]
)
