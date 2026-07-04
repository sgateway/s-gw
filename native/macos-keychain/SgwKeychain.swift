import Foundation
import Security

let usage = """
Usage:
  sgw-keychain get --service SERVICE --account ACCOUNT
  sgw-keychain set --service SERVICE --account ACCOUNT [--label LABEL]
  sgw-keychain delete --service SERVICE --account ACCOUNT
"""

enum SgwExit {
  static let usage: Int32 = 64
  static let unavailable: Int32 = 69
  static let notFound: Int32 = 44
  static let failed: Int32 = 70
}

func fail(_ message: String, code: Int32 = SgwExit.failed) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(code)
}

func option(_ name: String) -> String? {
  let args = CommandLine.arguments
  for index in args.indices {
    if args[index] == name, index + 1 < args.count {
      return args[index + 1]
    }
  }
  return nil
}

func requireOption(_ name: String) -> String {
  guard let value = option(name), !value.isEmpty else {
    fail(usage, code: SgwExit.usage)
  }
  return value
}

func baseQuery(service: String, account: String) -> [String: Any] {
  [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account
  ]
}

func check(_ status: OSStatus, notFoundOk: Bool = false) {
  if status == errSecSuccess {
    return
  }
  if status == errSecItemNotFound {
    exit(notFoundOk ? 0 : SgwExit.notFound)
  }

  let message = SecCopyErrorMessageString(status, nil) as String? ?? "Keychain operation failed"
  fail("\(message) (\(status))")
}

func getPassphrase(service: String, account: String) {
  var query = baseQuery(service: service, account: account)
  query[kSecReturnData as String] = true
  query[kSecMatchLimit as String] = kSecMatchLimitOne

  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)
  check(status)

  guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
    fail("Keychain item was not valid UTF-8")
  }
  print(value)
}

func setPassphrase(service: String, account: String) {
  let data = FileHandle.standardInput.readDataToEndOfFile()
  guard !data.isEmpty else {
    fail("No passphrase was supplied on stdin", code: SgwExit.usage)
  }

  let label = option("--label") ?? "s-gw local unlock passphrase"
  var addQuery = baseQuery(service: service, account: account)
  addQuery[kSecAttrLabel as String] = label
  addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
  addQuery[kSecValueData as String] = data

  let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
  if addStatus == errSecDuplicateItem {
    let query = baseQuery(service: service, account: account)
    let attrs: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrLabel as String: label
    ]
    check(SecItemUpdate(query as CFDictionary, attrs as CFDictionary))
    return
  }

  check(addStatus)
}

func deletePassphrase(service: String, account: String) {
  let status = SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
  check(status, notFoundOk: false)
}

guard CommandLine.arguments.count >= 2 else {
  fail(usage, code: SgwExit.usage)
}

let command = CommandLine.arguments[1]
let service = requireOption("--service")
let account = requireOption("--account")

switch command {
case "get":
  getPassphrase(service: service, account: account)
case "set":
  setPassphrase(service: service, account: account)
case "delete":
  deletePassphrase(service: service, account: account)
default:
  fail(usage, code: SgwExit.usage)
}
