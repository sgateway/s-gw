import Foundation
import Security

// Security.framework exports the same requirement validator used by `security dump-keychain`.
@_silgen_name("SecTrustedApplicationValidateWithPath")
func validateTrustedApplication(
  _ application: SecTrustedApplication,
  _ path: UnsafePointer<CChar>?
) -> OSStatus

let usage = """
Usage:
  sgw-keychain-inspector trusted-helper --service SERVICE --account ACCOUNT --candidate PATH [...]
"""

enum InspectorExit {
  static let usage: Int32 = 64
  static let notFound: Int32 = 44
  static let failed: Int32 = 70
}

func fail(_ message: String, code: Int32 = InspectorExit.failed) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(code)
}

func option(_ name: String) -> String? {
  let args = CommandLine.arguments
  for index in args.indices where args[index] == name {
    guard index + 1 < args.count else { return nil }
    return args[index + 1]
  }
  return nil
}

func options(_ name: String) -> [String] {
  var values: [String] = []
  let args = CommandLine.arguments
  for index in args.indices where args[index] == name && index + 1 < args.count {
    values.append(args[index + 1])
  }
  return values
}

func requireOption(_ name: String) -> String {
  guard let value = option(name), !value.isEmpty else {
    fail(usage, code: InspectorExit.usage)
  }
  return value
}

func check(_ status: OSStatus) {
  guard status != errSecSuccess else { return }
  if status == errSecItemNotFound {
    exit(InspectorExit.notFound)
  }

  let message = SecCopyErrorMessageString(status, nil) as String? ?? "Keychain inspection failed"
  fail("\(message) (\(status))")
}

func copyTrustedApplications(item: SecKeychainItem) -> [SecTrustedApplication] {
  var access: SecAccess?
  check(SecKeychainItemCopyAccess(item, &access))
  guard let access else { return [] }

  guard let aclList = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt) as? [SecACL]
  else { return [] }

  var result: [SecTrustedApplication] = []
  for acl in aclList {
    var applicationList: CFArray?
    var description: CFString?
    var prompt = SecKeychainPromptSelector()
    check(SecACLCopyContents(acl, &applicationList, &description, &prompt))

    guard let applications = applicationList as? [SecTrustedApplication] else { continue }
    result.append(contentsOf: applications)
  }
  return result
}

func trustedHelper(service: String, account: String, candidates: [String]) {
  var query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account,
    kSecReturnRef as String: true,
    kSecMatchLimit as String: kSecMatchLimitOne
  ]
  query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail

  var item: CFTypeRef?
  check(SecItemCopyMatching(query as CFDictionary, &item))
  guard let keychainItem = item as! SecKeychainItem? else {
    fail("Keychain item reference was unavailable")
  }

  let trustedApplications = copyTrustedApplications(item: keychainItem)
  var matches: [String] = []
  for candidate in candidates {
    let trusted = candidate.withCString { path in
      trustedApplications.contains { application in
        validateTrustedApplication(application, path) == errSecSuccess
      }
    }
    if trusted {
      matches.append(candidate)
    }
  }

  let encoded = try! JSONSerialization.data(withJSONObject: ["trustedHelpers": matches])
  FileHandle.standardOutput.write(encoded)
  FileHandle.standardOutput.write(Data("\n".utf8))
}

guard CommandLine.arguments.count >= 2 else {
  fail(usage, code: InspectorExit.usage)
}

let command = CommandLine.arguments[1]
let service = requireOption("--service")
let account = requireOption("--account")

switch command {
case "trusted-helper":
  trustedHelper(service: service, account: account, candidates: options("--candidate"))
default:
  fail(usage, code: InspectorExit.usage)
}
