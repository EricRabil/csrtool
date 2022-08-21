import SwiftCLI
import Security
import Foundation
import DictionaryCoding
import DarwinPrivate

func SecCertificateCopySHA256DigestAtURL(_ url: URL) -> Data? {
    do {
        let data = try Data(contentsOf: url)
        guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
            fatalError("no cert at \(url.path)")
        }
        guard let digest = SecCertificateCopySHA256Digest(cert) else {
            fatalError("no digest")
        }
        return digest as Data
    } catch {
        return nil
    }
}

struct AMFITrustedKeysContainer: Codable {
    struct TrustedKey: Codable {
        var certDigest: Data
    }
    
    var trustedKeys: [TrustedKey]
    
    init(certificatePaths: [String]) {
        trustedKeys = certificatePaths
            .map(URL.init(fileURLWithPath:))
            .compactMap(SecCertificateCopySHA256DigestAtURL(_:))
            .map(TrustedKey.init(certDigest:))
    }
}

class AMFICommands: CommandGroup {
    let name = "amfi"
    let shortDescription = "view and modify the amfi configuration for this system"
    
    class KeysCommands: CommandGroup {
        let name = "keys"
        let shortDescription = "view and modify trusted-key configurations"
        
        class CreateNVRAM: Command {
            let name = "create-nvram"
            
            @Param var output: String
            @CollectedParam var certs: [String]
            
            func execute() throws {
                let container = AMFITrustedKeysContainer(certificatePaths: certs)
                let dict: NSDictionary = try DictionaryEncoder().encode(container)
                guard let data = IOCFSerialize(dict as CFDictionary, 0) else {
                    fatalError("serialization failed")
                }
                let nvramDelta = [
                    "AMFITrustedKeys": data
                ]
                guard let superData = IOCFSerialize(nvramDelta as CFDictionary, 0) else {
                    fatalError("serialization failed")
                }
                print(String(decoding: superData as Data, as: UTF8.self))
                
                
//                var digests: [Data] = []
//                for cert in certs[1...] {
//                    guard let digest = SecCertificateCopySHA256DigestAtURL(URL(fileURLWithPath: cert)) else {
//                        print("skipping \(cert)")
//                        continue
//                    }
//                    digests.append(digest)
//                }
//                if digests.isEmpty {
//                    print("warn: digests array is empty")
//                }
//                let dict = [
//                    "trustedKeys": digests.map { digest in
//                        [
//                            "certDigest": digest
//                        ]
//                    }
//                ]
//                guard let data = IOCFSerialize(dict as CFDictionary, 0) else {
//                    fatalError("serialization failed")
//                }
//                let nvramDelta = [
//                    "AMFITrustedKeys": data
//                ]
//                let nvramData = try PropertyListSerialization.data(fromPropertyList: nvramDelta, format: .xml, options: 0)
//                try (nvramData as Data).write(to: URL(fileURLWithPath: certs[0]))
            }
        }
        
        let children: [Routable] = [CreateNVRAM()]
    }
    
    let children: [Routable] = [KeysCommands()]
}

struct CSRConfig: OptionSet, CaseIterable, Hashable, CustomDebugStringConvertible {
    typealias RawValue = csr_config_t
    
    let rawValue: RawValue
    
    init(rawValue: csr_config_t) {
        self.rawValue = rawValue
    }
    
    init(_ rawValue: csr_config_t) {
        self.rawValue = rawValue
    }
    
    init(_ rawValue: Int32) {
        self.rawValue = csr_config_t(rawValue)
    }
    
    static let UNTRUSTED_KEXTS = CSRConfig(CSR_ALLOW_UNTRUSTED_KEXTS)
    static let UNRESTRICTED_FS = CSRConfig(CSR_ALLOW_UNRESTRICTED_FS)
    static let TASK_FOR_PID = CSRConfig(CSR_ALLOW_TASK_FOR_PID)
    static let KERNEL_DEBUGGER = CSRConfig(CSR_ALLOW_KERNEL_DEBUGGER)
    static let APPLE_INTERNAL = CSRConfig(CSR_ALLOW_APPLE_INTERNAL)
    static let DESTRUCTIVE_DTRACE = CSRConfig(CSR_ALLOW_DESTRUCTIVE_DTRACE)
    static let UNRESTRICTED_DTRACE = CSRConfig(CSR_ALLOW_UNRESTRICTED_DTRACE)
    static let UNRESTRICTED_NVRAM = CSRConfig(CSR_ALLOW_UNRESTRICTED_NVRAM)
    static let DEVICE_CONFIGURATION = CSRConfig(CSR_ALLOW_DEVICE_CONFIGURATION)
    static let ANY_RECOVERY_OS = CSRConfig(CSR_ALLOW_ANY_RECOVERY_OS)
    static let UNAPPROVED_KEXTS = CSRConfig(CSR_ALLOW_UNAPPROVED_KEXTS)
    static let EXECUTABLE_POLICY_OVERRIDE = CSRConfig(CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE)
    static let UNAUTHENTICATED_ROOT = CSRConfig(CSR_ALLOW_UNAUTHENTICATED_ROOT)
    
    static let allCases: [CSRConfig] = [
        .UNTRUSTED_KEXTS,
        .UNRESTRICTED_FS,
        .TASK_FOR_PID,
        .KERNEL_DEBUGGER,
        .APPLE_INTERNAL,
        .DESTRUCTIVE_DTRACE,
        .UNRESTRICTED_DTRACE,
        .UNRESTRICTED_NVRAM,
        .DEVICE_CONFIGURATION,
        .ANY_RECOVERY_OS,
        .UNAPPROVED_KEXTS,
        .EXECUTABLE_POLICY_OVERRIDE,
        .UNAUTHENTICATED_ROOT
    ]
    
    static let switchFlags: [String: CSRConfig] = allCases.reduce(into: [String: CSRConfig]()) { dict, config in
        dict["--\(config.switchName)"] = config
    }
    
    public var switchName: String {
        let name = name
        guard isKnown else {
            return name
        }
        var parts = name.dropFirst("CSR_ALLOW_".count).split(separator: "_").map(String.init(_:))
        if !parts.isEmpty {
            parts[0] = parts[0].lowercased()
        }
        for index in parts.indices.dropFirst() {
            var part = parts[index].lowercased()
            if !part.isEmpty {
                part.replaceSubrange(part.startIndex..<part.index(after: part.startIndex), with: part.first!.uppercased())
            }
            parts[index] = part
        }
        return parts.joined(separator: "")
    }
    
    public var isKnown: Bool {
        Self.allCases.contains(self)
    }
    
    public var name: String {
        switch self {
            case .UNTRUSTED_KEXTS: return "CSR_ALLOW_UNTRUSTED_KEXTS"
            case .UNRESTRICTED_FS: return "CSR_ALLOW_UNRESTRICTED_FS"
            case .TASK_FOR_PID: return "CSR_ALLOW_TASK_FOR_PID"
            case .KERNEL_DEBUGGER: return "CSR_ALLOW_KERNEL_DEBUGGER"
            case .APPLE_INTERNAL: return "CSR_ALLOW_APPLE_INTERNAL"
            case .DESTRUCTIVE_DTRACE: return "CSR_ALLOW_DESTRUCTIVE_DTRACE"
            case .UNRESTRICTED_DTRACE: return "CSR_ALLOW_UNRESTRICTED_DTRACE"
            case .UNRESTRICTED_NVRAM: return "CSR_ALLOW_UNRESTRICTED_NVRAM"
            case .DEVICE_CONFIGURATION: return "CSR_ALLOW_DEVICE_CONFIGURATION"
            case .ANY_RECOVERY_OS: return "CSR_ALLOW_ANY_RECOVERY_OS"
            case .UNAPPROVED_KEXTS: return "CSR_ALLOW_UNAPPROVED_KEXTS"
            case .EXECUTABLE_POLICY_OVERRIDE: return "CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE"
            case .UNAUTHENTICATED_ROOT: return "CSR_ALLOW_UNAUTHENTICATED_ROOT"
            case let unknown: return "CSR_UNKNOWN(\(unknown.rawValue))"
        }
    }
    
    public var debugDescription: String {
        try! String(decoding: JSONSerialization.data(withJSONObject: Self.allCases.reduce(into: [String: Bool]()) { dict, config in
            dict[config.switchName] = contains(config)
        }, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)
    }
}

class FlagsCommand: Command {
    let name = "flags"
    let shortDescription = "list known switch flags for the csr config"
    
    func execute() throws {
        print(try String(decoding: JSONSerialization.data(withJSONObject: CSRConfig.switchFlags.mapValues(\.name), options: [.prettyPrinted, .sortedKeys]), as: UTF8.self))
    }
}

class CSRParse: CommandGroup {
    let name = "parse"
    let shortDescription = "parse different formats of the csr configuration"
    
    class Base64: Command {
        let name = "base64"
        
        @Param var base64: String
        
        func execute() throws {
            guard let data = Data(base64Encoded: base64) else {
                fatalError("invalid base64 input")
            }
            var config: csr_config_t = 0
            for byte in data {
                config |= UInt32(byte)
            }
            print(CSRConfig(config).debugDescription)
        }
    }
    
    class Host: Command {
        let name = "host"
        
        func execute() throws {
            var config: csr_config_t = 0
            csr_get_active_config(&config)
            print(CSRConfig(config).debugDescription)
        }
    }
    
    let children: [Routable] = [Base64(), Host()]
}

let csrCLIFlags = CSRConfig.switchFlags.map { flag, config in
    (Flag(flag, description: "toggles \(config.name)"), config)
}

class CSRCreate: Command {
    let name = "create"
    let shortDescription = "create a CSR value using the given switches"
    
    @Flag("-h", "--hex", description: "output the CSR value as hex") var hex: Bool
    @Flag("-b", "--base64", description: "output the CSR value as base64") var base64: Bool
    
    var options: [Option] {
        [$hex, $base64] + csrCLIFlags.map(\.0)
    }
    
    func execute() throws {
        var config = CSRConfig()
        for (flag, bit) in csrCLIFlags {
            if flag.value {
                config.insert(bit)
            }
        }
        if hex {
            stdout <<< String(config.rawValue, radix: 16, uppercase: true)
        } else if base64 {
            var rawValue = config.rawValue
            let data = Data(bytes: &rawValue, count: MemoryLayout.size(ofValue: rawValue))
            stdout <<< data.base64EncodedString()
        } else {
            print(config.debugDescription)
        }
    }
}

CLI(name: "csrtool", commands: [
    AMFICommands(),
    CSRParse(),
    FlagsCommand(),
    CSRCreate()
]).goAndExit()
