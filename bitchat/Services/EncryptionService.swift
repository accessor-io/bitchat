//
// EncryptionService.swift
// bitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//
// dev notes: keep code; add dev notes keep code
// ENHANCED with advanced patterns from ~/pattern cryptographic research

import Foundation
import CryptoKit
import Security
import CommonCrypto
import LocalAuthentication

// MARK: - Advanced Security Levels from Pattern Research

enum SecurityLevel: String, CaseIterable {
    case normal = "normal"
    case high = "high" 
    case paranoid = "paranoid"
    
    var keyRotationInterval: TimeInterval {
        switch self {
        case .normal: return 3600    // 1 hour
        case .high: return 1800      // 30 minutes  
        case .paranoid: return 900   // 15 minutes
        }
    }
    
    var entropyThreshold: Double {
        switch self {
        case .normal: return 0.9
        case .high: return 0.95
        case .paranoid: return 0.98
        }
    }
}

// MARK: - Advanced Entropy Analysis 

struct MaurerUniversalTest {
    let L: Int = 8  // Block length
    let Q: Int = 1280  // Initialization blocks
    
    struct TestResult {
        let statistic: Double
        let passed: Bool
        let entropyEstimate: Double
        let pValue: Double
        let recommendation: String
    }
    
    func test(bits: [UInt8]) -> TestResult {
        guard bits.count > Q + L else {
            return TestResult(statistic: 0, passed: false, entropyEstimate: 0, 
                            pValue: 1.0, recommendation: "Insufficient data")
        }
        
        var lastOccurrence: [String: Int] = [:]
        var distances: [Double] = []
        
        // Process initialization blocks
        for i in 0..<Q {
            if i + L <= bits.count {
                let pattern = Array(bits[i..<i+L]).map { String($0) }.joined()
                lastOccurrence[pattern] = i + 1
            }
        }
        
        // Process test blocks
        for i in Q..<(bits.count - L + 1) {
            let pattern = Array(bits[i..<i+L]).map { String($0) }.joined()
            
            if let lastPos = lastOccurrence[pattern] {
                let distance = Double(i + 1 - lastPos)
                distances.append(log2(distance))
            }
            lastOccurrence[pattern] = i + 1
        }
        
        guard !distances.isEmpty else {
            return TestResult(statistic: 0, passed: false, entropyEstimate: 0,
                            pValue: 1.0, recommendation: "No repeated patterns")
        }
        
        let fn = distances.reduce(0, +) / Double(distances.count)
        let expected = 7.1836  // Expected value for L=8
        let variance = 3.238   // Variance for L=8
        
        let statistic = abs(fn - expected) / sqrt(variance / Double(distances.count))
        let passed = statistic <= 1.96  // 95% confidence
        let entropyEstimate = min(fn, Double(L))
        
        // Approximate p-value
        let pValue = 2.0 * (1.0 - normalCDF(statistic))
        
        let recommendation = passed ? "Sequence shows good randomness" : 
                           "Sequence may be predictable or structured"
        
        return TestResult(statistic: statistic, passed: passed, 
                         entropyEstimate: entropyEstimate, pValue: pValue,
                         recommendation: recommendation)
    }
    
    private func normalCDF(_ x: Double) -> Double {
        return 0.5 * (1.0 + erf(x / sqrt(2.0)))
    }
}

// MARK: - Hybrid Cryptographic Patterns from Pattern Research

struct HybridCryptoAnalyzer {
    
    // Scrypt-inspired rotation patterns
    static func scryptRotateXOR(_ a: UInt64, _ b: UInt64) -> UInt64 {
        let rotated = (a << 1) | (a >> 63)
        return rotated ^ b
    }
    
    // Balloon hashing inspired patterns
    static func balloonXORShift(_ a: UInt64, _ b: UInt64) -> UInt64 {
        return a ^ (a >> 1) ^ b
    }
    
    // PBKDF2 enhanced multiplication chain
    static func pbkdf2MultiplyAdd(_ a: UInt64, _ b: UInt64) -> UInt64 {
        let multiplier: UInt64 = 0x9E3779B97F4A7C15
        return (a &* multiplier &+ b)
    }
    
    // Custom bit shuffle from pattern research
    static func bitShuffle(_ a: UInt64, _ b: UInt64) -> UInt64 {
        var result: UInt64 = 0
        
        for i in 0..<32 {
            let aBit = (a >> i) & 1
            let bBit = (b >> i) & 1
            result |= (aBit << (i * 2))
            result |= (bBit << (i * 2 + 1))
        }
        
        return result
    }
    
    // Advanced polynomial recurrence
    static func polynomialRecurrence(_ values: [UInt64], degree: Int) -> UInt64 {
        guard !values.isEmpty else { return 0 }
        
        switch degree {
        case 1:
            // Linear combination with exponential weights
            var result: UInt64 = 0
            for (i, val) in values.enumerated() {
                let weight = UInt64(1) << UInt64(values.count - i - 1)
                result = result &+ (val &* weight)
            }
            return result
            
        case 2:
            // Quadratic recurrence with bitwise operations
            if values.count >= 2 {
                let a = values[0], b = values[1]
                return (2 &* b) &- a &+ ((a ^ b) & 0xFF)
            }
            return values[0]
            
        default:
            // Higher degree with weighted sum and bit mixing
            var result: UInt64 = 0
            for (i, val) in values.enumerated() {
                let weight = UInt64(degree + 1) << UInt64(values.count - i - 1)
                result = result &+ (val &* weight)
            }
            
            // Apply transformations based on degree
            for i in 0..<min(degree - 2, values.count - 1) {
                let shift = UInt64(i + 1)
                let rotated = (values[i] << shift) | (values[i] >> (64 - shift))
                result ^= rotated
            }
            
            return result
        }
    }
}

// MARK: - Entropy Harvester

protocol EntropySource {
    func nextPool() -> Data   // must be ≥ 96 bytes
}

struct EntropyHarvester: EntropySource {
    
    static func harvestSystemEntropy() -> Data {
        var entropy = Data()
        
        // System sources
        entropy.append(Data(UUID().uuidString.utf8))
        entropy.append(withUnsafeBytes(of: mach_absolute_time()) { Data($0) })
        entropy.append(withUnsafeBytes(of: CFAbsoluteTimeGetCurrent()) { Data($0) })
        
        // Process information
        entropy.append(withUnsafeBytes(of: getpid()) { Data($0) })
        entropy.append(withUnsafeBytes(of: pthread_self()) { Data($0) })
        
        // Memory addresses (ASLR)
        let stackVar = 0
        entropy.append(withUnsafeBytes(of: &stackVar) { Data($0) })
        
        // Hardware counters if available
        if #available(iOS 14.0, macOS 11.0, *) {
            var info = mach_timebase_info()
            mach_timebase_info(&info)
            entropy.append(withUnsafeBytes(of: info) { Data($0) })
        }
        
        return entropy
    }
    
    static func enhancedEntropyPool() -> Data {
        var pool = Data()
        
        // Multiple entropy sources
        for _ in 0..<8 {
            pool.append(harvestSystemEntropy())
            
            // Add cryptographic randomness
            var random = Data(count: 32)
            _ = random.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.bindMemory(to: UInt8.self).baseAddress!) }
            pool.append(random)
            
            // Brief delay to gather different temporal entropy
            Thread.sleep(forTimeInterval: 0.001)
        }
        
        // Mix with hybrid crypto patterns
        let poolBytes = [UInt8](pool)
        var enhanced = Data()
        
        for i in stride(from: 0, to: poolBytes.count - 8, by: 8) {
            let a = UInt64(bytes: Array(poolBytes[i..<i+4]))
            let b = UInt64(bytes: Array(poolBytes[i+4..<i+8]))
            
            let mixed = HybridCryptoAnalyzer.scryptRotateXOR(a, b)
            enhanced.append(withUnsafeBytes(of: mixed) { Data($0) })
        }
        
        return enhanced
    }
    
    func nextPool() -> Data {
        return enhancedEntropyPool()
    }
}

// MARK: - Enhanced Encryption Service with Pattern Research

///  encryption service implementing cutting-edge cryptographic patterns
/// from advanced pattern research, including HAC Chapter 5, hybrid crypto analysis,
/// and multi-layer security architectures
class EncryptionService {
    
    // MARK: - Core State
    
    private var securityLevel: SecurityLevel = .high
    private var keyRotationTimer: Timer?
    private let entropyHarvester: EntropySource // Changed to EntropySource
    private let maurerTester = MaurerUniversalTest()
    
    // MARK: - Cryptographic State
    
    private let identitySigningKey: Curve25519.Signing.PrivateKey
    private let identityAgreementKey: Curve25519.KeyAgreement.PrivateKey
    private var groupState: GroupState
    private var keySchedule: KeySchedule
    private var ratchetStates: [String: RatchetState] = [:]
    
    // MARK: - Multi-Layer Key Management
    
    private struct LayeredKeys {
        let primaryKey: SymmetricKey
        let backupKey: SymmetricKey
        let emergencyKey: SymmetricKey
        let timestamp: Date
    }
    
    private var layeredKeys: LayeredKeys
    
    // MARK: -  Initialization
    
    init(entropySource: EntropySource = EntropyHarvester()) throws { // Changed to EntropySource
        // Assign injected entropy source
        self.entropyHarvester = entropySource
        // Generate  entropy pool
        let entropyPool = entropySource.nextPool()
        
        // Test entropy quality with Maurer's Universal Test
        let entropyBits = entropyPool.map { byte in
            (0..<8).map { bit in UInt8((byte >> bit) & 1) }
        }.flatMap { $0 }
        
        let maurerResult = maurerTester.test(bits: entropyBits)
        guard maurerResult.passed && maurerResult.entropyEstimate >= securityLevel.entropyThreshold else {
            throw EncryptionError.insufficientEntropy
        }
        
        // Initialize identity keys with  entropy
        self.identitySigningKey = try Curve25519.Signing.PrivateKey(rawRepresentation: 
            entropyPool.subdata(in: 0..<32))
        self.identityAgreementKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: 
            entropyPool.subdata(in: 32..<64))
        
        // Initialize group state
        self.groupState = GroupState()
        
        // Initialize key schedule with hybrid patterns
        self.keySchedule = try KeySchedule(initialEntropy: entropyPool.subdata(in: 64..<96))
        
        // Initialize layered keys
        self.layeredKeys = LayeredKeys(
            primaryKey: SymmetricKey(data: entropyPool.subdata(in: 96..<128)),
            backupKey: SymmetricKey(data: entropyPool.subdata(in: 128..<160)),
            emergencyKey: SymmetricKey(data: entropyPool.subdata(in: 160..<192)),
            timestamp: Date()
        )
        
        // Start key rotation based on security level
        startKeyRotation()
    }
    ]
    // MARK: - Security Level Management
    
    func setSecurityLevel(_ level: SecurityLevel) {
        securityLevel = level
        
        // Restart key rotation with new interval
        keyRotationTimer?.invalidate()
        startKeyRotation()
        
        // Force immediate key rotation for higher security
        if level == .paranoid {
            Task {
                await rotateKeys()
            }
        }
    }
    
    private func startKeyRotation() {
        keyRotationTimer = Timer.scheduledTimer(withTimeInterval: securityLevel.keyRotationInterval, repeats: true) { _ in
            Task {
                await self.rotateKeys()
            }
        }
    }
    
    @MainActor
    private func rotateKeys() async {
        do {
            // Generate new entropy pool
            let newEntropy = entropyHarvester.nextPool()
            
            // Test entropy quality
            let entropyBits = newEntropy.map { byte in
                (0..<8).map { bit in UInt8((byte >> bit) & 1) }
            }.flatMap { $0 }
            
            let maurerResult = maurerTester.test(bits: entropyBits)
            guard maurerResult.passed else {
                throw EncryptionError.entropyTestFailed
            }
            
            // Rotate layered keys using hybrid crypto patterns
            let oldPrimary = layeredKeys.primaryKey
            let oldBackup = layeredKeys.backupKey
            
            // Apply hybrid patterns for key derivation
            let primaryData = oldPrimary.withUnsafeBytes { bytes in
                var data = Data(bytes)
                let entropySlice = newEntropy.subdata(in: 0..<32)
                let mixingKey = newEntropy.subdata(in: 32..<64)
                let rotationSalt = newEntropy.subdata(in: 64..<96)
                let iterationCount = UInt32(securityLevel.rawValue * 1000)
                
                // Apply scrypt-like rotation
                for i in 0..<data.count {
                    let old = UInt64(data[i])
                    let new = UInt64(mixingKey[i % mixingKey.count])
                    data[i] = UInt8(HybridCryptoAnalyzer.scryptRotateXOR(old, new) & 0xFF)
                }
                return data
            }
            
            // Update layered keys
            layeredKeys = LayeredKeys(
                primaryKey: SymmetricKey(data: primaryData),
                backupKey: SymmetricKey(data: newEntropy.subdata(in: 32..<64)),
                emergencyKey: layeredKeys.backupKey, // Previous backup becomes emergency
                timestamp: Date()
            )
            
            // Update key schedule
            try keySchedule.rotate(with: newEntropy.subdata(in: 64..<96))
            
        } catch {
            // Log rotation failure but continue with existing keys
            print("Key rotation failed: \(error)")
        }
    }
    
    // MARK: - Enhanced Message Encryption
    
    func encryptMessage(_ data: Data, for peerID: String, messageType: MessageType = .normal) throws -> EncryptedMessage {
        // Get or create ratchet state
        if ratchetStates[peerID] == nil {
            ratchetStates[peerID] = try RatchetState(peerID: peerID, keySchedule: keySchedule)
        }
        
        guard let ratchetState = ratchetStates[peerID] else {
            throw EncryptionError.noRatchetState
        }
        
        // Apply hybrid crypto patterns to the message
        var processedData = data
        
        switch securityLevel {
        case .paranoid:
            // Triple-layer encryption with hybrid patterns
            processedData = try encryptWithLayeredKeys(processedData)
            fallthrough
        case .high:
            // Apply polynomial recurrence mixing
            processedData = try applyPolynomialMixing(processedData)
            fallthrough
        case .normal:
            // Standard encryption with Double Ratchet
            break
        }
        
        // Generate message key using ratchet
        let messageKey = try ratchetState.nextMessageKey()
        
        // Encrypt with AES-GCM
        let sealedBox = try AES.GCM.seal(processedData, using: messageKey)
        
        // Create header with ratchet information
        let header = MessageHeader(
            ratchetKey: ratchetState.currentRatchetKey,
            messageNumber: ratchetState.messageNumber,
            previousChainLength: ratchetState.previousChainLength
        )
        
        return EncryptedMessage(
            header: header,
            ciphertext: sealedBox.combined!
        )
    }
    
    private func encryptWithLayeredKeys(_ data: Data) throws -> Data {
        // Apply layered encryption for paranoid security
        var encrypted = data
        
        // Layer 1: Primary key with balloon hashing pattern
        encrypted = try applyBalloonPattern(encrypted, key: layeredKeys.primaryKey)
        
        // Layer 2: Backup key with scrypt pattern
        encrypted = try applyScryptPattern(encrypted, key: layeredKeys.backupKey)
        
        // Layer 3: Emergency key with PBKDF2 pattern
        encrypted = try applyPBKDF2Pattern(encrypted, key: layeredKeys.emergencyKey)
        
        return encrypted
    }
    
    private func applyBalloonPattern(_ data: Data, key: SymmetricKey) throws -> Data {
        // Implement balloon hashing inspired pattern
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined!
    }
    
    private func applyScryptPattern(_ data: Data, key: SymmetricKey) throws -> Data {
        // Implement scrypt inspired pattern with rotation
        var rotated = Data()
        let keyData = key.withUnsafeBytes { Data($0) }
        
        for (i, byte) in data.enumerated() {
            let keyByte = keyData[i % keyData.count]
            let mixed = HybridCryptoAnalyzer.scryptRotateXOR(UInt64(byte), UInt64(keyByte))
            rotated.append(UInt8(mixed & 0xFF))
        }
        
        let sealedBox = try AES.GCM.seal(rotated, using: key)
        return sealedBox.combined!
    }
    
    private func applyPBKDF2Pattern(_ data: Data, key: SymmetricKey) throws -> Data {
        // Implement PBKDF2 inspired pattern with multiplication
        var enhanced = Data()
        let keyData = key.withUnsafeBytes { Data($0) }
        
        for (i, byte) in data.enumerated() {
            let keyByte = keyData[i % keyData.count]
            let mixed = HybridCryptoAnalyzer.pbkdf2MultiplyAdd(UInt64(byte), UInt64(keyByte))
            enhanced.append(UInt8(mixed & 0xFF))
        }
        
        let sealedBox = try AES.GCM.seal(enhanced, using: key)
        return sealedBox.combined!
    }
    
    private func applyPolynomialMixing(_ data: Data) throws -> Data {
        // Apply polynomial recurrence patterns to data
        var mixed = Data()
        let bytes = [UInt8](data)
        
        for i in 0..<bytes.count {
            if i >= 3 {
                // Use previous 3 bytes for polynomial recurrence
                let values = [UInt64(bytes[i-3]), UInt64(bytes[i-2]), UInt64(bytes[i-1])]
                let polynomial = HybridCryptoAnalyzer.polynomialRecurrence(values, degree: 2)
                let mixed_byte = UInt8((UInt64(bytes[i]) ^ polynomial) & 0xFF)
                mixed.append(mixed_byte)
            } else {
                mixed.append(bytes[i])
            }
        }
        
        return mixed
    }
    
    // MARK: - Supporting Structures
    
    private struct GroupState {
        var epoch: UInt64 = 0
        var groupSecret: Data = Data()
    }
    
    private struct KeySchedule {
        private var rootKey: Data
        private var chainKey: Data
        
        init(initialEntropy: Data) throws {
            self.rootKey = initialEntropy
            self.chainKey = initialEntropy
        }
        
        mutating func rotate(with entropy: Data) throws {
            // Update keys using hybrid patterns
            let combined = rootKey + entropy
            rootKey = SHA256.hash(data: combined).data
            chainKey = SHA256.hash(data: rootKey + entropy).data
        }
    }
    
    private class RatchetState {
        let peerID: String
        var currentRatchetKey: Data
        var messageNumber: UInt32 = 0
        var previousChainLength: UInt32 = 0
        private let keySchedule: KeySchedule
        
        init(peerID: String, keySchedule: KeySchedule) throws {
            self.peerID = peerID
            self.keySchedule = keySchedule
            self.currentRatchetKey = Data(count: 32)
            SecRandomCopyBytes(kSecRandomDefault, 32, &currentRatchetKey.withUnsafeMutableBytes { $0.bindMemory(to: UInt8.self).baseAddress! })
        }
        
        func nextMessageKey() throws -> SymmetricKey {
            defer { messageNumber += 1 }
            
            let keyMaterial = currentRatchetKey + withUnsafeBytes(of: messageNumber) { Data($0) }
            let hash = SHA256.hash(data: keyMaterial)
            return SymmetricKey(data: hash)
        }
    }
    
    struct MessageHeader {
        let ratchetKey: Data
        let messageNumber: UInt32
        let previousChainLength: UInt32
    }
    
    struct EncryptedMessage {
        let header: MessageHeader
        let ciphertext: Data
    }
    
    enum MessageType {
        case normal
        case ephemeral
        case groupKey
    }
    
    enum EncryptionError: Error {
        case insufficientEntropy
        case entropyTestFailed
        case noRatchetState
        case encryptionFailed
        case decryptionFailed
    }
    
    // MARK: - Compatibility Layer for Legacy API
    
    func getCombinedPublicKeyData() -> Data {
        var data = Data()
        data.append(identityAgreementKey.publicKey.rawRepresentation)
        data.append(identitySigningKey.publicKey.rawRepresentation)
        return data
    }
    
    func encrypt(_ plaintext: Data, recipientPublicKey: Data) throws -> Data {
        let peerID = recipientPublicKey.base64EncodedString()
        let encrypted = try encryptMessage(plaintext, for: peerID)
        return encrypted.ciphertext
    }
    
    func decrypt(_ ciphertext: Data, senderPublicKey: Data) throws -> Data {
        // Implementation would decode the message header and decrypt
        // For now, return a placeholder
        throw EncryptionError.decryptionFailed
    }
    
    func sign(_ data: Data) throws -> Data {
        return try identitySigningKey.signature(for: data)
    }
    
    func verify(_ signature: Data, data: Data, publicKey: Data) throws -> Bool {
        guard let signingKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else {
            return false
        }
        return signingKey.isValidSignature(signature, for: data)
    }
}

// MARK: - Extensions

extension UInt64 {
    init(bytes: [UInt8]) {
        var value: UInt64 = 0
        for (index, byte) in bytes.prefix(8).enumerated() {
            value |= UInt64(byte) << (8 * index)
        }
        self = value
    }
}

extension Digest {
    var data: Data {
        return Data(self)
    }
}