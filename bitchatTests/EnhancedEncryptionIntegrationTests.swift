//
// EnhancedEncryptionIntegrationTests.swift
// bitchatTests
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//

import XCTest
import CryptoKit
@testable import bitchat

class EnhancedEncryptionIntegrationTests: XCTestCase {
    
    var encryptionService: EncryptionService!
    
    override func setUp() {
        super.setUp()
        encryptionService = EncryptionService()
    }
    
    override func tearDown() {
        encryptionService = nil
        super.tearDown()
    }
    
    // MARK: - Compatibility Layer Tests
    
    func testLegacyKeyExchangeCompatibility() {
        // Test that the legacy key exchange format still works
        let peerID = "test-peer-123"
        
        // Get legacy format key data
        let keyData = encryptionService.getCombinedPublicKeyData()
        XCTAssertEqual(keyData.count, 96, "Legacy key data should be 96 bytes")
        
        // Test adding peer key in legacy format
        XCTAssertNoThrow(try encryptionService.addPeerPublicKey(peerID, publicKeyData: keyData))
        
        // Verify peer identity key is accessible
        let identityKey = encryptionService.getPeerIdentityKey(peerID)
        XCTAssertNotNil(identityKey, "Should be able to retrieve peer identity key")
        XCTAssertEqual(identityKey?.count, 32, "Identity key should be 32 bytes")
    }
    
    func testLegacyEncryptDecryptCompatibility() {
        let peerID = "test-peer-456"
        let testMessage = "Hello from enhanced encryption!"
        let messageData = testMessage.data(using: .utf8)!
        
        // Set up peer for encryption
        let keyData = encryptionService.getCombinedPublicKeyData()
        XCTAssertNoThrow(try encryptionService.addPeerPublicKey(peerID, publicKeyData: keyData))
        
        // Test legacy encrypt/decrypt methods
        do {
            let encryptedData = try encryptionService.encrypt(messageData, for: peerID)
            XCTAssertGreaterThan(encryptedData.count, messageData.count, "Encrypted data should be larger")
            
            let decryptedData = try encryptionService.decrypt(encryptedData, from: peerID)
            let decryptedMessage = String(data: decryptedData, encoding: .utf8)
            
            XCTAssertEqual(decryptedMessage, testMessage, "Decrypted message should match original")
        } catch {
            XCTFail("Legacy encrypt/decrypt should work: \(error)")
        }
    }
    
    func testLegacySignVerifyCompatibility() {
        let peerID = "test-peer-789"
        let testData = "Test data for signing".data(using: .utf8)!
        
        // Set up peer for verification
        let keyData = encryptionService.getCombinedPublicKeyData()
        XCTAssertNoThrow(try encryptionService.addPeerPublicKey(peerID, publicKeyData: keyData))
        
        // Test legacy sign/verify methods
        do {
            let signature = try encryptionService.sign(testData)
            XCTAssertGreaterThan(signature.count, 0, "Signature should not be empty")
            
            let isValid = try encryptionService.verify(signature, for: testData, from: peerID)
            XCTAssertTrue(isValid, "Signature should be valid")
            
            // Test with modified data (should fail)
            let modifiedData = "Modified test data".data(using: .utf8)!
            let isValidModified = try encryptionService.verify(signature, for: modifiedData, from: peerID)
            XCTAssertFalse(isValidModified, "Signature should be invalid for modified data")
        } catch {
            XCTFail("Legacy sign/verify should work: \(error)")
        }
    }
    
    // MARK: - Enhanced Room Encryption Tests
    
    func testEnhancedRoomKeyDerivation() {
        let password = "test-room-password"
        let roomName = "#enhanced-test-room"
        
        // Test different difficulty levels
        let fastKey = encryptionService.deriveRoomKey(password: password, roomName: roomName, difficulty: .fast)
        let standardKey = encryptionService.deriveRoomKey(password: password, roomName: roomName, difficulty: .standard)
        let secureKey = encryptionService.deriveRoomKey(password: password, roomName: roomName, difficulty: .secure)
        
        // Keys should be different for different difficulty levels
        XCTAssertNotEqual(fastKey.withUnsafeBytes { Data($0) }, 
                         standardKey.withUnsafeBytes { Data($0) },
                         "Different difficulty levels should produce different keys")
        
        XCTAssertNotEqual(standardKey.withUnsafeBytes { Data($0) }, 
                         secureKey.withUnsafeBytes { Data($0) },
                         "Different difficulty levels should produce different keys")
        
        // Same parameters should produce same key
        let duplicateKey = encryptionService.deriveRoomKey(password: password, roomName: roomName, difficulty: .standard)
        XCTAssertEqual(standardKey.withUnsafeBytes { Data($0) }, 
                      duplicateKey.withUnsafeBytes { Data($0) },
                      "Same parameters should produce same key")
    }
    
    func testEnhancedRoomMessageEncryption() {
        let password = "secure-room-password"
        let roomName = "#secure-room"
        let testMessage = "This is a secret room message with enhanced security!"
        
        // Derive room key
        let roomKey = encryptionService.deriveRoomKey(password: password, roomName: roomName, difficulty: .standard)
        
        // Create room metadata
        let metadata = RoomMetadata(
            roomName: roomName,
            version: "1.0",
            participants: ["alice", "bob"]
        )
        
        // Test enhanced room message encryption
        do {
            let messageData = testMessage.data(using: .utf8)!
            let encryptedData = try encryptionService.encryptRoomMessage(messageData, key: roomKey, roomMetadata: metadata)
            
            XCTAssertGreaterThan(encryptedData.count, messageData.count, "Encrypted data should be larger")
            
            // Test decryption with correct metadata
            let decryptedData = try encryptionService.decryptRoomMessage(encryptedData, key: roomKey, expectedMetadata: metadata)
            let decryptedMessage = String(data: decryptedData, encoding: .utf8)
            
            XCTAssertEqual(decryptedMessage, testMessage, "Decrypted message should match original")
            
            // Test that wrong metadata fails
            let wrongMetadata = RoomMetadata(roomName: "#wrong-room", version: "1.0", participants: nil)
            XCTAssertThrowsError(try encryptionService.decryptRoomMessage(encryptedData, key: roomKey, expectedMetadata: wrongMetadata)) {
                error in
                XCTAssertTrue(error is EncryptionError, "Should throw EncryptionError for wrong metadata")
            }
            
        } catch {
            XCTFail("Enhanced room encryption should work: \(error)")
        }
    }
    
    // MARK: - Integration with Existing Architecture Tests
    
    func testBluetoothMeshServiceIntegration() {
        // Test that BluetoothMeshService can access the enhanced encryption service
        let meshService = BluetoothMeshService()
        
        // Verify that encryption service is accessible
        XCTAssertNotNil(meshService.encryptionService, "BluetoothMeshService should have access to encryption service")
        
        // Test that we can get key data for key exchange
        let keyData = meshService.encryptionService.getCombinedPublicKeyData()
        XCTAssertEqual(keyData.count, 96, "Key exchange data should be 96 bytes")
    }
    
    func testChatViewModelRoomKeyDerivation() {
        // Create a ChatViewModel instance
        let meshService = BluetoothMeshService()
        let chatViewModel = ChatViewModel(meshService: meshService)
        
        // Test that room key derivation works through the view model's private method
        // We'll test this indirectly by verifying that the enhanced service is accessible
        XCTAssertNotNil(meshService.encryptionService, "ChatViewModel should have access to enhanced encryption through mesh service")
        
        // Test enhanced room key derivation
        let password = "test-password"
        let roomName = "#test-room"
        let roomKey = meshService.encryptionService.deriveRoomKey(password: password, roomName: roomName, difficulty: .standard)
        
        // Verify the key is valid
        XCTAssertEqual(roomKey.withUnsafeBytes { $0.count }, 32, "Room key should be 32 bytes")
    }
    
    // MARK: - Security Feature Tests
    
    func testKeyRotationCompatibility() {
        // Test that session key rotation works without breaking compatibility
        let peerID = "rotation-test-peer"
        let testMessage = "Message before rotation"
        
        // Set up peer
        let keyData = encryptionService.getCombinedPublicKeyData()
        XCTAssertNoThrow(try encryptionService.addPeerPublicKey(peerID, publicKeyData: keyData))
        
        // Encrypt message before rotation
        let messageData = testMessage.data(using: .utf8)!
        let encryptedBefore = try! encryptionService.encrypt(messageData, for: peerID)
        
        // Trigger key rotation
        encryptionService.rotateSessionKeys()
        
        // Should still be able to decrypt message from before rotation
        XCTAssertNoThrow(try encryptionService.decrypt(encryptedBefore, from: peerID))
        
        // Should be able to encrypt new messages after rotation
        let newMessage = "Message after rotation"
        let newMessageData = newMessage.data(using: .utf8)!
        XCTAssertNoThrow(try encryptionService.encrypt(newMessageData, for: peerID))
    }
    
    func testPanicModeCompatibility() {
        let peerID = "panic-test-peer"
        
        // Set up peer
        let keyData = encryptionService.getCombinedPublicKeyData()
        XCTAssertNoThrow(try encryptionService.addPeerPublicKey(peerID, publicKeyData: keyData))
        
        // Verify peer is set up
        XCTAssertNotNil(encryptionService.getPeerIdentityKey(peerID))
        
        // Trigger panic mode (clear all states)
        encryptionService.clearPersistentIdentity()
        
        // Verify all peer data is cleared
        XCTAssertNil(encryptionService.getPeerIdentityKey(peerID))
    }
    
    // MARK: - Performance Tests
    
    func testEnhancedEncryptionPerformance() {
        let peerID = "performance-test-peer"
        let testMessage = "Performance test message"
        let messageData = testMessage.data(using: .utf8)!
        
        // Set up peer
        let keyData = encryptionService.getCombinedPublicKeyData()
        try! encryptionService.addPeerPublicKey(peerID, publicKeyData: keyData)
        
        // Measure encryption performance
        measure {
            for _ in 0..<100 {
                _ = try! encryptionService.encrypt(messageData, for: peerID)
            }
        }
    }
    
    func testRoomKeyDerivationPerformance() {
        let password = "performance-test-password"
        let roomName = "#performance-room"
        
        // Measure room key derivation performance
        measure {
            for _ in 0..<10 { // Fewer iterations since Argon2id is computationally intensive
                _ = encryptionService.deriveRoomKey(password: password, roomName: roomName, difficulty: .fast)
            }
        }
    }
} 