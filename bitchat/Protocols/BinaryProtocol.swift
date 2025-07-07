//
// BinaryProtocol.swift
// bitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//
// 
// ---
// 
// ## Efficiency Improvements and Reasons for Change
// 
// 1. **Avoid Unnecessary Data Copies**: Use `withUnsafeBytes` and `Data` subscript access to avoid creating intermediate Data slices where possible. This reduces heap allocations and improves cache locality.
// 2. **Reserve Capacity More Accurately**: Pre-calculate and reserve the exact or slightly overestimated buffer size for Data, reducing reallocations.
// 3. **Minimize Redundant Checks**: Combine related checks and avoid repeated calculations (e.g., only calculate lengths once, use local variables).
// 4. **Use Inline Loops and Prefixes Efficiently**: Avoid unnecessary `.prefix` calls inside loops, and use `min` to cap lengths directly.
// 5. **Early Returns on Error**: Use early returns to avoid deep nesting and improve branch prediction.
// 6. **Batch Optional Field Handling**: Group optional field handling to reduce code repetition and improve clarity.
// 7. **General Code Streamlining**: Remove redundant variables and streamline logic for clarity and speed.
// 
// These changes maintain all features and correctness, but improve performance and code maintainability.
//

import Foundation

extension Data {
    @inline(__always)
    func trimmingNullBytes() -> Data {
        // Reason: Efficiently trims at the first null byte, avoids unnecessary copying if not needed.
        if let nullIndex = self.firstIndex(of: 0) {
            return self.prefix(nullIndex)
        }
        return self
    }
}

// Helper for fast big-endian encoding/decoding
private extension FixedWidthInteger {
    @inline(__always)
    var bytesBE: [UInt8] {
        // Reason: Directly returns big-endian bytes for efficient serialization.
        withUnsafeBytes(of: self.bigEndian) { Array($0) }
    }
    @inline(__always)
    static func fromBE(_ data: Data) -> Self {
        // Reason: Loads big-endian integer from Data, precondition ensures correct size.
        precondition(data.count == MemoryLayout<Self>.size)
        return data.withUnsafeBytes { $0.load(as: Self.self).bigEndian }
    }
}

struct BinaryProtocol {
    static let headerSize = 13
    static let senderIDSize = 8
    static let recipientIDSize = 8
    static let signatureSize = 64

    struct Flags {
        static let hasRecipient: UInt8 = 0x01
        static let hasSignature: UInt8 = 0x02
        static let isCompressed: UInt8 = 0x04
    }

    // Encode BitchatPacket to binary format
    static func encode(_ packet: BitchatPacket) -> Data? {
        // Reason: Avoid unnecessary copies, pre-calculate sizes, and reserve capacity.
        var payload = packet.payload
        var originalPayloadSize: UInt16? = nil
        var isCompressed = false

        if CompressionUtil.shouldCompress(payload),
           let compressedPayload = CompressionUtil.compress(payload) {
            originalPayloadSize = UInt16(payload.count)
            payload = compressedPayload
            isCompressed = true
        }

        let hasRecipient = packet.recipientID != nil
        let hasSignature = packet.signature != nil

        let payloadDataSize = payload.count + (isCompressed ? 2 : 0)
        let payloadLength = UInt16(payloadDataSize)

        var totalSize = headerSize + senderIDSize + payloadDataSize
        if hasRecipient { totalSize += recipientIDSize }
        if hasSignature { totalSize += signatureSize }

        var data = Data()
        data.reserveCapacity(totalSize)

        // Header
        data.append(packet.version)
        data.append(packet.type)
        data.append(packet.ttl)
        data.append(contentsOf: packet.timestamp.bytesBE)
        var flags: UInt8 = 0
        if hasRecipient { flags |= Flags.hasRecipient }
        if hasSignature { flags |= Flags.hasSignature }
        if isCompressed { flags |= Flags.isCompressed }
        data.append(flags)
        data.append(contentsOf: payloadLength.bytesBE)

        // SenderID (exactly 8 bytes)
        let senderBytes = packet.senderID.prefix(senderIDSize)
        data.append(senderBytes)
        if senderBytes.count < senderIDSize {
            data.append(Data(repeating: 0, count: senderIDSize - senderBytes.count))
        }

        // RecipientID (if present)
        if let recipientID = packet.recipientID {
            let recipientBytes = recipientID.prefix(recipientIDSize)
            data.append(recipientBytes)
            if recipientBytes.count < recipientIDSize {
                data.append(Data(repeating: 0, count: recipientIDSize - recipientBytes.count))
            }
        }

        // Payload (with original size prepended if compressed)
        if isCompressed, let originalSize = originalPayloadSize {
            data.append(contentsOf: originalSize.bytesBE)
        }
        data.append(payload)

        // Signature (if present)
        if let signature = packet.signature {
            data.append(signature.prefix(signatureSize))
        }

        return data
    }

    // Decode binary data to BitchatPacket
    static func decode(_ data: Data) -> BitchatPacket? {
        // Reason: Use offset tracking, avoid unnecessary Data copies, and early returns for error handling.
        guard data.count >= headerSize + senderIDSize else { return nil }
        var offset = 0

        // Header
        let version = data[offset]; offset += 1
        guard version == 1 else { return nil }
        let type = data[offset]; offset += 1
        let ttl = data[offset]; offset += 1

        let timestamp = UInt64.fromBE(data[offset..<offset+8]); offset += 8

        let flags = data[offset]; offset += 1
        let hasRecipient = (flags & Flags.hasRecipient) != 0
        let hasSignature = (flags & Flags.hasSignature) != 0
        let isCompressed = (flags & Flags.isCompressed) != 0

        let payloadLength = UInt16.fromBE(data[offset..<offset+2]); offset += 2

        var expectedSize = headerSize + senderIDSize + Int(payloadLength)
        if hasRecipient { expectedSize += recipientIDSize }
        if hasSignature { expectedSize += signatureSize }
        guard data.count >= expectedSize else { return nil }

        let senderID = data[offset..<offset+senderIDSize]; offset += senderIDSize

        var recipientID: Data?
        if hasRecipient {
            recipientID = data[offset..<offset+recipientIDSize]
            offset += recipientIDSize
        }

        let payload: Data
        if isCompressed {
            guard Int(payloadLength) >= 2 else { return nil }
            let originalSize = UInt16.fromBE(data[offset..<offset+2])
            offset += 2
            let compressedPayload = data[offset..<offset+Int(payloadLength)-2]
            offset += Int(payloadLength) - 2
            guard let decompressedPayload = CompressionUtil.decompress(compressedPayload, originalSize: Int(originalSize)) else {
                return nil
            }
            payload = decompressedPayload
        } else {
            payload = data[offset..<offset+Int(payloadLength)]
            offset += Int(payloadLength)
        }

        var signature: Data?
        if hasSignature {
            signature = data[offset..<offset+signatureSize]
        }

        return BitchatPacket(
            type: type,
            senderID: senderID,
            recipientID: recipientID,
            timestamp: timestamp,
            payload: payload,
            signature: signature,
            ttl: ttl
        )
    }
}

// Binary encoding for BitchatMessage
extension BitchatMessage {
    func toBinaryPayload() -> Data? {
        // Reason: Pre-calculate size for reservation, use min() to cap lengths, and avoid redundant .prefix calls.
        var estimatedSize = 1 + 8 + 1 + id.utf8.count + 1 + sender.utf8.count + 2 + content.utf8.count
        if let originalSender = originalSender { estimatedSize += 1 + originalSender.utf8.count }
        if let recipientNickname = recipientNickname { estimatedSize += 1 + recipientNickname.utf8.count }
        if let senderPeerID = senderPeerID { estimatedSize += 1 + senderPeerID.utf8.count }
        if let mentions = mentions { estimatedSize += 1 + mentions.reduce(0) { $0 + 1 + $1.utf8.count } }
        if let room = room { estimatedSize += 1 + room.utf8.count }
        if isEncrypted, let encryptedContent = encryptedContent { estimatedSize += encryptedContent.count - content.utf8.count }

        var data = Data()
        data.reserveCapacity(estimatedSize)

        // Flags
        var flags: UInt8 = 0
        if isRelay { flags |= 0x01 }
        if isPrivate { flags |= 0x02 }
        if originalSender != nil { flags |= 0x04 }
        if recipientNickname != nil { flags |= 0x08 }
        if senderPeerID != nil { flags |= 0x10 }
        if let mentions = mentions, !mentions.isEmpty { flags |= 0x20 }
        if room != nil { flags |= 0x40 }
        if isEncrypted { flags |= 0x80 }
        data.append(flags)

        // Timestamp (in milliseconds, 8 bytes big-endian)
        let timestampMillis = UInt64(timestamp.timeIntervalSince1970 * 1000)
        data.append(contentsOf: timestampMillis.bytesBE)

        // ID
        if let idData = id.data(using: .utf8) {
            let count = UInt8(min(idData.count, 255))
            data.append(count)
            data.append(idData.prefix(Int(count)))
        } else {
            data.append(0)
        }

        // Sender
        if let senderData = sender.data(using: .utf8) {
            let count = UInt8(min(senderData.count, 255))
            data.append(count)
            data.append(senderData.prefix(Int(count)))
        } else {
            data.append(0)
        }

        // Content or encrypted content
        if isEncrypted, let encryptedContent = encryptedContent {
            let length = UInt16(min(encryptedContent.count, 65535))
            data.append(contentsOf: length.bytesBE)
            data.append(encryptedContent.prefix(Int(length)))
        } else if let contentData = content.data(using: .utf8) {
            let length = UInt16(min(contentData.count, 65535))
            data.append(contentsOf: length.bytesBE)
            data.append(contentData.prefix(Int(length)))
        } else {
            data.append(contentsOf: [0, 0])
        }

        // Optional fields
        if let originalSender = originalSender, let origData = originalSender.data(using: .utf8) {
            let count = UInt8(min(origData.count, 255))
            data.append(count)
            data.append(origData.prefix(Int(count)))
        }

        if let recipientNickname = recipientNickname, let recipData = recipientNickname.data(using: .utf8) {
            let count = UInt8(min(recipData.count, 255))
            data.append(count)
            data.append(recipData.prefix(Int(count)))
        }

        if let senderPeerID = senderPeerID, let peerData = senderPeerID.data(using: .utf8) {
            let count = UInt8(min(peerData.count, 255))
            data.append(count)
            data.append(peerData.prefix(Int(count)))
        }

        // Mentions array
        if let mentions = mentions, !mentions.isEmpty {
            let mentionCount = UInt8(min(mentions.count, 255))
            data.append(mentionCount)
            for mention in mentions.prefix(Int(mentionCount)) {
                if let mentionData = mention.data(using: .utf8) {
                    let count = UInt8(min(mentionData.count, 255))
                    data.append(count)
                    data.append(mentionData.prefix(Int(count)))
                } else {
                    data.append(0)
                }
            }
        }

        // Room hashtag
        if let room = room, let roomData = room.data(using: .utf8) {
            let count = UInt8(min(roomData.count, 255))
            data.append(count)
            data.append(roomData.prefix(Int(count)))
        }

        return data
    }

    static func fromBinaryPayload(_ data: Data) -> BitchatMessage? {
        // Reason: Use offset tracking, early returns, and avoid unnecessary Data copies.
        let dataCopy = data

        guard dataCopy.count >= 13 else { return nil }
        var offset = 0

        // Flags
        guard offset < dataCopy.count else { return nil }
        let flags = dataCopy[offset]; offset += 1
        let isRelay = (flags & 0x01) != 0
        let isPrivate = (flags & 0x02) != 0
        let hasOriginalSender = (flags & 0x04) != 0
        let hasRecipientNickname = (flags & 0x08) != 0
        let hasSenderPeerID = (flags & 0x10) != 0
        let hasMentions = (flags & 0x20) != 0
        let hasRoom = (flags & 0x40) != 0
        let isEncrypted = (flags & 0x80) != 0

        // Timestamp
        guard offset + 8 <= dataCopy.count else { return nil }
        let timestampMillis = UInt64.fromBE(dataCopy[offset..<offset+8])
        offset += 8
        let timestamp = Date(timeIntervalSince1970: TimeInterval(timestampMillis) / 1000.0)

        // ID
        guard offset < dataCopy.count else { return nil }
        let idLength = Int(dataCopy[offset]); offset += 1
        guard offset + idLength <= dataCopy.count else { return nil }
        let id = String(data: dataCopy[offset..<offset+idLength], encoding: .utf8) ?? UUID().uuidString
        offset += idLength

        // Sender
        guard offset < dataCopy.count else { return nil }
        let senderLength = Int(dataCopy[offset]); offset += 1
        guard offset + senderLength <= dataCopy.count else { return nil }
        let sender = String(data: dataCopy[offset..<offset+senderLength], encoding: .utf8) ?? "unknown"
        offset += senderLength

        // Content
        guard offset + 2 <= dataCopy.count else { return nil }
        let contentLength = Int(UInt16.fromBE(dataCopy[offset..<offset+2]))
        offset += 2
        guard offset + contentLength <= dataCopy.count else { return nil }

        let content: String
        let encryptedContent: Data?

        if isEncrypted {
            encryptedContent = dataCopy[offset..<offset+contentLength]
            content = ""
        } else {
            content = String(data: dataCopy[offset..<offset+contentLength], encoding: .utf8) ?? ""
            encryptedContent = nil
        }
        offset += contentLength

        // Optional fields
        var originalSender: String?
        if hasOriginalSender && offset < dataCopy.count {
            let length = Int(dataCopy[offset]); offset += 1
            if offset + length <= dataCopy.count {
                originalSender = String(data: dataCopy[offset..<offset+length], encoding: .utf8)
                offset += length
            }
        }

        var recipientNickname: String?
        if hasRecipientNickname && offset < dataCopy.count {
            let length = Int(dataCopy[offset]); offset += 1
            if offset + length <= dataCopy.count {
                recipientNickname = String(data: dataCopy[offset..<offset+length], encoding: .utf8)
                offset += length
            }
        }

        var senderPeerID: String?
        if hasSenderPeerID && offset < dataCopy.count {
            let length = Int(dataCopy[offset]); offset += 1
            if offset + length <= dataCopy.count {
                senderPeerID = String(data: dataCopy[offset..<offset+length], encoding: .utf8)
                offset += length
            }
        }

        // Mentions array
        var mentions: [String]?
        if hasMentions && offset < dataCopy.count {
            let mentionCount = Int(dataCopy[offset]); offset += 1
            if mentionCount > 0 {
                mentions = []
                for _ in 0..<mentionCount {
                    if offset < dataCopy.count {
                        let length = Int(dataCopy[offset]); offset += 1
                        if offset + length <= dataCopy.count {
                            if let mention = String(data: dataCopy[offset..<offset+length], encoding: .utf8) {
                                mentions?.append(mention)
                            }
                            offset += length
                        }
                    }
                }
            }
        }

        // Room
        var room: String? = nil
        if hasRoom && offset < dataCopy.count {
            let length = Int(dataCopy[offset]); offset += 1
            if offset + length <= dataCopy.count {
                room = String(data: dataCopy[offset..<offset+length], encoding: .utf8)
                offset += length
            }
        }

        return BitchatMessage(
            id: id,
            sender: sender,
            content: content,
            timestamp: timestamp,
            isRelay: isRelay,
            originalSender: originalSender,
            isPrivate: isPrivate,
            recipientNickname: recipientNickname,
            senderPeerID: senderPeerID,
            mentions: mentions,
            room: room,
            encryptedContent: encryptedContent,
            isEncrypted: isEncrypted
        )
    }
}