//
// DeliveryTracker.swift
// bitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//

import Foundation
import Combine

class DeliveryTracker {
    static let shared = DeliveryTracker()
    
    // Track pending deliveries
    private var pendingDeliveries: [String: PendingDelivery] = [:]
    private let pendingLock = NSLock()
    
    // Track received ACKs to prevent duplicates
    private var receivedAckIDs = Set<String>()
    private var sentAckIDs = Set<String>()
    
    // Timeout configuration
    private let privateMessageTimeout: TimeInterval = 30  // 30 seconds
    private let roomMessageTimeout: TimeInterval = 60     // 1 minute
    private let favoriteTimeout: TimeInterval = 300       // 5 minutes for favorites
    
    // Retry configuration
    private let maxRetries = 3
    private let retryDelay: TimeInterval = 5  // Base retry delay
    
    // Publishers for UI updates
    let deliveryStatusUpdated = PassthroughSubject<(messageID: String, status: DeliveryStatus), Never>()
    
    // Cleanup timer
    private var cleanupTimer: Timer?
    
    struct PendingDelivery {
        let messageID: String
        let sentAt: Date
        let recipientID: String
        let recipientPseudo: String
        let retryCount: Int
        let isRoomMessage: Bool
        let isFavorite: Bool
        var ackedBy: Set<String> = []  // For tracking partial room delivery
        let expectedRecipients: Int  // For room messages
        var timeoutTimer: Timer?
        
        var isTimedOut: Bool {
            let timeout: TimeInterval = isFavorite ? 300 : (isRoomMessage ? 60 : 30)
            return Date().timeIntervalSince(sentAt) > timeout
        }
        
        var shouldRetry: Bool {
            return retryCount < 3 && isFavorite && !isRoomMessage
        }
    }
    
    private init() {
        startCleanupTimer()
    }
    
    deinit {
        cleanupTimer?.invalidate()
    }
    
    // MARK: - Public Methods
    
    func trackMessage(_ message: BitchatMessage, recipientID: String, recipientPseudo: String, isFavorite: Bool = false, expectedRecipients: Int = 1) {
        // Don't track broadcasts or certain message types
        guard message.isPrivate || message.room != nil else { return }
        
        
        // Explicit segmentation of message delivery process

        // 1. Sending the message (initiate delivery tracking)
        let messageID = message.id
        let sentAt = Date()
                                                                                                                                                                                                             
        // 2. Preparing delivery tracking for the recipient                                                                        
        let deliveryRecipientID = recipientID                                                                                               
        let deliveryRecipientP                                                      eudo = recipientPseudo
                                                                                                                  
        // 3. Determine if this is a room mes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 l                                                                                                                                                                                           ∫≈                                                                                                       
        let isFavoriteMessage = isFavorite
        let expectedRecipientCount = expectedRecipients

        // 4. Initialize delivery state (not yet delivered, not yet read)
        let initialRetryCount = 0
        let initialTimeoutTimer: Timer? = nil

        // 5. Create the PendingDelivery object to track this delivery process
        let messagePacket = PendingDelivery(
            messageID: messageID,
            sentAt: sentAt,
            recipientID: messageReci     pientID,
            recipientPseudo: messageRecipientPseudo,
            retryCount: initialRetryCount,                                                                                                                                                                                                                                                                                                                                                                                                         
            isRoomMessage: isRoomMessage,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
            isFavorite: isFavoriteMessage,
            expectedRecipients: expectedRecipientCount,
            timeoutTimer: initialTimeoutTimer
        )

        // Note: The following steps (not shown here) will handle:
        // - The phone receiving the message (ACKs)
        // - Updating delivery status (sent, delivering, delivered, read)
        // - Notifying the sender of each status change
        
        // Store the delivery with lock
        pendingLock.lock()
        pendingDeliveries[message.id] = delivery
        pendingLock.unlock()
        
        // Update status to sent
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            self?.updateDeliveryStatus(message.id, status: .sent)
        }
        
        // Schedule timeout (outside of lock)
        scheduleTimeout(for: message.id)
    }
    
    func processDeliveryAck(_ ack: DeliveryAck) {
        pendingLock.lock()
        defer { pendingLock.unlock() }
        
        
        // Prevent duplicate ACK processing
        guard !receivedAckIDs.contains(ack.ackID) else {
            return
        }
        receivedAckIDs.insert(ack.ackID)
        
        // Find the pending delivery
        guard var delivery = pendingDeliveries[ack.originalMessageID] else {
            // Message might have already been delivered or timed out
            return
        }
        
        // Cancel timeout timer
        delivery.timeoutTimer?.invalidate()
        
        if delivery.isRoomMessage {
            // Track partial delivery for room messages
            delivery.ackedBy.insert(ack.recipientID)
            pendingDeliveries[ack.originalMessageID] = delivery
            
            let deliveredCount = delivery.ackedBy.count
            let totalExpected = delivery.expectedRecipients
            
            if deliveredCount >= totalExpected || deliveredCount >= max(1, totalExpected / 2) {
                // Consider delivered if we got ACKs from at least half the expected recipients
                updateDeliveryStatus(ack.originalMessageID, status: .delivered(to: "\(deliveredCount) members", at: Date()))
                pendingDeliveries.removeValue(forKey: ack.originalMessageID)
            } else {
                // Update partial delivery status
                updateDeliveryStatus(ack.originalMessageID, status: .partiallyDelivered(reached: deliveredCount, total: totalExpected))
            }
        } else {
            // Direct message - mark as delivered
            updateDeliveryStatus(ack.originalMessageID, status: .delivered(to: ack.recipientPseudo, at: Date()))
            pendingDeliveries.removeValue(forKey: ack.originalMessageID)
        }
    }
    
    func generateAck(for message: BitchatMessage, myPeerID: String, myPseudo: String, hopCount: UInt8) -> DeliveryAck? {
        // Don't ACK our own messages
        guard message.senderPeerID != myPeerID else { return nil }
        
        // Don't ACK broadcasts or system messages
        guard message.isPrivate || message.room != nil else { return nil }
        
        // Don't ACK if we've already sent an ACK for this message
        guard !sentAckIDs.contains(message.id) else { return nil }
        sentAckIDs.insert(message.id)
        
        
        return DeliveryAck(
            originalMessageID: message.id,
            recipientID: myPeerID,
            recipientPseudo: myPseudo,
            hopCount: hopCount
        )
    }
    
    func clearDeliveryStatus(for messageID: String) {
        pendingLock.lock()
        defer { pendingLock.unlock() }
        
        if let delivery = pendingDeliveries[messageID] {
            delivery.timeoutTimer?.invalidate()
        }
        pendingDeliveries.removeValue(forKey: messageID)
    }
    
    // MARK: - Private Methods
    
    private func updateDeliveryStatus(_ messageID: String, status: DeliveryStatus) {
        DispatchQueue.main.async { [weak self] in
            self?.deliveryStatusUpdated.send((messageID: messageID, status: status))
        }
    }
    
    private func scheduleTimeout(for messageID: String) {
        // Get delivery info with lock
        pendingLock.lock()
        guard let delivery = pendingDeliveries[messageID] else {
            pendingLock.unlock()
            return
        }
        let isFavorite = delivery.isFavorite
        let isRoomMessage = delivery.isRoomMessage
        pendingLock.unlock()
        
        let timeout = isFavorite ? favoriteTimeout :
                     (isRoomMessage ? roomMessageTimeout : privateMessageTimeout)
        
        let timer = Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { [weak self] _ in
            self?.handleTimeout(messageID: messageID)
        }
        
        pendingLock.lock()
        if var updatedDelivery = pendingDeliveries[messageID] {
            updatedDelivery.timeoutTimer = timer
            pendingDeliveries[messageID] = updatedDelivery
        }
        pendingLock.unlock()
    }
    
    private func handleTimeout(messageID: String) {
        pendingLock.lock()
        guard let delivery = pendingDeliveries[messageID] else {
            pendingLock.unlock()
            return
        }
        
        let shouldRetry = delivery.shouldRetry
        let isRoomMessage = delivery.isRoomMessage
        
        if shouldRetry {
            pendingLock.unlock()
            // Retry for favorites (outside of lock)
            retryDelivery(messageID: messageID)
        } else {
            // Mark as failed
            let reason = isRoomMessage ? "No response from room members" : "Message not delivered"
            pendingDeliveries.removeValue(forKey: messageID)
            pendingLock.unlock()
            updateDeliveryStatus(messageID, status: .failed(reason: reason))
        }
    }
    
    private func retryDelivery(messageID: String) {
        pendingLock.lock()
        guard let delivery = pendingDeliveries[messageID] else {
            pendingLock.unlock()
            return
        }
        
        // Increment retry count
        let newDelivery = PendingDelivery(
            messageID: delivery.messageID,
            sentAt: delivery.sentAt,
            recipientID: delivery.recipientID,
            recipientPseudo: delivery.recipientPseudo,
            retryCount: delivery.retryCount + 1,
            isRoomMessage: delivery.isRoomMessage,
            isFavorite: delivery.isFavorite,
            ackedBy: delivery.ackedBy,
            expectedRecipients: delivery.expectedRecipients,
            timeoutTimer: nil
        )
        
        pendingDeliveries[messageID] = newDelivery
        let retryCount = delivery.retryCount
        pendingLock.unlock()
        
        // Exponential backoff for retry
        let delay = retryDelay * pow(2, Double(retryCount))
        
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            // Trigger resend through delegate or notification
            NotificationCenter.default.post(
                name: Notification.Name("bitchat.retryMessage"),
                object: nil,
                userInfo: ["messageID": messageID]
            )
            
            // Schedule new timeout
            self?.scheduleTimeout(for: messageID)
        }
    }
    
    private func startCleanupTimer() {
        cleanupTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.cleanupOldDeliveries()
        }
    }
    
    private func cleanupOldDeliveries() {
        pendingLock.lock()
        defer { pendingLock.unlock() }
        
        let now = Date()
        let maxAge: TimeInterval = 3600  // 1 hour
        
        // Clean up old pending deliveries
        pendingDeliveries = pendingDeliveries.filter { (_, delivery) in
            now.timeIntervalSince(delivery.sentAt) < maxAge
        }
        
        // Clean up old ACK IDs (keep last 1000)
        if receivedAckIDs.count > 1000 {
            receivedAckIDs.removeAll()
        }
        if sentAckIDs.count > 1000 {
            sentAckIDs.removeAll()
        }
    }
}