// The Swift Programming Language
// https://docs.swift.org/swift-book

@preconcurrency import SealdSdk
import CryptoKit
import UIKit
@preconcurrency import CometChatSDK
import Security

final public class CometChatSealdSDK: Sendable {
    private let seald: SealdSdk!
    private let uid: String
    
    
    public init?(uid: String, appId: String, apiUrl: String, encryptionSessionCacheTTL: TimeInterval = 0) throws {
        guard let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return nil  // Failable init will return nil if documentsPath is not found
        }
        
        self.uid = uid
        
        do {
            self.seald = try SealdSdk.init(
                apiUrl: apiUrl,
                appId: appId,
                databasePath: "\(documentsPath.relativePath)/sealdDB/\(uid)",
                databaseEncryptionKey: CometChatSealdSDK.generateDBEncryptionKey(from: uid),
                instanceName: "\(uid)",
                logLevel: 0,
                logNoColor: true,
                encryptionSessionCacheTTL: encryptionSessionCacheTTL,
                keySize: 4096
            )
            SealdSdk.initialize()
            Task { [weak self] in
                await self?.populateSessionsCache()
            }
            
        } catch {
            throw error  // If any error occurs, return nil instead of throwing
        }
    }
    
    private func populateSessionsCache() async {
        guard let currUser = CometChat.getLoggedInUser(),
              let metaData = currUser.metadata,
              let sessionsId = metaData[SealdMetadataConstants.sessionsMetaadataKey] as? [String: String] else {
            return
        }
        
        for (receiverUid, sessionId)in sessionsId {
            if let session = try? seald.retrieveEncryptionSession(withSessionId: sessionId, useCache: true, lookupProxyKey: false, lookupGroupKey: false) {
                await CometChatSealdGlobalActor.shared.setSession(session, for: receiverUid)
                
            }
        }
    }
    
    static private func generateDBEncryptionKey(from userID: String) -> Data {
        if let data = getKeyFromKeychain(for: userID) {
            return data
        }
        
        let inputKey = SymmetricKey(data: userID.data(using: .utf8)!) // Convert user ID to key
        let salt = UUID().uuidString.data(using: .utf8)! // Salt ensures uniqueness across different contexts
        
        let derivedKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: Data(), // Additional context (optional)
            outputByteCount: 64 // Generate 64 bytes of cryptographic random data
        )
        
        let data = Data(derivedKey.withUnsafeBytes { Data($0) }) // Convert key to Data
        saveKeyToKeychain(data, for: userID)
        return data
    }
    
    static private func getKeyFromKeychain(for key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess, let data = result as? Data {
            return data
        }
        return nil
    }
    
    static private func saveKeyToKeychain(_ data: Data, for key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        SecItemDelete(query as CFDictionary) // Delete any existing key before saving
        SecItemAdd(query as CFDictionary, nil)
    }
}

public extension CometChatSealdSDK {
    
    private func isAccountAlreadyExist() -> Bool {
        seald.getCurrentAccountInfo() != nil
    }
    
    func getSealdAccountInfo() -> SealdAccountInfo? {
        seald.getCurrentAccountInfo()
    }
    
    func setupAccount(for user: User, signupJwt: String, completion: @escaping (Result<Void, CometChatException>) -> Void) async {
        if !isAccountAlreadyExist() {
            await createAccount(for: user, withSignupJwt: signupJwt) { [weak self] result in
                switch result {
                    
                case .success(let sealdAccountInfo):
                    self?.updateMetadataForSeadId(user: user, sealdID: sealdAccountInfo.userId, completion: completion)
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        } else {
            completion(.success(()))
        }
    }
    
    private func createAccount(for user: User, withSignupJwt: String, completion: @escaping (Result<SealdAccountInfo, CometChatException>) -> Void) async {
        guard let uid = user.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "user uid not found")))
            return
        }
        do {
            let sealdAccountInfo = try await seald.createAccountAsync(
                withSignupJwt: withSignupJwt,
                deviceName: UIDevice.current.identifierForVendor!.uuidString,
                displayName: uid,
                privateKeys: nil,
                expireAfter: 5 * 365 * 24 * 60 * 60
            )
            completion(.success(sealdAccountInfo))
        } catch {
            completion(.failure(error.toCometChatException))
        }
    }
    
    private func updateMetadataForSeadId(user: User, sealdID: String, completion: @escaping (Result<Void, CometChatException>) -> Void) {
        guard let uid = user.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
            return
        }
        if  user.metadata == nil {
            user.metadata = [:]
        }
        user.metadata![SealdMetadataConstants.sealdID] = sealdID
        
        CometChat.updateCurrentUserDetails(user: user, onSuccess: { user in
            completion(.success(()))
        }, onError: { error in
            if let error  {
                completion(.failure(error))
            } else {
                completion(.failure(.nilException("failed to update metadata for \(uid)")))
            }
        })
    }
}

public extension CometChatSealdSDK {
    
    private func getSessionFromCache(for receiver: User, completion: @escaping @Sendable (Result<SealdEncryptionSession?, CometChatException>) -> Void) {
        guard let receiverUid = receiver.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
            return
        }
        Task {
            let session = await CometChatSealdGlobalActor.shared.sessions[receiverUid]
            completion(.success(session))
        }
    }
    
    private func getSessionFromCustomMsg(for receiver: User, completion: @escaping (Result<SealdEncryptionSession?, CometChatException>) -> Void) {
        guard let receiverUid = receiver.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
            return
        }
        let reqBuilder = MessagesRequest
            .MessageRequestBuilder().set(limit: 1)
            .hideDeletedMessages(hide: true)
            .set(types: [SealdMetadataConstants.customMessageType])
            .set(uid: receiverUid)
            .build()
        
        // Store the request to keep it alive
        Task {@Sendable () -> Void in
            await CometChatSealdGlobalActor.shared.appendActiveRequest(reqBuilder)
        }
        
        reqBuilder.fetchPrevious { [weak self] msgs in
            // Remove request after completion
            defer {
                Task {@Sendable () -> Void in
                    await CometChatSealdGlobalActor.shared.removeActiveRequest(reqBuilder)
                }
            }
            if let msg = msgs?.first as? CustomMessage,
               let customData = msg.customData,
               let encryptedTxt = customData[SealdMetadataConstants.customMetaDataKey] as? String {
                let session = try? self?.seald.retrieveEncryptionSession(
                    fromMessage: encryptedTxt,
                    useCache: true,
                    lookupProxyKey: true,
                    lookupGroupKey: true
                )
                completion(.success(session))
            } else {
                completion(.success(nil)) // No session found
            }
        } onError: { [weak self] error in
            // Remove request after error
            defer {
                Task {@Sendable () -> Void in
                    await CometChatSealdGlobalActor.shared.removeActiveRequest(reqBuilder)
                }
            }
            if let error = error {
                completion(.failure(error))
            } else {
                completion(.failure(.nilException("failed to fetch custom-encryption message")))
            }
        }
    }
    
    private func getSessionFromReceiversMetaData(for receiver: User, completion: @escaping (Result<SealdEncryptionSession?, CometChatException>) -> Void) {
        
        guard let currUser = CometChat.getLoggedInUser() else {
            completion(.failure(.init(errorCode: "", errorDescription: "current logged in user not found")))
            return
        }
        guard let currUserUid = currUser.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "current user uid not found")))
            return
        }
        guard let metaData = receiver.metadata, let metaDataSessionsId = metaData[SealdMetadataConstants.sessionsMetaadataKey] as? [String: String] else {
            completion(.success(nil))
            return
        }
        
        if let sessionId = metaDataSessionsId[currUserUid] {
            do {
                let session = try seald.retrieveEncryptionSession(withSessionId: sessionId, useCache: false, lookupProxyKey: false, lookupGroupKey: false)
                completion(.success(session))
            } catch {
                completion(.failure(.init(errorCode: "", errorDescription: error.localizedDescription)))
            }
        } else {
            completion(.success(nil))
        }
    }
    
    private func updateMetaDataWithSessionId(_ sessionId: String, for receiver: User, completion: @escaping (Result<Void, CometChatException>) -> Void) {
        guard let receiverUid = receiver.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
            return
        }
        guard let currUser = CometChat.getLoggedInUser() else {
            completion(.failure(.init(errorCode: "", errorDescription: "current logged in user not found")))
            return
        }
        var metaData = currUser.metadata
        if metaData == nil {
            metaData = [:]
        }
        var metaDataSessionsId = metaData?[SealdMetadataConstants.sessionsMetaadataKey] as? [String: String] ?? [:]
        metaDataSessionsId[receiverUid] = sessionId
        
        metaData?[SealdMetadataConstants.sessionsMetaadataKey] = metaDataSessionsId
        currUser.metadata = metaData
        
        CometChat.updateCurrentUserDetails(user: currUser, onSuccess: { user in
            completion(.success(()))
        }, onError: { error in
            if let error  {
                completion(.failure(error))
            } else {
                completion(.failure(.nilException("failed to update metadata for \(String(describing: currUser.uid))")))
            }
        })
    }
    
    func fetchAndLoadEncryptionSession(for receiver: User, completion: @escaping @Sendable (Result<SealdEncryptionSession, CometChatException>) -> Void) {
        guard let receiverUid = receiver.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
            return
        }
        let session = SealdEncryptionSession(encryptionSession: .init())
        
        getSessionFromCache(for: receiver) { [weak self] result in
            switch result {
            case .success(let session):
                if let session {
                    completion(.success(session))
                } else {
                    self?.getSessionFromReceiversMetaData(for: receiver) { [weak self] result in
                        switch result {
                        case .success(let session):
                            if let session {
                                self?.cacheSession(for: receiverUid, session, completion: completion)
                            } else {
                                self?.getSessionFromCustomMsg(for: receiver) {[weak self] result in
                                    switch result {
                                    case .success(let session):
                                        if let session = session {
                                            self?.updateMetaDataWithSessionId(session.sessionId, for: receiver) { result in
                                                switch result {
                                                    
                                                case .success():
                                                    self?.cacheSession(for: receiverUid, session, completion: completion)
                                                case .failure(let error):
                                                    completion(.failure(error))
                                                }
                                            }
                                        } else {
                                            self?.createSession(for: receiver) { sessionResult in
                                                switch sessionResult {
                                                case .success(let newSession):
                                                    self?.sendCustomMessage(session: newSession, to: receiver) { msgResult in
                                                        switch msgResult {
                                                        case .success:
                                                            self?.updateMetaDataWithSessionId(newSession.sessionId, for: receiver) { result in
                                                                switch result {
                                                                    
                                                                case .success():
                                                                    self?.cacheSession(for: receiverUid, newSession, completion: completion)
                                                                case .failure(let error):
                                                                    completion(.failure(error))
                                                                }
                                                            }
                                                        case .failure(let error):
                                                            completion(.failure(error))
                                                        }
                                                    }
                                                case .failure(let error):
                                                    completion(.failure(error))
                                                }
                                            }
                                        }
                                    case .failure(let error):
                                        completion(.failure(error))
                                    }
                                }
                            }
                        case .failure(let error):
                            completion(.failure(error))
                        }
                    }
                    
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    private func cacheSession(for receiverUid: String, _ session: SealdEncryptionSession, completion: @escaping @Sendable (Result<SealdEncryptionSession, CometChatException>) -> Void) {
        Task {
            await CometChatSealdGlobalActor.shared.setSession(session, for: receiverUid)
            completion(.success(session))
        }
        
    }
    
    func fetchAndLoadEncryptionSession(for receiver: User) async throws -> SealdEncryptionSession {
        return try await withCheckedThrowingContinuation { continuation in
            fetchAndLoadEncryptionSession(for: receiver) { result in
                switch result {
                case .success(let session):
                    continuation.resume(returning: session)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
                
            }
        }
    }
    
    private func createSession(for receiver: User, completion: @escaping (Result<SealdEncryptionSession, CometChatException>) -> Void) {
        guard let sealdRecipientID = getSealdId(for: receiver) else {
            completion(.failure(.init(errorCode: "", errorDescription: "Recipient Seald-ID not found in user metadata")))
            return
        }
        
        guard let sealdSenderID = self.seald.getCurrentAccountInfo()?.userId else {
            completion(.failure(.init(errorCode: "", errorDescription: "Failed to retrieve sender Seald-ID")))
            return
        }
        
        do {
            let session = try self.seald.createEncryptionSession(
                withRecipients: [
                    .init(recipientId: sealdRecipientID),
                    .init(recipientId: sealdSenderID)
                ],
                metadata: nil,
                useCache: false
            )
            completion(.success(session))
        } catch {
            completion(.failure(error.toCometChatException))
        }
    }
    
    private func getSealdId(for user: User) -> String? {
        guard let metaData = user.metadata, let sealdID = metaData[SealdMetadataConstants.sealdID] else {
            return nil
        }
        return sealdID as? String
    }
    
    private func sendCustomMessage(session: SealdEncryptionSession, to receiver: User, completion: @escaping (Result<Void, CometChatException>) -> Void) {
        guard let receiverUid = receiver.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
            return
        }
        
        let txt = UUID().uuidString
        
        do {
            let encryptedMsg = try session.encryptMessage(txt)
            let msg = CustomMessage(
                receiverUid: receiverUid,
                receiverType: .user,
                customData: [SealdMetadataConstants.customMetaDataKey: encryptedMsg]
            )
            msg.type = SealdMetadataConstants.customMessageType
            msg.sender = CometChat.getLoggedInUser()
            
            sendTxtCustomMsg(cutmMsg: msg, completion: completion)
        } catch {
            completion(.failure(error.toCometChatException))
        }
    }
    
    private func sendTxtCustomMsg(cutmMsg: CustomMessage, completion: @escaping (Result<Void, CometChatException>) -> Void) {
        CometChat.sendCustomMessage(message: cutmMsg) { _ in
            completion(.success(()))
        } onError: { error in
            if let error {
                completion(.failure(error))
            } else {
                completion(.failure(.nilException("unknown error occurred while sending custom message")))
            }
        }
    }
    
    func encryptMessage(_ message: String, for receiver: User, completion: @escaping @Sendable (Result<String, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSession(for: receiver) { result in
            switch result {
            case .success(let session):
                do {
                    let encryptedMsg = try session.encryptMessage(message)
                    completion(.success(encryptedMsg))
                } catch {
                    completion(.failure(error.toCometChatException))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func encryptMessageAsync(_ message: String, for receiver: User) async throws -> String {
        let session = try await fetchAndLoadEncryptionSession(for: receiver)
        return try await session.encryptMessageAsync(message)
    }
    
    func decryptMessage(_ message: String, for receiver: User, completion: @escaping @Sendable (Result<String, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSession(for: receiver) { result in
            switch result {
            case .success(let session):
                do {
                    let decryptedMsg = try session.decryptMessage(message)
                    completion(.success(decryptedMsg))
                } catch {
                    completion(.failure(error.toCometChatException))
                }
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func decryptMessageAsync(_ message: String, for receiver: User) async throws -> String {
        let session = try await fetchAndLoadEncryptionSession(for: receiver)
        return try await session.decryptMessageAsync(message)
    }
    
    func encryptFile(fromData: Data, filename: String, for receiver: User, completion: @escaping @Sendable (Result<Data, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSession(for: receiver) { result in
            switch result {
            case .success(let session):
                do {
                    let encryptedData = try session.encryptFile(fromData, filename: filename)
                    completion(.success(encryptedData))
                } catch {
                    completion(.failure(error.toCometChatException))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func encryptFileAsync(fromData: Data, filename: String, for receiver: User) async throws -> Data {
        let session = try await fetchAndLoadEncryptionSession(for: receiver)
        return try await session.encryptFileAsync(fromData, filename: filename)
    }
    
    func decryptFile(fromData: Data, for receiver: User, completion: @escaping @Sendable (Result<SealdClearFile, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSession(for: receiver) { result in
            switch result {
            case .success(let session):
                do {
                    let decryptedClearFile = try session.decryptFile(fromData)
                    completion(.success(decryptedClearFile))
                } catch {
                    completion(.failure(error.toCometChatException))
                }
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func decryptFileAsync(fromData: Data, for receiver: User) async throws -> SealdClearFile {
        let session = try await fetchAndLoadEncryptionSession(for: receiver)
        return try await session.decryptFileAsync(fromData)
    }
    
    func encryptFile(fromURI: String, for receiver: User, completion: @escaping @Sendable (Result<String, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSession(for: receiver) { result in
            switch result {
            case .success(let session):
                do {
                    let encryptedFilePath = try session.encryptFile(fromURI: fromURI)
                    completion(.success(encryptedFilePath))
                } catch {
                    completion(.failure(error.toCometChatException))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func encryptFileAsync(fromURI: String, for receiver: User) async throws -> String {
        let session = try await fetchAndLoadEncryptionSession(for: receiver)
        return try await session.encryptFileAsync(fromURI: fromURI)
    }
    
    func decryptFile(fromURI: String, for receiver: User, completion: @escaping @Sendable (Result<String, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSession(for: receiver) { result in
            switch result {
            case .success(let session):
                do {
                    let decryptedFile = try session.decryptFile(fromURI: fromURI)
                    completion(.success(decryptedFile))
                } catch {
                    completion(.failure(error.toCometChatException))
                }
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func decryptFileAsync(fromURI: String, for receiver: User) async throws -> String {
        let session = try await fetchAndLoadEncryptionSession(for: receiver)
        return try await session.decryptFileAsync(fromURI: fromURI)
    }
    
}

public extension CometChatSealdSDK {
    func removeSessionForUser(for receiver: User, completion: @escaping @Sendable (Result<Bool, CometChatException>) -> Void) {
        guard let receiverUid = receiver.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
            return
        }
        
        Task {
            if await CometChatSealdGlobalActor.shared.hasSession(for: receiverUid) {
                completion(.success(true))
            } else {
                completion(.failure(.init(errorCode: "", errorDescription:  "session not found for \(receiverUid)")))
            }
        }
    }
    
    func clearEncryptionSessions() {
        Task {
            await CometChatSealdGlobalActor.shared.clearSessions()
        }
    }
}
