// The Swift Programming Language
// https://docs.swift.org/swift-book

@preconcurrency import SealdSdk
import CryptoKit
import UIKit
@preconcurrency import CometChatSDK
import Security

final public class CometChatSealdSDK: Sendable{
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
//            Task { [weak self] in
//                try? await Task.sleep(nanoseconds: 500_000_000)
//                await self?.populateSessionsCache()
//            }
            
        }
    }
        
//            private func populateSessionsCache() async {
//                guard let currUser = CometChat.getLoggedInUser(),
//                      let metaData = currUser.metadata,
//                      let sessionsId = metaData[SealdMetadataConstants.sessionsMetaadataKey] as? [String: String] else {
//                    return
//                }
//        
//                for (receiverUid, sessionId)in sessionsId {
//                    if let session = try? seald.retrieveEncryptionSession(withSessionId: sessionId, useCache: true, lookupProxyKey: false, lookupGroupKey: false) {
//                        await CometChatSealdGlobalActor.shared.setSession(session, for: receiverUid)
//        
//                    }
//                }
//            }
        
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
    
    private func getUpdatedUserMetadata(metaData : [String: Any],user: User, sessionId: String, completion: @escaping (Result<Void, CometChatException>) -> Void) {
        guard let uid = user.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
            return
        }
        if  user.metadata == nil {
            user.metadata = [:]
        }
        var currentMetaData = metaData
        var sessionsObject: [String: Any]
        if let existingSessions = currentMetaData[SealdMetadataConstants.sessionsMetaadataKey] as? [String : Any] {
            sessionsObject = existingSessions
        } else {
            sessionsObject = [:]
        }
        
        sessionsObject[uid] = sessionId
        
        currentMetaData[SealdMetadataConstants.sessionsMetaadataKey] = sessionsObject
        guard let loggedInUser = CometChat.loggedInUser else { return }
        loggedInUser.metadata = currentMetaData
        
        CometChat.updateCurrentUserDetails(user: loggedInUser, onSuccess: { user in
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
    
    private func getSessionFromCache(for receiver: User, completion: @escaping @Sendable (Result<CompositeEncryptionSession?, CometChatException>) -> Void) {
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
    
    //MARK: Previous Logic for EncryptionSessions
    
//    func fetchAndLoadEncryptionSession(for receiver: User, completion: @escaping @Sendable (Result<SealdEncryptionSession, CometChatException>) -> Void) {
//        guard let receiverUid = receiver.uid else {
//            completion(.failure(.init(errorCode: "", errorDescription: "receiver uid not found")))
//            return
//        }
//        let session = SealdEncryptionSession(encryptionSession: .init())
//        
//        getSessionFromCache(for: receiver) { [weak self] result in
//            switch result {
//            case .success(let session):
//                if let session {
//                    completion(.success(session))
//                } else {
//                    self?.getSessionFromReceiversMetaData(for: receiver) { [weak self] result in
//                        switch result {
//                        case .success(let session):
//                            if let session {
//                                self?.cacheSession(for: receiverUid, session, completion: completion)
//                            } else {
//                                self?.getSessionFromCustomMsg(for: receiver) {[weak self] result in
//                                    switch result {
//                                    case .success(let session):
//                                        if let session = session {
//                                            self?.updateMetaDataWithSessionId(session.sessionId, for: receiver) { result in
//                                                switch result {
//                                                    
//                                                case .success():
//                                                    self?.cacheSession(for: receiverUid, session, completion: completion)
//                                                case .failure(let error):
//                                                    completion(.failure(error))
//                                                }
//                                            }
//                                        } else {
//                                            self?.createSession(for: receiver) { sessionResult in
//                                                switch sessionResult {
//                                                case .success(let newSession):
//                                                    self?.sendCustomMessage(session: newSession, to: receiver) { msgResult in
//                                                        switch msgResult {
//                                                        case .success:
//                                                            self?.updateMetaDataWithSessionId(newSession.sessionId, for: receiver) { result in
//                                                                switch result {
//                                                                    
//                                                                case .success():
//                                                                    self?.cacheSession(for: receiverUid, newSession, completion: completion)
//                                                                case .failure(let error):
//                                                                    completion(.failure(error))
//                                                                }
//                                                            }
//                                                        case .failure(let error):
//                                                            completion(.failure(error))
//                                                        }
//                                                    }
//                                                case .failure(let error):
//                                                    completion(.failure(error))
//                                                }
//                                            }
//                                        }
//                                    case .failure(let error):
//                                        completion(.failure(error))
//                                    }
//                                }
//                            }
//                        case .failure(let error):
//                            completion(.failure(error))
//                        }
//                    }
//                    
//                }
//            case .failure(let error):
//                completion(.failure(error))
//            }
//        }
//    }
    
    //MARK: Changed Logic for EncryptionSessions

    func fetchAndLoadEncryptionSession(for conversationWith: User, completion: @escaping @Sendable (Result<CompositeEncryptionSession, CometChatException>) -> Void) {
        guard let loggedInUser = CometChat.getLoggedInUser() else {
            completion(.failure(.init(errorCode: "ERROR_USER_NOT_LOGGED_IN", errorDescription: "User not logged in. Please login to use this method")))
            return
        }
        
        guard let conversationWithUid = conversationWith.uid else {
            completion(.failure(.init(errorCode: "", errorDescription: "Conversation user UID is missing")))
            return
        }
        
        Task {
            let cachedSession = await CometChatSealdGlobalActor.shared.getSession(for: conversationWithUid)
            
            await MainActor.run {
                if let cachedSession = cachedSession {
                    completion(.success(cachedSession))
                    return
                }
                
                if let sessionId = self.fetchEncryptionSessionIdFromLoggedInUserMetadata(receiver: conversationWith) {
                    let compositeEncryptionSession = CompositeEncryptionSession()
                    do {
                        let senderEncryptionSession = try self.seald.retrieveEncryptionSession(
                            withSessionId: sessionId,
                            useCache: false,
                            lookupProxyKey: false,
                            lookupGroupKey: false
                        )
                        compositeEncryptionSession.setSenderEncryptionSession(senderEncryptionSession: senderEncryptionSession)
                        
                        Task {
                            await self.loadReceiverSessionFromMetadataOrFetch(conversationWith: conversationWith, compositeEncryptionSession: compositeEncryptionSession, completion: completion)
                        }
                    } catch {
                        completion(.failure(.init(errorCode: "", errorDescription: "Error retrieving encryption session: \(error.localizedDescription)")))
                    }
                } else {
                    self.createAndStoreNewEncryptionSession(loggedInUser: loggedInUser, conversationWith: conversationWith, completion: completion)
                }
            }
        }
    }

    private func loadReceiverSessionFromMetadataOrFetch(conversationWith: User, compositeEncryptionSession: CompositeEncryptionSession, completion: @escaping @Sendable (Result<CompositeEncryptionSession, CometChatException>) -> Void) async {
        
        guard let conversationWithUid = conversationWith.uid else {
            await MainActor.run {
                completion(.failure(.init(errorCode: "", errorDescription: "Conversation user UID is missing")))
            }
            return
        }
        
        if let receiverSessionId = self.fetchEncryptionSessionIdFromReceiverMetadata(receiver: conversationWith) {
            
            do {
                let receiverEncryptionSession = try self.seald.retrieveEncryptionSession(
                    withSessionId: receiverSessionId,
                    useCache: false,
                    lookupProxyKey: false,
                    lookupGroupKey: false
                )
                compositeEncryptionSession.setReceiverEncryptionSession(receiverEncryptionSession: receiverEncryptionSession)
            } catch {
                print("Error retrieving receiver session: \(error)")
            }
            
            await CometChatSealdGlobalActor.shared.setSession(compositeEncryptionSession, for: conversationWithUid)
            
            await MainActor.run {
                completion(.success(compositeEncryptionSession))
            }
            
        } else {
            await withCheckedContinuation { continuation in
                CometChat.getUser(UID: conversationWithUid) { user in
                    continuation.resume()
                    
                    Task {
                        do {
                            if let newReceiverSessionId = self.fetchEncryptionSessionIdFromReceiverMetadata(receiver: conversationWith) {
                                let receiverEncryptionSession = try self.seald.retrieveEncryptionSession(
                                    withSessionId: newReceiverSessionId,
                                    useCache: false,
                                    lookupProxyKey: false,
                                    lookupGroupKey: false
                                )
                                compositeEncryptionSession.setReceiverEncryptionSession(receiverEncryptionSession: receiverEncryptionSession)
                            }
                            
                            await CometChatSealdGlobalActor.shared.setSession(compositeEncryptionSession, for: conversationWithUid)
                            
                            await MainActor.run {
                                completion(.success(compositeEncryptionSession))
                            }
                            
                        } catch {
                            await MainActor.run {
                                completion(.failure(.init(errorCode: "", errorDescription: "Error retrieving encryption session: \(error.localizedDescription)")))
                            }
                        }
                    }
                } onError: { error in
                    continuation.resume()
                    Task {
                        await MainActor.run {
                            completion(.failure(.init(errorCode: "", errorDescription: "Error while getting user object")))
                        }
                    }
                }
            }
        }
    }

    private func createAndStoreNewEncryptionSession(loggedInUser: User, conversationWith: User, completion: @escaping @Sendable (Result<CompositeEncryptionSession, CometChatException>) -> Void) {
        
        guard let loggedInUserMetadata = loggedInUser.metadata,
              loggedInUserMetadata[SealdMetadataConstants.sealdID] != nil else {
            completion(.failure(.init(errorCode: "ERROR_SEALD_ID_NOT_FOUND", errorDescription: "SEALD_ID not found in logged in user metadata")))
            return
        }
        
        if let conversationWithMetadata = conversationWith.metadata,
           conversationWithMetadata[SealdMetadataConstants.sealdID] != nil {
        
            createNewEncryptionSession(loggedInUser: loggedInUser, conversationWith: conversationWith, completion: completion)
            
        } else {
            guard let conversationWithUid = conversationWith.uid else {
                completion(.failure(.init(errorCode: "ERROR_SEALD_ID_NOT_FOUND", errorDescription: "SEALD_ID not found in receiver user metadata")))
                return
            }
            
            CometChat.getUser(UID: conversationWithUid) { user in
                guard let user = user else {
                    completion(.failure(.init(errorCode: "ERROR_USER_NOT_FOUND", errorDescription: "User not found")))
                    return
                }
                
                if let userMetadata = user.metadata,
                   userMetadata[SealdMetadataConstants.sealdID] != nil {
                    
                    self.createNewEncryptionSession(loggedInUser: loggedInUser, conversationWith: user, completion: completion)
                    
                } else {
                    completion(.failure(.init(errorCode: "ERROR_SEALD_ID_NOT_FOUND", errorDescription: "SEALD_ID not found in receiver user metadata")))
                }
                
            } onError: { error in
                if let error = error {
                    completion(.failure(error))
                } else {
                    completion(.failure(.init(errorCode: "ERROR_UNKNOWN", errorDescription: "Unknown error occurred while fetching user")))
                }
            }
        }
    }

    private func createNewEncryptionSession(loggedInUser: User, conversationWith: User, completion: @escaping @Sendable (Result<CompositeEncryptionSession, CometChatException>) -> Void) {
        
        do {
            guard let loggedInUserSealdId = self.seald.getCurrentAccountInfo()?.userId,
                  let conversationUserSealdId = self.getSealdId(for: conversationWith) else {
                completion(.failure(.init(errorCode: "ERROR_SEALD_ID_NOT_FOUND", errorDescription: "SEALD_ID not found in user metadata")))
                return
            }
            
            let senderSession = try self.seald.createEncryptionSession(
                withRecipients: [
                    .init(recipientId: loggedInUserSealdId),
                    .init(recipientId: conversationUserSealdId)
                ],
                metadata: nil as String?,
                useCache: false
            )
            
            let session = CompositeEncryptionSession()
            session.setSenderEncryptionSession(senderEncryptionSession: senderSession)
            
            guard let loggedInUserMetadata = loggedInUser.metadata else {
                completion(.failure(.init(errorCode: "ERROR_METADATA_MISSING", errorDescription: "Logged in user metadata is missing")))
                return
            }
            
            self.getUpdatedUserMetadata(metaData: loggedInUserMetadata, user: conversationWith, sessionId: senderSession.sessionId) { result in
                switch result {
                case .success(_):
                    if let receiverSessionId = self.fetchEncryptionSessionIdFromReceiverMetadata(receiver: conversationWith) {
                        
                        do {
                            let receiverSession = try self.seald.retrieveEncryptionSession(
                                withSessionId: receiverSessionId,
                                useCache: false,
                                lookupProxyKey: false,
                                lookupGroupKey: false
                            )
                            session.setReceiverEncryptionSession(receiverEncryptionSession: receiverSession)
                        } catch {
                            print("Error retrieving receiver session: \(error)")
                        }
                    }
                    
                    guard let conversationWithUid = conversationWith.uid else {
                        completion(.failure(.init(errorCode: "ERROR_UID_MISSING", errorDescription: "Conversation user UID is missing")))
                        return
                    }
                    
                    Task {
                        await CometChatSealdGlobalActor.shared.setSession(session, for: conversationWithUid)
                        
                        await MainActor.run {
                            completion(.success(session))
                        }
                    }
                    
                case .failure(let failure):
                    completion(.failure(failure))
                }
            }
            
        } catch {
            completion(.failure(.init(errorCode: "ERROR_JSON_EXCEPTION", errorDescription: error.localizedDescription)))
        }
    }

    private func fetchAndLoadEncryptionSessionInternal(conversationWith: User,isEncrypting: Bool,isSenderDecrypting: Bool,completion: @escaping @Sendable (Result<CompositeEncryptionSession, CometChatException>) -> Void
    ) {
        guard let loggedInUser = CometChat.getLoggedInUser() else {
            completion(.failure(.init(errorCode: "ERROR_USER_NOT_LOGGED_IN", errorDescription: "User not logged in. Please login to use this method")))
            return
        }
        
        guard let uid = conversationWith.uid else {
            completion(.failure(.init(errorCode: "ERROR_INVALID_UID", errorDescription: "Conversation user UID is missing")))
            return
        }
        
        Task {
            let cachedSession = await CometChatSealdGlobalActor.shared.getSession(for: uid)
            
                if let cachedSession = cachedSession {
                    
                    var needsRefresh = false
                    
                    if isEncrypting {
                        if cachedSession.getSenderEncryptionSession() == nil {
                            print("Sender session missing for encryption, refreshing...")
                            needsRefresh = true
                        }
                    } else {
                        if isSenderDecrypting {
                            if cachedSession.getSenderEncryptionSession() == nil {
                                print("Sender session missing for decryption, refreshing...")
                                needsRefresh = true
                            }
                        } else {
                            if cachedSession.getReceiverEncryptionSession() == nil {
                                print("Receiver session missing for decryption, refreshing...")
                                needsRefresh = true
                            }
                        }
                    }
                    
                    if needsRefresh {
                        await CometChatSealdGlobalActor.shared.removeSession(for: uid)
                        self.fetchAndLoadEncryptionSessionInternal(
                            conversationWith: conversationWith,
                            isEncrypting: isEncrypting,
                            isSenderDecrypting: isSenderDecrypting,
                            completion: completion
                        )
                        return
                    }
                    
                    completion(.success(cachedSession))
                    return
                }
            
            self.continueMetadataCheck(loggedInUser: loggedInUser, conversationWith: conversationWith, completion: completion)
        }
        
    }

    private func continueMetadataCheck(loggedInUser: User,conversationWith: User,completion: @escaping @Sendable (Result<CompositeEncryptionSession, CometChatException>) -> Void
    ) {
        if let senderSessionId = self.fetchEncryptionSessionIdFromLoggedInUserMetadata(receiver: conversationWith) {
            print("fetchAndLoadEncryptionSession Logged in user ES found in user metadata")
            
            let compositeEncryptionSession = CompositeEncryptionSession()
            
            do {
                let senderSession = try self.seald.retrieveEncryptionSession(
                    withSessionId: senderSessionId,
                    useCache: false,
                    lookupProxyKey: false,
                    lookupGroupKey: false
                )
                compositeEncryptionSession.setSenderEncryptionSession(senderEncryptionSession: senderSession)
                
                Task {
                    await self.loadReceiverSessionFromMetadataOrFetch(
                        conversationWith: conversationWith,
                        compositeEncryptionSession: compositeEncryptionSession,
                        completion: completion
                    )
                }
                
            } catch {
                completion(.failure(.init(errorCode: "ERROR_RETRIEVE_SESSION", errorDescription: "Error retrieving sender session: \(error.localizedDescription)")))
            }
            
        } else {
            createAndStoreNewEncryptionSession(loggedInUser: loggedInUser, conversationWith: conversationWith, completion: completion)
        }
    }
    
    private func fetchEncryptionSessionIdFromLoggedInUserMetadata(receiver: User) -> String? {
        guard let loggedInUser = CometChat.getLoggedInUser(),
              let currentMetadata = loggedInUser.metadata,
              let sessionsObject = currentMetadata["SESSIONS"] as? [String: Any],
              let receiverUid = receiver.uid else {
            return nil
        }
        return sessionsObject[receiverUid] as? String
    }
    
    private func fetchEncryptionSessionIdFromReceiverMetadata(receiver: User) -> String? {
        guard let loggedInUser = CometChat.getLoggedInUser(),
              let currentMetadata = receiver.metadata,
              let sessionsObject = currentMetadata["SESSIONS"] as? [String: Any],
              let loggedInUserUid = loggedInUser.uid else {
            return nil
        }
        return sessionsObject[loggedInUserUid] as? String
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
    
    private func cacheSession(for receiverUid: String, _ session: CompositeEncryptionSession, completion: @escaping @Sendable (Result<CompositeEncryptionSession, CometChatException>) -> Void) {
        Task {
            await CometChatSealdGlobalActor.shared.setSession(session, for: receiverUid)
            completion(.success(session))
        }
    }
    
    func fetchAndLoadEncryptionSession(for receiver: User) async throws -> CompositeEncryptionSession {
        return try await withCheckedThrowingContinuation { continuation in
            fetchAndLoadEncryptionSession(for: receiver) { result in
                switch result {
                case .success(let compositeEncryptionSession):
                    continuation.resume(returning: compositeEncryptionSession)
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
                metadata: nil as String?,
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
    
    private func getConversationWithFromSenderAndReceiver(_ sender: User,_ receiver: User) -> User? {
        if let loggedInUser = CometChat.getLoggedInUser(){
            if (sender.uid == loggedInUser.uid) {
                return receiver;
            } else {
                return sender;
            }
        }
        return nil
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
    
    func encryptMessage(_ message: String, receiver: User, completion: @escaping @Sendable (Result<String, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSessionInternal(conversationWith: receiver,isEncrypting: true,isSenderDecrypting: false) { result in
            switch result {
            case .success(let session):
                do {
                    if session.getSenderEncryptionSession() != nil {
                        if let senderSession = session.getSenderEncryptionSession() {
                            let encryptedMsg = try senderSession.encryptMessage(message)
                            DispatchQueue.main.async {
                                completion(.success(encryptedMsg))
                            }
                        }
                    }
                } catch {
                    completion(.failure(error.toCometChatException))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func encryptMessageAsync(_ message: String,for receiver: User) async throws -> String {
         return try await withCheckedThrowingContinuation { continuation in
             fetchAndLoadEncryptionSessionInternal(
                 conversationWith: receiver,
                 isEncrypting: true,
                 isSenderDecrypting: false
             ) { result in
                 switch result {
                 case .success(let session):
                     do {
                         guard let senderSession = session.getSenderEncryptionSession() else {
                             continuation.resume(throwing: CometChatException(errorCode: "NO_SENDER_SESSION", errorDescription: "Sender session not found"))
                             return
                         }
                         Task{
                             let encryptedMessage = try await senderSession.encryptMessageAsync(message)
                             continuation.resume(returning: encryptedMessage)
                         }
                         
                     } catch {
                         continuation.resume(throwing: error)
                     }
                     
                 case .failure(let error):
                     continuation.resume(throwing: error)
                 }
             }
         }
    }
    
    func decryptMessage(_ message: String,sender: User, receiver: User, completion: @escaping @Sendable (Result<String, CometChatException>) -> Void) {
        guard let conversationWith = getConversationWithFromSenderAndReceiver(sender, receiver) else { return }
        let isSenderDecrypting = CometChat.loggedInUser?.uid == sender.uid
        fetchAndLoadEncryptionSessionInternal(conversationWith: conversationWith,isEncrypting: false,isSenderDecrypting: isSenderDecrypting) { result in
            switch result {
            case .success(let session):
                do {
                    if sender.uid == CometChat.getLoggedInUser()?.uid {
                        if let session = session.getSenderEncryptionSession() {
                            let decryptedMsg = try session.decryptMessage(message)
                            DispatchQueue.main.async {
                                completion(.success(decryptedMsg))
                            }
                            
                        }
                    }else{
                        if let session = session.getReceiverEncryptionSession() {
                            let decryptedMsg = try session.decryptMessage(message)
                            DispatchQueue.main.async {
                                completion(.success(decryptedMsg))
                            }
                        }
                    }
                } catch {
                    completion(.failure(error.toCometChatException))
                }
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }

    func decryptMessageAsync(_ message: String,sender: User, receiver: User) async throws -> String {
        guard let conversationWith = getConversationWithFromSenderAndReceiver(sender, receiver) else {
            throw CometChatException(errorCode: "ERROR_CONVERSATION_USER", errorDescription: "Unable to determine conversation user")
        }
        
        let isSenderDecrypting = CometChat.loggedInUser?.uid == sender.uid
        return try await withCheckedThrowingContinuation { continuation in
            fetchAndLoadEncryptionSessionInternal(
                conversationWith: conversationWith,
                isEncrypting: false,
                isSenderDecrypting: isSenderDecrypting
            ) { result in
                switch result {
                case .success(let session):
                    do {
                        if isSenderDecrypting {
                            guard let senderSession = session.getSenderEncryptionSession() else {
                                continuation.resume(throwing: CometChatException(errorCode: "NO_SENDER_SESSION", errorDescription: "Sender session not found"))
                                return
                            }
                            Task{
                                let decryptedMessage = try await senderSession.decryptMessageAsync(message)
                                continuation.resume(returning: decryptedMessage)
                            }
                        }else{
                            guard let receiverSession = session.getReceiverEncryptionSession() else {
                                continuation.resume(throwing: CometChatException(errorCode: "NO_SENDER_SESSION", errorDescription: "Sender session not found"))
                                return
                            }
                            Task{
                                let decryptedMessage = try await receiverSession.decryptMessageAsync(message)
                                continuation.resume(returning: decryptedMessage)
                            }
                        }
                        
                    } catch {
                        continuation.resume(throwing: error)
                    }
                    
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    func encryptFile(fromData: Data, filename: String, for receiver: User, completion: @escaping @Sendable (Result<Data, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSessionInternal(conversationWith: receiver,isEncrypting: true,isSenderDecrypting: false) { result in
            switch result {
            case .success(let session):
                do {
                    if let session = session.getSenderEncryptionSession() {
                        let encryptedData = try session.encryptFile(fromData, filename: filename)
                        completion(.success(encryptedData))
                    }
                } catch {
                    completion(.failure(error.toCometChatException))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func encryptFileAsync(fromData: Data, filename: String, for receiver: User) async throws -> Data {
        
        return try await withCheckedThrowingContinuation { continuation in
            fetchAndLoadEncryptionSessionInternal(
                conversationWith: receiver,
                isEncrypting: true,
                isSenderDecrypting: false
            ) { result in
                switch result {
                case .success(let session):
                    do {
                        guard let senderSession = session.getSenderEncryptionSession() else {
                            continuation.resume(throwing: CometChatException(errorCode: "NO_SENDER_SESSION", errorDescription: "Sender session not found"))
                            return
                        }
                        Task{
                            let encryptedfile = try await senderSession.encryptFileAsync(fromData, filename: filename)
                            continuation.resume(returning: encryptedfile)
                        }
                        
                    } catch {
                        continuation.resume(throwing: error)
                    }
                    
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    func decryptFile(fromData: Data,sender: User,receiver: User, completion: @escaping @Sendable (Result<SealdClearFile, CometChatException>) -> Void) {
        guard let conversationWith = getConversationWithFromSenderAndReceiver(sender, receiver) else { return }
        let isSenderDecrypting = CometChat.loggedInUser?.uid == sender.uid
        fetchAndLoadEncryptionSessionInternal(conversationWith: conversationWith, isEncrypting: false, isSenderDecrypting: isSenderDecrypting) { result in
            switch result {
            case .success(let session):
                do {
                    if isSenderDecrypting {
                        if let session = session.getSenderEncryptionSession(){
                            let decryptedClearFile = try session.decryptFile(fromData)
                            completion(.success(decryptedClearFile))
                        }
                    }else{
                        if let session = session.getReceiverEncryptionSession(){
                            let decryptedClearFile = try session.decryptFile(fromData)
                            completion(.success(decryptedClearFile))
                        }
                    }
                } catch {
                    completion(.failure(error.toCometChatException))
                }
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func decryptFileAsync(fromData: Data, sender: User, receiver: User) async throws -> SealdClearFile {
        guard let conversationWith = getConversationWithFromSenderAndReceiver(sender, receiver) else {
            throw CometChatException(errorCode: "ERROR_CONVERSATION_USER", errorDescription: "Unable to determine conversation user")
        }
        
        let isSenderDecrypting = CometChat.loggedInUser?.uid == sender.uid
        
        return try await withCheckedThrowingContinuation { continuation in
            
            fetchAndLoadEncryptionSessionInternal(
                conversationWith: conversationWith,
                isEncrypting: false,
                isSenderDecrypting: isSenderDecrypting
            ) { result in
                switch result {
                case .success(let session):
                    if isSenderDecrypting {
                        guard let senderSession = session.getSenderEncryptionSession() else {
                            continuation.resume(throwing: CometChatException(errorCode: "NO_RECEIVER_SESSION", errorDescription: "Receiver session not found"))
                            return
                        }
                        
                        Task{
                            do {
                                let decryptedFile = try await senderSession.decryptFileAsync(fromData)
                                continuation.resume(returning: decryptedFile)
                            } catch {
                                continuation.resume(throwing: error)
                            }
                        }
                        
                        
                    } else {
                        guard let receiverSession = session.getReceiverEncryptionSession() else {
                            continuation.resume(throwing: CometChatException(errorCode: "NO_RECEIVER_SESSION", errorDescription: "Receiver session not found"))
                            return
                        }
                        
                        Task{
                            do {
                                let decryptedFile = try await receiverSession.decryptFileAsync(fromData)
                                continuation.resume(returning: decryptedFile)
                            } catch {
                                continuation.resume(throwing: error)
                            }
                        }
                        
                    }
                    
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func encryptFile(fromURI: String, for receiver: User, completion: @escaping @Sendable (Result<String, CometChatException>) -> Void) {
        fetchAndLoadEncryptionSessionInternal(conversationWith: receiver, isEncrypting: true, isSenderDecrypting: false) { result in
            switch result {
            case .success(let session):
                do {
                    if let session = session.getSenderEncryptionSession(){
                        let encryptedFilePath = try session.encryptFile(fromURI: fromURI)
                        completion(.success(encryptedFilePath))
                    }
                } catch {
                    completion(.failure(error.toCometChatException))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func encryptFileAsync(fromURI: String, for receiver: User) async throws -> String {
        return try await withCheckedThrowingContinuation { continuation in
            fetchAndLoadEncryptionSessionInternal(
                conversationWith: receiver,
                isEncrypting: true,
                isSenderDecrypting: false
            ) { result in
                switch result {
                case .success(let session):
                    do {
                        guard let senderSession = session.getSenderEncryptionSession() else {
                            continuation.resume(throwing: CometChatException(errorCode: "NO_SENDER_SESSION", errorDescription: "Sender session not found"))
                            return
                        }
                        Task{
                            let encryptedfile = try await senderSession.encryptFileAsync(fromURI: fromURI)
                            continuation.resume(returning: encryptedfile)
                        }
                    } catch {
                        continuation.resume(throwing: error)
                    }
                    
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    func decryptFile(fromURI: String,sender: User, receiver: User, completion: @escaping @Sendable (Result<String, CometChatException>) -> Void) {
        guard let conversationWith = getConversationWithFromSenderAndReceiver(sender, receiver) else { return }
        let isSenderDecrypting = CometChat.loggedInUser?.uid == sender.uid
        fetchAndLoadEncryptionSessionInternal(conversationWith: conversationWith, isEncrypting: false, isSenderDecrypting: isSenderDecrypting) { result in
            switch result {
            case .success(let session):
                do {
                    if isSenderDecrypting{
                        if let session = session.getSenderEncryptionSession(){
                            let decryptedFile = try session.decryptFile(fromURI: fromURI)
                            completion(.success(decryptedFile))
                        }
                    }else{
                        if let session = session.getReceiverEncryptionSession(){
                            let decryptedFile = try session.decryptFile(fromURI: fromURI)
                            completion(.success(decryptedFile))
                        }
                    }
                } catch {
                    completion(.failure(error.toCometChatException))
                }
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func decryptFileAsync(fromURI: String,sender: User, receiver: User) async throws -> String {
        guard let conversationWith = getConversationWithFromSenderAndReceiver(sender, receiver) else {
            throw CometChatException(errorCode: "ERROR_CONVERSATION_USER", errorDescription: "Unable to determine conversation user")
        }
        
        let isSenderDecrypting = CometChat.loggedInUser?.uid == sender.uid
        return try await withCheckedThrowingContinuation { continuation in
            fetchAndLoadEncryptionSessionInternal(
                conversationWith: conversationWith,
                isEncrypting: false,
                isSenderDecrypting: isSenderDecrypting
            ) { result in
                switch result {
                case .success(let session):
                    
                    if isSenderDecrypting {
                        guard let senderSession = session.getSenderEncryptionSession() else {
                            continuation.resume(throwing: CometChatException(errorCode: "NO_SENDER_SESSION", errorDescription: "Sender session not found"))
                            return
                        }
                        Task{
                            do{
                                let decryptedFile = try await senderSession.decryptFileAsync(fromURI: fromURI)
                                continuation.resume(returning: decryptedFile)
                            }catch{
                                continuation.resume(throwing: error)
                            }
                        }
                    }else{
                        guard let receiverSession = session.getReceiverEncryptionSession() else {
                            continuation.resume(throwing: CometChatException(errorCode: "NO_SENDER_SESSION", errorDescription: "Sender session not found"))
                            return
                        }
                        Task{
                            do{
                                let decryptedFile = try await receiverSession.decryptFileAsync(fromURI: fromURI)
                                continuation.resume(returning: decryptedFile)
                            }catch{
                                continuation.resume(throwing: error)
                            }
                        }
                    }
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
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

