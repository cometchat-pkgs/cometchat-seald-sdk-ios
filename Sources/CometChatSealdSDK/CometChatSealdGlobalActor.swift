//
//  CometChatSealdGlobalActor.swift
//  CometChatSealdSDK
//
//  Created by Lalit Vinde on 4/10/25.
//

@preconcurrency import SealdSdk
import CometChatSDK

@globalActor final class CometChatSealdGlobalActor {
    public static let shared = CometChatSealdActor()
}

actor CometChatSealdActor{
    var sessions = [String: CompositeEncryptionSession]()
    var activeRequests: [MessagesRequest] = []
    
    func setSession(_ session: CompositeEncryptionSession, for uid: String) {
        sessions[uid] = session
    }
    
    func getSession(for uid: String) -> CompositeEncryptionSession? {
        return sessions[uid]
    }
    
    func removeSession(for uid: String) {
        sessions.removeValue(forKey: uid)
    }
    
    func clearSessions() {
        sessions.removeAll()
    }
    
    func hasSession(for uid: String) -> Bool {
        sessions[uid] != nil
    }
    
    func appendActiveRequest(_ req: MessagesRequest) {
        activeRequests.append(req)
    }
    
    func removeActiveRequest(_ req: MessagesRequest) {
        activeRequests.removeAll { $0 === req }
    }
    
}
