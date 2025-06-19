//
//  CompositeEncryptionSession.swift
//  CometChatSealdSDK
//
//  Created by Prathmesh on 11/06/25.
//

import SealdSdk

final public class CompositeEncryptionSession : @unchecked Sendable{
    
    private var senderEncryptionSession : SealdEncryptionSession?
    private var receiverEncryptionSession : SealdEncryptionSession?
    
    public init(senderSession: SealdEncryptionSession? = nil, receiverSession: SealdEncryptionSession? = nil) {
            self.senderEncryptionSession = senderSession
            self.receiverEncryptionSession = receiverSession
    }
    
    public func setSenderEncryptionSession(senderEncryptionSession : SealdEncryptionSession) {
        self.senderEncryptionSession = senderEncryptionSession
    }
     
    public func setReceiverEncryptionSession(receiverEncryptionSession : SealdEncryptionSession) {
         self.receiverEncryptionSession = receiverEncryptionSession
    }
    
    public func getSenderEncryptionSession() -> SealdEncryptionSession? {
        return senderEncryptionSession
    }
    
    public func getReceiverEncryptionSession() -> SealdEncryptionSession? {
        return receiverEncryptionSession
    }
}
