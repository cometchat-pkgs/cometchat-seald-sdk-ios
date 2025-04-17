//
//  CometChatException.swift
//  CometChatSealdSDK
//
//  Created by Lalit Vinde on 4/2/25.
//

import CometChatSDK

extension CometChatException: @retroactive @unchecked Sendable {}
extension CometChatException: @retroactive Error {}
extension Error {
    var toCometChatException: CometChatException {
        .init(errorCode: "", errorDescription: localizedDescription)
    }
}

extension CometChatException {
    static func nilException(_ msg: String?) -> CometChatException {
        .init(errorCode: "", errorDescription: msg ?? "unknown nil exception")
    }
}
