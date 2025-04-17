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
        let nsError = self as NSError
        let errorCode = nsError.userInfo["code"] as? String ?? "UNKNOWN"
        let errorDescription = nsError.userInfo["details"] as? String ?? nsError.localizedDescription
        return .init(errorCode: errorCode, errorDescription: errorDescription)
    }
}

extension CometChatException {
    static func nilException(_ msg: String?) -> CometChatException {
        .init(errorCode: "", errorDescription: msg ?? "unknown nil exception")
    }
}
