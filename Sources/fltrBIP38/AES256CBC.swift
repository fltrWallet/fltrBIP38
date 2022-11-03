//===----------------------------------------------------------------------===//
//
// This source file is part of the fltrBIP38 open source project
//
// Copyright (c) 2022 fltrWallet AG and the fltrBIP38 project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import CommonCrypto

enum AES {}

extension AES {
    @usableFromInline
    static func aes(key: ArraySlice<UInt8>, data: ArraySlice<UInt8>, operation: CCOperation) throws -> [UInt8] {
        precondition(key.count == 32)
        precondition(data.count == 16)
        
        return try Array(unsafeUninitializedCapacity: 16) { buffer, setSizeTo in
            let cResult = key.withUnsafeBufferPointer { key in
                data.withUnsafeBufferPointer { data in
                    CCCrypt(operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0), // kCCOptionPKCS7Padding?
                            key.baseAddress!,
                            key.count,
                            nil, // iv
                            data.baseAddress!,
                            data.count,
                            buffer.baseAddress, //output
                            16, // available size
                            &setSizeTo) // result size
                }
            }
            
            guard cResult == CCCryptorStatus(kCCSuccess)
            else {
                struct AESError: Swift.Error {}
                throw AESError()
            }
        }
    }

    @usableFromInline
    static func aesEncrypt(key: [UInt8], data: [UInt8]) throws -> [UInt8] {
        try Self.aes(key: key[...], data: data[...], operation: .encrypt)
    }
    
    @usableFromInline
    static func aesDecrypt(key: [UInt8], data: [UInt8]) throws -> [UInt8] {
        try Self.aes(key: key[...], data: data[...], operation: .decrypt)
    }

    @usableFromInline
    static func aesEncrypt(key: ArraySlice<UInt8>, data: ArraySlice<UInt8>) throws -> [UInt8] {
        try Self.aes(key: key, data: data, operation: .encrypt)
    }
    
    @usableFromInline
    static func aesDecrypt(key: ArraySlice<UInt8>, data: ArraySlice<UInt8>) throws -> [UInt8] {
        try Self.aes(key: key, data: data, operation: .decrypt)
    }

    @usableFromInline
    static func aesEncrypt(key: Array<UInt8>, data: ArraySlice<UInt8>) throws -> [UInt8] {
        try Self.aes(key: key[...], data: data, operation: .encrypt)
    }
    
    @usableFromInline
    static func aesDecrypt(key: Array<UInt8>, data: ArraySlice<UInt8>) throws -> [UInt8] {
        try Self.aes(key: key[...], data: data, operation: .decrypt)
    }

    @usableFromInline
    static func aesEncrypt(key: ArraySlice<UInt8>, data: Array<UInt8>) throws -> [UInt8] {
        try Self.aes(key: key, data: data[...], operation: .encrypt)
    }
    
    @usableFromInline
    static func aesDecrypt(key: ArraySlice<UInt8>, data: Array<UInt8>) throws -> [UInt8] {
        try Self.aes(key: key, data: data[...], operation: .decrypt)
    }
}

extension CCOperation {
    static let encrypt = CCOperation(kCCEncrypt)
    static let decrypt = CCOperation(kCCDecrypt)
}
