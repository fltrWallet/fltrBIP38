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
import fltrECC
import fltrScrypt
import CryptoKit
import fltrTx
import HaByLo

public enum BIP38 {}

public extension BIP38 {
    static let prefixBase58NonMul: [UInt8] = [ 0x01, 0x42, ]
    static let prefixBase58Mul: [UInt8] = [ 0x01, 0x43, ]
    static let prefixBase58IntermediateWithLot: [UInt8] = [ 0x2c, 0xe9, 0xb3, 0xe1,
                                                            0xff, 0x39, 0xe2, 0x51, ]
    static let prefixBase58IntermediateNoLot: [UInt8] = [ 0x2c, 0xe9, 0xb3, 0xe1,
                                                          0xff, 0x39, 0xe2, 0x53, ]
    static let prefixBase58Confirmation: [UInt8] = [ 0x64, 0x3b, 0xf6, 0xa8, 0x9a, ]

    struct KeyFlags: OptionSet {
        public let rawValue: UInt64
        public init(rawValue: UInt64) {
            self.rawValue = rawValue
        }

        public static let mainNet: Self = .init(rawValue: 0)
        public static let testNet: Self = .init(rawValue: 111)
        public static let compressed: Self = .init(rawValue: 256)
        public static let ecMultiplied: Self = .init(rawValue: 512)
        public static let quickCheck: Self = .init(rawValue: 1024)
        public static let rawMode: Self = .init(rawValue: 2048)
        public static let swapOrder: Self = .init(rawValue: 4096)
    }
    
    struct FlagByte: OptionSet {
        public let rawValue: UInt8
        
        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        public static let nonMultiplied: Self = .init(rawValue: 0x40 | 0x80)
        public static let compressed: Self = .init(rawValue: 0x20)
        public static let reserved1: Self = .init(rawValue: 0x10)
        public static let reserved2: Self = .init(rawValue: 0x08)
        public static let haveLot: Self = .init(rawValue: 0x04)
        public static let reserved3: Self = .init(rawValue: 0x02)
        public static let reserved4: Self = .init(rawValue: 0x01)
        public static let reserved: Self = [ .reserved1, .reserved2, .reserved3, .reserved4 ]
        public static let all: Self = [ .reserved, .nonMultiplied, .compressed, .haveLot, ]
        
        var mul: Bool {
            self.isDisjoint(with: .nonMultiplied)
        }
        
        var isValid: Bool {
            self.subtracting(.all).isEmpty
        }
    }

    static func encodeIntermediate(password: String,
                                   lot: (Int, Int)? = nil) -> String {
        func noLot() -> [UInt8] {
            UInt64.random(in: .min ... .max).bigEndianBytes
        }
        
        func withLot(lot: Int, sequence: Int) -> [UInt8] {
            let ownerSalt = UInt32.random(in: .min ... .max).bigEndianBytes
            precondition(lot < (1 << 20))
            precondition(sequence < (1 << 12))
            
            let lotSequence = (UInt32(lot) << 12) | UInt32(sequence)
            
            return ownerSalt + lotSequence.bigEndianBytes
        }

        let haveLot: Bool = lot != nil
        let ownerEntropy = haveLot
            ? withLot(lot: lot!.0, sequence: lot!.1)
            : noLot()
        precondition(ownerEntropy.count == 8)
        guard let passScalar = Self.passFactor(from: password,
                                               haveLot: haveLot,
                                               ownerEntropy: ownerEntropy[...])
        else { // Scalar out of range, retry
            return encodeIntermediate(password: password,
                                         lot: lot)
        }
        let passPoint = Point(passScalar)
        
        return [ haveLot
                    ? BIP38.prefixBase58IntermediateWithLot
                    : BIP38.prefixBase58IntermediateNoLot,
                 ownerEntropy,
                 DSA.PublicKey(passPoint).serialize(), ]
            .joined()
            .base58CheckEncode()
    }
    
    static func encodeMul(intermediate passphrase: String,
                          compressed: Bool = false,
                          prefix: BitcoinLegacyAddressPrefix)
    -> (address: String, encrypted: String, confirmation: String)? {
        func decode(intermediate: ArraySlice<UInt8>) -> (hasLot: Bool, ownerEntropy: ArraySlice<UInt8>, passPoint: Point)? {
            let start = intermediate.startIndex
            func index(_ num: Int) -> Int {
                intermediate.index(start, offsetBy: num)
            }
            
            let magic = Array(intermediate[..<index(8)])
            let ownerEntropy = intermediate[index(8)..<index(16)]
            guard let point = Point(from: Array(intermediate[index(16)...]))
            else { return nil }
            
            if magic.elementsEqual(BIP38.prefixBase58IntermediateWithLot) {
                return (true, ownerEntropy, point)
            } else if magic.elementsEqual(BIP38.prefixBase58IntermediateNoLot) {
                return (false, ownerEntropy, point)
            } else {
                return nil
            }
        }
        
        guard let intermediate = try? passphrase.base58CheckDecode(),
              intermediate.count == 49,
              let (haveLot, ownerEntropy, passPoint) = decode(intermediate: intermediate)
        else { return nil }
        
        let flags: FlagByte = [ haveLot ? .haveLot : [],
                                compressed ? .compressed : [], ]

        let seedB = (0..<24).map { _ in UInt8.random(in: .min ... .max) }
        let factorB = seedB.hash256
        guard let scalarB = Scalar(factorB)
        else {
            return encodeMul(intermediate: passphrase,
                             compressed: compressed,
                             prefix: prefix)
        }
        let pointB = scalarB * passPoint

        let addressString = compressed
        ? PublicKeyHash(.init(pointB)).addressLegacyPKH(prefix)
        : UncompressedPublicKeyHash(.init(pointB)).addressLegacyPKH(prefix)
        let addressHash = addressString.ascii.hash256.prefix(4)
        let (derivedHalf1, derivedHalf2) = Self.derived(from: passPoint,
                                                        addressHash: addressHash,
                                                        ownerEntropy: ownerEntropy)
        let data1 = seedB.prefix(16) ^ derivedHalf1.prefix(16)
        let encryptedPart1 = try! AES.aesEncrypt(key: derivedHalf2, data: data1)
        let data2 = [ encryptedPart1.suffix(8), seedB.suffix(8), ].joined() ^ derivedHalf1.suffix(16)
        let encryptedPart2 = try! AES.aesEncrypt(key: derivedHalf2, data: data2)

        let mulEncoded = [ BIP38.prefixBase58Mul[...],
                        [ flags.rawValue ][...],
                        addressHash,
                        ownerEntropy,
                        encryptedPart1.prefix(8),
                        encryptedPart2[...], ]
            .joined()
            .base58CheckEncode()
        
        let confirm = BIP38.confirmation(flags: flags,
                                         ownerEntropy: ownerEntropy,
                                         factorB: scalarB,
                                         addressHash: addressHash,
                                         derivedHalf1: derivedHalf1,
                                         derivedHalf2: derivedHalf2)
        
        return (addressString, mulEncoded, confirm)
    }
    
    @usableFromInline
    internal static func confirmation(flags: FlagByte,
                                      ownerEntropy: ArraySlice<UInt8>,
                                      factorB: Scalar,
                                      addressHash: ArraySlice<UInt8>,
                                      derivedHalf1: ArraySlice<UInt8>,
                                      derivedHalf2: ArraySlice<UInt8>) -> String {
        let pointB = Point(factorB)
        let compressed = DSA.PublicKey(pointB).serialize()
        let xorOperand = [ derivedHalf2.last! & 0x01 ][...]
        let pointDataXor = compressed ^ [ xorOperand, derivedHalf1 ].joined()
        let encryptedPoint: ArraySlice<UInt8> = Array(
            Self.aes32(data: pointDataXor[1...],
                       key: derivedHalf2,
                       operation: .encrypt)
        )[...]

        return [ BIP38.prefixBase58Confirmation[...],
                 [ flags.rawValue ][...],
                 addressHash,
                 ownerEntropy,
                 pointDataXor[0...0],
                 encryptedPoint, ]
            .joined()
            .base58CheckEncode()
    }
    
    static func decodeMul(encoded: String,
                          password: String,
                          prefix: BitcoinLegacyAddressPrefix) -> Scalar? {
        func decode(_ bytes: ArraySlice<UInt8>) -> (flags: FlagByte,
                                                    addressHash: ArraySlice<UInt8>,
                                                    ownerEntropy: ArraySlice<UInt8>,
                                                    encrypted: ArraySlice<UInt8>) {
            let startIndex = bytes.startIndex
            func index(_ i: Int) -> Int {
                bytes.index(startIndex, offsetBy: i)
            }
            
            let flags = FlagByte(rawValue: bytes[index(0)])
            let addressHash = bytes[index(1)..<index(5)]
            let ownerEntropy = bytes[index(5)..<index(13)]
            let encrypted = bytes[index(13)...]
            assert(encrypted.count == 24)
            
            return (flags, addressHash, ownerEntropy, encrypted)
        }

        guard let mulDecoded = try? encoded.base58CheckDecode(),
        mulDecoded.count == 39,
        mulDecoded.prefix(BIP38.prefixBase58Mul.count)
            .elementsEqual(BIP38.prefixBase58Mul)
        else { return nil }
        
        let (flags, addressHash, ownerEntropy, encrypted) = decode(
            mulDecoded.dropFirst(BIP38.prefixBase58Mul.count)
        )
        
        guard flags.isValid
        else { return nil }
        let haveLot = flags.contains(.haveLot)

        guard let passScalar = Self.passFactor(from: password,
                                               haveLot: haveLot,
                                               ownerEntropy: ownerEntropy)
        else { return nil }
        let (derivedHalf1, derivedHalf2) = Self.derived(from: Point(passScalar),
                                                        addressHash: addressHash,
                                                        ownerEntropy: ownerEntropy)
        let decryptedPart2 = try! AES.aesDecrypt(key: derivedHalf2, data: encrypted.suffix(16)) ^ derivedHalf1.suffix(16)
        let encryptedPart1SecondHalf = decryptedPart2.prefix(8)
        let seedBSuffix8 = decryptedPart2.suffix(8)
        let data1 = Array([ encrypted.prefix(8), encryptedPart1SecondHalf, ].joined())
        let seedBPrefix16 = try! AES.aesDecrypt(key: derivedHalf2, data: data1) ^ derivedHalf1.prefix(16)
        guard let factorB = Scalar(
            [ seedBPrefix16[...], seedBSuffix8, ]
                .joined()
                .hash256
        )
        else { return nil }
        let scalarB = factorB * passScalar
        let pointB = Point(scalarB)

        let addressBytes = Self.keyToAddressBytes(key: pointB,
                                                  compressed: flags.contains(.compressed),
                                                  prefix: prefix)
        guard addressBytes.hash256.prefix(4)
                .elementsEqual(addressHash)
        else {
            print("BIP38 - decodeMul: Illegal key encoded with point \(pointB)")
            return nil
        }
        
        return scalarB
    }
    
    static func check(confirmation: String,
                      password: String,
                      prefix: BitcoinLegacyAddressPrefix) -> (Bool, (lot: Int, sequence: Int)?) {
        func decode(confirmation: ArraySlice<UInt8>) -> (flags: FlagByte,
                                                         addressHash: ArraySlice<UInt8>,
                                                         ownerEntropy: ArraySlice<UInt8>,
                                                         pointBPrefix: ArraySlice<UInt8>,
                                                         pointBEncrypted: ArraySlice<UInt8>) {
            let start = confirmation.startIndex
            func index(_ num: Int) -> Int {
                confirmation.index(start, offsetBy: num)
            }
            
            let flags: FlagByte = .init(rawValue: confirmation[index(0)])
            let addressHash = confirmation[index(1)..<index(5)]
            let ownerEntropy = confirmation[index(5)..<index(13)]
            let pointBPrefix = confirmation[index(13)...index(13)]
            let pointBEncrypted = confirmation[index(14)...]
            assert(pointBEncrypted.count == 32)

            return (flags, addressHash, ownerEntropy, pointBPrefix, pointBEncrypted)
        }
        
        guard let confirmationBytes = try? confirmation.base58CheckDecode(),
              confirmationBytes.count == 51,
              confirmationBytes.prefix(5).elementsEqual(BIP38.prefixBase58Confirmation)
        else { return (false, nil) }

        let (flags, addressHash, ownerEntropy, pointBPrefix, pointBEncrypted) = decode(confirmation: confirmationBytes.dropFirst(5))
        let haveLot = flags.contains(.haveLot)
        guard flags.isValid,
              let passScalar = Self.passFactor(from: password,
                                               haveLot: haveLot,
                                               ownerEntropy: ownerEntropy)
        else {
            return (false, nil)
        }
        let passPoint = Point(passScalar)
        let (derivedHalf1, derivedHalf2) = Self.derived(from: passPoint,
                                                        addressHash: addressHash,
                                                        ownerEntropy: ownerEntropy)
        let pointBDecrypted: ArraySlice<UInt8> = Array(Self.aes32(data: pointBEncrypted, key: derivedHalf2, operation: .decrypt))[...]
        let xorPrefix = [ derivedHalf2.last! & 0x01 ][...]
        let pointData = [ pointBPrefix, pointBDecrypted, ].joined() ^ [ xorPrefix, derivedHalf1, ].joined()
        guard let pointB = Point(from: pointData)
        else { return (false, nil) }
        let mul = pointB * passScalar

        let addressBytes = Self.keyToAddressBytes(key: mul,
                                                  compressed: flags.contains(.compressed),
                                                  prefix: prefix)
        let matches = addressBytes.hash256.prefix(4)
            .elementsEqual(addressHash)
        let lotSequence: (Int, Int)? = haveLot ? Self.lotSequence(from: ownerEntropy) : nil

        return (matches, lotSequence)
    }
}


// MARK: Non-Multiplied
public extension BIP38 {
    static func encodeNonMul(key: Scalar,
                             password: String,
                             compressed: Bool = false,
                             prefix: BitcoinLegacyAddressPrefix) -> String {
        let addressBytes = Self.keyToAddressBytes(key: key,
                                                  compressed: compressed,
                                                  prefix: prefix)
        let addressChecksum = Array(addressBytes.hash256.prefix(4))
        
        let passwordBytes = Self.passwordToBytes(password)
        let passwordScrypt = try! scrypt(password: passwordBytes, salt: addressChecksum, parameters: .bip38nonmul)
        precondition(passwordScrypt.count == 64)
        let derivedHalf1 = passwordScrypt[..<32]
        let derivedHalf2 = passwordScrypt[32...]
        
        let encrypted = key.withUnsafeBytes { key in
            let data = key ^ derivedHalf1
            return Self.aes32(data: data, key: derivedHalf2, operation: .encrypt)
        }
        
        let flags: FlagByte = [ .nonMultiplied,
                                compressed ? .compressed : [], ]
        
        return [
            BIP38.prefixBase58NonMul,
            [ flags.rawValue, ],
            addressChecksum,
            Array(encrypted),
        ]
        .joined()
        .base58CheckEncode()
    }
    
    static func decodeNonMul(encoded: String,
                             password: String,
                             prefix: BitcoinLegacyAddressPrefix) -> Scalar? {
        func decode(_ data: ArraySlice<UInt8>) -> (flags: FlagByte,
                                                   salt: ArraySlice<UInt8>,
                                                   encrypted: ArraySlice<UInt8>) {
            let startIndex = data.startIndex
            func index(_ i: Int) -> Int {
                data.index(startIndex, offsetBy: i)
            }
            
            let flags = FlagByte(rawValue: data[index(0)])
            let salt = data[index(1)..<index(5)]
            let encrypted = data[index(5)...]
            assert(encrypted.count == 32)
            
            return (flags, salt, encrypted)
        }
        
        guard let data = try? encoded.base58CheckDecode(),
              data.count == 39,
              data.prefix(BIP38.prefixBase58NonMul.count)
                .elementsEqual(BIP38.prefixBase58NonMul)
        else { return nil }

        let (flags, salt, encrypted) = decode(data.dropFirst(BIP38.prefixBase58NonMul.count))
        
        guard flags.isValid,
              let scryptDerived = try? scrypt(password: Self.passwordToBytes(password),
                                              salt: .init(salt),
                                              parameters: .bip38nonmul)
        else { return nil }
        
        precondition(scryptDerived.count == 64)
        let derivedHalf1 = scryptDerived[..<32]
        let derivedHalf2 = scryptDerived[32...]
        
        let decrypted = Self.aes32(data: encrypted, key: derivedHalf2, operation: .decrypt)
        precondition(decrypted.count == 32)

        let keyBytes =  decrypted ^ derivedHalf1
        guard let scalar = Scalar(keyBytes)
        else { return nil }
        
        let point = Point(scalar)
        let addressBytes = Self.keyToAddressBytes(key: point,
                                                  compressed: flags.contains(.compressed),
                                                  prefix: prefix)
        guard addressBytes.hash256.prefix(4)
                .elementsEqual(salt)
        else {
            print("BIP38 - address mismatch when comparing address checksum to salt"
            + " for decoded address", scalar)
            return nil
        }
        
        return scalar
    }
}

// MARK: Utility functions
extension BIP38 {
    @usableFromInline
    static func keyToAddressBytes(key: Scalar, compressed: Bool, prefix: BitcoinLegacyAddressPrefix) -> [UInt8] {
        Self.keyToAddressBytes(key: Point(key), compressed: compressed, prefix: prefix)
    }
    
    @usableFromInline
    static func keyToAddressBytes(key point: Point, compressed: Bool, prefix: BitcoinLegacyAddressPrefix) -> [UInt8] {
        compressed
        ? PublicKeyHash(.init(point))
            .addressLegacyPKH(prefix)
            .ascii
        : UncompressedPublicKeyHash(.init(point))
            .addressLegacyPKH(prefix)
            .ascii
    }
    
    @usableFromInline
    static func passwordToBytes(_ password: String) -> [UInt8] {
        .init(password.precomposedStringWithCanonicalMapping.utf8)
    }

    @usableFromInline
    enum Operation {
        case encrypt
        case decrypt
    }
    
    @usableFromInline
    static func aes32(data: ArraySlice<UInt8>, key: ArraySlice<UInt8>, operation: Operation) -> FlattenSequence<[[UInt8]]> {
        precondition(data.count == 32)
        let first = data.prefix(16)
        let second = data.suffix(16)
        
        let callAES: (ArraySlice<UInt8>) -> [UInt8] = {
            switch operation {
            case .encrypt:
                return {
                    try! AES.aes(key: key, data: $0, operation: .encrypt)
                }
            case .decrypt:
                return {
                    try! AES.aes(key: key, data: $0, operation: .decrypt)
                }
            }
        }()
        
        return [ callAES(first), callAES(second), ].joined()
    }
    
    @usableFromInline
    static func aes32(data: [UInt8], key: ArraySlice<UInt8>, operation: Operation) -> FlattenSequence<[[UInt8]]> {
        Self.aes32(data: data[...], key: key, operation: operation)
    }

    @usableFromInline
    static func aes32(data: ArraySlice<UInt8>, key: [UInt8], operation: Operation) -> FlattenSequence<[[UInt8]]> {
        Self.aes32(data: data, key: key[...], operation: operation)
    }

    @usableFromInline
    static func aes32(data: [UInt8], key: [UInt8], operation: Operation) -> FlattenSequence<[[UInt8]]> {
        Self.aes32(data: data[...], key: key[...], operation: operation)
    }

    @usableFromInline
    static func passFactor(from password: String, haveLot: Bool, ownerEntropy: ArraySlice<UInt8>) -> Scalar? {
        let ownerSalt = haveLot ? Array(ownerEntropy[..<ownerEntropy.index(ownerEntropy.startIndex, offsetBy: 4)]) : Array(ownerEntropy)
        let preFactor = try! scrypt(password: Self.passwordToBytes(password),
                                    salt: ownerSalt,
                                    parameters: .bip38intermediate)
        let passFactor = haveLot
            ? [ preFactor[...], ownerEntropy, ].joined().hash256
            : preFactor
        return Scalar(passFactor)
    }
    
    @usableFromInline
    static func derived(from passPoint: Point,
                        addressHash: ArraySlice<UInt8>,
                        ownerEntropy: ArraySlice<UInt8>) -> (derivedHalf1: ArraySlice<UInt8>,
                                                             derivedHalf2: ArraySlice<UInt8>) {
        let d = try! scrypt(password: DSA.PublicKey(passPoint).serialize(),
                            salt: Array(addressHash + ownerEntropy),
                            parameters: .bip38mul)
        assert(d.count == 64)
        return (d.prefix(32), d.suffix(32))
    }
    
    @usableFromInline
    static func lotSequence(from userEntropy: ArraySlice<UInt8>) -> (lot: Int, sequence: Int) {
        precondition(userEntropy.count == 8)
        
        let lotSequenceStart = userEntropy.index(userEntropy.startIndex, offsetBy: 4)
        let lotSequenceEnd = userEntropy.index(lotSequenceStart, offsetBy: 4)
        
        var load: UInt32 = 0
        withUnsafeMutableBytes(of: &load) { loadPtr in
            userEntropy[lotSequenceStart..<lotSequenceEnd].withUnsafeBytes { source in
                loadPtr.copyMemory(from: source)
            }
        }
        load = load.byteSwapped
        
        let lot = load &>> 12
        let sequence = load & 0x0f_ff
        
        return (Int(lot), Int(sequence))
    }
}

// MARK: XOR sequences of bytes
@usableFromInline
func ^<LHS, RHS>(lhs: LHS, rhs:RHS) -> [UInt8]
where LHS: Sequence, RHS: Sequence, LHS.Element == UInt8, RHS.Element == UInt8 {
    assert(Array(lhs).count == Array(rhs).count)
    
    return zip(lhs, rhs)
    .map { lhs, rhs in
        lhs ^ rhs
    }
}
