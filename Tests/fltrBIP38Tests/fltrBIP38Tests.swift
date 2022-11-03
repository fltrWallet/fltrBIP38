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
import fltrBIP38
import fltrECC
import fltrTx
import XCTest

final class BIP38Tests: XCTestCase {
    let testDataMultiplyNoLot: [(password: String, passphrase: String, encrypted: String, key: [UInt8], address: String)] = [
        ( "TestingOneTwoThree",
          "passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
          "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
          "A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519".hex2Bytes,
          "1PE6TQi6HTVNz5DLwB1LcpMBALubfuN2z2" ),
        ( "Satoshi",
          "passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
          "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
          "C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A".hex2Bytes,
          "1CqzrtZC6mXSAhoxtFwVjz8LtwLJjDYU3V" ),
    ]
    
    func testDataMultiplyNoLotNumber() {
        self.testDataMultiplyNoLot.forEach {
            guard let decode = BIP38.decodeMul(encoded: $0.encrypted,
                                               password: $0.password,
                                               prefix: .main)
            else {
                XCTFail()
                return
            }
            
            XCTAssertNil(BIP38.decodeMul(encoded: $0.encrypted,
                                         password: $0.password + "0",
                                         prefix: .main))
            XCTAssertNil(BIP38.decodeMul(encoded: $0.encrypted,
                                         password: $0.password,
                                         prefix: .testnet))

            let key = $0.key
            decode.withUnsafeBytes { decode in
                XCTAssertEqual(Array(decode), key)
            }
            
            // Encode/decode random test key
            guard let (addressString, encrypted, confirm) = BIP38.encodeMul(intermediate: $0.passphrase,
                                                                            compressed: true,
                                                                            prefix: .main)
            else {
                XCTFail()
                return
            }
            
            let (checked, lotSequence) = BIP38.check(confirmation: confirm, password: $0.password, prefix: .main)
            XCTAssert(checked)
            XCTAssertNil(lotSequence)
            
            let decodedScalar = BIP38.decodeMul(encoded: encrypted, password: $0.password, prefix: .main)
            XCTAssertNotNil(decodedScalar)
            XCTAssertEqual(
                decodedScalar
                    .map(Point.init)
                    .map(DSA.PublicKey.init)
                    .map(PublicKeyHash.init)
                    .map { $0.addressLegacyPKH(.main) },
                addressString
            )
        }
    }
    
    let testDataMultiplyWithLot: [(password: String, passphrase: String, encrypted: String, key: [UInt8],
                                   cfrm: String, lot: Int, sequence: Int)] = [
        ( "MOLON LABE",
          "passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
          "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
          "44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190".hex2Bytes,
          "cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD",
          263183,
          1 ),
        ( "ΜΟΛΩΝ ΛΑΒΕ",
          "passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
          "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
          "CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006".hex2Bytes,
          "cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51",
          806938,
          1 ),
    ]
    
    func testDataMultiplyWithLotNumber() {
        self.testDataMultiplyWithLot.forEach {
            guard let decode = BIP38.decodeMul(encoded: $0.encrypted,
                                               password: $0.password,
                                               prefix: .main)
            else {
                XCTFail()
                return
            }
            
            XCTAssertNil(BIP38.decodeMul(encoded: $0.encrypted,
                                         password: $0.password + "0",
                                         prefix: .main))
            XCTAssertNil(BIP38.decodeMul(encoded: $0.encrypted,
                                         password: $0.password,
                                         prefix: .testnet))

            let key = $0.key
            decode.withUnsafeBytes { decode in
                XCTAssertEqual(Array(decode), key)
            }

            let (checked, lotSequence) = BIP38.check(confirmation: $0.cfrm,
                                                     password: $0.password,
                                                     prefix: .main)
            XCTAssert(checked)
            guard let (lot, sequence) = lotSequence
            else {
                XCTFail()
                return
            }
            XCTAssertEqual(lot, $0.lot)
            XCTAssertEqual(sequence, $0.sequence)
        }
    }
    
    let testDataNoMul: [(password: String, encrypted: String, key: [UInt8], compressed: Bool)] = [
        ( "TestingOneTwoThree",
          "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
          "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5".hex2Bytes,
          false ),
        ( "Satoshi",
          "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
          "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE".hex2Bytes,
          false ),
        ( "\u{03D2}\u{0301}\u{0000}\u{00010400}\u{0001F4A9}",
          "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
          "64EEAB5F9BE2A01A8365A579511EB3373C87C40DA6D2A25F05BDA68FE077B66E".hex2Bytes,
          false ),
        ( "TestingOneTwoThree",
          "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
          "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5".hex2Bytes,
          true ),
        ( "Satoshi",
          "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
          "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE".hex2Bytes,
          true ),
    ]

    func testDataNoMulNoComp() {
        self.testDataNoMul.forEach {
            let enc = BIP38.encodeNonMul(key: Scalar($0.key)!,
                                         password: $0.password,
                                         compressed: $0.compressed,
                                         prefix: .main)
            XCTAssertEqual(enc, $0.encrypted)
            
            let dec = BIP38.decodeNonMul(encoded: $0.encrypted,
                                         password: $0.password,
                                         prefix: .main)
            let key = $0.key
            dec?.withUnsafeBytes { dec in
                XCTAssertEqual(Array(dec), key)
            }
            
            XCTAssertNil(BIP38.decodeNonMul(encoded: $0.encrypted,
                                            password: $0.password + "0",
                                            prefix: .main))
            XCTAssertNil(BIP38.decodeNonMul(encoded: $0.encrypted,
                                            password: $0.password,
                                            prefix: .testnet))
        }
    }

}
