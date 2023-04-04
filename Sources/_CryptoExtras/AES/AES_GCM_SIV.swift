//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
@_implementationOnly import CryptoBoringWrapper
import Foundation

/// Types associated with the AES GCM SIV algorithm
@available(macOS 10.15, *)
@available(tvOS 13.0, *)
@available(iOS 13.0, *)
@available(watchOS 6.0, *)
extension AES.GCM {
    /// AES in GCM SIV mode with 128-bit tags.
    public enum _SIV {
        static let tagByteCount = 16
        static let nonceByteCount = 12

        /// Encrypts and authenticates data using AES-GCM-SIV.
        ///
        /// - Parameters:
        ///   - message: The message to encrypt and authenticate
        ///   - key: An encryption key of 128 or 256 bits
        ///   - nonce: An Nonce for AES-GCM-SIV encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.GCM.Nonce()
        ///   - authenticatedData: Data to authenticate as part of the seal
        /// - Returns: A sealed box returning the authentication tag (seal) and the ciphertext
        /// - Throws: CipherError errors
        @available(macOS 10.15, *)
        @available(iOS 13.0, *)
        @available(watchOS 6.0, *)
        public static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>
            (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> SealedBox {
            return try OpenSSLAESGCMSIVImpl.seal(key: key, message: message, nonce: nonce, authenticatedData: authenticatedData)
        }

        /// Encrypts and authenticates data using AES-GCM-SIV.
        ///
        /// - Parameters:
        ///   - message: The message to encrypt and authenticate
        ///   - key: An encryption key of 128 or 256 bits
        ///   - nonce: An Nonce for AES-GCM-SIV encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.GCM.Nonce()
        /// - Returns: A sealed box returning the authentication tag (seal) and the ciphertext
        /// - Throws: CipherError errors
        @available(macOS 10.15, *)
        @available(iOS 13.0, *)
        @available(watchOS 6.0, *)
        public static func seal<Plaintext: DataProtocol>
            (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil) throws -> SealedBox {
            return try OpenSSLAESGCMSIVImpl.seal(key: key, message: message, nonce: nonce, authenticatedData: Data?.none)
        }

        /// Authenticates and decrypts data using AES-GCM-SIV.
        ///
        /// - Parameters:
        ///   - sealedBox: The sealed box to authenticate and decrypt
        ///   - key: An encryption key of 128 or 256 bits
        ///   - nonce: An Nonce for AES-GCM-SIV encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.GCM.Nonce().
        ///   - authenticatedData:  Data that was authenticated as part of the seal
        /// - Returns: The ciphertext if opening was successful
        /// - Throws: CipherError errors. If the authentication of the sealedbox failed, incorrectTag is thrown.
        @available(macOS 10.15, *)
        @available(iOS 13.0, *)
        @available(watchOS 6.0, *)
        public static func open<AuthenticatedData: DataProtocol>
            (_ sealedBox: SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data {
            return try OpenSSLAESGCMSIVImpl.open(key: key, sealedBox: sealedBox, authenticatedData: authenticatedData)
        }

        /// Authenticates and decrypts data using AES-GCM-SIV.
        ///
        /// - Parameters:
        ///   - sealedBox: The sealed box to authenticate and decrypt
        ///   - key: An encryption key of 128 or 256 bits
        ///   - nonce: An Nonce for AES-GCM-SIV encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.GCM.Nonce().
        /// - Returns: The ciphertext if opening was successful
        /// - Throws: CipherError errors. If the authentication of the sealedbox failed, incorrectTag is thrown.
        @available(macOS 10.15, *)
        @available(iOS 13.0, *)
        @available(watchOS 6.0, *)
        public static func open(_ sealedBox: SealedBox, using key: SymmetricKey) throws -> Data {
            return try OpenSSLAESGCMSIVImpl.open(key: key, sealedBox: sealedBox, authenticatedData: Data?.none)
        }
    }
}

@available(macOS 10.15, *)
@available(tvOS 13.0, *)
@available(iOS 13.0, *)
@available(watchOS 6.0, *)
extension AES.GCM._SIV {
    public struct Nonce: ContiguousBytes, Sequence {
        let bytes: Data

        /// Generates a fresh random Nonce. Unless required by a specification to provide a specific Nonce, this is the recommended initializer.
        @available(tvOS 13.0, *)
        @available(watchOS 6.0, *)
        public init() {
            var data = Data(repeating: 0, count: AES.GCM._SIV.nonceByteCount)
            data.withUnsafeMutableBytes {
                assert($0.count == AES.GCM._SIV.nonceByteCount)
                $0.initializeWithRandomBytes(count: AES.GCM._SIV.nonceByteCount)
            }
            self.bytes = data
        }

        @available(tvOS 13.0, *)
        @available(watchOS 6.0, *)
        public init<D: DataProtocol>(data: D) throws {
            if data.count != AES.GCM._SIV.nonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }

        @available(watchOS 6.0, *)
        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }
    }
}

@available(macOS 10.15, *)
@available(tvOS 13.0, *)
@available(iOS 13.0, *)
@available(watchOS 6.0, *)
extension AES.GCM._SIV {
    public struct SealedBox {
        /// The combined representation ( nonce || ciphertext || tag)
        public let combined: Data
        /// The authentication tag
        @available(watchOS 6.0, *)
        public var tag: Data {
            return combined.suffix(AES.GCM._SIV.tagByteCount)
        }
        /// The ciphertext
        @available(watchOS 6.0, *)
        public var ciphertext: Data {
            return combined.dropFirst(AES.GCM._SIV.nonceByteCount).dropLast(AES.GCM._SIV.tagByteCount)
        }
        /// The Nonce
        @available(macOS 10.15, *)
        @available(tvOS 13.0, *)
        @available(iOS 13.0, *)
        @available(watchOS 6.0, *)
        public var nonce: AES.GCM._SIV.Nonce {
            return try! AES.GCM._SIV.Nonce(data: combined.prefix(AES.GCM._SIV.nonceByteCount))
        }

        @available(macOS 10.15, *)
        @available(tvOS 13.0, *)
        @available(iOS 13.0, *)
        @available(watchOS 6.0, *)
        @inlinable
        public init<D: DataProtocol>(combined: D) throws {
            // AES minimum nonce (12 bytes) + AES tag (16 bytes)
            // While we have these values in the internal APIs, we can't use it in inlinable code.
            let aesGCMOverhead = 12 + 16

            if combined.count < aesGCMOverhead {
                throw CryptoKitError.incorrectParameterSize
            }

            self.combined = Data(combined)
        }

        @available(macOS 10.15, *)
        @available(tvOS 13.0, *)
        @available(iOS 13.0, *)
        @available(watchOS 6.0, *)
        public init<C: DataProtocol, T: DataProtocol>(nonce: AES.GCM._SIV.Nonce, ciphertext: C, tag: T) throws {
            guard tag.count == AES.GCM._SIV.tagByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.combined = Data(nonce) + ciphertext + tag
        }

        internal init(combined: Data, nonceByteCount: Int) {
            assert(nonceByteCount == AES.GCM._SIV.nonceByteCount)
            self.combined = combined
        }
    }
}
