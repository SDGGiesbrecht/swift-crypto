//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
import Crypto

@available(macOS 10.15, *)
@available(tvOS 13.0, *)
@available(iOS 13.0, *)
@available(watchOS 6.0, *)
extension CryptoKitError {
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @available(macOS 10.15, *)
    @available(tvOS 13.0, *)
    @available(iOS 13.0, *)
    @available(watchOS 6.0, *)
    @usableFromInline
    static func internalBoringSSLError() -> CryptoKitError {
        return .underlyingCoreCryptoError(error: Int32(bitPattern: CCryptoBoringSSL_ERR_get_error()))
    }
}
