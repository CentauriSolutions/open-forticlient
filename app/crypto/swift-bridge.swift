import CommonCrypto
import CryptoKit
import Foundation
import Security

private final class P384Box {
    let privateKey: P384.KeyAgreement.PrivateKey
    init(_ key: P384.KeyAgreement.PrivateKey) { privateKey = key }
}

// Prototype C ABI for the observed crypto suite. Return 0 on success, -1 on bad
// arguments, -2 on a framework failure. Caller owns each handle until free.
@_cdecl("oftc_swift_group20_generate")
public func group20Generate(_ keyOut: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
                     _ publicOut: UnsafeMutablePointer<UInt8>?) -> Int32 {
    guard let keyOut, let publicOut else { return -1 }
    keyOut.pointee = nil
    let key = P384.KeyAgreement.PrivateKey()
    let encoded = key.publicKey.x963Representation
    guard encoded.count == 97, encoded.first == 4 else { return -2 }
    for (index, byte) in encoded.dropFirst().enumerated() {
        publicOut[index] = byte
    }
    keyOut.pointee = Unmanaged.passRetained(P384Box(key)).toOpaque()
    return 0
}

@_cdecl("oftc_swift_group20_shared")
public func group20Shared(_ keyHandle: UnsafeMutableRawPointer?,
                   _ peer: UnsafePointer<UInt8>?, _ peerLen: Int,
                   _ secret: UnsafeMutablePointer<UInt8>?,
                   _ secretLen: Int) -> Int32 {
    guard let keyHandle, let peer, let secret,
          peerLen == 96, secretLen == 48 else { return -1 }
    let key = Unmanaged<P384Box>.fromOpaque(keyHandle).takeUnretainedValue()
    do {
        let peerKey = try P384.KeyAgreement.PublicKey(
            x963Representation: Data([4]) + Data(bytes: peer, count: peerLen))
        let shared = try key.privateKey.sharedSecretFromKeyAgreement(with: peerKey)
        let bytes = shared.withUnsafeBytes { Data($0) }
        guard bytes.count == 48 else { return -2 }
        for (index, byte) in bytes.enumerated() { secret[index] = byte }
        return 0
    } catch { return -2 }
}

@_cdecl("oftc_swift_group20_free")
public func group20Free(_ keyHandle: UnsafeMutableRawPointer?) {
    if let keyHandle { Unmanaged<P384Box>.fromOpaque(keyHandle).release() }
}

@_cdecl("oftc_swift_aes256_cbc")
public func aes256CBC(_ encrypt: Int32, _ key: UnsafePointer<UInt8>?,
                      _ keyLen: Int, _ iv: UnsafePointer<UInt8>?,
                      _ ivLen: Int, _ input: UnsafePointer<UInt8>?,
                      _ inputLen: Int, _ output: UnsafeMutablePointer<UInt8>?,
                      _ outputLen: Int) -> Int32 {
    guard encrypt == 0 || encrypt == 1, let key, let iv, let input,
          let output, keyLen == 32, ivLen == 16, inputLen > 0,
          inputLen.isMultiple(of: 16), outputLen >= inputLen else { return -1 }
    var moved = 0
    let status = CCCrypt(encrypt == 1 ? CCOperation(kCCEncrypt) :
                                        CCOperation(kCCDecrypt),
                         CCAlgorithm(kCCAlgorithmAES), CCOptions(0), key,
                         keyLen, iv, input, inputLen, output, outputLen, &moved)
    return status == kCCSuccess && moved == inputLen ? 0 : -2
}

@_cdecl("oftc_swift_hmac")
public func hmac(_ sha256: Int32, _ key: UnsafePointer<UInt8>?,
                 _ keyLen: Int, _ input: UnsafePointer<UInt8>?,
                 _ inputLen: Int, _ digest: UnsafeMutablePointer<UInt8>?,
                 _ digestLen: Int) -> Int32 {
    guard sha256 == 0 || sha256 == 1, let key, let input, let digest,
          keyLen >= 0, inputLen >= 0,
          digestLen == (sha256 == 1 ? 32 : 20) else { return -1 }
    CCHmac(sha256 == 1 ? CCHmacAlgorithm(kCCHmacAlgSHA256) :
                         CCHmacAlgorithm(kCCHmacAlgSHA1),
           key, keyLen, input, inputLen, digest)
    return 0
}

@_cdecl("oftc_swift_random")
public func random(_ output: UnsafeMutablePointer<UInt8>?,
                   _ outputLen: Int) -> Int32 {
    guard let output, outputLen > 0 else { return -1 }
    return SecRandomCopyBytes(kSecRandomDefault, outputLen, output) ==
        errSecSuccess ? 0 : -2
}
