import CommonCrypto
import CryptoKit
import Foundation
import Security

// Standalone proof of the Swift adapter path. These are public test vectors,
// not gateway secrets or captured VPN material.
func decode(_ hex: String) -> Data {
    precondition(hex.count.isMultiple(of: 2))
    let characters = Array(hex.utf8)
    return Data(stride(from: 0, to: characters.count, by: 2).map { index in
        func digit(_ character: UInt8) -> UInt8 {
            switch character {
            case 48...57: character - 48
            case 65...70: character - 55
            case 97...102: character - 87
            default: preconditionFailure("invalid hex")
            }
        }
        return digit(characters[index]) << 4 | digit(characters[index + 1])
    })
}

func group20Shared(_ key: P384.KeyAgreement.PrivateKey, peerXY: Data) throws -> Data {
    guard peerXY.count == 96 else { throw CryptoError.invalidInput }
    let peer = try P384.KeyAgreement.PublicKey(x963Representation: Data([4]) + peerXY)
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    return shared.withUnsafeBytes { Data($0) }
}

enum CryptoError: Error { case invalidInput, cryptor(CCCryptorStatus), random(OSStatus) }

func cbc(encrypt: Bool, key: Data, iv: Data, input: Data) throws -> Data {
    guard key.count == 32, iv.count == 16, !input.isEmpty,
          input.count.isMultiple(of: 16) else { throw CryptoError.invalidInput }
    var output = Data(count: input.count)
    var moved = 0
    let status: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
        iv.withUnsafeBytes { ivBytes in
            input.withUnsafeBytes { inputBytes in
                output.withUnsafeMutableBytes { outputBytes in
                    CCCrypt(encrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                            keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                            inputBytes.baseAddress, input.count,
                            outputBytes.baseAddress, outputBytes.count, &moved)
                }
            }
        }
    }
    guard status == kCCSuccess, moved == input.count else {
        throw CryptoError.cryptor(status)
    }
    return output
}

func hmac(sha256: Bool, key: Data, input: Data) -> Data {
    var digest = Data(count: sha256 ? 32 : 20)
    key.withUnsafeBytes { keyBytes in
        input.withUnsafeBytes { inputBytes in
            digest.withUnsafeMutableBytes { digestBytes in
                CCHmac(sha256 ? CCHmacAlgorithm(kCCHmacAlgSHA256) :
                                 CCHmacAlgorithm(kCCHmacAlgSHA1),
                       keyBytes.baseAddress, key.count, inputBytes.baseAddress,
                       input.count, digestBytes.baseAddress)
            }
        }
    }
    return digest
}

func randomBytes(count: Int) throws -> Data {
    guard count > 0 else { throw CryptoError.invalidInput }
    var output = Data(count: count)
    let status = output.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
    }
    guard status == errSecSuccess else { throw CryptoError.random(status) }
    return output
}

func check(_ condition: Bool, _ name: String) {
    guard condition else { fatalError("FAIL: \(name)") }
    print("PASS: \(name)")
}

let initiatorXY = decode(
    "667842d7d180ac2cde6f74f37551f55755c7645c20ef73e31634fe72b4c55ee6" +
    "de3ac808acb4bdb4c88732aee95f41aa" +
    "9482ed1fc0eeb9cafc4984625ccfc23f65032149e0e144ada024181535a0f38e" +
    "eb9fcff3c2c947dae69b4c634573a81c")
let responderXY = decode(
    "e558dbef53eecde3d3fccfc1aea08a89a987475d12fd950d83cfa41732bc509d" +
    "0d1ac43a0336def96fda41d0774a3571" +
    "dcfbec7aacf3196472169e838430367f66eebe3c6e70c416dd5f0c68759dd1ff" +
    "f83fa40142209dff5eaad96db9e6386c")
let initiatorScalar = decode(
    "099f3c7034d4a2c699884d73a375a67f7624ef7c6b3c0f160647b67414dce655" +
    "e35b538041e649ee3faef896783ab194")
let expectedSecret = decode(
    "11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4" +
    "d603135569b9e9d09cf5d4a270f59746")
let initiator = try P384.KeyAgreement.PrivateKey(
    x963Representation: Data([4]) + initiatorXY + initiatorScalar)
check(initiator.publicKey.x963Representation == Data([4]) + initiatorXY,
      "RFC 5903 group-20 public encoding")
check(try group20Shared(initiator, peerXY: responderXY) == expectedSecret,
      "RFC 5903 group-20 shared secret")
let a = P384.KeyAgreement.PrivateKey()
let b = P384.KeyAgreement.PrivateKey()
let ab = try group20Shared(a, peerXY: b.publicKey.x963Representation.dropFirst())
let ba = try group20Shared(b, peerXY: a.publicKey.x963Representation.dropFirst())
check(a.publicKey.x963Representation.count == 97 &&
      b.publicKey.x963Representation.count == 97 &&
      ab == ba,
      "ephemeral P-384 key generation and agreement")
do {
    _ = try group20Shared(a, peerXY: Data(repeating: 0, count: 96))
    fatalError("invalid EC point accepted")
} catch { print("PASS: invalid EC point rejected") }

let aesKey = decode("603deb1015ca71be2b73aef0857d7781" +
                    "1f352c073b6108d72d9810a30914dff4")
let aesIV = decode("000102030405060708090a0b0c0d0e0f")
let plain = decode("6bc1bee22e409f96e93d7e117393172a" +
                   "ae2d8a571e03ac9c9eb76fac45af8e51" +
                   "30c81c46a35ce411e5fbc1191a0a52ef" +
                   "f69f2445df4f9b17ad2b417be66c3710")
let encrypted = decode("f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
                       "9cfc4e967edb808d679f777bc6702c7d" +
                       "39f23369a9d9bacfa530e26304231461" +
                       "b2eb05e2c39be9fcda6c19078c6a9d1b")
let sealed = try cbc(encrypt: true, key: aesKey, iv: aesIV, input: plain)
let opened = try cbc(encrypt: false, key: aesKey, iv: aesIV, input: encrypted)
check(sealed == encrypted && opened == plain,
      "NIST SP 800-38A AES-256-CBC without padding")
do {
    _ = try cbc(encrypt: true, key: aesKey, iv: aesIV,
                input: plain.dropLast())
    fatalError("non-block input accepted")
} catch { print("PASS: non-block CBC input rejected") }

let hmacKey = Data(repeating: 0x0b, count: 20)
let message = Data("Hi There".utf8)
check(hmac(sha256: false, key: hmacKey, input: message) ==
      decode("b617318655057264e28bc0b6fb378c8ef146be00") &&
      hmac(sha256: true, key: hmacKey, input: message) ==
      decode("b0344c61d8db38535ca8afceaf0bf12b" +
             "881dc200c9833da726e9376c2e32cff7"),
      "RFC 2202/4231 HMAC-SHA1/SHA256")
let r1 = try randomBytes(count: 32)
let r2 = try randomBytes(count: 32)
check(r1 != r2 && r1 != Data(repeating: 0, count: 32),
      "Security framework random bytes")
