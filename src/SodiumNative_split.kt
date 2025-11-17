package yourpackage.sodium

@OptIn(ExperimentalForeignApi::class)
internal object SodiumNative : Sodium {

    override val aead: SodiumAead = SodiumAeadNative
    override val sign: SodiumSign = SodiumSignNative
    override val hash: SodiumHash = SodiumHashNative
    override val kx: SodiumKeyExchange = SodiumKeyExchangeNative
    override val pwhash: SodiumPwHash = SodiumPwHashNative

    init {
        if (libsodium.sodium_init() < 0) error("Failed to initialize libsodium")
    }

    override fun cleanup() { /* No cleanup needed */ }
}

internal actual fun getSodium(): Sodium = SodiumNative

-------------------
package yourpackage.sodium

import kotlinx.cinterop.*
import libsodium.*

internal object SodiumAeadNative : SodiumAead {

    private fun MemScope.ptr(bytes: ByteArray): CPointer<UByteVar> {
        val pinned = bytes.asUByteArray().pin()
        this.defer { pinned.unpin() }
        return pinned.addressOf(0)
    }

    override fun secretBoxEasy(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        require(nonce.size == crypto_secretbox_NONCEBYTES)
        require(key.size == crypto_secretbox_KEYBYTES)

        val out = ByteArray(message.size + crypto_secretbox_MACBYTES)
        memScoped {
            val m = ptr(message)
            val n = ptr(nonce)
            val k = ptr(key)
            val c = allocArray<UByteVar>(out.size)

            if (crypto_secretbox_easy(c, m, message.size.convert(), n, k) != 0)
                throw RuntimeException("secretBoxEasy failed")

            memcpy(out.refTo(0), c, out.size.convert())
        }
        return out
    }

    override fun secretBoxOpenEasy(cipher: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(cipher.size - crypto_secretbox_MACBYTES)
        memScoped {
            val c = ptr(cipher)
            val n = ptr(nonce)
            val k = ptr(key)
            val m = allocArray<UByteVar>(out.size)
            if (crypto_secretbox_open_easy(m, c, cipher.size.convert(), n, k) != 0)
                throw RuntimeException("secretBoxOpenEasy failed")
            memcpy(out.refTo(0), m, out.size.convert())
        }
        return out
    }

    override fun cryptoBoxKeypair(): Pair<ByteArray, ByteArray> {
        val pk = ByteArray(crypto_box_PUBLICKEYBYTES)
        val sk = ByteArray(crypto_box_SECRETKEYBYTES)
        memScoped {
            val pkc = allocArray<UByteVar>(pk.size)
            val skc = allocArray<UByteVar>(sk.size)
            crypto_box_keypair(pkc, skc)
            memcpy(pk.refTo(0), pkc, pk.size.convert())
            memcpy(sk.refTo(0), skc, sk.size.convert())
        }
        return pk to sk
    }

    override fun cryptoBoxEasy(
        message: ByteArray,
        nonce: ByteArray,
        publicKey: ByteArray,
        secretKey: ByteArray
    ): ByteArray {
        val out = ByteArray(message.size + crypto_box_MACBYTES)
        memScoped {
            if (crypto_box_easy(
                    out.asCPointer(), message.asCPointer(), message.size.convert(),
                    nonce.asCPointer(), publicKey.asCPointer(), secretKey.asCPointer()
                ) != 0
            ) throw RuntimeException("cryptoBoxEasy failed")
        }
        return out
    }

    override fun cryptoBoxOpenEasy(
        cipher: ByteArray,
        nonce: ByteArray,
        publicKey: ByteArray,
        secretKey: ByteArray
    ): ByteArray {
        val out = ByteArray(cipher.size - crypto_box_MACBYTES)
        memScoped {
            if (crypto_box_open_easy(
                    out.asCPointer(), cipher.asCPointer(), cipher.size.convert(),
                    nonce.asCPointer(), publicKey.asCPointer(), secretKey.asCPointer()
                ) != 0
            ) throw RuntimeException("cryptoBoxOpenEasy failed")
        }
        return out
    }
}