package com.yourpackage.sodium

import kotlinx.cinterop.*
import platform.posix.memcpy
import platform.posix.size_tVar
import kotlin.native.concurrent.ThreadLocal
import libsodium.*    // cinterop package — adjust if different

@OptIn(ExperimentalUnsignedTypes::class, ExperimentalForeignApi::class)
public object SodiumNative : Sodium {

    init {
        // initialize libsodium once per process
        if (sodium_init() < 0) {
            error("libsodium initialization failed")
        }
    }

    // -----------------------
    // Helpers & Exceptions
    // -----------------------
    class SodiumException(message: String) : RuntimeException(message)

    private fun MemScope.toCPointer(bytes: ByteArray): CPointer<UByteVar> {
        val u = bytes.asUByteArray()
        val pinned = u.pin()
        this.defer { pinned.unpin() }
        return pinned.addressOf(0)
    }

    private fun ByteArray.asPinnedCPointer(scope: MemScope): CPointer<UByteVar> = scope.toCPointer(this)

    // convenience for copying native buffer -> kotlin
    private fun UByteVarArray.readBytesChecked(len: Int): ByteArray {
        return this.readBytes(len)
    }

    // -----------------------
    // Random
    // -----------------------
    public override fun randomBytes(len: Int): ByteArray {
        require(len >= 0)
        val out = ByteArray(len)
        memScoped {
            val o = allocArray<UByteVar>(len)
            randombytes_buf(o, len.convert())
            // copy into Kotlin ByteArray
            val pinnedOut = out.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), o, len.convert())
            } finally {
                pinnedOut.unpin()
            }
        }
        return out
    }

    // -----------------------
    // crypto_secretbox (XSalsa20-Poly1305)
    // -----------------------
    public override fun secretBoxEasy(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        require(nonce.size == crypto_secretbox_NONCEBYTES)
        require(key.size == crypto_secretbox_KEYBYTES)

        val cipher = ByteArray(message.size + crypto_secretbox_MACBYTES)

        memScoped {
            val m = toCPointer(message)
            val n = toCPointer(nonce)
            val k = toCPointer(key)
            val c = allocArray<UByteVar>(cipher.size)

            if (crypto_secretbox_easy(c, m, message.size.convert(), n, k) != 0) {
                throw SodiumException("crypto_secretbox_easy failed")
            }

            // copy back
            val pinnedOut = cipher.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), c, cipher.size.convert())
            } finally {
                pinnedOut.unpin()
            }
        }

        return cipher
    }

    public override fun secretBoxOpenEasy(cipher: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        require(nonce.size == crypto_secretbox_NONCEBYTES)
        require(key.size == crypto_secretbox_KEYBYTES)
        require(cipher.size >= crypto_secretbox_MACBYTES)

        val message = ByteArray(cipher.size - crypto_secretbox_MACBYTES)

        memScoped {
            val c = toCPointer(cipher)
            val n = toCPointer(nonce)
            val k = toCPointer(key)
            val m = allocArray<UByteVar>(message.size)

            if (crypto_secretbox_open_easy(m, c, cipher.size.convert(), n, k) != 0) {
                throw SodiumException("crypto_secretbox_open_easy failed: authentication failed")
            }

            val pinnedOut = message.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), m, message.size.convert())
            } finally {
                pinnedOut.unpin()
            }
        }

        return message
    }

    // -----------------------
    // crypto_box (public-key)
    // -----------------------
    public override fun cryptoBoxKeypair(): Pair<ByteArray, ByteArray> {
        val pk = ByteArray(crypto_box_PUBLICKEYBYTES)
        val sk = ByteArray(crypto_box_SECRETKEYBYTES)

        memScoped {
            val pkPtr = allocArray<UByteVar>(pk.size)
            val skPtr = allocArray<UByteVar>(sk.size)

            if (crypto_box_keypair(pkPtr, skPtr) != 0) {
                throw SodiumException("crypto_box_keypair failed")
            }

            val ppk = pk.asUByteArray().pin()
            val psk = sk.asUByteArray().pin()
            try {
                memcpy(ppk.addressOf(0), pkPtr, pk.size.convert())
                memcpy(psk.addressOf(0), skPtr, sk.size.convert())
            } finally {
                ppk.unpin(); psk.unpin()
            }
        }
        return Pair(pk, sk)
    }

    public override fun cryptoBoxEasy(message: ByteArray, nonce: ByteArray, publicKey: ByteArray, secretKey: ByteArray): ByteArray {
        require(nonce.size == crypto_box_NONCEBYTES)
        require(publicKey.size == crypto_box_PUBLICKEYBYTES)
        require(secretKey.size == crypto_box_SECRETKEYBYTES)

        val cipher = ByteArray(message.size + crypto_box_MACBYTES)
        memScoped {
            val m = toCPointer(message)
            val n = toCPointer(nonce)
            val pk = toCPointer(publicKey)
            val sk = toCPointer(secretKey)
            val c = allocArray<UByteVar>(cipher.size)

            if (crypto_box_easy(c, m, message.size.convert(), n, pk, sk) != 0) {
                throw SodiumException("crypto_box_easy failed")
            }

            val pinnedOut = cipher.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), c, cipher.size.convert())
            } finally {
                pinnedOut.unpin()
            }
        }
        return cipher
    }

    public override fun cryptoBoxOpenEasy(cipher: ByteArray, nonce: ByteArray, publicKey: ByteArray, secretKey: ByteArray): ByteArray {
        require(nonce.size == crypto_box_NONCEBYTES)
        require(publicKey.size == crypto_box_PUBLICKEYBYTES)
        require(secretKey.size == crypto_box_SECRETKEYBYTES)
        require(cipher.size >= crypto_box_MACBYTES)

        val message = ByteArray(cipher.size - crypto_box_MACBYTES)
        memScoped {
            val c = toCPointer(cipher)
            val n = toCPointer(nonce)
            val pk = toCPointer(publicKey)
            val sk = toCPointer(secretKey)
            val m = allocArray<UByteVar>(message.size)

            if (crypto_box_open_easy(m, c, cipher.size.convert(), n, pk, sk) != 0) {
                throw SodiumException("crypto_box_open_easy failed: authentication failed")
            }

            val pinnedOut = message.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), m, message.size.convert())
            } finally {
                pinnedOut.unpin()
            }
        }
        return message
    }

    // -----------------------
    // crypto_generichash (BLAKE2b) — one-shot
    // -----------------------
    public override fun genericHash(message: ByteArray, outLen: Int, key: ByteArray? /* nullable */): ByteArray {
        require(outLen in crypto_generichash_BYTES_MIN..crypto_generichash_BYTES_MAX)

        val out = ByteArray(outLen)
        memScoped {
            val m = toCPointer(message)
            val o = allocArray<UByteVar>(outLen)
            val keyPtr = key?.let { toCPointer(it) } ?: null
            val keyLen = key?.size?.convert() ?: 0u

            val rc = crypto_generichash(
                o, outLen.convert(),
                m, message.size.convert(),
                keyPtr, keyLen
            )
            if (rc != 0) throw SodiumException("crypto_generichash failed (rc=$rc)")

            val pinnedOut = out.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), o, outLen.convert())
            } finally {
                pinnedOut.unpin()
            }
        }
        return out
    }

    // -----------------------
    // crypto_generichash_state (stateful streaming)
    // -----------------------
    public inner class GenericHashState internal constructor(private val statePtr: CPointer<crypto_generichash_state>) : AutoCloseable {
        private var closed = false

        fun update(data: ByteArray) {
            require(!closed)
            memScoped {
                val d = toCPointer(data)
                if (crypto_generichash_update(statePtr, d, data.size.convert()) != 0) {
                    throw SodiumException("crypto_generichash_update failed")
                }
            }
        }

        fun final(outLen: Int): ByteArray {
            require(!closed)
            val out = ByteArray(outLen)
            memScoped {
                val o = allocArray<UByteVar>(outLen)
                if (crypto_generichash_final(statePtr, o, outLen.convert()) != 0) {
                    throw SodiumException("crypto_generichash_final failed")
                }
                val pinnedOut = out.asUByteArray().pin()
                try {
                    memcpy(pinnedOut.addressOf(0), o, outLen.convert())
                } finally {
                    pinnedOut.unpin()
                }
            }
            return out
        }

        override fun close() {
            if (!closed) {
                // free the native struct
                nativeHeap.free(statePtr.pointed)
                closed = true
            }
        }
    }

    public override fun genericHashInit(outLen: Int, key: ByteArray?): GenericHashState {
        require(outLen in crypto_generichash_BYTES_MIN..crypto_generichash_BYTES_MAX)
        memScoped {
            val state = nativeHeap.alloc<crypto_generichash_state>()
            val keyPtr = key?.let { toCPointer(it) } ?: null
            val keyLen = key?.size?.convert() ?: 0u

            if (crypto_generichash_init(state.ptr, keyPtr, keyLen, outLen.convert()) != 0) {
                nativeHeap.free(state)
                throw SodiumException("crypto_generichash_init failed")
            }
            return GenericHashState(state.ptr)
        }
    }

    // -----------------------
    // crypto_pwhash (Argon2id)
    // -----------------------
    public override fun pwhash(
        outLen: Int,
        password: ByteArray,
        salt: ByteArray,
        opslimit: ULong,
        memlimit: ULong,
        alg: Int = crypto_pwhash_ALG_ARGON2ID13
    ): ByteArray {
        require(salt.size == crypto_pwhash_SALTBYTES)
        val out = ByteArray(outLen)
        memScoped {
            val outPtr = allocArray<UByteVar>(outLen)
            val pw = toCPointer(password)
            val rc = crypto_pwhash(
                outPtr, outLen.convert(),
                pw, password.size.convert(),
                toCPointer(salt),
                opslimit, memlimit, alg.convert()
            )
            if (rc != 0) throw SodiumException("crypto_pwhash failed (rc=$rc)")
            val pinnedOut = out.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), outPtr, outLen.convert())
            } finally {
                pinnedOut.unpin()
            }
        }
        return out
    }

    // convenience: derive a key with recommended ops/mem
    public override fun pwhashDeriveKey(password: ByteArray, salt: ByteArray, outLen: Int): ByteArray {
        return pwhash(
            outLen,
            password,
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        )
    }

    // -----------------------
    // crypto_sign (Ed25519)
    // -----------------------
    public override fun signKeypair(): Pair<ByteArray, ByteArray> {
        val pk = ByteArray(crypto_sign_PUBLICKEYBYTES)
        val sk = ByteArray(crypto_sign_SECRETKEYBYTES)
        memScoped {
            val pkPtr = allocArray<UByteVar>(pk.size)
            val skPtr = allocArray<UByteVar>(sk.size)
            if (crypto_sign_keypair(pkPtr, skPtr) != 0) throw SodiumException("crypto_sign_keypair failed")
            val ppk = pk.asUByteArray().pin()
            val psk = sk.asUByteArray().pin()
            try {
                memcpy(ppk.addressOf(0), pkPtr, pk.size.convert())
                memcpy(psk.addressOf(0), skPtr, sk.size.convert())
            } finally {
                ppk.unpin(); psk.unpin()
            }
        }
        return Pair(pk, sk)
    }

    public override fun sign(message: ByteArray, secretKey: ByteArray): ByteArray {
        require(secretKey.size == crypto_sign_SECRETKEYBYTES)
        val signed = ByteArray(message.size + crypto_sign_BYTES)
        memScoped {
            val m = toCPointer(message)
            val sk = toCPointer(secretKey)
            val sm = allocArray<UByteVar>(signed.size)
            val smlen = alloc<size_tVar>()
            if (crypto_sign(sm, smlen.ptr, m, message.size.convert(), sk) != 0) {
                throw SodiumException("crypto_sign failed")
            }
            val pinnedOut = signed.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), sm, signed.size.convert())
            } finally {
                pinnedOut.unpin()
            }
        }
        return signed
    }

    public override fun signDetached(message: ByteArray, secretKey: ByteArray): ByteArray {
        require(secretKey.size == crypto_sign_SECRETKEYBYTES)
        val sig = ByteArray(crypto_sign_BYTES)
        memScoped {
            val m = toCPointer(message)
            val sk = toCPointer(secretKey)
            val sigPtr = allocArray<UByteVar>(sig.size)
            val siglen = alloc<size_tVar>()
            if (crypto_sign_detached(sigPtr, siglen.ptr, m, message.size.convert(), sk) != 0) {
                throw SodiumException("crypto_sign_detached failed")
            }
            val pinnedOut = sig.asUByteArray().pin()
            try {
                memcpy(pinnedOut.addressOf(0), sigPtr, sig.size.convert())
            } finally {
                pinnedOut.unpin()
            }
        }
        return sig
    }

    public override fun signVerify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        require(publicKey.size == crypto_sign_PUBLICKEYBYTES)
        require(signature.size == crypto_sign_BYTES)
        memScoped {
            val m = toCPointer(message)
            val sig = toCPointer(signature)
            val pk = toCPointer(publicKey)
            return crypto_sign_verify_detached(sig, m, message.size.convert(), pk) == 0
        }
    }

    // -----------------------
    // Secure memory helpers (sodium_malloc / sodium_free / sodium_memzero)
    // -----------------------
    public override fun secureAlloc(len: Int): Long {
        // we return an opaque handle (address) as Long — caller must call secureFree(handle)
        if (len <= 0) throw IllegalArgumentException("len must be > 0")
        val ptr = sodium_malloc(len.convert()) ?: throw SodiumException("sodium_malloc returned null")
        return ptr.toLong()
    }

    public override fun secureFree(handle: Long) {
        val ptr = handle.toCPointer<UByteVar>() ?: return
        sodium_memzero(ptr, /* len? libsodium memzero expects pointer only */ 0.convert()) // optionally zero if you know length; libsodium provides sodium_free which zeroes
        sodium_free(ptr)
    }

    public override fun secureZero(handle: Long, len: Int) {
        val ptr = handle.toCPointer<UByteVar>() ?: return
        sodium_memzero(ptr, len.convert())
    }

    // -----------------------
    // Misc / cleanup
    // -----------------------
    public override fun cleanup() {
        // libsodium has no global cleanup. But we could clear any persistent native allocations if we had stored some.
    }
}

// helper extension to cast long to CPointer
@Suppress("UNCHECKED_CAST")
private fun Long.toCPointer(): CPointer<UByteVar>? = interpretCPointer<UByteVar>(this.toLong())

// allow retrieving Sodium from expect/actual pattern
internal actual fun getSodium(): Sodium = SodiumNative
