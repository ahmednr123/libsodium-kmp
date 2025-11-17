
%module Sodium

%include "typemaps.i"
%include "stdint.i"
%include "arrays_java.i"
%include "carrays.i"
%include "various.i"
%include "java.swg"

/* Basic mappings */
%apply int {unsigned long long};
%apply long[] {unsigned long long *};
%apply int {size_t};
%apply int {uint32_t};
%apply long {uint64_t};

/* unsigned char */
%typemap(jni) unsigned char *       "jbyteArray"
%typemap(jtype) unsigned char *     "byte[]"
%typemap(jstype) unsigned char *    "byte[]"
%typemap(in) unsigned char *{
    $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) unsigned char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) unsigned char *"$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) unsigned char *""

/* uint8_t */
%typemap(jni) uint8_t *"jbyteArray"
%typemap(jtype) uint8_t *"byte[]"
%typemap(jstype) uint8_t *"byte[]"
%typemap(in) uint8_t *{
    $1 = (uint8_t *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) uint8_t *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) uint8_t *"$javainput"
%typemap(freearg) uint8_t *""

/* Strings */
%typemap(jni) char *"jbyteArray"
%typemap(jtype) char *"byte[]"
%typemap(jstype) char *"byte[]"
%typemap(in) char *{
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char *"$javainput"
%typemap(freearg) char *""


/* char types */
%typemap(jni) char *BYTE "jbyteArray"
%typemap(jtype) char *BYTE "byte[]"
%typemap(jstype) char *BYTE "byte[]"
%typemap(in) char *BYTE {
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char *BYTE {
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char *BYTE "$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) char *BYTE ""

/* Fixed size strings/char arrays */
%typemap(jni) char [ANY]"jbyteArray"
%typemap(jtype) char [ANY]"byte[]"
%typemap(jstype) char [ANY]"byte[]"
%typemap(in) char [ANY]{
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char [ANY]{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char [ANY]"$javainput"
%typemap(freearg) char [ANY]""



/* =============================================================================

    TYPEMAPS FOR CRYPTO_*_STATE DATATYPES

============================================================================= */


    /*
        crypto_aead_aes256gcm_state
    */
    %typemap(jni) crypto_aead_aes256gcm_state *"jbyteArray"
    %typemap(jtype) crypto_aead_aes256gcm_state *"byte[]"
    %typemap(jstype) crypto_aead_aes256gcm_state *"byte[]"
    %typemap(in) crypto_aead_aes256gcm_state *{
        $1 = (crypto_aead_aes256gcm_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_aead_aes256gcm_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_aead_aes256gcm_state *"$javainput"
    %typemap(freearg) crypto_aead_aes256gcm_state *""

    
    /*
        crypto_auth_hmacsha512256_state
    */
    %typemap(jni) crypto_auth_hmacsha512256_state *"jbyteArray"
    %typemap(jtype) crypto_auth_hmacsha512256_state *"byte[]"
    %typemap(jstype) crypto_auth_hmacsha512256_state *"byte[]"
    %typemap(in) crypto_auth_hmacsha512256_state *{
        $1 = (crypto_auth_hmacsha512256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_auth_hmacsha512256_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_auth_hmacsha512256_state *"$javainput"
    %typemap(freearg) crypto_auth_hmacsha512256_state *""

    
    /*
        crypto_onetimeauth_state
    */
    %typemap(jni) crypto_onetimeauth_state *"jbyteArray"
    %typemap(jtype) crypto_onetimeauth_state *"byte[]"
    %typemap(jstype) crypto_onetimeauth_state *"byte[]"
    %typemap(in) crypto_onetimeauth_state *{
        $1 = (crypto_onetimeauth_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_onetimeauth_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_onetimeauth_state *"$javainput"
    %typemap(freearg) crypto_onetimeauth_state *""

    
    /*
        crypto_generichash_state
    */
    %typemap(jni) crypto_generichash_state *"jbyteArray"
    %typemap(jtype) crypto_generichash_state *"byte[]"
    %typemap(jstype) crypto_generichash_state *"byte[]"
    %typemap(in) crypto_generichash_state *{
        $1 = (crypto_generichash_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_generichash_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_generichash_state *"$javainput"
    %typemap(freearg) crypto_generichash_state *""

    
    /*
        crypto_sign_state
    */
    %typemap(jni) crypto_sign_state *"jbyteArray"
    %typemap(jtype) crypto_sign_state *"byte[]"
    %typemap(jstype) crypto_sign_state *"byte[]"
    %typemap(in) crypto_sign_state *{
        $1 = (crypto_sign_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_sign_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_sign_state *"$javainput"
    %typemap(freearg) crypto_sign_state *""

    
    /*
        crypto_aead_aes256gcm_state_
    */
    %typemap(jni) crypto_aead_aes256gcm_state_ *"jbyteArray"
    %typemap(jtype) crypto_aead_aes256gcm_state_ *"byte[]"
    %typemap(jstype) crypto_aead_aes256gcm_state_ *"byte[]"
    %typemap(in) crypto_aead_aes256gcm_state_ *{
        $1 = (crypto_aead_aes256gcm_state_ *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_aead_aes256gcm_state_ *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_aead_aes256gcm_state_ *"$javainput"
    %typemap(freearg) crypto_aead_aes256gcm_state_ *""

    
    /*
        crypto_hash_sha512_state
    */
    %typemap(jni) crypto_hash_sha512_state *"jbyteArray"
    %typemap(jtype) crypto_hash_sha512_state *"byte[]"
    %typemap(jstype) crypto_hash_sha512_state *"byte[]"
    %typemap(in) crypto_hash_sha512_state *{
        $1 = (crypto_hash_sha512_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_hash_sha512_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_hash_sha512_state *"$javainput"
    %typemap(freearg) crypto_hash_sha512_state *""

    
    /*
        crypto_hash_sha256_state
    */
    %typemap(jni) crypto_hash_sha256_state *"jbyteArray"
    %typemap(jtype) crypto_hash_sha256_state *"byte[]"
    %typemap(jstype) crypto_hash_sha256_state *"byte[]"
    %typemap(in) crypto_hash_sha256_state *{
        $1 = (crypto_hash_sha256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_hash_sha256_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_hash_sha256_state *"$javainput"
    %typemap(freearg) crypto_hash_sha256_state *""

    
    /*
        crypto_kdf_hkdf_sha512_state
    */
    %typemap(jni) crypto_kdf_hkdf_sha512_state *"jbyteArray"
    %typemap(jtype) crypto_kdf_hkdf_sha512_state *"byte[]"
    %typemap(jstype) crypto_kdf_hkdf_sha512_state *"byte[]"
    %typemap(in) crypto_kdf_hkdf_sha512_state *{
        $1 = (crypto_kdf_hkdf_sha512_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_kdf_hkdf_sha512_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_kdf_hkdf_sha512_state *"$javainput"
    %typemap(freearg) crypto_kdf_hkdf_sha512_state *""

    
    /*
        randombytes_implementation
    */
    %typemap(jni) randombytes_implementation *"jbyteArray"
    %typemap(jtype) randombytes_implementation *"byte[]"
    %typemap(jstype) randombytes_implementation *"byte[]"
    %typemap(in) randombytes_implementation *{
        $1 = (randombytes_implementation *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) randombytes_implementation *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) randombytes_implementation *"$javainput"
    %typemap(freearg) randombytes_implementation *""

    
    /*
        crypto_xof_shake256_state
    */
    %typemap(jni) crypto_xof_shake256_state *"jbyteArray"
    %typemap(jtype) crypto_xof_shake256_state *"byte[]"
    %typemap(jstype) crypto_xof_shake256_state *"byte[]"
    %typemap(in) crypto_xof_shake256_state *{
        $1 = (crypto_xof_shake256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_xof_shake256_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_xof_shake256_state *"$javainput"
    %typemap(freearg) crypto_xof_shake256_state *""

    
    /*
        crypto_sign_ed25519ph_state
    */
    %typemap(jni) crypto_sign_ed25519ph_state *"jbyteArray"
    %typemap(jtype) crypto_sign_ed25519ph_state *"byte[]"
    %typemap(jstype) crypto_sign_ed25519ph_state *"byte[]"
    %typemap(in) crypto_sign_ed25519ph_state *{
        $1 = (crypto_sign_ed25519ph_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_sign_ed25519ph_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_sign_ed25519ph_state *"$javainput"
    %typemap(freearg) crypto_sign_ed25519ph_state *""

    
    /*
        crypto_secretstream_xchacha20poly1305_state
    */
    %typemap(jni) crypto_secretstream_xchacha20poly1305_state *"jbyteArray"
    %typemap(jtype) crypto_secretstream_xchacha20poly1305_state *"byte[]"
    %typemap(jstype) crypto_secretstream_xchacha20poly1305_state *"byte[]"
    %typemap(in) crypto_secretstream_xchacha20poly1305_state *{
        $1 = (crypto_secretstream_xchacha20poly1305_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_secretstream_xchacha20poly1305_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_secretstream_xchacha20poly1305_state *"$javainput"
    %typemap(freearg) crypto_secretstream_xchacha20poly1305_state *""

    
    /*
        crypto_onetimeauth_poly1305_state
    */
    %typemap(jni) crypto_onetimeauth_poly1305_state *"jbyteArray"
    %typemap(jtype) crypto_onetimeauth_poly1305_state *"byte[]"
    %typemap(jstype) crypto_onetimeauth_poly1305_state *"byte[]"
    %typemap(in) crypto_onetimeauth_poly1305_state *{
        $1 = (crypto_onetimeauth_poly1305_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_onetimeauth_poly1305_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_onetimeauth_poly1305_state *"$javainput"
    %typemap(freearg) crypto_onetimeauth_poly1305_state *""

    
    /*
        crypto_auth_hmacsha512_state
    */
    %typemap(jni) crypto_auth_hmacsha512_state *"jbyteArray"
    %typemap(jtype) crypto_auth_hmacsha512_state *"byte[]"
    %typemap(jstype) crypto_auth_hmacsha512_state *"byte[]"
    %typemap(in) crypto_auth_hmacsha512_state *{
        $1 = (crypto_auth_hmacsha512_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_auth_hmacsha512_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_auth_hmacsha512_state *"$javainput"
    %typemap(freearg) crypto_auth_hmacsha512_state *""

    
    /*
        crypto_kdf_hkdf_sha256_state
    */
    %typemap(jni) crypto_kdf_hkdf_sha256_state *"jbyteArray"
    %typemap(jtype) crypto_kdf_hkdf_sha256_state *"byte[]"
    %typemap(jstype) crypto_kdf_hkdf_sha256_state *"byte[]"
    %typemap(in) crypto_kdf_hkdf_sha256_state *{
        $1 = (crypto_kdf_hkdf_sha256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_kdf_hkdf_sha256_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_kdf_hkdf_sha256_state *"$javainput"
    %typemap(freearg) crypto_kdf_hkdf_sha256_state *""

    
    /*
        crypto_xof_turboshake128_state
    */
    %typemap(jni) crypto_xof_turboshake128_state *"jbyteArray"
    %typemap(jtype) crypto_xof_turboshake128_state *"byte[]"
    %typemap(jstype) crypto_xof_turboshake128_state *"byte[]"
    %typemap(in) crypto_xof_turboshake128_state *{
        $1 = (crypto_xof_turboshake128_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_xof_turboshake128_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_xof_turboshake128_state *"$javainput"
    %typemap(freearg) crypto_xof_turboshake128_state *""

    
    /*
        crypto_xof_shake128_state
    */
    %typemap(jni) crypto_xof_shake128_state *"jbyteArray"
    %typemap(jtype) crypto_xof_shake128_state *"byte[]"
    %typemap(jstype) crypto_xof_shake128_state *"byte[]"
    %typemap(in) crypto_xof_shake128_state *{
        $1 = (crypto_xof_shake128_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_xof_shake128_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_xof_shake128_state *"$javainput"
    %typemap(freearg) crypto_xof_shake128_state *""

    
    /*
        crypto_generichash_blake2b_state
    */
    %typemap(jni) crypto_generichash_blake2b_state *"jbyteArray"
    %typemap(jtype) crypto_generichash_blake2b_state *"byte[]"
    %typemap(jstype) crypto_generichash_blake2b_state *"byte[]"
    %typemap(in) crypto_generichash_blake2b_state *{
        $1 = (crypto_generichash_blake2b_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_generichash_blake2b_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_generichash_blake2b_state *"$javainput"
    %typemap(freearg) crypto_generichash_blake2b_state *""

    
    /*
        crypto_auth_hmacsha256_state
    */
    %typemap(jni) crypto_auth_hmacsha256_state *"jbyteArray"
    %typemap(jtype) crypto_auth_hmacsha256_state *"byte[]"
    %typemap(jstype) crypto_auth_hmacsha256_state *"byte[]"
    %typemap(in) crypto_auth_hmacsha256_state *{
        $1 = (crypto_auth_hmacsha256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_auth_hmacsha256_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_auth_hmacsha256_state *"$javainput"
    %typemap(freearg) crypto_auth_hmacsha256_state *""

    
    /*
        crypto_xof_turboshake256_state
    */
    %typemap(jni) crypto_xof_turboshake256_state *"jbyteArray"
    %typemap(jtype) crypto_xof_turboshake256_state *"byte[]"
    %typemap(jstype) crypto_xof_turboshake256_state *"byte[]"
    %typemap(in) crypto_xof_turboshake256_state *{
        $1 = (crypto_xof_turboshake256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    }
    %typemap(argout) crypto_xof_turboshake256_state *{
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
    }
    %typemap(javain) crypto_xof_turboshake256_state *"$javainput"
    %typemap(freearg) crypto_xof_turboshake256_state *""

    

/* *****************************************************************************

    HIGH-LEVEL LIBSODIUM API'S

***************************************************************************** */

int crypto_aead_aes256gcm_is_available(void);

size_t crypto_aead_aes256gcm_keybytes(void);

size_t crypto_aead_aes256gcm_nsecbytes(void);

size_t crypto_aead_aes256gcm_npubbytes(void);

size_t crypto_aead_aes256gcm_abytes(void);

size_t crypto_aead_aes256gcm_messagebytes_max(void);

size_t crypto_aead_aes256gcm_statebytes(void);

int crypto_aead_aes256gcm_encrypt(unsigned char * c,
			unsigned char * clen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aes256gcm_decrypt(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aes256gcm_encrypt_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * maclen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aes256gcm_decrypt_detached(unsigned char * m,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * mac,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aes256gcm_beforenm(crypto_aead_aes256gcm_state * ctx_,
			crypto_aead_aes256gcm_state * k);

int crypto_aead_aes256gcm_encrypt_afternm(unsigned char * c,
			unsigned char * clen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * ctx_);

int crypto_aead_aes256gcm_decrypt_afternm(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * ctx_);

int crypto_aead_aes256gcm_encrypt_detached_afternm(unsigned char * c,
			unsigned char * mac,
			unsigned char * maclen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * ctx_);

int crypto_aead_aes256gcm_decrypt_detached_afternm(unsigned char * m,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * mac,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * ctx_);

void crypto_aead_aes256gcm_keygen(unsigned char * k);

size_t crypto_stream_salsa208_keybytes(void);

size_t crypto_stream_salsa208_noncebytes(void);

size_t crypto_stream_salsa208_messagebytes_max(void);

int crypto_stream_salsa208(unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_salsa208_xor(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

void crypto_stream_salsa208_keygen(unsigned char * k);

size_t crypto_scalarmult_curve25519_bytes(void);

size_t crypto_scalarmult_curve25519_scalarbytes(void);

int crypto_scalarmult_curve25519(unsigned char * q,
			unsigned char * n,
			unsigned char * p);

int crypto_scalarmult_curve25519_base(unsigned char * q,
			unsigned char * n);

size_t crypto_verify_32_bytes(void);

int crypto_verify_32(const unsigned char * x,
			const unsigned char * y);

size_t crypto_scalarmult_ed25519_bytes(void);

size_t crypto_scalarmult_ed25519_scalarbytes(void);

int crypto_scalarmult_ed25519(unsigned char * q,
			unsigned char * n,
			unsigned char * p);

int crypto_scalarmult_ed25519_noclamp(unsigned char * q,
			unsigned char * n,
			unsigned char * p);

int crypto_scalarmult_ed25519_base(unsigned char * q,
			unsigned char * n);

int crypto_scalarmult_ed25519_base_noclamp(unsigned char * q,
			unsigned char * n);

size_t crypto_stream_xchacha20_keybytes(void);

size_t crypto_stream_xchacha20_noncebytes(void);

size_t crypto_stream_xchacha20_messagebytes_max(void);

int crypto_stream_xchacha20(unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_xchacha20_xor(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_xchacha20_xor_ic(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * ic,
			unsigned char * k);

void crypto_stream_xchacha20_keygen(unsigned char * k);

size_t crypto_hash_sha512_statebytes(void);

size_t crypto_hash_sha512_bytes(void);

int crypto_hash_sha512(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen);

int crypto_hash_sha512_init(crypto_hash_sha512_state * state);

int crypto_hash_sha512_update(crypto_hash_sha512_state * state,
			crypto_hash_sha512_state * in,
			crypto_hash_sha512_state * inlen);

int crypto_hash_sha512_final(crypto_hash_sha512_state * state,
			crypto_hash_sha512_state * out);

size_t crypto_core_ed25519_bytes(void);

size_t crypto_core_ed25519_uniformbytes(void);

size_t crypto_core_ed25519_hashbytes(void);

size_t crypto_core_ed25519_scalarbytes(void);

size_t crypto_core_ed25519_nonreducedscalarbytes(void);

int crypto_core_ed25519_is_valid_point(const unsigned char * p);

int crypto_core_ed25519_add(unsigned char * r,
			unsigned char * p,
			unsigned char * q);

int crypto_core_ed25519_sub(unsigned char * r,
			unsigned char * p,
			unsigned char * q);

int crypto_core_ed25519_from_uniform(unsigned char * p,
			unsigned char * r);

int crypto_core_ed25519_from_string(unsigned char * p,
			unsigned char * ctx,
			unsigned char * msg,
			unsigned char * msg_len,
			unsigned char * hash_alg);

int crypto_core_ed25519_from_string_ro(unsigned char * p,
			unsigned char * ctx,
			unsigned char * msg,
			unsigned char * msg_len,
			unsigned char * hash_alg);

void crypto_core_ed25519_random(unsigned char * p);

void crypto_core_ed25519_scalar_random(unsigned char * r);

int crypto_core_ed25519_scalar_invert(unsigned char * recip,
			unsigned char * s);

void crypto_core_ed25519_scalar_negate(unsigned char * neg,
			unsigned char * s);

void crypto_core_ed25519_scalar_complement(unsigned char * comp,
			unsigned char * s);

void crypto_core_ed25519_scalar_add(unsigned char * z,
			unsigned char * x,
			unsigned char * y);

void crypto_core_ed25519_scalar_sub(unsigned char * z,
			unsigned char * x,
			unsigned char * y);

void crypto_core_ed25519_scalar_mul(unsigned char * z,
			unsigned char * x,
			unsigned char * y);

void crypto_core_ed25519_scalar_reduce(unsigned char * r,
			unsigned char * s);

int crypto_core_ed25519_scalar_is_canonical(const unsigned char * s);

size_t crypto_shorthash_bytes(void);

size_t crypto_shorthash_keybytes(void);

const char * crypto_shorthash_primitive(void);

int crypto_shorthash(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

void crypto_shorthash_keygen(unsigned char * k);

size_t crypto_hash_sha256_statebytes(void);

size_t crypto_hash_sha256_bytes(void);

int crypto_hash_sha256(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen);

int crypto_hash_sha256_init(crypto_hash_sha256_state * state);

int crypto_hash_sha256_update(crypto_hash_sha256_state * state,
			crypto_hash_sha256_state * in,
			crypto_hash_sha256_state * inlen);

int crypto_hash_sha256_final(crypto_hash_sha256_state * state,
			crypto_hash_sha256_state * out);

size_t crypto_kdf_hkdf_sha512_keybytes(void);

size_t crypto_kdf_hkdf_sha512_bytes_min(void);

size_t crypto_kdf_hkdf_sha512_bytes_max(void);

int crypto_kdf_hkdf_sha512_extract(unsigned char * prk,
			unsigned char * salt,
			unsigned char * salt_len,
			unsigned char * ikm,
			unsigned char * ikm_len);

void crypto_kdf_hkdf_sha512_keygen(unsigned char * prk);

int crypto_kdf_hkdf_sha512_expand(unsigned char * out,
			unsigned char * out_len,
			unsigned char * ctx,
			unsigned char * ctx_len,
			unsigned char * prk);

size_t crypto_kdf_hkdf_sha512_statebytes(void);

int crypto_kdf_hkdf_sha512_extract_init(crypto_kdf_hkdf_sha512_state * state,
			crypto_kdf_hkdf_sha512_state * salt,
			crypto_kdf_hkdf_sha512_state * salt_len);

int crypto_kdf_hkdf_sha512_extract_update(crypto_kdf_hkdf_sha512_state * state,
			crypto_kdf_hkdf_sha512_state * ikm,
			crypto_kdf_hkdf_sha512_state * ikm_len);

int crypto_kdf_hkdf_sha512_extract_final(crypto_kdf_hkdf_sha512_state * state,
			crypto_kdf_hkdf_sha512_state * prk);

size_t crypto_box_curve25519xchacha20poly1305_seedbytes(void);

size_t crypto_box_curve25519xchacha20poly1305_publickeybytes(void);

size_t crypto_box_curve25519xchacha20poly1305_secretkeybytes(void);

size_t crypto_box_curve25519xchacha20poly1305_beforenmbytes(void);

size_t crypto_box_curve25519xchacha20poly1305_noncebytes(void);

size_t crypto_box_curve25519xchacha20poly1305_macbytes(void);

size_t crypto_box_curve25519xchacha20poly1305_messagebytes_max(void);

int crypto_box_curve25519xchacha20poly1305_seed_keypair(unsigned char * pk,
			unsigned char * sk,
			unsigned char * seed);

int crypto_box_curve25519xchacha20poly1305_keypair(unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xchacha20poly1305_easy(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xchacha20poly1305_open_easy(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xchacha20poly1305_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xchacha20poly1305_open_detached(unsigned char * m,
			unsigned char * c,
			unsigned char * mac,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xchacha20poly1305_beforenm(unsigned char * k,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xchacha20poly1305_easy_afternm(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_box_curve25519xchacha20poly1305_open_easy_afternm(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_box_curve25519xchacha20poly1305_detached_afternm(unsigned char * c,
			unsigned char * mac,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_box_curve25519xchacha20poly1305_open_detached_afternm(unsigned char * m,
			unsigned char * c,
			unsigned char * mac,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

size_t crypto_box_curve25519xchacha20poly1305_sealbytes(void);

int crypto_box_curve25519xchacha20poly1305_seal(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * pk);

int crypto_box_curve25519xchacha20poly1305_seal_open(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * pk,
			unsigned char * sk);

int crypto_pwhash_argon2id_alg_argon2id13(void);

size_t crypto_pwhash_argon2id_bytes_min(void);

size_t crypto_pwhash_argon2id_bytes_max(void);

size_t crypto_pwhash_argon2id_passwd_min(void);

size_t crypto_pwhash_argon2id_passwd_max(void);

size_t crypto_pwhash_argon2id_saltbytes(void);

size_t crypto_pwhash_argon2id_strbytes(void);

const char * crypto_pwhash_argon2id_strprefix(void);

unsigned long long crypto_pwhash_argon2id_opslimit_min(void);

unsigned long long crypto_pwhash_argon2id_opslimit_max(void);

size_t crypto_pwhash_argon2id_memlimit_min(void);

size_t crypto_pwhash_argon2id_memlimit_max(void);

unsigned long long crypto_pwhash_argon2id_opslimit_interactive(void);

size_t crypto_pwhash_argon2id_memlimit_interactive(void);

unsigned long long crypto_pwhash_argon2id_opslimit_moderate(void);

size_t crypto_pwhash_argon2id_memlimit_moderate(void);

unsigned long long crypto_pwhash_argon2id_opslimit_sensitive(void);

size_t crypto_pwhash_argon2id_memlimit_sensitive(void);

int crypto_pwhash_argon2id(unsigned char *const out,
			unsigned char *const outlen,
			unsigned char *const passwd,
			unsigned char *const passwdlen,
			unsigned char *const salt,
			unsigned char *const opslimit,
			unsigned char *const memlimit,
			unsigned char *const alg);

int crypto_pwhash_argon2id_str(char * out,
			char * passwd,
			char * passwdlen,
			char * opslimit,
			char * memlimit);

int crypto_pwhash_argon2id_str_verify(const char * str,
			const char * passwd,
			const char * passwdlen);

int crypto_pwhash_argon2id_str_needs_rehash(const char * str,
			const char * opslimit,
			const char * memlimit);

size_t crypto_stream_xsalsa20_keybytes(void);

size_t crypto_stream_xsalsa20_noncebytes(void);

size_t crypto_stream_xsalsa20_messagebytes_max(void);

int crypto_stream_xsalsa20(unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_xsalsa20_xor(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_xsalsa20_xor_ic(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * ic,
			unsigned char * k);

void crypto_stream_xsalsa20_keygen(unsigned char * k);

size_t crypto_aead_chacha20poly1305_ietf_keybytes(void);

size_t crypto_aead_chacha20poly1305_ietf_nsecbytes(void);

size_t crypto_aead_chacha20poly1305_ietf_npubbytes(void);

size_t crypto_aead_chacha20poly1305_ietf_abytes(void);

size_t crypto_aead_chacha20poly1305_ietf_messagebytes_max(void);

int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char * c,
			unsigned char * clen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_chacha20poly1305_ietf_encrypt_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * maclen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_chacha20poly1305_ietf_decrypt_detached(unsigned char * m,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * mac,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

void crypto_aead_chacha20poly1305_ietf_keygen(unsigned char * k);

size_t crypto_aead_chacha20poly1305_keybytes(void);

size_t crypto_aead_chacha20poly1305_nsecbytes(void);

size_t crypto_aead_chacha20poly1305_npubbytes(void);

size_t crypto_aead_chacha20poly1305_abytes(void);

size_t crypto_aead_chacha20poly1305_messagebytes_max(void);

int crypto_aead_chacha20poly1305_encrypt(unsigned char * c,
			unsigned char * clen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_chacha20poly1305_decrypt(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_chacha20poly1305_encrypt_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * maclen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_chacha20poly1305_decrypt_detached(unsigned char * m,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * mac,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

void crypto_aead_chacha20poly1305_keygen(unsigned char * k);

size_t crypto_stream_keybytes(void);

size_t crypto_stream_noncebytes(void);

size_t crypto_stream_messagebytes_max(void);

const char * crypto_stream_primitive(void);

int crypto_stream(unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_xor(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

void crypto_stream_keygen(unsigned char * k);

size_t randombytes_seedbytes(void);

void randombytes_buf(void *const buf,
			void *const size);

void randombytes_buf_deterministic(void *const buf,
			void *const size,
			void *const seed);

uint32_t randombytes_random(void);

uint32_t randombytes_uniform(const uint32_t upper_bound);

void randombytes_stir(void);

int randombytes_close(void);

int randombytes_set_implementation(const randombytes_implementation * impl);

const char * randombytes_implementation_name(void);

void randombytes(unsigned char *const buf,
			unsigned char *const buf_len);

size_t crypto_verify_16_bytes(void);

int crypto_verify_16(const unsigned char * x,
			const unsigned char * y);

size_t crypto_stream_salsa2012_keybytes(void);

size_t crypto_stream_salsa2012_noncebytes(void);

size_t crypto_stream_salsa2012_messagebytes_max(void);

int crypto_stream_salsa2012(unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_salsa2012_xor(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

void crypto_stream_salsa2012_keygen(unsigned char * k);

size_t crypto_xof_shake256_blockbytes(void);

size_t crypto_xof_shake256_statebytes(void);

unsigned char crypto_xof_shake256_domain_standard(void);

int crypto_xof_shake256(unsigned char * out,
			unsigned char * outlen,
			unsigned char * in,
			unsigned char * inlen);

int crypto_xof_shake256_init(crypto_xof_shake256_state * state);

int crypto_xof_shake256_init_with_domain(crypto_xof_shake256_state * state,
			crypto_xof_shake256_state * domain);

int crypto_xof_shake256_update(crypto_xof_shake256_state * state,
			crypto_xof_shake256_state * in,
			crypto_xof_shake256_state * inlen);

int crypto_xof_shake256_final(crypto_xof_shake256_state * state,
			crypto_xof_shake256_state * out,
			crypto_xof_shake256_state * outlen);

int crypto_xof_shake256_squeeze(crypto_xof_shake256_state * state,
			crypto_xof_shake256_state * out,
			crypto_xof_shake256_state * outlen);

size_t crypto_auth_bytes(void);

size_t crypto_auth_keybytes(void);

const char * crypto_auth_primitive(void);

int crypto_auth(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

int crypto_auth_verify(const unsigned char * h,
			const unsigned char * in,
			const unsigned char * inlen,
			const unsigned char * k);

void crypto_auth_keygen(unsigned char * k);

size_t crypto_auth_hmacsha512256_bytes(void);

size_t crypto_auth_hmacsha512256_keybytes(void);

int crypto_auth_hmacsha512256(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

int crypto_auth_hmacsha512256_verify(const unsigned char * h,
			const unsigned char * in,
			const unsigned char * inlen,
			const unsigned char * k);

size_t crypto_auth_hmacsha512256_statebytes(void);

int crypto_auth_hmacsha512256_init(crypto_auth_hmacsha512256_state * state,
			crypto_auth_hmacsha512256_state * key,
			crypto_auth_hmacsha512256_state * keylen);

int crypto_auth_hmacsha512256_update(crypto_auth_hmacsha512256_state * state,
			crypto_auth_hmacsha512256_state * in,
			crypto_auth_hmacsha512256_state * inlen);

int crypto_auth_hmacsha512256_final(crypto_auth_hmacsha512256_state * state,
			crypto_auth_hmacsha512256_state * out);

void crypto_auth_hmacsha512256_keygen(unsigned char * k);

size_t crypto_kdf_blake2b_bytes_min(void);

size_t crypto_kdf_blake2b_bytes_max(void);

size_t crypto_kdf_blake2b_contextbytes(void);

size_t crypto_kdf_blake2b_keybytes(void);

int crypto_kdf_blake2b_derive_from_key(unsigned char * subkey,
			unsigned char * subkey_len,
			unsigned char * subkey_id,
			unsigned char * ctx,
			unsigned char * key);

size_t crypto_aead_xchacha20poly1305_ietf_keybytes(void);

size_t crypto_aead_xchacha20poly1305_ietf_nsecbytes(void);

size_t crypto_aead_xchacha20poly1305_ietf_npubbytes(void);

size_t crypto_aead_xchacha20poly1305_ietf_abytes(void);

size_t crypto_aead_xchacha20poly1305_ietf_messagebytes_max(void);

int crypto_aead_xchacha20poly1305_ietf_encrypt(unsigned char * c,
			unsigned char * clen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_xchacha20poly1305_ietf_decrypt(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * maclen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_xchacha20poly1305_ietf_decrypt_detached(unsigned char * m,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * mac,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

void crypto_aead_xchacha20poly1305_ietf_keygen(unsigned char * k);

size_t crypto_secretbox_keybytes(void);

size_t crypto_secretbox_noncebytes(void);

size_t crypto_secretbox_macbytes(void);

const char * crypto_secretbox_primitive(void);

size_t crypto_secretbox_messagebytes_max(void);

int crypto_secretbox_easy(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_secretbox_open_easy(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_secretbox_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_secretbox_open_detached(unsigned char * m,
			unsigned char * c,
			unsigned char * mac,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

void crypto_secretbox_keygen(unsigned char * k);

size_t crypto_secretbox_zerobytes(void);

size_t crypto_secretbox_boxzerobytes(void);

int crypto_secretbox(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_secretbox_open(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

size_t crypto_sign_ed25519ph_statebytes(void);

size_t crypto_sign_ed25519_bytes(void);

size_t crypto_sign_ed25519_seedbytes(void);

size_t crypto_sign_ed25519_publickeybytes(void);

size_t crypto_sign_ed25519_secretkeybytes(void);

size_t crypto_sign_ed25519_messagebytes_max(void);

int crypto_sign_ed25519(unsigned char * sm,
			unsigned char * smlen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * sk);

int crypto_sign_ed25519_open(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * sm,
			unsigned char * smlen,
			unsigned char * pk);

int crypto_sign_ed25519_detached(unsigned char * sig,
			unsigned char * siglen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * sk);

int crypto_sign_ed25519_verify_detached(const unsigned char * sig,
			const unsigned char * m,
			const unsigned char * mlen,
			const unsigned char * pk);

int crypto_sign_ed25519_keypair(unsigned char * pk,
			unsigned char * sk);

int crypto_sign_ed25519_seed_keypair(unsigned char * pk,
			unsigned char * sk,
			unsigned char * seed);

int crypto_sign_ed25519_pk_to_curve25519(unsigned char * curve25519_pk,
			unsigned char * ed25519_pk);

int crypto_sign_ed25519_sk_to_curve25519(unsigned char * curve25519_sk,
			unsigned char * ed25519_sk);

int crypto_sign_ed25519_sk_to_seed(unsigned char * seed,
			unsigned char * sk);

int crypto_sign_ed25519_sk_to_pk(unsigned char * pk,
			unsigned char * sk);

int crypto_sign_ed25519ph_init(crypto_sign_ed25519ph_state * state);

int crypto_sign_ed25519ph_update(crypto_sign_ed25519ph_state * state,
			crypto_sign_ed25519ph_state * m,
			crypto_sign_ed25519ph_state * mlen);

int crypto_sign_ed25519ph_final_create(crypto_sign_ed25519ph_state * state,
			crypto_sign_ed25519ph_state * sig,
			crypto_sign_ed25519ph_state * siglen_p,
			crypto_sign_ed25519ph_state * sk);

int crypto_sign_ed25519ph_final_verify(crypto_sign_ed25519ph_state * state,
			crypto_sign_ed25519ph_state * sig,
			crypto_sign_ed25519ph_state * pk);

size_t crypto_core_salsa20_outputbytes(void);

size_t crypto_core_salsa20_inputbytes(void);

size_t crypto_core_salsa20_keybytes(void);

size_t crypto_core_salsa20_constbytes(void);

int crypto_core_salsa20(unsigned char * out,
			unsigned char * in,
			unsigned char * k,
			unsigned char * c);

size_t crypto_secretstream_xchacha20poly1305_abytes(void);

size_t crypto_secretstream_xchacha20poly1305_headerbytes(void);

size_t crypto_secretstream_xchacha20poly1305_keybytes(void);

size_t crypto_secretstream_xchacha20poly1305_messagebytes_max(void);

unsigned char crypto_secretstream_xchacha20poly1305_tag_message(void);

unsigned char crypto_secretstream_xchacha20poly1305_tag_push(void);

unsigned char crypto_secretstream_xchacha20poly1305_tag_rekey(void);

unsigned char crypto_secretstream_xchacha20poly1305_tag_final(void);

size_t crypto_secretstream_xchacha20poly1305_statebytes(void);

void crypto_secretstream_xchacha20poly1305_keygen(unsigned char * k);

int crypto_secretstream_xchacha20poly1305_init_push(crypto_secretstream_xchacha20poly1305_state * state,
			crypto_secretstream_xchacha20poly1305_state * header,
			crypto_secretstream_xchacha20poly1305_state * k);

int crypto_secretstream_xchacha20poly1305_push(crypto_secretstream_xchacha20poly1305_state * state,
			crypto_secretstream_xchacha20poly1305_state * c,
			crypto_secretstream_xchacha20poly1305_state * clen_p,
			crypto_secretstream_xchacha20poly1305_state * m,
			crypto_secretstream_xchacha20poly1305_state * mlen,
			crypto_secretstream_xchacha20poly1305_state * ad,
			crypto_secretstream_xchacha20poly1305_state * adlen,
			crypto_secretstream_xchacha20poly1305_state * tag);

int crypto_secretstream_xchacha20poly1305_init_pull(crypto_secretstream_xchacha20poly1305_state * state,
			crypto_secretstream_xchacha20poly1305_state * header,
			crypto_secretstream_xchacha20poly1305_state * k);

int crypto_secretstream_xchacha20poly1305_pull(crypto_secretstream_xchacha20poly1305_state * state,
			crypto_secretstream_xchacha20poly1305_state * m,
			crypto_secretstream_xchacha20poly1305_state * mlen_p,
			crypto_secretstream_xchacha20poly1305_state * tag_p,
			crypto_secretstream_xchacha20poly1305_state * c,
			crypto_secretstream_xchacha20poly1305_state * clen,
			crypto_secretstream_xchacha20poly1305_state * ad,
			crypto_secretstream_xchacha20poly1305_state * adlen);

void crypto_secretstream_xchacha20poly1305_rekey(crypto_secretstream_xchacha20poly1305_state * state);

size_t crypto_scalarmult_bytes(void);

size_t crypto_scalarmult_scalarbytes(void);

const char * crypto_scalarmult_primitive(void);

int crypto_scalarmult_base(unsigned char * q,
			unsigned char * n);

int crypto_scalarmult(unsigned char * q,
			unsigned char * n,
			unsigned char * p);

int crypto_pwhash_alg_argon2i13(void);

int crypto_pwhash_alg_argon2id13(void);

int crypto_pwhash_alg_default(void);

size_t crypto_pwhash_bytes_min(void);

size_t crypto_pwhash_bytes_max(void);

size_t crypto_pwhash_passwd_min(void);

size_t crypto_pwhash_passwd_max(void);

size_t crypto_pwhash_saltbytes(void);

size_t crypto_pwhash_strbytes(void);

const char * crypto_pwhash_strprefix(void);

unsigned long long crypto_pwhash_opslimit_min(void);

unsigned long long crypto_pwhash_opslimit_max(void);

size_t crypto_pwhash_memlimit_min(void);

size_t crypto_pwhash_memlimit_max(void);

unsigned long long crypto_pwhash_opslimit_interactive(void);

size_t crypto_pwhash_memlimit_interactive(void);

unsigned long long crypto_pwhash_opslimit_moderate(void);

size_t crypto_pwhash_memlimit_moderate(void);

unsigned long long crypto_pwhash_opslimit_sensitive(void);

size_t crypto_pwhash_memlimit_sensitive(void);

int crypto_pwhash(unsigned char *const out,
			unsigned char *const outlen,
			unsigned char *const passwd,
			unsigned char *const passwdlen,
			unsigned char *const salt,
			unsigned char *const opslimit,
			unsigned char *const memlimit,
			unsigned char *const alg);

int crypto_pwhash_str(char * out,
			char * passwd,
			char * passwdlen,
			char * opslimit,
			char * memlimit);

int crypto_pwhash_str_alg(char * out,
			char * passwd,
			char * passwdlen,
			char * opslimit,
			char * memlimit,
			char * alg);

int crypto_pwhash_str_verify(const char * str,
			const char * passwd,
			const char * passwdlen);

int crypto_pwhash_str_needs_rehash(const char * str,
			const char * opslimit,
			const char * memlimit);

const char * crypto_pwhash_primitive(void);

void sodium_memzero(void *const pnt,
			void *const len);

void sodium_stackzero(const size_t len);

int sodium_memcmp(const void *const b1_,
			const void *const b2_,
			const void *const len);

int sodium_compare(const unsigned char * b1_,
			const unsigned char * b2_,
			const unsigned char * len);

int sodium_is_zero(const unsigned char * n,
			const unsigned char * nlen);

void sodium_increment(unsigned char * n,
			unsigned char * nlen);

void sodium_add(unsigned char * a,
			unsigned char * b,
			unsigned char * len);

void sodium_sub(unsigned char * a,
			unsigned char * b,
			unsigned char * len);

char * sodium_bin2hex(char *const hex,
			char *const hex_maxlen,
			char *const bin,
			char *const bin_len);

int sodium_hex2bin(unsigned char *const bin,
			unsigned char *const bin_maxlen,
			unsigned char *const hex,
			unsigned char *const hex_len,
			unsigned char *const ignore,
			unsigned char *const bin_len,
			unsigned char *const hex_end);

size_t sodium_base64_encoded_len(const size_t bin_len,
			const size_t variant);

char * sodium_bin2base64(char *const b64,
			char *const b64_maxlen,
			char *const bin,
			char *const bin_len,
			char *const variant);

int sodium_base642bin(unsigned char *const bin,
			unsigned char *const bin_maxlen,
			unsigned char *const b64,
			unsigned char *const b64_len,
			unsigned char *const ignore,
			unsigned char *const bin_len,
			unsigned char *const b64_end,
			unsigned char *const variant);

int sodium_mlock(void *const addr,
			void *const len);

int sodium_munlock(void *const addr,
			void *const len);

void * sodium_malloc(const size_t size);

void * sodium_allocarray(size_t count,
			size_t size);

void sodium_free(void * ptr);

int sodium_mprotect_noaccess(void * ptr);

int sodium_mprotect_readonly(void * ptr);

int sodium_mprotect_readwrite(void * ptr);

int sodium_pad(size_t * padded_buflen_p,
			size_t * buf,
			size_t * unpadded_buflen,
			size_t * blocksize,
			size_t * max_buflen);

int sodium_unpad(size_t * unpadded_buflen_p,
			size_t * buf,
			size_t * padded_buflen,
			size_t * blocksize);

int _sodium_alloc_init(void);

size_t crypto_stream_salsa20_keybytes(void);

size_t crypto_stream_salsa20_noncebytes(void);

size_t crypto_stream_salsa20_messagebytes_max(void);

int crypto_stream_salsa20(unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_salsa20_xor(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_salsa20_xor_ic(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * ic,
			unsigned char * k);

void crypto_stream_salsa20_keygen(unsigned char * k);

size_t crypto_onetimeauth_poly1305_statebytes(void);

size_t crypto_onetimeauth_poly1305_bytes(void);

size_t crypto_onetimeauth_poly1305_keybytes(void);

int crypto_onetimeauth_poly1305(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

int crypto_onetimeauth_poly1305_verify(const unsigned char * h,
			const unsigned char * in,
			const unsigned char * inlen,
			const unsigned char * k);

int crypto_onetimeauth_poly1305_init(crypto_onetimeauth_poly1305_state * state,
			crypto_onetimeauth_poly1305_state * key);

int crypto_onetimeauth_poly1305_update(crypto_onetimeauth_poly1305_state * state,
			crypto_onetimeauth_poly1305_state * in,
			crypto_onetimeauth_poly1305_state * inlen);

int crypto_onetimeauth_poly1305_final(crypto_onetimeauth_poly1305_state * state,
			crypto_onetimeauth_poly1305_state * out);

void crypto_onetimeauth_poly1305_keygen(unsigned char * k);

size_t crypto_box_seedbytes(void);

size_t crypto_box_publickeybytes(void);

size_t crypto_box_secretkeybytes(void);

size_t crypto_box_noncebytes(void);

size_t crypto_box_macbytes(void);

size_t crypto_box_messagebytes_max(void);

const char * crypto_box_primitive(void);

int crypto_box_seed_keypair(unsigned char * pk,
			unsigned char * sk,
			unsigned char * seed);

int crypto_box_keypair(unsigned char * pk,
			unsigned char * sk);

int crypto_box_easy(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_open_easy(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_open_detached(unsigned char * m,
			unsigned char * c,
			unsigned char * mac,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

size_t crypto_box_beforenmbytes(void);

int crypto_box_beforenm(unsigned char * k,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_easy_afternm(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_box_open_easy_afternm(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_box_detached_afternm(unsigned char * c,
			unsigned char * mac,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_box_open_detached_afternm(unsigned char * m,
			unsigned char * c,
			unsigned char * mac,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

size_t crypto_box_sealbytes(void);

int crypto_box_seal(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * pk);

int crypto_box_seal_open(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * pk,
			unsigned char * sk);

size_t crypto_box_zerobytes(void);

size_t crypto_box_boxzerobytes(void);

int crypto_box(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_open(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_afternm(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_box_open_afternm(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

size_t crypto_hash_bytes(void);

int crypto_hash(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen);

const char * crypto_hash_primitive(void);

size_t crypto_aead_aegis256_keybytes(void);

size_t crypto_aead_aegis256_nsecbytes(void);

size_t crypto_aead_aegis256_npubbytes(void);

size_t crypto_aead_aegis256_abytes(void);

size_t crypto_aead_aegis256_messagebytes_max(void);

int crypto_aead_aegis256_encrypt(unsigned char * c,
			unsigned char * clen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aegis256_decrypt(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aegis256_encrypt_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * maclen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aegis256_decrypt_detached(unsigned char * m,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * mac,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

void crypto_aead_aegis256_keygen(unsigned char * k);

size_t crypto_auth_hmacsha512_bytes(void);

size_t crypto_auth_hmacsha512_keybytes(void);

int crypto_auth_hmacsha512(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

int crypto_auth_hmacsha512_verify(const unsigned char * h,
			const unsigned char * in,
			const unsigned char * inlen,
			const unsigned char * k);

size_t crypto_auth_hmacsha512_statebytes(void);

int crypto_auth_hmacsha512_init(crypto_auth_hmacsha512_state * state,
			crypto_auth_hmacsha512_state * key,
			crypto_auth_hmacsha512_state * keylen);

int crypto_auth_hmacsha512_update(crypto_auth_hmacsha512_state * state,
			crypto_auth_hmacsha512_state * in,
			crypto_auth_hmacsha512_state * inlen);

int crypto_auth_hmacsha512_final(crypto_auth_hmacsha512_state * state,
			crypto_auth_hmacsha512_state * out);

void crypto_auth_hmacsha512_keygen(unsigned char * k);

size_t crypto_kdf_hkdf_sha256_keybytes(void);

size_t crypto_kdf_hkdf_sha256_bytes_min(void);

size_t crypto_kdf_hkdf_sha256_bytes_max(void);

int crypto_kdf_hkdf_sha256_extract(unsigned char * prk,
			unsigned char * salt,
			unsigned char * salt_len,
			unsigned char * ikm,
			unsigned char * ikm_len);

void crypto_kdf_hkdf_sha256_keygen(unsigned char * prk);

int crypto_kdf_hkdf_sha256_expand(unsigned char * out,
			unsigned char * out_len,
			unsigned char * ctx,
			unsigned char * ctx_len,
			unsigned char * prk);

size_t crypto_kdf_hkdf_sha256_statebytes(void);

int crypto_kdf_hkdf_sha256_extract_init(crypto_kdf_hkdf_sha256_state * state,
			crypto_kdf_hkdf_sha256_state * salt,
			crypto_kdf_hkdf_sha256_state * salt_len);

int crypto_kdf_hkdf_sha256_extract_update(crypto_kdf_hkdf_sha256_state * state,
			crypto_kdf_hkdf_sha256_state * ikm,
			crypto_kdf_hkdf_sha256_state * ikm_len);

int crypto_kdf_hkdf_sha256_extract_final(crypto_kdf_hkdf_sha256_state * state,
			crypto_kdf_hkdf_sha256_state * prk);

size_t crypto_stream_chacha20_keybytes(void);

size_t crypto_stream_chacha20_noncebytes(void);

size_t crypto_stream_chacha20_messagebytes_max(void);

int crypto_stream_chacha20(unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_chacha20_xor(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_chacha20_xor_ic(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * ic,
			unsigned char * k);

void crypto_stream_chacha20_keygen(unsigned char * k);

size_t crypto_stream_chacha20_ietf_keybytes(void);

size_t crypto_stream_chacha20_ietf_noncebytes(void);

size_t crypto_stream_chacha20_ietf_messagebytes_max(void);

int crypto_stream_chacha20_ietf(unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_chacha20_ietf_xor(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_stream_chacha20_ietf_xor_ic(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * ic,
			unsigned char * k);

void crypto_stream_chacha20_ietf_keygen(unsigned char * k);

size_t crypto_scalarmult_ristretto255_bytes(void);

size_t crypto_scalarmult_ristretto255_scalarbytes(void);

int crypto_scalarmult_ristretto255(unsigned char * q,
			unsigned char * n,
			unsigned char * p);

int crypto_scalarmult_ristretto255_base(unsigned char * q,
			unsigned char * n);

size_t crypto_secretbox_xsalsa20poly1305_keybytes(void);

size_t crypto_secretbox_xsalsa20poly1305_noncebytes(void);

size_t crypto_secretbox_xsalsa20poly1305_macbytes(void);

size_t crypto_secretbox_xsalsa20poly1305_messagebytes_max(void);

void crypto_secretbox_xsalsa20poly1305_keygen(unsigned char * k);

size_t crypto_secretbox_xsalsa20poly1305_boxzerobytes(void);

size_t crypto_secretbox_xsalsa20poly1305_zerobytes(void);

int crypto_secretbox_xsalsa20poly1305(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_secretbox_xsalsa20poly1305_open(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

size_t crypto_xof_turboshake128_blockbytes(void);

size_t crypto_xof_turboshake128_statebytes(void);

unsigned char crypto_xof_turboshake128_domain_standard(void);

int crypto_xof_turboshake128(unsigned char * out,
			unsigned char * outlen,
			unsigned char * in,
			unsigned char * inlen);

int crypto_xof_turboshake128_init(crypto_xof_turboshake128_state * state);

int crypto_xof_turboshake128_init_with_domain(crypto_xof_turboshake128_state * state,
			crypto_xof_turboshake128_state * domain);

int crypto_xof_turboshake128_update(crypto_xof_turboshake128_state * state,
			crypto_xof_turboshake128_state * in,
			crypto_xof_turboshake128_state * inlen);

int crypto_xof_turboshake128_final(crypto_xof_turboshake128_state * state,
			crypto_xof_turboshake128_state * out,
			crypto_xof_turboshake128_state * outlen);

int crypto_xof_turboshake128_squeeze(crypto_xof_turboshake128_state * state,
			crypto_xof_turboshake128_state * out,
			crypto_xof_turboshake128_state * outlen);

size_t crypto_xof_shake128_blockbytes(void);

size_t crypto_xof_shake128_statebytes(void);

unsigned char crypto_xof_shake128_domain_standard(void);

int crypto_xof_shake128(unsigned char * out,
			unsigned char * outlen,
			unsigned char * in,
			unsigned char * inlen);

int crypto_xof_shake128_init(crypto_xof_shake128_state * state);

int crypto_xof_shake128_init_with_domain(crypto_xof_shake128_state * state,
			crypto_xof_shake128_state * domain);

int crypto_xof_shake128_update(crypto_xof_shake128_state * state,
			crypto_xof_shake128_state * in,
			crypto_xof_shake128_state * inlen);

int crypto_xof_shake128_final(crypto_xof_shake128_state * state,
			crypto_xof_shake128_state * out,
			crypto_xof_shake128_state * outlen);

int crypto_xof_shake128_squeeze(crypto_xof_shake128_state * state,
			crypto_xof_shake128_state * out,
			crypto_xof_shake128_state * outlen);

size_t crypto_secretbox_xchacha20poly1305_keybytes(void);

size_t crypto_secretbox_xchacha20poly1305_noncebytes(void);

size_t crypto_secretbox_xchacha20poly1305_macbytes(void);

size_t crypto_secretbox_xchacha20poly1305_messagebytes_max(void);

int crypto_secretbox_xchacha20poly1305_easy(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_secretbox_xchacha20poly1305_open_easy(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_secretbox_xchacha20poly1305_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_secretbox_xchacha20poly1305_open_detached(unsigned char * m,
			unsigned char * c,
			unsigned char * mac,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int crypto_pwhash_argon2i_alg_argon2i13(void);

size_t crypto_pwhash_argon2i_bytes_min(void);

size_t crypto_pwhash_argon2i_bytes_max(void);

size_t crypto_pwhash_argon2i_passwd_min(void);

size_t crypto_pwhash_argon2i_passwd_max(void);

size_t crypto_pwhash_argon2i_saltbytes(void);

size_t crypto_pwhash_argon2i_strbytes(void);

const char * crypto_pwhash_argon2i_strprefix(void);

unsigned long long crypto_pwhash_argon2i_opslimit_min(void);

unsigned long long crypto_pwhash_argon2i_opslimit_max(void);

size_t crypto_pwhash_argon2i_memlimit_min(void);

size_t crypto_pwhash_argon2i_memlimit_max(void);

unsigned long long crypto_pwhash_argon2i_opslimit_interactive(void);

size_t crypto_pwhash_argon2i_memlimit_interactive(void);

unsigned long long crypto_pwhash_argon2i_opslimit_moderate(void);

size_t crypto_pwhash_argon2i_memlimit_moderate(void);

unsigned long long crypto_pwhash_argon2i_opslimit_sensitive(void);

size_t crypto_pwhash_argon2i_memlimit_sensitive(void);

int crypto_pwhash_argon2i(unsigned char *const out,
			unsigned char *const outlen,
			unsigned char *const passwd,
			unsigned char *const passwdlen,
			unsigned char *const salt,
			unsigned char *const opslimit,
			unsigned char *const memlimit,
			unsigned char *const alg);

int crypto_pwhash_argon2i_str(char * out,
			char * passwd,
			char * passwdlen,
			char * opslimit,
			char * memlimit);

int crypto_pwhash_argon2i_str_verify(const char * str,
			const char * passwd,
			const char * passwdlen);

int crypto_pwhash_argon2i_str_needs_rehash(const char * str,
			const char * opslimit,
			const char * memlimit);

size_t crypto_generichash_blake2b_bytes_min(void);

size_t crypto_generichash_blake2b_bytes_max(void);

size_t crypto_generichash_blake2b_bytes(void);

size_t crypto_generichash_blake2b_keybytes_min(void);

size_t crypto_generichash_blake2b_keybytes_max(void);

size_t crypto_generichash_blake2b_keybytes(void);

size_t crypto_generichash_blake2b_saltbytes(void);

size_t crypto_generichash_blake2b_personalbytes(void);

size_t crypto_generichash_blake2b_statebytes(void);

int crypto_generichash_blake2b(unsigned char * out,
			unsigned char * outlen,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * key,
			unsigned char * keylen);

int crypto_generichash_blake2b_salt_personal(unsigned char * out,
			unsigned char * outlen,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * key,
			unsigned char * keylen,
			unsigned char * salt,
			unsigned char * personal);

int crypto_generichash_blake2b_init(crypto_generichash_blake2b_state * state,
			crypto_generichash_blake2b_state * key,
			crypto_generichash_blake2b_state * keylen,
			crypto_generichash_blake2b_state * outlen);

int crypto_generichash_blake2b_init_salt_personal(crypto_generichash_blake2b_state * state,
			crypto_generichash_blake2b_state * key,
			crypto_generichash_blake2b_state * keylen,
			crypto_generichash_blake2b_state * outlen,
			crypto_generichash_blake2b_state * salt,
			crypto_generichash_blake2b_state * personal);

int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state * state,
			crypto_generichash_blake2b_state * in,
			crypto_generichash_blake2b_state * inlen);

int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state * state,
			crypto_generichash_blake2b_state * out,
			crypto_generichash_blake2b_state * outlen);

void crypto_generichash_blake2b_keygen(unsigned char * k);

size_t crypto_pwhash_scryptsalsa208sha256_bytes_min(void);

size_t crypto_pwhash_scryptsalsa208sha256_bytes_max(void);

size_t crypto_pwhash_scryptsalsa208sha256_passwd_min(void);

size_t crypto_pwhash_scryptsalsa208sha256_passwd_max(void);

size_t crypto_pwhash_scryptsalsa208sha256_saltbytes(void);

size_t crypto_pwhash_scryptsalsa208sha256_strbytes(void);

const char * crypto_pwhash_scryptsalsa208sha256_strprefix(void);

unsigned long long crypto_pwhash_scryptsalsa208sha256_opslimit_min(void);

unsigned long long crypto_pwhash_scryptsalsa208sha256_opslimit_max(void);

size_t crypto_pwhash_scryptsalsa208sha256_memlimit_min(void);

size_t crypto_pwhash_scryptsalsa208sha256_memlimit_max(void);

unsigned long long crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(void);

size_t crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(void);

unsigned long long crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(void);

size_t crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(void);

int crypto_pwhash_scryptsalsa208sha256(unsigned char *const out,
			unsigned char *const outlen,
			unsigned char *const passwd,
			unsigned char *const passwdlen,
			unsigned char *const salt,
			unsigned char *const opslimit,
			unsigned char *const memlimit);

int crypto_pwhash_scryptsalsa208sha256_str(char * out,
			char * passwd,
			char * passwdlen,
			char * opslimit,
			char * memlimit);

int crypto_pwhash_scryptsalsa208sha256_str_verify(const char * str,
			const char * passwd,
			const char * passwdlen);

int crypto_pwhash_scryptsalsa208sha256_ll(const uint8_t * passwd,
			const uint8_t * passwdlen,
			const uint8_t * salt,
			const uint8_t * saltlen,
			const uint8_t * N,
			const uint8_t * r,
			const uint8_t * p,
			const uint8_t * buf,
			const uint8_t * buflen);

int crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(const char * str,
			const char * opslimit,
			const char * memlimit);

size_t crypto_shorthash_siphash24_bytes(void);

size_t crypto_shorthash_siphash24_keybytes(void);

int crypto_shorthash_siphash24(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

size_t crypto_shorthash_siphashx24_bytes(void);

size_t crypto_shorthash_siphashx24_keybytes(void);

int crypto_shorthash_siphashx24(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

size_t crypto_core_ristretto255_bytes(void);

size_t crypto_core_ristretto255_hashbytes(void);

size_t crypto_core_ristretto255_scalarbytes(void);

size_t crypto_core_ristretto255_nonreducedscalarbytes(void);

int crypto_core_ristretto255_is_valid_point(const unsigned char * p);

int crypto_core_ristretto255_add(unsigned char * r,
			unsigned char * p,
			unsigned char * q);

int crypto_core_ristretto255_sub(unsigned char * r,
			unsigned char * p,
			unsigned char * q);

int crypto_core_ristretto255_from_hash(unsigned char * p,
			unsigned char * r);

int crypto_core_ristretto255_from_string(unsigned char * p,
			unsigned char * ctx,
			unsigned char * msg,
			unsigned char * msg_len,
			unsigned char * hash_alg);

int crypto_core_ristretto255_from_string_ro(unsigned char * p,
			unsigned char * ctx,
			unsigned char * msg,
			unsigned char * msg_len,
			unsigned char * hash_alg);

void crypto_core_ristretto255_random(unsigned char * p);

void crypto_core_ristretto255_scalar_random(unsigned char * r);

int crypto_core_ristretto255_scalar_invert(unsigned char * recip,
			unsigned char * s);

void crypto_core_ristretto255_scalar_negate(unsigned char * neg,
			unsigned char * s);

void crypto_core_ristretto255_scalar_complement(unsigned char * comp,
			unsigned char * s);

void crypto_core_ristretto255_scalar_add(unsigned char * z,
			unsigned char * x,
			unsigned char * y);

void crypto_core_ristretto255_scalar_sub(unsigned char * z,
			unsigned char * x,
			unsigned char * y);

void crypto_core_ristretto255_scalar_mul(unsigned char * z,
			unsigned char * x,
			unsigned char * y);

void crypto_core_ristretto255_scalar_reduce(unsigned char * r,
			unsigned char * s);

int crypto_core_ristretto255_scalar_is_canonical(const unsigned char * s);

size_t crypto_aead_aegis128l_keybytes(void);

size_t crypto_aead_aegis128l_nsecbytes(void);

size_t crypto_aead_aegis128l_npubbytes(void);

size_t crypto_aead_aegis128l_abytes(void);

size_t crypto_aead_aegis128l_messagebytes_max(void);

int crypto_aead_aegis128l_encrypt(unsigned char * c,
			unsigned char * clen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aegis128l_decrypt(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aegis128l_encrypt_detached(unsigned char * c,
			unsigned char * mac,
			unsigned char * maclen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * nsec,
			unsigned char * npub,
			unsigned char * k);

int crypto_aead_aegis128l_decrypt_detached(unsigned char * m,
			unsigned char * nsec,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * mac,
			unsigned char * ad,
			unsigned char * adlen,
			unsigned char * npub,
			unsigned char * k);

void crypto_aead_aegis128l_keygen(unsigned char * k);

size_t crypto_core_hchacha20_outputbytes(void);

size_t crypto_core_hchacha20_inputbytes(void);

size_t crypto_core_hchacha20_keybytes(void);

size_t crypto_core_hchacha20_constbytes(void);

int crypto_core_hchacha20(unsigned char * out,
			unsigned char * in,
			unsigned char * k,
			unsigned char * c);

size_t crypto_verify_64_bytes(void);

int crypto_verify_64(const unsigned char * x,
			const unsigned char * y);

size_t crypto_core_keccak1600_statebytes(void);

void crypto_core_keccak1600_init(void * state);

void crypto_core_keccak1600_xor_bytes(void * state,
			void * bytes,
			void * offset,
			void * length);

void crypto_core_keccak1600_extract_bytes(const void * state,
			const void * bytes,
			const void * offset,
			const void * length);

void crypto_core_keccak1600_permute_24(void * state);

void crypto_core_keccak1600_permute_12(void * state);

size_t crypto_core_salsa2012_outputbytes(void);

size_t crypto_core_salsa2012_inputbytes(void);

size_t crypto_core_salsa2012_keybytes(void);

size_t crypto_core_salsa2012_constbytes(void);

int crypto_core_salsa2012(unsigned char * out,
			unsigned char * in,
			unsigned char * k,
			unsigned char * c);

size_t crypto_kdf_bytes_min(void);

size_t crypto_kdf_bytes_max(void);

size_t crypto_kdf_contextbytes(void);

size_t crypto_kdf_keybytes(void);

const char * crypto_kdf_primitive(void);

int crypto_kdf_derive_from_key(unsigned char * subkey,
			unsigned char * subkey_len,
			unsigned char * subkey_id,
			unsigned char * ctx,
			unsigned char * key);

void crypto_kdf_keygen(unsigned char * k);

size_t crypto_onetimeauth_statebytes(void);

size_t crypto_onetimeauth_bytes(void);

size_t crypto_onetimeauth_keybytes(void);

const char * crypto_onetimeauth_primitive(void);

int crypto_onetimeauth(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

int crypto_onetimeauth_verify(const unsigned char * h,
			const unsigned char * in,
			const unsigned char * inlen,
			const unsigned char * k);

int crypto_onetimeauth_init(crypto_onetimeauth_state * state,
			crypto_onetimeauth_state * key);

int crypto_onetimeauth_update(crypto_onetimeauth_state * state,
			crypto_onetimeauth_state * in,
			crypto_onetimeauth_state * inlen);

int crypto_onetimeauth_final(crypto_onetimeauth_state * state,
			crypto_onetimeauth_state * out);

void crypto_onetimeauth_keygen(unsigned char * k);

size_t crypto_core_salsa208_outputbytes(void);

size_t crypto_core_salsa208_inputbytes(void);

size_t crypto_core_salsa208_keybytes(void);

size_t crypto_core_salsa208_constbytes(void);

int crypto_core_salsa208(unsigned char * out,
			unsigned char * in,
			unsigned char * k,
			unsigned char * c);

size_t crypto_generichash_bytes_min(void);

size_t crypto_generichash_bytes_max(void);

size_t crypto_generichash_bytes(void);

size_t crypto_generichash_keybytes_min(void);

size_t crypto_generichash_keybytes_max(void);

size_t crypto_generichash_keybytes(void);

const char * crypto_generichash_primitive(void);

size_t crypto_generichash_statebytes(void);

int crypto_generichash(unsigned char * out,
			unsigned char * outlen,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * key,
			unsigned char * keylen);

int crypto_generichash_init(crypto_generichash_state * state,
			crypto_generichash_state * key,
			crypto_generichash_state * keylen,
			crypto_generichash_state * outlen);

int crypto_generichash_update(crypto_generichash_state * state,
			crypto_generichash_state * in,
			crypto_generichash_state * inlen);

int crypto_generichash_final(crypto_generichash_state * state,
			crypto_generichash_state * out,
			crypto_generichash_state * outlen);

void crypto_generichash_keygen(unsigned char * k);

size_t crypto_box_curve25519xsalsa20poly1305_seedbytes(void);

size_t crypto_box_curve25519xsalsa20poly1305_publickeybytes(void);

size_t crypto_box_curve25519xsalsa20poly1305_secretkeybytes(void);

size_t crypto_box_curve25519xsalsa20poly1305_beforenmbytes(void);

size_t crypto_box_curve25519xsalsa20poly1305_noncebytes(void);

size_t crypto_box_curve25519xsalsa20poly1305_macbytes(void);

size_t crypto_box_curve25519xsalsa20poly1305_messagebytes_max(void);

int crypto_box_curve25519xsalsa20poly1305_seed_keypair(unsigned char * pk,
			unsigned char * sk,
			unsigned char * seed);

int crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xsalsa20poly1305_beforenm(unsigned char * k,
			unsigned char * pk,
			unsigned char * sk);

size_t crypto_box_curve25519xsalsa20poly1305_boxzerobytes(void);

size_t crypto_box_curve25519xsalsa20poly1305_zerobytes(void);

int crypto_box_curve25519xsalsa20poly1305(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xsalsa20poly1305_open(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * pk,
			unsigned char * sk);

int crypto_box_curve25519xsalsa20poly1305_afternm(unsigned char * c,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * n,
			unsigned char * k);

int crypto_box_curve25519xsalsa20poly1305_open_afternm(unsigned char * m,
			unsigned char * c,
			unsigned char * clen,
			unsigned char * n,
			unsigned char * k);

int sodium_init(void);

void sodium_misuse(void);

int sodium_runtime_has_neon(void);

int sodium_runtime_has_armcrypto(void);

int sodium_runtime_has_sse2(void);

int sodium_runtime_has_sse3(void);

int sodium_runtime_has_ssse3(void);

int sodium_runtime_has_sse41(void);

int sodium_runtime_has_avx(void);

int sodium_runtime_has_avx2(void);

int sodium_runtime_has_avx512f(void);

int sodium_runtime_has_pclmul(void);

int sodium_runtime_has_aesni(void);

int sodium_runtime_has_rdrand(void);

int _sodium_runtime_get_cpu_features(void);

size_t crypto_auth_hmacsha256_bytes(void);

size_t crypto_auth_hmacsha256_keybytes(void);

int crypto_auth_hmacsha256(unsigned char * out,
			unsigned char * in,
			unsigned char * inlen,
			unsigned char * k);

int crypto_auth_hmacsha256_verify(const unsigned char * h,
			const unsigned char * in,
			const unsigned char * inlen,
			const unsigned char * k);

size_t crypto_auth_hmacsha256_statebytes(void);

int crypto_auth_hmacsha256_init(crypto_auth_hmacsha256_state * state,
			crypto_auth_hmacsha256_state * key,
			crypto_auth_hmacsha256_state * keylen);

int crypto_auth_hmacsha256_update(crypto_auth_hmacsha256_state * state,
			crypto_auth_hmacsha256_state * in,
			crypto_auth_hmacsha256_state * inlen);

int crypto_auth_hmacsha256_final(crypto_auth_hmacsha256_state * state,
			crypto_auth_hmacsha256_state * out);

void crypto_auth_hmacsha256_keygen(unsigned char * k);

size_t crypto_xof_turboshake256_blockbytes(void);

size_t crypto_xof_turboshake256_statebytes(void);

unsigned char crypto_xof_turboshake256_domain_standard(void);

int crypto_xof_turboshake256(unsigned char * out,
			unsigned char * outlen,
			unsigned char * in,
			unsigned char * inlen);

int crypto_xof_turboshake256_init(crypto_xof_turboshake256_state * state);

int crypto_xof_turboshake256_init_with_domain(crypto_xof_turboshake256_state * state,
			crypto_xof_turboshake256_state * domain);

int crypto_xof_turboshake256_update(crypto_xof_turboshake256_state * state,
			crypto_xof_turboshake256_state * in,
			crypto_xof_turboshake256_state * inlen);

int crypto_xof_turboshake256_final(crypto_xof_turboshake256_state * state,
			crypto_xof_turboshake256_state * out,
			crypto_xof_turboshake256_state * outlen);

int crypto_xof_turboshake256_squeeze(crypto_xof_turboshake256_state * state,
			crypto_xof_turboshake256_state * out,
			crypto_xof_turboshake256_state * outlen);

size_t crypto_sign_statebytes(void);

size_t crypto_sign_bytes(void);

size_t crypto_sign_seedbytes(void);

size_t crypto_sign_publickeybytes(void);

size_t crypto_sign_secretkeybytes(void);

size_t crypto_sign_messagebytes_max(void);

const char * crypto_sign_primitive(void);

int crypto_sign_seed_keypair(unsigned char * pk,
			unsigned char * sk,
			unsigned char * seed);

int crypto_sign_keypair(unsigned char * pk,
			unsigned char * sk);

int crypto_sign(unsigned char * sm,
			unsigned char * smlen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * sk);

int crypto_sign_open(unsigned char * m,
			unsigned char * mlen_p,
			unsigned char * sm,
			unsigned char * smlen,
			unsigned char * pk);

int crypto_sign_detached(unsigned char * sig,
			unsigned char * siglen_p,
			unsigned char * m,
			unsigned char * mlen,
			unsigned char * sk);

int crypto_sign_verify_detached(const unsigned char * sig,
			const unsigned char * m,
			const unsigned char * mlen,
			const unsigned char * pk);

int crypto_sign_init(crypto_sign_state * state);

int crypto_sign_update(crypto_sign_state * state,
			crypto_sign_state * m,
			crypto_sign_state * mlen);

int crypto_sign_final_create(crypto_sign_state * state,
			crypto_sign_state * sig,
			crypto_sign_state * siglen_p,
			crypto_sign_state * sk);

int crypto_sign_final_verify(crypto_sign_state * state,
			crypto_sign_state * sig,
			crypto_sign_state * pk);

size_t crypto_core_hsalsa20_outputbytes(void);

size_t crypto_core_hsalsa20_inputbytes(void);

size_t crypto_core_hsalsa20_keybytes(void);

size_t crypto_core_hsalsa20_constbytes(void);

int crypto_core_hsalsa20(unsigned char * out,
			unsigned char * in,
			unsigned char * k,
			unsigned char * c);

size_t crypto_kx_publickeybytes(void);

size_t crypto_kx_secretkeybytes(void);

size_t crypto_kx_seedbytes(void);

size_t crypto_kx_sessionkeybytes(void);

const char * crypto_kx_primitive(void);

int crypto_kx_seed_keypair(unsigned char * pk,
			unsigned char * sk,
			unsigned char * seed);

int crypto_kx_keypair(unsigned char * pk,
			unsigned char * sk);

int crypto_kx_client_session_keys(unsigned char * rx,
			unsigned char * tx,
			unsigned char * client_pk,
			unsigned char * client_sk,
			unsigned char * server_pk);

int crypto_kx_server_session_keys(unsigned char * rx,
			unsigned char * tx,
			unsigned char * server_pk,
			unsigned char * server_sk,
			unsigned char * client_pk);


