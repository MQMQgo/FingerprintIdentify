// Modified by mqmqgo, 2026-09-25: hardware-backed AES-256-GCM key bound to BIOMETRIC_STRONG
package com.wei.android.lib.fingerprintidentify.util;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.ProviderException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Hardened Keystore helper.
 * <p>
 * - AES-256 / GCM / NoPadding, randomized IV (12 bytes) required.
 * - Key is hardware backed (StrongBox preferred, TEE fallback); software keys are refused and deleted.
 * - User authentication required for EVERY use (API 30+: timeout 0 + AUTH_BIOMETRIC_STRONG only;
 *   API 23-29: validity -1 = auth per use via fingerprint CryptoObject).
 * - Key is invalidated when a new biometric is enrolled.
 * - There is intentionally NO software fallback key.
 */
@TargetApi(Build.VERSION_CODES.M)
public class CryptoObjectHelper {

    private static final String TAG = "CryptoObjectHelper";
    private static final String KEYSTORE_NAME = "AndroidKeyStore";
    public static final String TRANSFORMATION = "AES/GCM/NoPadding";
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_BITS = 128;

    /** Thrown when the key was permanently invalidated (e.g. biometric enrollment changed) or is missing. */
    public static class KeyInvalidatedException extends Exception {
        public KeyInvalidatedException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }

    private final KeyStore keystore;
    private final String keyAlias;

    public CryptoObjectHelper(String keyAlias) throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            throw new UnsupportedOperationException("Android Keystore auth-bound keys require API 23+");
        }
        if (keyAlias == null || keyAlias.isEmpty()) {
            throw new IllegalArgumentException("keyAlias must not be empty");
        }
        this.keyAlias = keyAlias;
        keystore = KeyStore.getInstance(KEYSTORE_NAME);
        keystore.load(null);
    }

    public <T> T createCryptoObject(Class<T> tClass, int opmode, byte[] iv) throws Exception {
        Cipher cipher = opmode == Cipher.ENCRYPT_MODE ? createEncryptCipher() : createDecryptCipher(iv);
        Constructor<T> tCon = tClass.getDeclaredConstructor(Cipher.class);
        return tCon.newInstance(cipher);
    }

    /** Always generates a brand new key under the alias (old key under the same alias is deleted). */
    public Cipher createEncryptCipher() throws Exception {
        removeKey();
        SecretKey key = generateKey();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (KeyPermanentlyInvalidatedException e) {
            removeKey();
            throw new KeyInvalidatedException("Freshly generated key is invalid", e);
        }
        return cipher;
    }

    public Cipher createDecryptCipher(byte[] iv) throws Exception {
        if (iv == null || iv.length != GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid GCM IV");
        }
        if (!keystore.containsAlias(keyAlias)) {
            throw new KeyInvalidatedException("Key " + keyAlias + " does not exist", null);
        }
        SecretKey key = (SecretKey) keystore.getKey(keyAlias, null);
        if (key == null) {
            throw new KeyInvalidatedException("Key " + keyAlias + " unreadable", null);
        }
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        } catch (KeyPermanentlyInvalidatedException e) {
            removeKey();
            throw new KeyInvalidatedException("Key permanently invalidated", e);
        }
        return cipher;
    }

    public void removeKey() {
        try {
            if (keystore.containsAlias(keyAlias)) {
                keystore.deleteEntry(keyAlias);
            }
        } catch (Exception e) {
            Log.e(TAG, "removeKey", e);
        }
    }

    public static void removeKey(String keyAlias) {
        try {
            new CryptoObjectHelper(keyAlias).removeKey();
        } catch (Exception e) {
            Log.e(TAG, "removeKey", e);
        }
    }

    private SecretKey generateKey() throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generateKey(true);
            } catch (Exception e) {
                // StrongBoxUnavailableException (API 28) or vendor ProviderException -> fall back to TEE
                Log.w(TAG, "StrongBox unavailable, falling back to TEE: " + e);
                removeKey();
            }
        }
        return generateKey(false);
    }

    private SecretKey generateKey(boolean strongBox) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_NAME);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            //noinspection deprecation
            builder.setUserAuthenticationValidityDurationSeconds(-1);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) {
            builder.setIsStrongBoxBacked(true);
        }
        keyGen.init(builder.build());
        SecretKey key = keyGen.generateKey();
        try {
            verifyHardwareBacked(key);
        } catch (Exception e) {
            removeKey();
            throw e;
        }
        return key;
    }

    @SuppressWarnings("deprecation")
    private static void verifyHardwareBacked(SecretKey key) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE_NAME);
        KeyInfo keyInfo = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
        boolean hardware;
        String detail;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            int level = keyInfo.getSecurityLevel();
            hardware = level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                    || level == KeyProperties.SECURITY_LEVEL_STRONGBOX
                    || level == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE;
            detail = "securityLevel=" + level;
        } else {
            hardware = keyInfo.isInsideSecureHardware();
            detail = "insideSecureHardware=" + hardware;
        }
        if (!hardware) {
            throw new ProviderException("Refusing non hardware-backed key (" + detail + ")");
        }
        if (!keyInfo.isUserAuthenticationRequired()) {
            throw new ProviderException("Refusing key without user authentication requirement");
        }
        Log.i(TAG, "Keystore key verified: " + detail);
    }
}
