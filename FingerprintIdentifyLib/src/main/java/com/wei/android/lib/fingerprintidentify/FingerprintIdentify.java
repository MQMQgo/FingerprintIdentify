// Modified by mqmqgo, 2026-09-25: removed vendor SDKs/fallbacks, key alias, key invalidation
package com.wei.android.lib.fingerprintidentify;

import android.content.Context;
import android.os.Build;

import com.wei.android.lib.fingerprintidentify.base.BaseFingerprint;
import com.wei.android.lib.fingerprintidentify.impl.AndroidFingerprint;
import com.wei.android.lib.fingerprintidentify.impl.BiometricImpl;

import javax.crypto.Cipher;

/**
 * Copyright (c) 2017 Awei
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * <p>
 * Created by Awei on 2017/2/8.
 */
public class FingerprintIdentify {

    protected Context mContext;
    protected BaseFingerprint.ExceptionListener mExceptionListener;

    protected BaseFingerprint mFingerprint;
    protected BaseFingerprint mSubFingerprint;

    private int mMaxAvailableTimes = 5;

    private int mCipherMode = Cipher.ENCRYPT_MODE;

    private byte[] mCipherIV = null;

    private String mKeyAlias = null;

    public FingerprintIdentify(Context context) {
        mContext = context;
    }

    public void setMaxAvailableTimes(int v) {
        this.mMaxAvailableTimes = v;
    }

    public void setCipherMode(int cipherMode, byte[] cipherIV) {
        this.mCipherMode = cipherMode;
        this.mCipherIV = cipherIV;
    }

    public int getCipherMode() {
        return this.mCipherMode;
    }

    /** Android Keystore alias of the auth-bound AES-256-GCM key. */
    public void setKeyAlias(String keyAlias) {
        this.mKeyAlias = keyAlias;
    }

    public boolean isUsingBiometricApi() {
        return mFingerprint instanceof BiometricImpl;
    }

    public void setExceptionListener(BaseFingerprint.ExceptionListener exceptionListener) {
        mExceptionListener = exceptionListener;
    }

    /**
     * Hardened selection:
     * API 30+  : framework BiometricPrompt, BIOMETRIC_STRONG only, with CryptoObject.
     * API 23-29: framework FingerprintManager with CryptoObject (fingerprint = strong class).
     * API < 23 : unsupported (no auth-bound Keystore keys). Vendor SDKs were removed.
     */
    public void init() {
        mFingerprint = null;
        mSubFingerprint = null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricImpl biometricImpl = new BiometricImpl(mContext, mExceptionListener);
            if (biometricImpl.isHardwareEnable()) {
                mSubFingerprint = biometricImpl;
                if (biometricImpl.isRegisteredFingerprint()) {
                    mFingerprint = biometricImpl;
                }
            }
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            AndroidFingerprint androidFingerprint = new AndroidFingerprint(mContext, mExceptionListener);
            if (androidFingerprint.isHardwareEnable()) {
                mSubFingerprint = androidFingerprint;
                if (androidFingerprint.isRegisteredFingerprint()) {
                    mFingerprint = androidFingerprint;
                }
            }
        }
    }

    // DO
    public void startIdentify(BaseFingerprint.IdentifyListener listener) {
        if (!isFingerprintEnable()) {
            return;
        }

        mFingerprint.startIdentify(this.mMaxAvailableTimes,
                this.mCipherMode, this.mCipherIV, this.mKeyAlias, listener);
    }

    public void cancelIdentify() {
        if (mFingerprint != null) {
            mFingerprint.cancelIdentify();
        }
    }

    public void resumeIdentify() {
        if (!isFingerprintEnable()) {
            return;
        }

        mFingerprint.resumeIdentify();
    }

    // GET & SET
    public boolean isFingerprintEnable() {
        return mFingerprint != null && mFingerprint.isEnable();
    }

    public boolean isHardwareEnable() {
        return isFingerprintEnable() || (mSubFingerprint != null && mSubFingerprint.isHardwareEnable());
    }

    public boolean isRegisteredFingerprint() {
        return isFingerprintEnable() || (mSubFingerprint != null && mSubFingerprint.isRegisteredFingerprint());
    }
}
