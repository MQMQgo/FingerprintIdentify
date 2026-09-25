// Modified by mqmqgo, 2026-09-25: removed vendor SDKs/fallbacks, key alias, key invalidation
package com.wei.android.lib.fingerprintidentify.base;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.Nullable;

import com.wei.android.lib.fingerprintidentify.bean.FingerprintIdentifyFailInfo;
import com.wei.android.lib.fingerprintidentify.util.CryptoObjectHelper;

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
 * Created by Awei on 2017/2/9.
 */
public abstract class BaseFingerprint {

    protected Context mContext;

    private Handler mHandler;
    private IdentifyListener mIdentifyListener;
    private ExceptionListener mExceptionListener;

    private int mNumberOfFailures = 0;                      // number of failures
    private int mMaxAvailableTimes = 3;                     // the most available times

    private boolean mIsHardwareEnable = false;              // if the phone equipped fingerprint hardware
    private boolean mIsRegisteredFingerprint = false;       // if the phone has any fingerprints

    private boolean mIsCalledStartIdentify = false;         // if started identify
    private boolean mIsCanceledIdentify = false;            // if canceled identify

    protected int mCipherMode = Cipher.ENCRYPT_MODE;

    protected byte[] mCipherIV = null;

    protected String mKeyAlias = null;

    public BaseFingerprint(Context context, ExceptionListener exceptionListener) {
        mContext = context;
        mExceptionListener = exceptionListener;
        mHandler = new Handler(Looper.getMainLooper());
    }

    // DO
    public void startIdentify(int maxAvailableTimes,
                              int cipherMode, byte[] cipherIV, String keyAlias,
                              IdentifyListener identifyListener) {
        mKeyAlias = keyAlias;
        mMaxAvailableTimes = maxAvailableTimes;
        mIdentifyListener = identifyListener;
        mIsCalledStartIdentify = true;
        mIsCanceledIdentify = false;
        mNumberOfFailures = 0;
        mCipherMode = cipherMode;
        mCipherIV = cipherIV;

        doIdentify();
    }

    public void resumeIdentify() {
        if (mIsCalledStartIdentify && mIdentifyListener != null && mNumberOfFailures < mMaxAvailableTimes) {
            mIsCanceledIdentify = false;
            doIdentify();
        }
    }

    public void cancelIdentify() {
        mIsCanceledIdentify = true;
        doCancelIdentify();
    }

    // IMPL
    protected abstract void doIdentify();

    protected abstract void doCancelIdentify();

    // CALLBACK
    protected void onSucceed(@Nullable Cipher cipher) {
        if (mIsCanceledIdentify) {
            return;
        }

        if (cipher == null) {
            // Hardened: success without an authenticated CryptoObject is treated as failure.
            onFailed(new FingerprintIdentifyFailInfo(false, new IllegalStateException("No authenticated cipher")));
            return;
        }

        mNumberOfFailures = mMaxAvailableTimes;

        if (mIdentifyListener != null) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    try {
                        mIdentifyListener.onSucceed(cipher);
                    } catch (Exception e) {
                        onCatchException(e);
                    }
                }
            });
        }

        cancelIdentify();
    }

    protected void onNotMatch() {
        if (mIsCanceledIdentify) {
            return;
        }

        if (++mNumberOfFailures < mMaxAvailableTimes) {
            if (mIdentifyListener != null) {
                final int chancesLeft = mMaxAvailableTimes - mNumberOfFailures;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            mIdentifyListener.onNotMatch(chancesLeft);
                        } catch (Exception e) {
                            onCatchException(e);
                        }
                    }
                });
            }

            if (needToCallDoIdentifyAgainAfterNotMatch()) {
                doIdentify();
            }

            return;
        }

        onFailed(new FingerprintIdentifyFailInfo(false, -2, "not match"));
    }

    protected void onFailed(final FingerprintIdentifyFailInfo failInfo) {
        if (mIsCanceledIdentify) {
            return;
        }

        final boolean isStartFailedByDeviceLocked = failInfo.deviceLocked && mNumberOfFailures == 0;

        mNumberOfFailures = mMaxAvailableTimes;

        if (mIdentifyListener != null) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    try {
                        if (isStartFailedByDeviceLocked) {
                            mIdentifyListener.onStartFailedByDeviceLocked();
                        } else {
                            mIdentifyListener.onFailed(failInfo);
                        }
                    } catch (Exception e) {
                        onCatchException(e);
                    }
                }
            });
        }

        cancelIdentify();
    }

    protected void onCatchException(Throwable exception) {
        if (mExceptionListener != null && exception != null) {
            mExceptionListener.onCatchException(exception);
        }
    }

    // GET & SET
    public boolean isEnable() {
        return mIsHardwareEnable && mIsRegisteredFingerprint;
    }

    public boolean isHardwareEnable() {
        return mIsHardwareEnable;
    }

    protected void setHardwareEnable(boolean hardwareEnable) {
        mIsHardwareEnable = hardwareEnable;
    }

    public boolean isRegisteredFingerprint() {
        return mIsRegisteredFingerprint;
    }

    protected void setRegisteredFingerprint(boolean registeredFingerprint) {
        mIsRegisteredFingerprint = registeredFingerprint;
    }

    // OTHER
    protected void runOnUiThread(Runnable runnable) {
        mHandler.post(runnable);
    }

    protected boolean needToCallDoIdentifyAgainAfterNotMatch() {
        return true;
    }

    /**
     * Creates the CryptoObject bound to the hardware Keystore key.
     * On any error this reports {@link #onFailed} (there is no software fallback) and returns null;
     * callers must then abort the identification.
     */
    @Nullable
    protected <T> T createCryptoObject(Class<T> tClass) {
        int cipherMode = this.mCipherMode;
        byte[] iv = this.mCipherIV;
        try {
            CryptoObjectHelper cryptoObjectHelper = new CryptoObjectHelper(mKeyAlias);
            return cryptoObjectHelper.createCryptoObject(tClass, cipherMode, iv);
        } catch (CryptoObjectHelper.KeyInvalidatedException e) {
            onCatchException(e);
            FingerprintIdentifyFailInfo info = new FingerprintIdentifyFailInfo(false, e);
            info.keyInvalidated = true;
            onFailed(info);
        } catch (Throwable e) {
            onCatchException(e);
            onFailed(new FingerprintIdentifyFailInfo(false, e));
        }
        return null;
    }

    public interface IdentifyListener {
        void onSucceed(@Nullable Cipher cipher);

        void onNotMatch(int availableTimes);

        void onFailed(FingerprintIdentifyFailInfo failInfo);

        void onStartFailedByDeviceLocked();
    }

    public interface ExceptionListener {
        void onCatchException(Throwable exception);
    }
}