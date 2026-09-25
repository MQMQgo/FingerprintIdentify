package com.wei.android.lib.fingerprintidentify.impl;

import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;

import com.wei.android.lib.fingerprintidentify.base.BaseFingerprint;
import com.wei.android.lib.fingerprintidentify.bean.FingerprintIdentifyFailInfo;

import java.util.Locale;
import java.util.concurrent.Executor;

/**
 * Hardened: framework BiometricPrompt (API 30+), BIOMETRIC_STRONG only, CryptoObject mandatory,
 * no device credential, no authenticate(null) pre-auth. Negative button = "使用密码".
 */
@TargetApi(Build.VERSION_CODES.R)
public class BiometricImpl extends BaseFingerprint {

    private static final String TAG = "BiometricImpl";
    private CancellationSignal mCancellationSignal;

    public BiometricImpl(Context context, ExceptionListener exceptionListener) {
        super(context, exceptionListener);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return;
        }

        try {
            BiometricManager biometricManager = context.getSystemService(BiometricManager.class);
            setHardwareEnable(false);
            int v = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
            switch (v) {
                case BiometricManager.BIOMETRIC_SUCCESS:
                    setHardwareEnable(true);
                    setRegisteredFingerprint(true);
                    break;
                case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                    setHardwareEnable(true);
                    setRegisteredFingerprint(false);
                    Log.e(TAG, "No strong biometric enrolled.");
                    break;
                default:
                    Log.e(TAG, "Strong biometric unavailable: " + v);
                    break;
            }
        } catch (Throwable e) {
            onCatchException(e);
        }
    }

    private static boolean isZh() {
        return Locale.getDefault().getLanguage().toLowerCase(Locale.ROOT).contains("zh");
    }

    @Override
    protected void doIdentify() {
        BiometricPrompt.CryptoObject cryptoObject = createCryptoObject(BiometricPrompt.CryptoObject.class);
        if (cryptoObject == null) {
            // createCryptoObject already reported onFailed(); never authenticate without a CryptoObject.
            Log.e(TAG, "Unable to create CryptoObject, abort.");
            return;
        }
        try {
            mCancellationSignal = new CancellationSignal();
            BiometricPrompt.Builder builder = new BiometricPrompt.Builder(this.mContext);
            builder.setTitle(isZh() ? "指纹支付" : "Fingerprint pay");
            builder.setNegativeButton(isZh() ? "使用密码" : "Use password", new PromptExecutor(), (dialog, which) ->
                    onFailed(new FingerprintIdentifyFailInfo(false,
                            FingerprintIdentifyFailInfo.ERROR_NEGATIVE_BUTTON, "negative button")));
            builder.setConfirmationRequired(false);
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
            BiometricPrompt prompt = builder.build();
            BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {

                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    BiometricPrompt.CryptoObject crypto = result.getCryptoObject();
                    onSucceed(crypto == null ? null : crypto.getCipher());
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    onNotMatch();
                }

                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    boolean deviceLocked = errorCode == FingerprintManager.FINGERPRINT_ERROR_LOCKOUT ||
                            errorCode == FingerprintManager.FINGERPRINT_ERROR_LOCKOUT_PERMANENT;
                    onFailed(new FingerprintIdentifyFailInfo(deviceLocked, errorCode, String.valueOf(errString)));
                }
            };
            prompt.authenticate(cryptoObject, this.mCancellationSignal, new PromptExecutor(), callback);
        } catch (Throwable e) {
            onCatchException(e);
            onFailed(new FingerprintIdentifyFailInfo(false, e));
        }
    }

    @Override
    protected void doCancelIdentify() {
        try {
            if (mCancellationSignal != null) {
                mCancellationSignal.cancel();
            }
        } catch (Throwable e) {
            onCatchException(e);
        }
    }

    @Override
    protected boolean needToCallDoIdentifyAgainAfterNotMatch() {
        return false;
    }

    private static class PromptExecutor implements Executor {
        private final Handler mPromptHandler = new Handler(Looper.getMainLooper());

        @Override
        public void execute(@NonNull Runnable runnable) {
            mPromptHandler.post(runnable);
        }
    }
}
