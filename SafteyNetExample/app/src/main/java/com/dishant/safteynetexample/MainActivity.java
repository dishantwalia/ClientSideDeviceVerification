package com.dishant.safteynetexample;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.view.KeyEvent;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.dishant.safteynetexample.Utility.JWSParser;
import com.dishant.safteynetexample.Utility.Util;
import com.dishant.safteynetexample.model.AttestationStatement;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;


/**
 * Created by punchh_dishant on 19,June,2018
 */
public class MainActivity extends AppCompatActivity {


    private ProgressBar mProgress;
    private TextView txtStatus;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mProgress = findViewById(R.id.progress);
        txtStatus = findViewById(R.id.txt_status);
        initClient();

    }


    private void initClient() {
        mProgress.setVisibility(View.VISIBLE);

        if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(MainActivity.this)
                == ConnectionResult.SUCCESS) {
            // The SafetyNet Attestation API is available.
            startVerification();

        }
    }


    private void startVerification() {

        final byte[] nonce = getRequestNonce();

        if (nonce != null) {
            SafetyNet.getClient(this).attest(nonce, getString(R.string.api_key))
                    .addOnSuccessListener(this,
                            new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
                                @Override
                                public void onSuccess(SafetyNetApi.AttestationResponse response) {
                                    // Indicates communication with the service was successful.
                                    // Use response.getJwsResult() to get the result data.
                                    String jwsResult = response.getJwsResult();
                                    AttestationStatement statement = new JWSParser().parseAndVerify(jwsResult);
                                    if (statement != null) {
                                        displayResults(statement.hasBasicIntegrity(), statement.isCtsProfileMatch());
                                    } else {
                                        mProgress.setVisibility(View.GONE);
                                        Util.showAlert(MainActivity.this, "Verification Error!", "Unable to perform operation due to invalid signature", "Okay",
                                                new DialogInterface.OnClickListener() {
                                                    @Override
                                                    public void onClick(DialogInterface dialog, int which) {
                                                        dialog.dismiss();
                                                        finish();
                                                    }
                                                }, new Dialog.OnKeyListener() {
                                                    @Override
                                                    public boolean onKey(DialogInterface arg0, int keyCode, KeyEvent event) {
                                                        if (keyCode == KeyEvent.KEYCODE_BACK) {
                                                        }
                                                        return true;
                                                    }
                                                });
                                    }
                                }
                            })
                    .addOnFailureListener(this, new OnFailureListener() {
                        @Override
                        public void onFailure(@NonNull Exception e) {
                            mProgress.setVisibility(View.GONE);
                            // An error occurred while communicating with the service.
                            String error;
                            if (e instanceof ApiException) {
                                // An error with the Google Play services API contains some
                                // additional details.
                                ApiException apiException = (ApiException) e;
                                // You can retrieve the status code using the
                                // apiException.getStatusCode() method.
                                error = CommonStatusCodes.getStatusCodeString(apiException.getStatusCode());
                            } else {
                                // A different, unknown type of error occurred.
                                error = e.getLocalizedMessage();
                            }
                            Util.showAlert(MainActivity.this, "Verification", "Unable to perform operation due to :" + error, "Okay",
                                    new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            dialog.dismiss();
                                            finish();
                                        }
                                    }, new Dialog.OnKeyListener() {
                                        @Override
                                        public boolean onKey(DialogInterface arg0, int keyCode, KeyEvent event) {
                                            if (keyCode == KeyEvent.KEYCODE_BACK) {
                                            }
                                            return true;
                                        }
                                    });
                        }
                    });
        }


    }


    private byte[] getRequestNonce() {

        String data = String.valueOf(System.currentTimeMillis());

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byte[] bytes = new byte[24];
        Random random = new Random();
        random.nextBytes(bytes);
        try {
            byteStream.write(bytes);
            byteStream.write(data.getBytes());
        } catch (IOException e) {
            return null;
        }

        return byteStream.toByteArray();
    }

    private void displayResults(boolean integrity, boolean cts) {
        mProgress.setVisibility(View.GONE);
        if (integrity && cts) {
            txtStatus.setVisibility(View.VISIBLE);
            Util.showAlert(MainActivity.this, "Verification", "Your Device is verified", "Okay",
                    new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    }, new Dialog.OnKeyListener() {
                        @Override
                        public boolean onKey(DialogInterface arg0, int keyCode, KeyEvent event) {
                            if (keyCode == KeyEvent.KEYCODE_BACK) {
                            }
                            return true;
                        }
                    });
        } else {
            Util.showAlert(MainActivity.this, "Verification", "Your device compatibility test check failed, Probably your device is tampered", "Okay",
                    new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                            finish();
                        }
                    }, new Dialog.OnKeyListener() {
                        @Override
                        public boolean onKey(DialogInterface arg0, int keyCode, KeyEvent event) {
                            if (keyCode == KeyEvent.KEYCODE_BACK) {
                            }
                            return true;
                        }
                    });
        }
    }

}
