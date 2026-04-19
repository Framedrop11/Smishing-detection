package com.example.smishingdetector;
 
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.util.List;

public class MainActivity extends AppCompatActivity {
 
    public static MainActivity instance;
    private TextView tvMessage;
    private TextView tvStatus;
    private TextView tvStatusIcon;
    private TextView tvRiskScore;
    private TextView tvReason;
    private LinearLayout layoutStatus;

    // AI Awareness Alert card
    private LinearLayout cardAwarenessAlert;
    private TextView tvAlertIcon;
    private TextView tvAlertTitle;
    private View alertAccentLine;
    private TextView tvAlertMessage;
 
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
 
        // BUG FIX #4: Assign instance BEFORE requestRequiredPermissions() so there is
        // no window where the SmsReceiver could fire and find instance == null.
        instance = this;
 
        tvMessage    = findViewById(R.id.tvMessage);
        tvStatus     = findViewById(R.id.tvStatus);
        tvStatusIcon = findViewById(R.id.tvStatusIcon);
        tvRiskScore  = findViewById(R.id.tvRiskScore);
        tvReason     = findViewById(R.id.tvReason);
        layoutStatus = findViewById(R.id.layoutStatus);

        cardAwarenessAlert = findViewById(R.id.cardAwarenessAlert);
        tvAlertIcon        = findViewById(R.id.tvAlertIcon);
        tvAlertTitle       = findViewById(R.id.tvAlertTitle);
        alertAccentLine    = findViewById(R.id.alertAccentLine);
        tvAlertMessage     = findViewById(R.id.tvAlertMessage);
 
        requestRequiredPermissions();
    }
 
    private void requestRequiredPermissions() {
        /*
         * BUG FIX #4 (continued): READ_SMS was missing from the runtime-permission
         * request. On Android 6+ every dangerous permission must be requested at runtime;
         * declaring it in the manifest alone is not sufficient. Without READ_SMS the OS
         * can refuse to pass SMS extras to non-default-SMS-app receivers on some ROMs.
         *
         * POST_NOTIFICATIONS is required on Android 13+ (TIRAMISU); it was already here.
         * READ_SMS is dangerous on all API levels, so we always request it.
         */
        String[] permissions;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions = new String[]{
                    Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.READ_SMS,
                    Manifest.permission.POST_NOTIFICATIONS
            };
        } else {
            permissions = new String[]{
                    Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.READ_SMS
            };
        }
 
        boolean needsRequest = false;
        for (String perm : permissions) {
            if (ContextCompat.checkSelfPermission(this, perm) != PackageManager.PERMISSION_GRANTED) {
                needsRequest = true;
                break;
            }
        }
 
        if (needsRequest) {
            ActivityCompat.requestPermissions(this, permissions, 123);
        }
    }
 
    @Override
    protected void onDestroy() {
        super.onDestroy();
        // Prevent SmsReceiver from trying to update a destroyed Activity
        if (instance == this) {
            instance = null;
        }
    }
 
    /**
     * Update the full dashboard UI with scan results + AI awareness alert.
     */
    public void updateUi(final String message, final String status,
                         final double riskScore, final String reason,
                         final String alertMessage) {
        runOnUiThread(() -> {
            // ── Update message text ─────────────────────────────
            tvMessage.setText(message);

            // ── Update risk score ───────────────────────────────
            tvRiskScore.setText(String.format("%.2f", riskScore));

            // ── Update technical reason ─────────────────────────
            if (reason != null && !reason.isEmpty()) {
                tvReason.setText(reason);
            } else {
                tvReason.setText("—");
            }
 
            // ── Update status indicator with visual styling ─────
            if ("Smishing Detected".equals(status)) {
                tvStatus.setText("⚠ SMISHING DETECTED");
                tvStatusIcon.setText("✘");
                layoutStatus.setBackgroundResource(R.drawable.gradient_danger);
                tvRiskScore.setTextColor(0xFFE53935);
            } else if ("Safe".equals(status)) {
                tvStatus.setText("✓ SAFE");
                tvStatusIcon.setText("✔");
                layoutStatus.setBackgroundResource(R.drawable.gradient_safe);
                tvRiskScore.setTextColor(0xFF43A047);
            } else {
                tvStatus.setText(status);
                tvStatusIcon.setText("⚠");
                layoutStatus.setBackgroundResource(R.drawable.badge_background);
                tvRiskScore.setTextColor(0xFF757575);
            }

            // ── Show the AI Awareness Alert card ────────────────
            if (alertMessage != null && !alertMessage.isEmpty()) {
                cardAwarenessAlert.setVisibility(View.VISIBLE);
                tvAlertMessage.setText(alertMessage);

                if ("Smishing Detected".equals(status)) {
                    tvAlertIcon.setText("⚠️");
                    tvAlertTitle.setText("Phishing Warning");
                    tvAlertTitle.setTextColor(0xFFE53935);
                    alertAccentLine.setBackgroundColor(0xFFE53935);
                } else {
                    tvAlertIcon.setText("✅");
                    tvAlertTitle.setText("Safety Report");
                    tvAlertTitle.setTextColor(0xFF43A047);
                    alertAccentLine.setBackgroundColor(0xFF43A047);
                }
            }
        });
    }
}