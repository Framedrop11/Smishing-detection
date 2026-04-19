package com.example.smishingdetector;
 
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.util.Log;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.os.Build;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
 
public class SmsReceiver extends BroadcastReceiver {
    private static final String TAG = "SmsReceiver";
    private static final String CHANNEL_ID = "smish_alert_channel";
 
    private void createNotificationChannel(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Smishing Alerts", NotificationManager.IMPORTANCE_HIGH);
            channel.setDescription("Alerts for malicious SMS messages");
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
 
    private void showNotification(Context context, String title, String text) {
        createNotificationChannel(context);
        Intent intent = new Intent(context, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                context, 0, intent, PendingIntent.FLAG_IMMUTABLE);
 
        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(text)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(text))
                .setContentIntent(pendingIntent)
                .setAutoCancel(true);
 
        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
        try {
            notificationManager.notify((int) System.currentTimeMillis(), builder.build());
        } catch (SecurityException e) {
            Log.e(TAG, "Notification permission not granted", e);
        }
    }
 
    @Override
    public void onReceive(final Context context, Intent intent) {
        if (!"android.provider.Telephony.SMS_RECEIVED".equals(intent.getAction())) {
            return;
        }
 
        Bundle bundle = intent.getExtras();
        if (bundle == null) return;
 
        Object[] pdus = (Object[]) bundle.get("pdus");
        if (pdus == null) return;
 
        /*
         * BUG FIX #2: Removed abortBroadcast() from inside the loop.
         *
         * abortBroadcast() was called immediately inside onReceive(), BEFORE the async
         * HTTP call to the backend returned. This has two bad side-effects:
         *   a) On Android 10+ abortBroadcast() on a non-ordered SMS_RECEIVED broadcast
         *      throws an IllegalStateException that silently kills the receiver.
         *   b) Even on older Android where it is ordered, aborting the broadcast removes
         *      it from the system entirely, so the user never sees the original SMS in
         *      their messaging app. That is disruptive and not the intended UX.
         *
         * The correct approach: let the broadcast propagate normally so the default
         * messaging app still delivers it, while we independently analyse it in the
         * background and overlay a warning notification if it is malicious.
         */
 
        for (Object pdu : pdus) {
            // BUG FIX #3: Guard against null format string.
            // bundle.getString("format") can return null on some ROMs (e.g. older MIUI).
            // SmsMessage.createFromPdu(byte[], null) throws a NullPointerException,
            // which silently kills the receiver without any visible error.
            // Default to "3gpp" (GSM) which is correct for the vast majority of devices.
            String format = bundle.getString("format");
            if (format == null) {
                format = "3gpp"; // safe default: GSM/UMTS/LTE
            }
 
            SmsMessage smsMessage = SmsMessage.createFromPdu((byte[]) pdu, format);
            if (smsMessage == null) continue; // guard: malformed PDU
 
            final String senderNum = smsMessage.getDisplayOriginatingAddress();
            final String message = smsMessage.getDisplayMessageBody();
 
            Log.d(TAG, "SMS received — Sender: " + senderNum + ", Message: " + message);
 
            // Analyse asynchronously so we never block the main thread
            ApiService.analyzeSms(context, message, new ApiService.SmsCallback() {
                @Override
                public void onResult(String status, double riskScore, String reason,
                                     String alertMessage,
                                     java.util.List<ExplainabilityEngine.ImportantWord> importantWords) {
                    Log.d(TAG, "Analysis result — status: " + status
                            + ", risk: " + riskScore + ", reason: " + reason);
 
                    // Update the live UI if MainActivity is in the foreground
                    if (MainActivity.instance != null) {
                        MainActivity.instance.updateUi(message, status, riskScore,
                                reason, alertMessage);
                    }
 
                    // Always show a notification for smishing regardless of foreground state
                    if ("Smishing Detected".equals(status)) {
                        String notifBody = AlertMessageBuilder.buildNotificationSummary(
                                riskScore, reason, importantWords);
                        showNotification(
                                context,
                                "⚠️ SMISHING ALERT — From: " + senderNum,
                                notifBody);
                    }
                }
            });
        }
    }
}