import os

base = "android_app"

def create_file(path, content):
    os.makedirs(os.path.dirname(os.path.join(base, path)), exist_ok=True)
    with open(os.path.join(base, path), "w", encoding="utf-8") as f:
        f.write(content.strip())

# settings.gradle
create_file("settings.gradle", '''
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "SmishingDetector"
include ':app'
''')

# project build.gradle
create_file("build.gradle", '''
// Top-level build file
plugins {
    id 'com.android.application' version '8.2.0' apply false
}
''')

# app build.gradle
create_file("app/build.gradle", '''
plugins {
    id 'com.android.application'
}

android {
    namespace 'com.example.smishingdetector'
    compileSdk 34

    defaultConfig {
        applicationId "com.example.smishingdetector"
        minSdk 26
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }

    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.11.0'
    implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
}
''')

create_file("app/src/main/res/values/strings.xml", '''
<resources>
    <string name="app_name">Smishing Detector</string>
</resources>
''')

# AndroidManifest.xml
create_file("app/src/main/AndroidManifest.xml", '''
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.smishingdetector">

    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="true"
        android:label="@string/app_name"
        android:supportsRtl="true"
        android:theme="@style/Theme.AppCompat.Light.DarkActionBar"
        android:usesCleartextTraffic="true">
        
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <receiver android:name=".SmsReceiver" android:exported="true"
            android:permission="android.permission.BROADCAST_SMS">
            <intent-filter android:priority="999">
                <action android:name="android.provider.Telephony.SMS_RECEIVED" />
            </intent-filter>
        </receiver>
        
    </application>

</manifest>
''')

# layout
create_file("app/src/main/res/layout/activity_main.xml", '''
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp">

    <TextView
        android:id="@+id/tvTitle"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Latest SMS Scan Result"
        android:textSize="20sp"
        android:textStyle="bold"
        android:layout_marginBottom="16dp" />

    <TextView
        android:id="@+id/tvMessage"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Waiting for SMS..."
        android:textSize="16sp"
        android:layout_marginBottom="16dp" />

    <TextView
        android:id="@+id/tvStatus"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text=""
        android:textSize="18sp"
        android:textStyle="bold" />

</LinearLayout>
''')

# MainActivity.java
create_file("app/src/main/java/com/example/smishingdetector/MainActivity.java", '''
package com.example.smishingdetector;

import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    public static MainActivity instance;
    private TextView tvMessage;
    private TextView tvStatus;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        instance = this;
        tvMessage = findViewById(R.id.tvMessage);
        tvStatus = findViewById(R.id.tvStatus);
    }

    public void updateUi(final String message, final String status, final double riskScore, final String reason) {
        runOnUiThread(() -> {
            tvMessage.setText(message);
            String displayStatus = status + " (Risk: " + String.format("%.2f", riskScore) + ")";
            if(reason != null && !reason.isEmpty()){
                displayStatus += "\\nReason: " + reason;
            }
            tvStatus.setText(displayStatus);

            if (status.equals("Smishing Detected")) {
                tvStatus.setTextColor(0xFFFF0000); // Red
            } else {
                tvStatus.setTextColor(0xFF00AA00); // Green
            }
        });
    }
}
''')

# ApiService.java
create_file("app/src/main/java/com/example/smishingdetector/ApiService.java", '''
package com.example.smishingdetector;

import org.json.JSONObject;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

public class ApiService {
    // Change this IP to the PC's local network IP hosting the FastAPI server
    private static final String API_URL = "http://10.0.2.2:8000/predict";

    public static void analyzeSms(String message, SmsCallback callback) {
        new Thread(() -> {
            try {
                URL url = new URL(API_URL);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json; utf-8");
                conn.setRequestProperty("Accept", "application/json");
                conn.setDoOutput(true);

                JSONObject jsonParam = new JSONObject();
                jsonParam.put("message", message);

                try(OutputStream os = conn.getOutputStream()) {
                    byte[] input = jsonParam.toString().getBytes("utf-8");
                    os.write(input, 0, input.length);			
                }

                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    InputStream inputStream = conn.getInputStream();
                    Scanner scanner = new Scanner(inputStream).useDelimiter("\\\\A");
                    String responseStr = scanner.hasNext() ? scanner.next() : "";
                    
                    JSONObject responseJson = new JSONObject(responseStr);
                    String status = responseJson.getString("status");
                    double risk = responseJson.getDouble("risk_score");
                    String reason = responseJson.getString("reason");
                    callback.onResult(status, risk, reason);
                } else {
                    callback.onResult("Error", 0.0, "API Error: " + responseCode);
                }
                
                conn.disconnect();
            } catch (Exception e) {
                e.printStackTrace();
                callback.onResult("Error", 0.0, e.getMessage());
            }
        }).start();
    }

    public interface SmsCallback {
        void onResult(String status, double riskScore, String reason);
    }
}
''')

# SmsReceiver.java
create_file("app/src/main/java/com/example/smishingdetector/SmsReceiver.java", '''
package com.example.smishingdetector;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.util.Log;

public class SmsReceiver extends BroadcastReceiver {
    private static final String TAG = "SmsReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if ("android.provider.Telephony.SMS_RECEIVED".equals(intent.getAction())) {
            // Intercepting SMS - preventing it from hitting default messaging app immediately if lower priority
            // Note: In newer Android versions, true blocking requires being the Default SMS App.
            // For this project, we receive it at priority=999 and analyze.

            Bundle bundle = intent.getExtras();
            if (bundle != null) {
                Object[] pdus = (Object[]) bundle.get("pdus");
                if (pdus != null) {
                    for (Object pdu : pdus) {
                        SmsMessage smsMessage;
                        String format = bundle.getString("format");
                        smsMessage = SmsMessage.createFromPdu((byte[]) pdu, format);
                        
                        String senderNum = smsMessage.getDisplayOriginatingAddress();
                        String message = smsMessage.getDisplayMessageBody();
                        
                        Log.d(TAG, "Sender: " + senderNum + ", Message: " + message);

                        // Abort Broadcast theoretically preventing notification (works on older Android or if Default App)
                        abortBroadcast();

                        // Send to backend for analysis
                        ApiService.analyzeSms(message, new ApiService.SmsCallback() {
                            @Override
                            public void onResult(String status, double riskScore, String reason) {
                                // Show warning on UI
                                if (MainActivity.instance != null) {
                                    MainActivity.instance.updateUi(message, status, riskScore, reason);
                                }
                            }
                        });
                    }
                }
            }
        }
    }
}
''')

print("Android files created!")
