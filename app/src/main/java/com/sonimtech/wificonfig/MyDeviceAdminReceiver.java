package com.sonimtech.wificonfig;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class MyDeviceAdminReceiver extends BroadcastReceiver {
    private static String TAG = "MyDeviceAdminReceiver";
    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, " onReceive");
    }
}
