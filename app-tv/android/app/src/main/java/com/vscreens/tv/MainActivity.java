package com.vscreens.tv;

import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.webkit.ValueCallback;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Toast;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    private int backPressCount = 0;
    private long lastBackPressMs = 0L;
    private static final long BACK_RESET_WINDOW_MS = 3500L;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Mantener pantalla encendida 24/7 en modo señalización comercial
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        enterImmersiveMode();
    }

    @Override
    public void onStart() {
        super.onStart();
        if (this.bridge != null && this.bridge.getWebView() != null) {
            WebView webView = this.bridge.getWebView();
            WebSettings settings = webView.getSettings();
            settings.setMediaPlaybackRequiresUserGesture(false);
            settings.setDomStorageEnabled(true);
            settings.setJavaScriptEnabled(true);
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        enterImmersiveMode();
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) {
            enterImmersiveMode();
        }
    }

    private void enterImmersiveMode() {
        View decorView = getWindow().getDecorView();
        decorView.setSystemUiVisibility(
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
            | View.SYSTEM_UI_FLAG_LAYOUT_STABLE
            | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
            | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
            | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
            | View.SYSTEM_UI_FLAG_FULLSCREEN
        );
    }

    @Override
    public void onBackPressed() {
        if (this.bridge != null && this.bridge.getWebView() != null) {
            WebView wv = this.bridge.getWebView();
            wv.evaluateJavascript(
                "(function(){ return (window.__vscreensHandleBack && window.__vscreensHandleBack()) ? '1' : '0'; })()",
                new ValueCallback<String>() {
                    @Override
                    public void onReceiveValue(String value) {
                        if ("\"1\"".equals(value) || "1".equals(value)) {
                            backPressCount = 0;
                            return;
                        }
                        handleExitBackPress();
                    }
                }
            );
            return;
        }
        handleExitBackPress();
    }

    private void handleExitBackPress() {
        long now = System.currentTimeMillis();
        if (now - lastBackPressMs > BACK_RESET_WINDOW_MS) {
            backPressCount = 0;
        }
        backPressCount += 1;
        lastBackPressMs = now;

        if (backPressCount == 2) {
            Toast.makeText(
                this,
                "Presiona Atrás una vez más para salir de VScreenS",
                Toast.LENGTH_LONG
            ).show();
        } else if (backPressCount >= 3) {
            backPressCount = 0;
            finish();
        }
    }
}
