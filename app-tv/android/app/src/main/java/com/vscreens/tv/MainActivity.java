package com.vscreens.tv;

import android.app.SearchManager;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.Toast;
import androidx.activity.OnBackPressedCallback;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    private static final String SMART_TV_UA =
        "Mozilla/5.0 (SMART-TV; LINUX; Tizen 6.0) AppleWebKit/537.36 (KHTML, like Gecko) 76.0.3809.146/6.0 TV Safari/537.36";

    private int backPressCount = 0;
    private long lastBackPressMs = 0L;
    private long lastYtBackMs = 0L;
    private static final long BACK_RESET_WINDOW_MS = 3500L;
    private static final long YT_EXIT_DOUBLE_BACK_MS = 900L;

    private WebView youtubeTvWebView = null;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Mantener pantalla encendida 24/7 en modo señalización comercial
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        enterImmersiveMode();

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                handleBackInput();
            }
        });

        handleSearchIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleSearchIntent(intent);
    }

    private void handleSearchIntent(Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (Intent.ACTION_SEARCH.equals(action)
                || "android.media.action.MEDIA_PLAY_FROM_SEARCH".equals(action)
                || "com.google.android.gms.actions.SEARCH_ACTION".equals(action)) {
            String query = intent.getStringExtra(SearchManager.QUERY);
            if (query == null) {
                query = intent.getStringExtra("query");
            }
            if (query != null && !query.trim().isEmpty()) {
                final String targetUrl = "https://www.youtube.com/tv#/results?search_query=" + Uri.encode(query.trim());
                mainHandler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        if (MainActivity.this.bridge != null && MainActivity.this.bridge.getWebView() != null) {
                            MainActivity.this.bridge.getWebView().evaluateJavascript(
                                "window.dispatchEvent(new CustomEvent('vscreens:pause_for_search'))", null
                            );
                        }
                        openYouTubeTVInternal(0, 0, 0, 0, targetUrl);
                    }
                }, 400);
            }
        }
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
            webView.addJavascriptInterface(new VScreenSNativeBridge(), "VScreenSNative");
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
    public boolean dispatchKeyEvent(KeyEvent event) {
        if (event != null && event.getKeyCode() == KeyEvent.KEYCODE_BACK) {
            if (event.getAction() == KeyEvent.ACTION_UP && event.getRepeatCount() == 0) {
                handleBackInput();
            }
            return true;
        }
        if (event != null && (event.getKeyCode() == KeyEvent.KEYCODE_SEARCH || event.getKeyCode() == KeyEvent.KEYCODE_VOICE_ASSIST)) {
            if (event.getAction() == KeyEvent.ACTION_UP && event.getRepeatCount() == 0) {
                if (youtubeTvWebView == null || youtubeTvWebView.getVisibility() != View.VISIBLE) {
                    if (this.bridge != null && this.bridge.getWebView() != null) {
                        this.bridge.getWebView().evaluateJavascript(
                            "window.__vscreensOpenSearch && window.__vscreensOpenSearch();",
                            null
                        );
                    }
                    return true;
                }
            }
        }
        return super.dispatchKeyEvent(event);
    }

    @Override
    public void onBackPressed() {
        handleBackInput();
    }

    private void handleBackInput() {
        if (youtubeTvWebView != null && youtubeTvWebView.getVisibility() == View.VISIBLE) {
            long now = System.currentTimeMillis();
            if (now - lastYtBackMs < YT_EXIT_DOUBLE_BACK_MS) {
                lastYtBackMs = 0L;
                closeYouTubeTVInternal(true);
                return;
            }
            lastYtBackMs = now;
            // Enviar Escape/Back a la SPA de YouTube TV para regresar a la búsqueda o lista anterior
            youtubeTvWebView.evaluateJavascript(
                "(function(){" +
                "var ev = new KeyboardEvent('keydown',{key:'Escape',code:'Escape',keyCode:27,which:27,bubbles:true,cancelable:true});" +
                "document.dispatchEvent(ev);" +
                "if (document.activeElement) document.activeElement.dispatchEvent(ev);" +
                "if (window.history && window.history.length > 1) { window.history.back(); }" +
                "})()",
                null
            );
            Toast.makeText(this, "Presiona Atrás 2 veces rápido para volver a tu playlist", Toast.LENGTH_SHORT).show();
            return;
        }
        processBackAction();
    }

    private void processBackAction() {
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

    private void openYouTubeTVInternal(final int cssLeft, final int cssTop, final int cssWidth, final int cssHeight) {
        openYouTubeTVInternal(cssLeft, cssTop, cssWidth, cssHeight, "https://www.youtube.com/tv");
    }

    private void openYouTubeTVInternal(final int cssLeft, final int cssTop, final int cssWidth, final int cssHeight, final String targetUrl) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                ViewGroup root = findViewById(android.R.id.content);
                if (root == null) return;

                float density = getResources().getDisplayMetrics().density;
                int pxLeft = Math.max(0, Math.round(cssLeft * density));
                int pxTop = Math.max(0, Math.round(cssTop * density));
                int pxWidth = cssWidth > 0 ? Math.round(cssWidth * density) : ViewGroup.LayoutParams.MATCH_PARENT;
                int pxHeight = cssHeight > 0 ? Math.round(cssHeight * density) : ViewGroup.LayoutParams.MATCH_PARENT;

                if (youtubeTvWebView == null) {
                    youtubeTvWebView = new WebView(MainActivity.this);
                    youtubeTvWebView.setBackgroundColor(Color.BLACK);
                    youtubeTvWebView.setFocusable(true);
                    youtubeTvWebView.setFocusableInTouchMode(true);

                    WebSettings s = youtubeTvWebView.getSettings();
                    s.setJavaScriptEnabled(true);
                    s.setDomStorageEnabled(true);
                    s.setMediaPlaybackRequiresUserGesture(false);
                    s.setUserAgentString(SMART_TV_UA);
                    s.setUseWideViewPort(true);
                    s.setLoadWithOverviewMode(true);

                    youtubeTvWebView.setWebChromeClient(new WebChromeClient() {
                        @Override
                        public void onPermissionRequest(final PermissionRequest request) {
                            mainHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    if (request != null) {
                                        request.grant(request.getResources());
                                    }
                                }
                            });
                        }
                    });
                    youtubeTvWebView.setWebViewClient(new WebViewClient() {
                        @Override
                        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                            String url = request != null && request.getUrl() != null ? request.getUrl().toString() : "";
                            if (url.startsWith("https://www.youtube.com") || url.startsWith("https://m.youtube.com") || url.startsWith("https://accounts.google.com")) {
                                return false;
                            }
                            return true;
                        }
                    });
                    root.addView(youtubeTvWebView);
                }

                FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(pxWidth, pxHeight, Gravity.TOP | Gravity.START);
                lp.leftMargin = pxLeft;
                lp.topMargin = pxTop;
                youtubeTvWebView.setLayoutParams(lp);
                youtubeTvWebView.setVisibility(View.VISIBLE);
                youtubeTvWebView.bringToFront();
                youtubeTvWebView.loadUrl(targetUrl != null ? targetUrl : "https://www.youtube.com/tv");
                youtubeTvWebView.requestFocus();
                Toast.makeText(MainActivity.this, "YouTube TV activo. Usa Back para regresar.", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void closeYouTubeTVInternal(final boolean notifyJs) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                if (youtubeTvWebView != null) {
                    youtubeTvWebView.loadUrl("about:blank");
                    youtubeTvWebView.setVisibility(View.GONE);
                }
                if (bridge != null && bridge.getWebView() != null) {
                    bridge.getWebView().requestFocus();
                    if (notifyJs) {
                        bridge.getWebView().evaluateJavascript(
                            "window.__vscreensOnYouTubeClosed && window.__vscreensOnYouTubeClosed();",
                            null
                        );
                    }
                }
            }
        });
    }

    public class VScreenSNativeBridge {
        @JavascriptInterface
        public void openYouTubeTV(int left, int top, int width, int height) {
            openYouTubeTVInternal(left, top, width, height);
        }

        @JavascriptInterface
        public void closeYouTubeTV() {
            closeYouTubeTVInternal(false);
        }
    }
}
