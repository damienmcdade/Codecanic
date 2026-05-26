import SwiftUI
import WebKit
import SafariServices

private let primaryURL = URL(string: "https://codecanic.app")!
private let fallbackURL = URL(string: "https://codecanic-production.up.railway.app")!

struct ContentView: View {
    @State private var safariURL: URL?

    var body: some View {
        CodecanicWebView(
            primaryURL: primaryURL,
            fallbackURL: fallbackURL,
            openExternally: { url in
                safariURL = url
            }
        )
        .ignoresSafeArea()
        .sheet(item: Binding(
            get: { safariURL.map(IdentifiableURL.init) },
            set: { safariURL = $0?.url }
        )) { wrapper in
            SafariView(url: wrapper.url)
                .ignoresSafeArea()
        }
    }
}

private struct IdentifiableURL: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

private struct SafariView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> SFSafariViewController {
        let cfg = SFSafariViewController.Configuration()
        cfg.entersReaderIfAvailable = false
        let vc = SFSafariViewController(url: url, configuration: cfg)
        vc.dismissButtonStyle = .close
        return vc
    }

    func updateUIViewController(_ uiViewController: SFSafariViewController, context: Context) {}
}

struct CodecanicWebView: UIViewRepresentable {
    let primaryURL: URL
    let fallbackURL: URL
    let openExternally: (URL) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(fallbackURL: fallbackURL, openExternally: openExternally)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
        configuration.websiteDataStore = .default()

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.allowsLinkPreview = false
        webView.customUserAgent = (webView.value(forKey: "userAgent") as? String ?? "") + " CodecaniciOS/1.1.0"

        let refresh = UIRefreshControl()
        refresh.tintColor = UIColor(red: 0.08, green: 0.72, blue: 0.65, alpha: 1)
        refresh.addTarget(context.coordinator, action: #selector(Coordinator.pullToRefresh(_:)), for: .valueChanged)
        webView.scrollView.refreshControl = refresh
        context.coordinator.webView = webView

        webView.load(URLRequest(url: primaryURL))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        private let fallbackURL: URL
        private let openExternally: (URL) -> Void
        private var didLoadFallback = false
        weak var webView: WKWebView?

        init(fallbackURL: URL, openExternally: @escaping (URL) -> Void) {
            self.fallbackURL = fallbackURL
            self.openExternally = openExternally
        }

        @objc func pullToRefresh(_ sender: UIRefreshControl) {
            webView?.reload()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                sender.endRefreshing()
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            loadFallbackIfNeeded(in: webView)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            loadFallbackIfNeeded(in: webView)
        }

        private func loadFallbackIfNeeded(in webView: WKWebView) {
            guard !didLoadFallback else { return }
            didLoadFallback = true
            webView.load(URLRequest(url: fallbackURL))
        }

        // OAuth pop-ups and target=_blank links: open in Safari sheet so the main WebView keeps wizard state.
        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
            if let url = navigationAction.request.url {
                openExternally(url)
            }
            return nil
        }

        // mailto:, tel:, and unsupported schemes — let the system handle them.
        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }
            let externalSchemes: Set<String> = ["mailto", "tel", "sms", "facetime"]
            if let scheme = url.scheme?.lowercased(), externalSchemes.contains(scheme) {
                UIApplication.shared.open(url, options: [:], completionHandler: nil)
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }
    }
}
