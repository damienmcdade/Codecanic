import SwiftUI
import WebKit

struct ContentView: View {
    var body: some View {
        CodecanicWebView(
            primaryURL: URL(string: "https://codecanic-production.up.railway.app")!,
            fallbackURL: URL(string: "https://codecanic-pv4d3rk5o-damienmcdade17-2595s-projects.vercel.app")!
        )
        .ignoresSafeArea()
    }
}

struct CodecanicWebView: UIViewRepresentable {
    let primaryURL: URL
    let fallbackURL: URL

    func makeCoordinator() -> Coordinator {
        Coordinator(fallbackURL: fallbackURL)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.load(URLRequest(url: primaryURL))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate {
        private let fallbackURL: URL
        private var didLoadFallback = false

        init(fallbackURL: URL) {
            self.fallbackURL = fallbackURL
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
    }
}
