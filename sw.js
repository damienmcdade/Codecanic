// CACHE_NAME embeds a build id (the placeholder below is replaced by
// scripts/build.mjs with the deploy commit). Each deploy gets a fresh cache
// name, so stale bundles from a previous deploy are evicted on activate instead
// of lingering until a manual version bump.
const BUILD_ID = "__BUILD_ID__";
const CACHE_NAME = `codecanic-${BUILD_ID}`;
const ASSETS = [
  "./",
  "./index.html",
  "./styles.css",
  "./app.js",
  "./manifest.webmanifest",
  "./icon.svg",
  "./icon-192.png",
  "./icon-512.png",
  "./icon-1024.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

// Stale-while-revalidate for the app shell: serve the cached asset immediately
// (fast, offline-capable) but always refetch in the background and update the
// cache, so a new deploy is picked up on the very next load — no waiting for a
// manual CACHE_NAME bump and no indefinitely-stale app.js/styles.css.
self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/")) return;

  event.respondWith(
    caches.open(CACHE_NAME).then((cache) =>
      cache.match(request).then((cached) => {
        const network = fetch(request)
          .then((response) => {
            if (response && response.ok && response.type === "basic") {
              cache.put(request, response.clone());
            }
            return response;
          })
          .catch(() => cached);
        return cached || network;
      })
    )
  );
});
