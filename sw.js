/* TruckLoyal service worker
   Minimal network-passthrough worker. Its main job is to make the app
   meet PWA installability criteria so Chrome/Android offers "Install app".
   We intentionally do NOT cache the app shell — the app relies on fresh
   content from the server (no-store headers), so caching would risk
   serving stale UI after deploys. */

const VERSION = 'truckloyal-v1';

self.addEventListener('install', (event) => {
  // Activate immediately on first install
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  // Take control of open pages right away
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  // Network-first passthrough. A fetch handler is required for
  // installability; we just forward the request to the network.
  event.respondWith(
    fetch(event.request).catch(() => {
      // If offline and the request was a navigation, show the app shell
      if (event.request.mode === 'navigate') {
        return fetch('/app');
      }
      return new Response('', { status: 504, statusText: 'Offline' });
    })
  );
});
