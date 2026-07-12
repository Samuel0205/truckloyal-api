/* TruckLoyal service worker
   Minimal network-passthrough worker. Its main job is to make the app
   meet PWA installability criteria so Chrome/Android offers "Install app".
   We intentionally do NOT cache the app shell — the app relies on fresh
   content from the server (no-store headers), so caching would risk
   serving stale UI after deploys. */

const VERSION = 'truckloyal-v2';

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

/* ── Web Push ─────────────────────────────────────────
   Displays notifications sent by vendors via /api/vendor/push.
   Payload: JSON {title, body, url}. */
self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {
    data = { title: 'Food Truck Rewards', body: event.data ? event.data.text() : '' };
  }
  const title = data.title || 'Food Truck Rewards';
  event.waitUntil(self.registration.showNotification(title, {
    body:  data.body || '',
    icon:  '/icon-192.png',
    badge: '/icon-192.png',
    data:  { url: data.url || '/app' },
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/app';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((wins) => {
      for (const w of wins) {
        if (w.url.includes('/app') && 'focus' in w) return w.focus();
      }
      return clients.openWindow(url);
    })
  );
});
