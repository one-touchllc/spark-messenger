// Jab page load ho, tab check karein ki kya URL mein token hai
window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const googleToken = urlParams.get('token');

    if (googleToken) {
        // 1. Token ko LocalStorage mein save karein (taaki user login rahe)
        localStorage.setItem('spark_token', googleToken);

        // 2. URL ko saaf karein (f फालतू ka ?token=... hata dein)
        window.history.replaceState({}, document.title, window.location.pathname);

        // 3. User ko chat screen par bhejein (apna login logic trigger karein)
        checkAuthStatus(); 
    }
});

// Ye function check karega ki user logged in hai ya nahi
function checkAuthStatus() {
    const token = localStorage.getItem('spark_token');
    if (token) {
        // Yahan wo code likhein jo aapke "Auth Screen" ko chhupata hai 
        // aur "Chat Screen" ko dikhata hai.
        document.getElementById('auth-screen').style.display = 'none';
        document.getElementById('main-app').style.display = 'flex';
        
        // Agar aapne socket setup kiya hai toh use connect karein
        if (typeof socket !== 'undefined') {
            socket.emit('authenticate', token);
        }
    }
}self.addEventListener('push', event => {
  const data = event.data ? event.data.json() : {};
  const title = data.title || 'Spark Messenger';
  const body = data.body || 'New message';
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: '/icon.png',
      badge: '/icon.png',
      vibrate: [200, 100, 200],
      tag: 'spark-msg',
      renotify: true
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow('/'));
});

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(clients.claim()));
