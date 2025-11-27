/**
 * HackInterface Service Worker
 * Mode hors-ligne avec stratégies de cache intelligentes
 */

const CACHE_VERSION = 'v1.0.0';
const CACHE_NAME = `hackinterface-${CACHE_VERSION}`;

// Ressources essentielles à mettre en cache immédiatement
const CORE_ASSETS = [
    '/',
    '/index.html',
    '/static/css/style.css',
    '/static/js/app.js',
    '/manifest.json'
];

// Ressources API à mettre en cache pour le mode hors-ligne
const API_CACHE_PATTERNS = [
    '/api/workflows',
    '/api/templates',
    '/api/templates/popular',
    '/api/tools/status',
    '/api/sessions'
];

// Durée de cache pour différents types de ressources (en secondes)
const CACHE_TTL = {
    static: 86400 * 7,    // 7 jours pour les fichiers statiques
    api: 300,             // 5 minutes pour les données API
    templates: 3600,      // 1 heure pour les templates
    sessions: 60          // 1 minute pour les sessions
};

/**
 * Installation du Service Worker
 */
self.addEventListener('install', (event) => {
    console.log('[SW] Installation...');
    
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('[SW] Mise en cache des ressources essentielles');
                return cache.addAll(CORE_ASSETS);
            })
            .then(() => {
                console.log('[SW] Installation terminée');
                return self.skipWaiting();
            })
            .catch((error) => {
                console.error('[SW] Erreur installation:', error);
            })
    );
});

/**
 * Activation - Nettoyage des anciens caches
 */
self.addEventListener('activate', (event) => {
    console.log('[SW] Activation...');
    
    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames
                        .filter((name) => name.startsWith('hackinterface-') && name !== CACHE_NAME)
                        .map((name) => {
                            console.log('[SW] Suppression ancien cache:', name);
                            return caches.delete(name);
                        })
                );
            })
            .then(() => {
                console.log('[SW] Activation terminée');
                return self.clients.claim();
            })
    );
});

/**
 * Interception des requêtes
 */
self.addEventListener('fetch', (event) => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Ignorer les requêtes WebSocket
    if (url.protocol === 'ws:' || url.protocol === 'wss:') {
        return;
    }
    
    // Ignorer les requêtes cross-origin
    if (url.origin !== self.location.origin) {
        return;
    }
    
    // Stratégie selon le type de requête
    if (request.method === 'GET') {
        if (url.pathname.startsWith('/api/')) {
            // API: Network First avec fallback cache
            event.respondWith(networkFirstStrategy(request));
        } else if (url.pathname.startsWith('/static/')) {
            // Fichiers statiques: Cache First
            event.respondWith(cacheFirstStrategy(request));
        } else {
            // Pages HTML: Network First
            event.respondWith(networkFirstStrategy(request));
        }
    } else {
        // POST, PUT, DELETE: Queue si hors-ligne
        event.respondWith(handleMutation(request));
    }
});

/**
 * Stratégie Cache First (fichiers statiques)
 */
async function cacheFirstStrategy(request) {
    const cachedResponse = await caches.match(request);
    
    if (cachedResponse) {
        // Rafraîchir le cache en arrière-plan
        refreshCache(request);
        return cachedResponse;
    }
    
    try {
        const networkResponse = await fetch(request);
        if (networkResponse.ok) {
            const cache = await caches.open(CACHE_NAME);
            cache.put(request, networkResponse.clone());
        }
        return networkResponse;
    } catch (error) {
        return createOfflineResponse(request);
    }
}

/**
 * Stratégie Network First (API et pages)
 */
async function networkFirstStrategy(request) {
    try {
        const networkResponse = await fetch(request);
        
        if (networkResponse.ok) {
            // Mettre en cache les réponses GET réussies
            const cache = await caches.open(CACHE_NAME);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.log('[SW] Réseau indisponible, utilisation du cache');
        
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        return createOfflineResponse(request);
    }
}

/**
 * Rafraîchissement du cache en arrière-plan
 */
async function refreshCache(request) {
    try {
        const networkResponse = await fetch(request);
        if (networkResponse.ok) {
            const cache = await caches.open(CACHE_NAME);
            await cache.put(request, networkResponse);
        }
    } catch (error) {
        // Silencieux en cas d'erreur
    }
}

/**
 * Gestion des mutations (POST, PUT, DELETE) hors-ligne
 */
async function handleMutation(request) {
    try {
        return await fetch(request);
    } catch (error) {
        // Stocker la requête pour synchronisation ultérieure
        await queueRequest(request);
        
        return new Response(
            JSON.stringify({
                status: 'queued',
                message: 'Requête mise en file d\'attente pour synchronisation',
                offline: true
            }),
            {
                status: 202,
                headers: { 'Content-Type': 'application/json' }
            }
        );
    }
}

/**
 * Mise en file d'attente des requêtes hors-ligne
 */
async function queueRequest(request) {
    const db = await openIndexedDB();
    const tx = db.transaction('pendingRequests', 'readwrite');
    const store = tx.objectStore('pendingRequests');
    
    const requestData = {
        url: request.url,
        method: request.method,
        headers: Object.fromEntries(request.headers.entries()),
        body: await request.text(),
        timestamp: Date.now()
    };
    
    await store.add(requestData);
    
    // Programmer une synchronisation si supporté
    if ('sync' in self.registration) {
        await self.registration.sync.register('sync-pending-requests');
    }
}

/**
 * Ouverture de IndexedDB
 */
function openIndexedDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('hackinterface-offline', 1);
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains('pendingRequests')) {
                db.createObjectStore('pendingRequests', { keyPath: 'id', autoIncrement: true });
            }
        };
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Synchronisation des requêtes en attente
 */
self.addEventListener('sync', (event) => {
    if (event.tag === 'sync-pending-requests') {
        event.waitUntil(syncPendingRequests());
    }
});

async function syncPendingRequests() {
    const db = await openIndexedDB();
    const tx = db.transaction('pendingRequests', 'readwrite');
    const store = tx.objectStore('pendingRequests');
    const requests = await store.getAll();
    
    for (const requestData of requests) {
        try {
            const response = await fetch(requestData.url, {
                method: requestData.method,
                headers: requestData.headers,
                body: requestData.body
            });
            
            if (response.ok) {
                await store.delete(requestData.id);
                
                // Notifier l'application
                self.clients.matchAll().then((clients) => {
                    clients.forEach((client) => {
                        client.postMessage({
                            type: 'sync-success',
                            url: requestData.url
                        });
                    });
                });
            }
        } catch (error) {
            console.log('[SW] Sync échouée pour:', requestData.url);
        }
    }
}

/**
 * Création d'une réponse hors-ligne
 */
function createOfflineResponse(request) {
    const url = new URL(request.url);
    
    if (url.pathname.startsWith('/api/')) {
        // Réponse JSON pour les API
        return new Response(
            JSON.stringify({
                status: 'offline',
                error: 'Mode hors-ligne - Données du cache non disponibles',
                offline: true,
                cachedAt: null
            }),
            {
                status: 503,
                headers: { 'Content-Type': 'application/json' }
            }
        );
    }
    
    // Page HTML hors-ligne
    return new Response(
        `<!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>HackInterface - Hors ligne</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Courier New', monospace;
                    background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
                    color: #00ff41;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    text-align: center;
                    max-width: 500px;
                }
                .icon {
                    font-size: 80px;
                    margin-bottom: 20px;
                }
                h1 {
                    font-size: 24px;
                    margin-bottom: 15px;
                    color: #ff4444;
                }
                p {
                    font-size: 14px;
                    line-height: 1.6;
                    margin-bottom: 20px;
                    opacity: 0.8;
                }
                .status {
                    padding: 15px 25px;
                    background: rgba(255, 68, 68, 0.1);
                    border: 1px solid #ff4444;
                    border-radius: 8px;
                    margin-bottom: 25px;
                }
                button {
                    background: linear-gradient(135deg, #00ff41 0%, #00cc33 100%);
                    color: #0f0f23;
                    border: none;
                    padding: 12px 30px;
                    font-size: 14px;
                    font-weight: bold;
                    border-radius: 5px;
                    cursor: pointer;
                    font-family: inherit;
                    transition: transform 0.2s, box-shadow 0.2s;
                }
                button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0, 255, 65, 0.3);
                }
                .features {
                    margin-top: 30px;
                    text-align: left;
                    padding: 20px;
                    background: rgba(0, 255, 65, 0.05);
                    border-radius: 8px;
                }
                .features h3 {
                    margin-bottom: 10px;
                    font-size: 14px;
                }
                .features ul {
                    list-style: none;
                    font-size: 12px;
                }
                .features li {
                    padding: 5px 0;
                    opacity: 0.8;
                }
                .features li::before {
                    content: '✓ ';
                    color: #00ff41;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">📡</div>
                <h1>Mode Hors-Ligne</h1>
                <div class="status">
                    <p>Vous êtes actuellement hors ligne.<br>
                    Reconnectez-vous pour accéder à toutes les fonctionnalités.</p>
                </div>
                <button onclick="location.reload()">🔄 Réessayer</button>
                
                <div class="features">
                    <h3>Fonctionnalités disponibles hors-ligne :</h3>
                    <ul>
                        <li>Consultation des résultats en cache</li>
                        <li>Accès aux templates de workflows</li>
                        <li>Historique des commandes récentes</li>
                        <li>Documentation embarquée</li>
                    </ul>
                </div>
            </div>
            
            <script>
                // Auto-refresh quand la connexion revient
                window.addEventListener('online', () => {
                    location.reload();
                });
            </script>
        </body>
        </html>`,
        {
            status: 503,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        }
    );
}

/**
 * Messages depuis l'application principale
 */
self.addEventListener('message', (event) => {
    const { type, data } = event.data;
    
    switch (type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;
            
        case 'CACHE_URLS':
            // Mettre en cache des URLs spécifiques
            caches.open(CACHE_NAME).then((cache) => {
                cache.addAll(data.urls);
            });
            break;
            
        case 'CLEAR_CACHE':
            caches.delete(CACHE_NAME);
            break;
            
        case 'GET_CACHE_STATUS':
            getCacheStatus().then((status) => {
                event.source.postMessage({
                    type: 'CACHE_STATUS',
                    data: status
                });
            });
            break;
    }
});

/**
 * Obtenir le statut du cache
 */
async function getCacheStatus() {
    const cache = await caches.open(CACHE_NAME);
    const keys = await cache.keys();
    
    let totalSize = 0;
    const entries = [];
    
    for (const request of keys) {
        const response = await cache.match(request);
        if (response) {
            const blob = await response.clone().blob();
            totalSize += blob.size;
            entries.push({
                url: request.url,
                size: blob.size
            });
        }
    }
    
    return {
        cacheVersion: CACHE_VERSION,
        cacheName: CACHE_NAME,
        entriesCount: keys.length,
        totalSize: totalSize,
        entries: entries.slice(0, 50) // Limiter à 50 entrées
    };
}

/**
 * Notifications push (préparation)
 */
self.addEventListener('push', (event) => {
    if (!event.data) return;
    
    const data = event.data.json();
    
    const options = {
        body: data.body || 'Nouvelle notification HackInterface',
        icon: '/static/icons/icon-192.png',
        badge: '/static/icons/badge-72.png',
        vibrate: [100, 50, 100],
        data: data.url || '/',
        actions: [
            { action: 'view', title: 'Voir' },
            { action: 'dismiss', title: 'Ignorer' }
        ]
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title || 'HackInterface', options)
    );
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    if (event.action === 'dismiss') return;
    
    event.waitUntil(
        clients.matchAll({ type: 'window' }).then((clientList) => {
            // Focaliser sur une fenêtre existante si possible
            for (const client of clientList) {
                if (client.url === event.notification.data && 'focus' in client) {
                    return client.focus();
                }
            }
            // Sinon ouvrir une nouvelle fenêtre
            if (clients.openWindow) {
                return clients.openWindow(event.notification.data);
            }
        })
    );
});

console.log('[SW] Service Worker HackInterface chargé');
