/**
 * HackInterface - Application JavaScript
 * Gestion de l'interface et communication avec l'API
 */

// ============================================
// Configuration et État
// ============================================

const API_BASE = '';
let ws = null;
let targets = [];
let results = {};
let availableActions = {};
let availableWorkflows = [];
let currentSessionId = null;
let currentSessionKey = '';
let currentApiToken = '';

const SESSION_KEY_STORAGE_KEY = 'hackinterface_session_key';
const API_TOKEN_STORAGE_KEY = 'hackinterface_api_token';
const SESSION_KEY_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;
const nativeFetch = window.fetch.bind(window);
let fetchInterceptorInstalled = false;

// Instances Chart.js
let vulnSeverityChart = null;
let portsChart = null;
let discoveryChart = null;

// Configuration notifications
let notificationsEnabled = false;
let notificationPermission = 'default';

// ============================================
// Système de Notifications Navigateur
// ============================================

class NotificationManager {
    constructor() {
        this.permission = Notification.permission || 'default';
        this.enabled = localStorage.getItem('notifications_enabled') === 'true';
        this.sound = localStorage.getItem('notification_sound') !== 'false';
        this.soundAudio = null;
        this.init();
    }
    
    init() {
        // Créer un son de notification (optionnel)
        try {
            this.soundAudio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2teleTPYoa2zqYIzHVSLqLzPtJNbKzNhj6e3zaOLYC8kSXuYrcjCpYxdLSFBa4yfr762qpFnNh48YImdr7a0rZ9zRyktUHqXp7GxrKaEXDolN1p9l6OwsKylhmE/JjJXd5Sfq66qqI1oRCstTnWToauuq6iPbUksMkxyl6CprauqkXBNLzFJb5SeoKiqrJNzUDEuRmqRm52go6mXd1QyLEJmjZibnqGnnXtXNC1AYYqVmJudn59+WjYtPl6Gk5aYmp2dfV05LjxbgpGUlpmcnIBfOy87WX6PkpWXmpp/YjwuOVZ7jJCTlZmZf2U+LjdUeImNkZOXmIFnQC01UXWGio6Rk5WAakIuNE9yg4iMj5KUgm1FLjJNcIGFio2PlIOBgjMvJVJ5iIuNjpCQfXFLNjdEbYKHi4yNjX9yTTc5Q2qAhomKjIx/dFM6OUBmfIOHiYuLgXdXPTk9Y3uBhYeJin94Wz85O2B4f4OGh4l/emBAOjlddHyBhIaHfntjQzs4W3J6foKEhn18ZkY7N1hwd3uAgYSCfWhIQDdWbXV4fn+AgXpqSkI3U2pzdn19f395bE1FN1FobnR6e31+eW9QRzhPZWxydHh6e3ZwVEo5TWJqcHJ1eHl0clhMOkpgZ25wb3N3dnJbTjtIXWVrbnBzdXRxXFA+RlpjamxucHNyb19UQENXYGdqbG9wcGxgVkNBVV5laGprbmxtYllGQFNcY2ZoamxtamRcST9QWmBjZmhqa2djXkxATldcYWNlZ2hnYV9QQU1UWV5hY2VmZGBbUkJLUldcXmFjY2JeWFNFSE9UWVteYGFfXFZRR0VNU1dbXV5gXltTTUZDSlFVWFpcXV1ZUFJHR0hNUlVXWVxbV09MSUZGSlBTV1lZW1lTTEpISEZJT1NVV1lZVlBNTEhGRUlMUVNWV1dUUE1MSUVFRkhMT1FTVVRST05LSEVDREZJTVBSU1JQT0xKSEVCQkRGSUxPUVFQT0xKSUdEQkFCREZJTE5PUE5NSkpIREJAQEFDRkhKTE1NT0xKSUdEQkBAQEFDRUdJSktMTEpJR0VCQD8/QEFCQ0VGR0hJSEhHRkVDQkBAPz9AQEFCREVGRkdHRkZFRENCQD8+Pz4/P0ACAFBQT05NTEtKSUhHRkVEQ0JBQD8+PT08Ozo=');
        } catch (e) {
            console.log('Audio notification non supporté');
        }
    }
    
    async requestPermission() {
        if (!('Notification' in window)) {
            console.log('Ce navigateur ne supporte pas les notifications');
            return false;
        }
        
        if (Notification.permission === 'granted') {
            this.permission = 'granted';
            this.enabled = true;
            localStorage.setItem('notifications_enabled', 'true');
            return true;
        }
        
        if (Notification.permission !== 'denied') {
            const permission = await Notification.requestPermission();
            this.permission = permission;
            if (permission === 'granted') {
                this.enabled = true;
                localStorage.setItem('notifications_enabled', 'true');
                this.show('Notifications activées', 'Vous recevrez des notifications pour les événements importants.', 'info');
                return true;
            }
        }
        
        return false;
    }
    
    show(title, body, type = 'info', options = {}) {
        // Toujours afficher une notification dans l'interface
        notify(type, `${title}: ${body}`);
        
        // Si les notifications navigateur sont activées
        if (this.enabled && Notification.permission === 'granted') {
            const icons = {
                success: '✅',
                error: '❌',
                warning: '⚠️',
                info: 'ℹ️'
            };
            
            const notification = new Notification(`${icons[type] || ''} ${title}`, {
                body: body,
                icon: options.icon || '/static/img/icon.png',
                badge: options.badge,
                tag: options.tag || `hackinterface-${Date.now()}`,
                requireInteraction: options.requireInteraction || type === 'error',
                silent: !this.sound
            });
            
            // Jouer le son si activé
            if (this.sound && this.soundAudio) {
                this.soundAudio.play().catch(() => {});
            }
            
            // Auto-close après 5 secondes (sauf erreurs)
            if (type !== 'error') {
                setTimeout(() => notification.close(), 5000);
            }
            
            // Callback au clic
            notification.onclick = () => {
                window.focus();
                notification.close();
                if (options.onClick) options.onClick();
            };
            
            return notification;
        }
        
        return null;
    }
    
    // Méthodes de raccourci
    success(title, body, options = {}) {
        return this.show(title, body, 'success', options);
    }
    
    error(title, body, options = {}) {
        return this.show(title, body, 'error', { ...options, requireInteraction: true });
    }
    
    warning(title, body, options = {}) {
        return this.show(title, body, 'warning', options);
    }
    
    info(title, body, options = {}) {
        return this.show(title, body, 'info', options);
    }
    
    // Notifications spécifiques aux événements
    actionCompleted(action, target) {
        this.success('Action terminée', `${action} sur ${target} complétée avec succès`);
    }
    
    actionError(action, error) {
        this.error('Erreur action', `${action} a échoué: ${error}`);
    }
    
    workflowCompleted(workflowName) {
        this.success('Workflow terminé', `${workflowName} terminé avec succès`, {
            requireInteraction: true
        });
    }
    
    vulnerabilityFound(severity, count) {
        const severityColors = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
        this.warning('Vulnérabilités détectées', 
            `${severityColors[severity] || ''} ${count} vulnérabilité(s) ${severity} trouvée(s)`,
            { requireInteraction: severity === 'critical' }
        );
    }
    
    toggleSound() {
        this.sound = !this.sound;
        localStorage.setItem('notification_sound', this.sound.toString());
        return this.sound;
    }
    
    getStatus() {
        return {
            supported: 'Notification' in window,
            permission: this.permission,
            enabled: this.enabled,
            sound: this.sound
        };
    }
}

// Instance globale du gestionnaire de notifications
const notificationManager = new NotificationManager();

// ============================================
// Initialisation
// ============================================

document.addEventListener('DOMContentLoaded', async () => {
    await bootstrapNetworkContext();
    initWebSocket();
    initNavigation();
    initVpnUpload();
    loadInitialData();
    initTerminalToggle();
    initNotifications();
});

function isValidSessionKey(value) {
    return typeof value === 'string' && SESSION_KEY_REGEX.test(value.trim());
}

function setSessionKey(value) {
    if (!isValidSessionKey(value)) return;
    currentSessionKey = value.trim();
    localStorage.setItem(SESSION_KEY_STORAGE_KEY, currentSessionKey);
}

function getApiTokenFromSources() {
    const fromStorage = localStorage.getItem(API_TOKEN_STORAGE_KEY) || '';
    const fromQuery = new URLSearchParams(window.location.search).get('api_token') || '';
    const token = (fromQuery || fromStorage).trim();
    if (fromQuery) {
        localStorage.setItem(API_TOKEN_STORAGE_KEY, token);
    }
    return token;
}

function installFetchInterceptor() {
    if (fetchInterceptorInstalled) return;

    window.fetch = async (input, init = {}) => {
        const request = input instanceof Request ? input : null;
        const headers = new Headers(init.headers || (request ? request.headers : undefined));

        if (currentSessionKey) {
            headers.set('X-Session-Key', currentSessionKey);
        }

        if (currentApiToken && !headers.has('Authorization') && !headers.has('X-API-Key')) {
            headers.set('Authorization', `Bearer ${currentApiToken}`);
        }

        let finalInput = input;
        let finalInit = { ...init, headers };

        if (request) {
            finalInput = new Request(request, finalInit);
            finalInit = undefined;
        }

        const response = await nativeFetch(finalInput, finalInit);
        const serverSessionKey = response.headers.get('X-Session-Key');
        if (isValidSessionKey(serverSessionKey)) {
            setSessionKey(serverSessionKey);
        }

        return response;
    };

    fetchInterceptorInstalled = true;
}

async function bootstrapNetworkContext() {
    const querySessionKey = new URLSearchParams(window.location.search).get('session_key') || '';
    const storedSessionKey = localStorage.getItem(SESSION_KEY_STORAGE_KEY) || '';

    if (isValidSessionKey(querySessionKey)) {
        setSessionKey(querySessionKey);
    } else if (isValidSessionKey(storedSessionKey)) {
        setSessionKey(storedSessionKey);
    }

    currentApiToken = getApiTokenFromSources();
    installFetchInterceptor();

    try {
        const response = await fetch(`${API_BASE}/api/session/context`);
        if (response.ok) {
            const context = await response.json();
            if (isValidSessionKey(context.session_key)) {
                setSessionKey(context.session_key);
            }
        }
    } catch (error) {
        console.warn('Impossible de récupérer le contexte de session:', error);
    }
}

// ============================================
// Initialisation des Notifications
// ============================================

function initNotifications() {
    // Vérifier si les notifications sont déjà autorisées
    if (notificationManager.permission === 'granted' && notificationManager.enabled) {
        updateNotificationButton(true);
    }
    
    // Ajouter le bouton de notification s'il n'existe pas
    const header = document.querySelector('.header-right') || document.querySelector('.header');
    if (header && !document.getElementById('notification-btn')) {
        const notifBtn = document.createElement('button');
        notifBtn.id = 'notification-btn';
        notifBtn.className = 'btn btn-secondary btn-sm';
        notifBtn.innerHTML = '🔔 Notifications';
        notifBtn.onclick = toggleNotifications;
        notifBtn.title = 'Activer les notifications navigateur';
        header.insertBefore(notifBtn, header.firstChild);
    }
}

async function toggleNotifications() {
    const status = notificationManager.getStatus();
    
    if (!status.supported) {
        notify('warning', 'Les notifications ne sont pas supportées par votre navigateur');
        return;
    }
    
    if (status.enabled) {
        // Désactiver
        notificationManager.enabled = false;
        localStorage.setItem('notifications_enabled', 'false');
        updateNotificationButton(false);
        notify('info', 'Notifications désactivées');
    } else {
        // Demander la permission
        const granted = await notificationManager.requestPermission();
        updateNotificationButton(granted);
        if (!granted) {
            notify('warning', 'Permission de notification refusée');
        }
    }
}

function updateNotificationButton(enabled) {
    const btn = document.getElementById('notification-btn');
    if (btn) {
        if (enabled) {
            btn.innerHTML = '🔔 Notifs: ON';
            btn.classList.remove('btn-secondary');
            btn.classList.add('btn-success');
        } else {
            btn.innerHTML = '🔕 Notifs: OFF';
            btn.classList.remove('btn-success');
            btn.classList.add('btn-secondary');
        }
    }
}

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsParams = new URLSearchParams();
    if (currentSessionKey) {
        wsParams.set('session_key', currentSessionKey);
    }
    if (currentApiToken) {
        wsParams.set('token', currentApiToken);
    }
    const wsQuery = wsParams.toString();
    const wsUrl = `${protocol}//${window.location.host}/ws${wsQuery ? `?${wsQuery}` : ''}`;

    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('WebSocket connecté');
        addTerminalLine('WebSocket connecté', 'success');
    };
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
    
    ws.onclose = () => {
        console.log('WebSocket déconnecté, reconnexion...');
        setTimeout(initWebSocket, 3000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'action_update':
            handleActionUpdate(data);
            break;
        case 'workflow_update':
            handleWorkflowUpdate(data);
            break;
        case 'log':
            handleLog(data);
            break;
        case 'output':
            addTerminalLine(data.output, data.stream);
            break;
    }
}

function handleActionUpdate(data) {
    addActivityLog(data.status, `Action ${data.action} - ${data.status}`);
    
    if (data.status === 'completed') {
        notify('success', `Action ${data.action} terminée`);
        notificationManager.actionCompleted(data.action, data.target_id || 'cible');
        loadResults();
    } else if (data.status === 'error') {
        notify('error', `Erreur: ${data.action}`);
        notificationManager.actionError(data.action, data.error || 'Erreur inconnue');
    }
}

function handleWorkflowUpdate(data) {
    const progressDiv = document.getElementById('workflow-progress');
    const progressBar = document.getElementById('workflow-progress-bar');
    const statusText = document.getElementById('workflow-status-text');
    const workflowLog = document.getElementById('workflow-log');
    
    if (data.status === 'started') {
        progressDiv.style.display = 'block';
        progressBar.style.width = '0%';
        workflowLog.innerHTML = '';
        notificationManager.info('Workflow démarré', `Exécution en cours...`);
    } else if (data.status === 'running') {
        const progress = (data.current_step_num / data.total_steps) * 100;
        progressBar.style.width = `${progress}%`;
        statusText.textContent = `Étape ${data.current_step_num}/${data.total_steps}: ${data.current_step}`;
        workflowLog.innerHTML += `<div class="log-line">[${new Date().toLocaleTimeString()}] ${data.current_step}</div>`;
        workflowLog.scrollTop = workflowLog.scrollHeight;
    } else if (data.status === 'completed') {
        progressBar.style.width = '100%';
        statusText.textContent = 'Workflow terminé !';
        notify('success', 'Workflow terminé avec succès');
        notificationManager.workflowCompleted(data.workflow_id || 'Workflow');
        loadResults();
        updateStats();
    } else if (data.status === 'cancelled') {
        progressBar.style.width = '0%';
        statusText.textContent = 'Workflow annulé';
        notify('warning', 'Workflow annulé');
        notificationManager.warning('Workflow annulé', 'Le workflow a été interrompu par l\'utilisateur');
    }
}

function handleLog(data) {
    addTerminalLine(`[${data.level.toUpperCase()}] ${data.message}`, data.level);
    addActivityLog(data.level, data.message);
}

// ============================================
// Navigation
// ============================================

function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            showSection(section);
        });
    });
}

function showSection(sectionId) {
    // Masquer toutes les sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    
    // Afficher la section demandée
    const section = document.getElementById(`section-${sectionId}`);
    if (section) {
        section.classList.add('active');
    }
    
    // Mettre à jour la navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.section === sectionId);
    });
    
    // Mettre à jour le titre
    const titles = {
        dashboard: 'Dashboard',
        vpn: 'Configuration VPN',
        targets: 'Gestion des cibles',
        actions: 'Actions individuelles',
        workflows: 'Workflows automatisés',
        results: 'Résultats',
        reports: 'Rapports'
    };
    document.getElementById('section-title').textContent = titles[sectionId] || sectionId;
}

// ============================================
// VPN
// ============================================

function initVpnUpload() {
    const uploadZone = document.getElementById('vpn-upload-zone');
    const fileInput = document.getElementById('vpn-file');
    
    uploadZone.addEventListener('click', () => fileInput.click());
    
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.style.borderColor = 'var(--accent-primary)';
    });
    
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.style.borderColor = '';
    });
    
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.style.borderColor = '';
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleVpnFile(files[0]);
        }
    });
    
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            handleVpnFile(fileInput.files[0]);
        }
    });
}

async function handleVpnFile(file) {
    if (!file.name.endsWith('.ovpn')) {
        notify('error', 'Le fichier doit être un .ovpn');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE}/api/vpn/upload`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            notify('success', 'Fichier VPN uploadé');
            document.getElementById('vpn-upload-zone').style.display = 'none';
            document.getElementById('vpn-file-info').style.display = 'flex';
            document.getElementById('vpn-filename').textContent = file.name;
            updateVpnStatus();
        } else {
            notify('error', data.detail || 'Erreur lors de l\'upload');
        }
    } catch (error) {
        notify('error', 'Erreur de connexion');
    } finally {
        hideLoading();
    }
}

function clearVpnFile() {
    document.getElementById('vpn-upload-zone').style.display = 'block';
    document.getElementById('vpn-file-info').style.display = 'none';
    document.getElementById('vpn-file').value = '';
}

async function connectVpn() {
    try {
        showLoading();
        document.getElementById('btn-vpn-connect').disabled = true;
        
        const response = await fetch(`${API_BASE}/api/vpn/connect`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            notify('success', data.message);
            updateVpnStatus();
        } else {
            notify('error', data.message);
        }
    } catch (error) {
        notify('error', 'Erreur de connexion VPN');
    } finally {
        hideLoading();
        document.getElementById('btn-vpn-connect').disabled = false;
    }
}

async function disconnectVpn() {
    try {
        showLoading();
        const response = await fetch(`${API_BASE}/api/vpn/disconnect`, {
            method: 'POST'
        });
        
        const data = await response.json();
        notify('info', data.message);
        updateVpnStatus();
    } catch (error) {
        notify('error', 'Erreur');
    } finally {
        hideLoading();
    }
}

async function updateVpnStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/vpn/status`);
        const data = await response.json();
        
        const indicator = document.getElementById('vpn-indicator');
        const statusDisplay = document.getElementById('vpn-status-display');
        const connectBtn = document.getElementById('btn-vpn-connect');
        const disconnectBtn = document.getElementById('btn-vpn-disconnect');
        
        if (data.connected) {
            indicator.classList.add('connected');
            indicator.innerHTML = '<i class="fas fa-circle"></i><span>VPN Connecté</span>';
            
            statusDisplay.innerHTML = `
                <div class="status-icon connected">
                    <i class="fas fa-check-circle"></i>
                </div>
                <div class="status-text">
                    <h4>Connecté</h4>
                    <p>IP: ${data.tun_ip || 'N/A'}</p>
                </div>
            `;
            
            connectBtn.disabled = true;
            disconnectBtn.disabled = false;
        } else {
            indicator.classList.remove('connected');
            indicator.innerHTML = '<i class="fas fa-circle"></i><span>VPN Déconnecté</span>';
            
            statusDisplay.innerHTML = `
                <div class="status-icon disconnected">
                    <i class="fas fa-times-circle"></i>
                </div>
                <div class="status-text">
                    <h4>Déconnecté</h4>
                    <p>-</p>
                </div>
            `;
            
            connectBtn.disabled = !data.config_loaded;
            disconnectBtn.disabled = true;
        }
    } catch (error) {
        console.error('Erreur status VPN:', error);
    }
}

async function pingTarget() {
    const target = document.getElementById('ping-target').value.trim();
    if (!target) {
        notify('warning', 'Entrez une cible à tester');
        return;
    }
    
    const resultDiv = document.getElementById('ping-result');
    resultDiv.textContent = 'Ping en cours...';
    
    try {
        const response = await fetch(`${API_BASE}/api/vpn/ping`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        
        const data = await response.json();
        
        if (data.success) {
            resultDiv.innerHTML = `<span style="color: var(--accent-success)">✓ Succès</span>\n${data.output}`;
        } else {
            resultDiv.innerHTML = `<span style="color: var(--accent-danger)">✗ Échec</span>\n${data.output}`;
        }
    } catch (error) {
        resultDiv.textContent = 'Erreur de connexion';
    }
}

// ============================================
// Cibles
// ============================================

async function addTarget(event) {
    event.preventDefault();
    
    const type = document.getElementById('target-type').value;
    const value = document.getElementById('target-value').value.trim();
    const description = document.getElementById('target-description').value.trim();
    
    if (!value) {
        notify('warning', 'Entrez une valeur de cible');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/targets`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, value, description })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            notify('success', 'Cible ajoutée');
            document.getElementById('target-value').value = '';
            document.getElementById('target-description').value = '';
            loadTargets();
        } else {
            notify('error', data.detail || 'Erreur');
        }
    } catch (error) {
        notify('error', 'Erreur de connexion');
    }
}

async function loadTargets() {
    try {
        const response = await fetch(`${API_BASE}/api/targets`);
        targets = await response.json();
        
        renderTargets();
        updateTargetSelects();
        updateStats();
    } catch (error) {
        console.error('Erreur chargement cibles:', error);
    }
}

function renderTargets() {
    const container = document.getElementById('targets-list');
    
    if (targets.length === 0) {
        container.innerHTML = '<p class="empty-state">Aucune cible ajoutée</p>';
        return;
    }
    
    container.innerHTML = targets.map(target => `
        <div class="target-item">
            <div class="target-info">
                <span class="target-type">${target.type}</span>
                <span class="target-value">${target.value}</span>
                ${target.description ? `<span class="target-desc">${target.description}</span>` : ''}
            </div>
            <div class="target-actions">
                <button class="btn btn-sm btn-primary" onclick="runQuickScan(${target.id})">
                    <i class="fas fa-bolt"></i> Quick Scan
                </button>
                <button class="btn btn-sm btn-danger" onclick="deleteTarget(${target.id})">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `).join('');
}

function updateTargetSelects() {
    const selects = ['action-target-select', 'workflow-target-select', 'results-target-filter'];
    
    selects.forEach(selectId => {
        const select = document.getElementById(selectId);
        if (!select) return;
        
        const currentValue = select.value;
        
        if (selectId === 'results-target-filter') {
            select.innerHTML = '<option value="all">Toutes les cibles</option>';
        } else {
            select.innerHTML = '<option value="">Sélectionner une cible...</option>';
        }
        
        targets.forEach(target => {
            select.innerHTML += `<option value="${target.id}">${target.value} (${target.type})</option>`;
        });
        
        select.value = currentValue;
    });
}

async function deleteTarget(id) {
    if (!confirm('Supprimer cette cible ?')) return;
    
    try {
        await fetch(`${API_BASE}/api/targets/${id}`, { method: 'DELETE' });
        notify('success', 'Cible supprimée');
        loadTargets();
    } catch (error) {
        notify('error', 'Erreur');
    }
}

async function clearAllTargets() {
    if (!confirm('Supprimer toutes les cibles ?')) return;
    
    try {
        await fetch(`${API_BASE}/api/targets`, { method: 'DELETE' });
        notify('success', 'Toutes les cibles supprimées');
        loadTargets();
    } catch (error) {
        notify('error', 'Erreur');
    }
}

// ============================================
// Actions
// ============================================

async function loadActions() {
    try {
        const response = await fetch(`${API_BASE}/api/actions/available`);
        availableActions = await response.json();
        renderActions();
        renderCustomActionsList();
    } catch (error) {
        console.error('Erreur chargement actions:', error);
    }
}

function renderActions() {
    const container = document.getElementById('actions-grid');
    
    let html = '';
    
    for (const [category, actions] of Object.entries(availableActions)) {
        const categoryNames = {
            recon: 'Reconnaissance',
            web_enum: 'Énumération Web',
            vuln_scan: 'Scan de Vulnérabilités'
        };
        
        html += `
            <div class="action-category">
                <h3><i class="fas fa-folder"></i> ${categoryNames[category] || category}</h3>
                <div class="actions-list">
        `;
        
        actions.forEach(action => {
            html += `
                <div class="action-card" onclick="runAction('${action.id}')">
                    <h4><i class="fas fa-play-circle"></i> ${action.name}</h4>
                    <p>${action.description}</p>
                </div>
            `;
        });
        
        html += '</div></div>';
    }
    
    container.innerHTML = html;
}

function renderCustomActionsList() {
    const container = document.getElementById('custom-actions-list');
    let html = '';
    
    for (const [category, actions] of Object.entries(availableActions)) {
        actions.forEach(action => {
            html += `
                <label class="custom-action-item">
                    <input type="checkbox" name="custom-action" value="${action.id}">
                    ${action.name}
                </label>
            `;
        });
    }
    
    container.innerHTML = html;
}

async function runAction(actionId) {
    const targetId = document.getElementById('action-target-select').value;
    
    if (!targetId) {
        notify('warning', 'Sélectionnez d\'abord une cible');
        return;
    }
    
    try {
        notify('info', `Lancement de ${actionId}...`);
        addTerminalLine(`> Exécution: ${actionId} sur cible ${targetId}`, 'info');
        
        const response = await fetch(`${API_BASE}/api/actions/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_id: parseInt(targetId),
                action: actionId,
                options: {}
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            addTerminalLine(`Action ${actionId} terminée`, 'success');
            loadResults();
        } else {
            notify('error', data.detail || 'Erreur');
        }
    } catch (error) {
        notify('error', 'Erreur de connexion');
    }
}

async function runQuickScan(targetId) {
    try {
        notify('info', 'Lancement du Quick Scan...');
        
        const response = await fetch(`${API_BASE}/api/actions/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_id: targetId,
                action: 'nmap_quick',
                options: {}
            })
        });
        
        if (response.ok) {
            showSection('results');
        }
    } catch (error) {
        notify('error', 'Erreur');
    }
}

// ============================================
// Workflows
// ============================================

async function loadWorkflows() {
    try {
        const response = await fetch(`${API_BASE}/api/workflows/available`);
        availableWorkflows = await response.json();
        renderWorkflows();
    } catch (error) {
        console.error('Erreur chargement workflows:', error);
    }
}

function renderWorkflows() {
    const container = document.getElementById('workflows-grid');
    
    container.innerHTML = availableWorkflows.map(wf => `
        <div class="workflow-card" onclick="runWorkflow('${wf.id}')">
            <h4>
                <i class="fas fa-project-diagram"></i>
                ${wf.name}
            </h4>
            <p>${wf.description}</p>
            <div class="workflow-meta">
                <span><i class="fas fa-tasks"></i> ${wf.step_count} étapes</span>
                <span><i class="fas fa-crosshairs"></i> ${wf.target_types.join(', ')}</span>
                ${wf.auto_chain ? '<span><i class="fas fa-link"></i> Auto-chain</span>' : ''}
            </div>
        </div>
    `).join('');
}

async function runWorkflow(workflowId) {
    const targetId = document.getElementById('workflow-target-select').value;
    
    if (!targetId) {
        notify('warning', 'Sélectionnez d\'abord une cible');
        return;
    }
    
    try {
        notify('info', `Lancement du workflow...`);
        
        const response = await fetch(`${API_BASE}/api/workflows/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                workflow_id: workflowId,
                target_id: parseInt(targetId),
                options: {}
            })
        });
        
        if (response.ok) {
            document.getElementById('workflow-progress').style.display = 'block';
        }
    } catch (error) {
        notify('error', 'Erreur');
    }
}

async function runCustomWorkflow() {
    const targetId = document.getElementById('workflow-target-select').value;
    
    if (!targetId) {
        notify('warning', 'Sélectionnez d\'abord une cible');
        return;
    }
    
    const checkboxes = document.querySelectorAll('input[name="custom-action"]:checked');
    const actions = Array.from(checkboxes).map(cb => cb.value);
    
    if (actions.length === 0) {
        notify('warning', 'Sélectionnez au moins une action');
        return;
    }
    
    try {
        notify('info', `Lancement du workflow personnalisé (${actions.length} actions)...`);
        
        const response = await fetch(`${API_BASE}/api/workflows/custom`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_id: parseInt(targetId),
                actions: actions
            })
        });
        
        if (response.ok) {
            document.getElementById('workflow-progress').style.display = 'block';
        }
    } catch (error) {
        notify('error', 'Erreur');
    }
}

// ============================================
// Résultats
// ============================================

async function loadResults() {
    try {
        const response = await fetch(`${API_BASE}/api/results`);
        results = await response.json();
        renderResults();
        updateStats();
    } catch (error) {
        console.error('Erreur chargement résultats:', error);
    }
}

function renderResults() {
    const container = document.getElementById('results-container');
    const filter = document.getElementById('results-target-filter').value;
    
    let filteredResults = results;
    if (filter !== 'all') {
        filteredResults = { [filter]: results[filter] };
    }
    
    if (Object.keys(filteredResults).length === 0) {
        container.innerHTML = '<p class="empty-state">Aucun résultat disponible</p>';
        return;
    }
    
    let html = '';
    
    for (const [targetId, targetResults] of Object.entries(filteredResults)) {
        if (!targetResults) continue;
        
        const target = targets.find(t => t.id === parseInt(targetId));
        const targetName = target ? target.value : `Cible ${targetId}`;
        
        html += `<h3 style="margin: 20px 0 10px;"><i class="fas fa-crosshairs"></i> ${targetName}</h3>`;
        
        for (const [action, result] of Object.entries(targetResults)) {
            const statusClass = result.status === 'completed' ? 'success' : 
                               result.status === 'error' ? 'error' : 'running';
            
            html += `
                <div class="result-card" onclick="toggleResult(this)">
                    <div class="result-header">
                        <h4>
                            <i class="fas fa-terminal"></i>
                            ${action}
                        </h4>
                        <div class="result-status ${statusClass}">
                            <span>${result.duration ? result.duration.toFixed(2) + 's' : ''}</span>
                            <i class="fas fa-${statusClass === 'success' ? 'check-circle' : 
                                               statusClass === 'error' ? 'times-circle' : 'spinner fa-spin'}"></i>
                        </div>
                    </div>
                    <div class="result-body">
                        ${result.command ? `<p><strong>Commande:</strong> <code>${escapeHtml(result.command)}</code></p>` : ''}
                        <div class="result-output">${escapeHtml(result.output || result.error || 'Pas de sortie')}</div>
                        ${renderParsedData(result.parsed_data)}
                    </div>
                </div>
            `;
        }
    }
    
    container.innerHTML = html;
}

function renderParsedData(data) {
    if (!data) return '';
    
    let html = '<div class="result-parsed"><h5>Données parsées</h5>';
    
    // Ports
    if (data.hosts) {
        data.hosts.forEach(host => {
            if (host.ports && host.ports.length > 0) {
                html += `
                    <table class="parsed-table">
                        <tr><th>Port</th><th>État</th><th>Service</th><th>Version</th></tr>
                        ${host.ports.map(p => `
                            <tr>
                                <td>${p.port}/${p.protocol}</td>
                                <td>${p.state}</td>
                                <td>${p.service}</td>
                                <td>${p.version || '-'}</td>
                            </tr>
                        `).join('')}
                    </table>
                `;
            }
        });
    }
    
    // Vulnérabilités (Nuclei)
    if (data.findings && data.findings.length > 0) {
        html += `
            <table class="parsed-table">
                <tr><th>Sévérité</th><th>Nom</th><th>Localisation</th></tr>
                ${data.findings.map(f => `
                    <tr>
                        <td><span class="severity-${f.severity}">${f.severity}</span></td>
                        <td>${f.name}</td>
                        <td>${f.matched_at || '-'}</td>
                    </tr>
                `).join('')}
            </table>
        `;
    }
    
    // Sous-domaines
    if (data.all_subdomains && data.all_subdomains.length > 0) {
        html += `<p><strong>Sous-domaines trouvés:</strong> ${data.count}</p>`;
        html += `<div style="max-height: 200px; overflow-y: auto; background: var(--bg-darker); padding: 10px; border-radius: 5px;">`;
        html += data.all_subdomains.slice(0, 50).join('<br>');
        if (data.all_subdomains.length > 50) {
            html += `<br>... et ${data.all_subdomains.length - 50} autres`;
        }
        html += '</div>';
    }
    
    html += '</div>';
    return html;
}

function toggleResult(element) {
    element.classList.toggle('expanded');
}

function filterResults() {
    renderResults();
}

async function clearResults() {
    if (!confirm('Effacer tous les résultats ?')) return;
    
    try {
        await fetch(`${API_BASE}/api/results`, { method: 'DELETE' });
        results = {};
        renderResults();
        notify('success', 'Résultats effacés');
    } catch (error) {
        notify('error', 'Erreur');
    }
}

// ============================================
// Rapports
// ============================================

async function generateReport() {
    const type = document.getElementById('report-type').value;
    const includeScreenshots = document.getElementById('report-screenshots').checked;
    
    try {
        showLoading();
        notify('info', 'Génération du rapport en cours...');
        
        const response = await fetch(`${API_BASE}/api/reports/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type,
                include_screenshots: includeScreenshots
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            notify('success', 'Rapport généré !');
            loadReports();
        } else {
            notify('error', data.detail || 'Erreur');
        }
    } catch (error) {
        notify('error', 'Erreur de génération');
    } finally {
        hideLoading();
    }
}

async function loadReports() {
    try {
        const response = await fetch(`${API_BASE}/api/reports/list`);
        const reports = await response.json();
        
        const container = document.getElementById('reports-list');
        
        if (reports.length === 0) {
            container.innerHTML = '<p class="empty-state">Aucun rapport généré</p>';
            return;
        }
        
        container.innerHTML = reports.map(report => `
            <div class="report-item">
                <div class="report-info">
                    <i class="fas fa-file-${report.filename.endsWith('.html') ? 'code' : 'alt'}"></i>
                    <div>
                        <strong>${report.filename}</strong>
                        <p style="font-size: 0.85em; color: var(--text-muted);">
                            ${(report.size / 1024).toFixed(1)} KB - 
                            ${new Date(report.created * 1000).toLocaleString()}
                        </p>
                    </div>
                </div>
                <a href="/api/reports/download/${report.filename}" class="btn btn-primary btn-sm" target="_blank">
                    <i class="fas fa-download"></i> Télécharger
                </a>
            </div>
        `).join('');
    } catch (error) {
        console.error('Erreur chargement rapports:', error);
    }
}

// ============================================
// Terminal
// ============================================

function initTerminalToggle() {
    const header = document.querySelector('.terminal-header');
    header.addEventListener('click', toggleTerminal);
}

function toggleTerminal() {
    const panel = document.getElementById('terminal-panel');
    panel.classList.toggle('expanded');
}

function addTerminalLine(text, type = 'stdout') {
    const content = document.getElementById('terminal-content');
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    content.appendChild(line);
    content.scrollTop = content.scrollHeight;
    
    // Ouvrir le terminal automatiquement
    document.getElementById('terminal-panel').classList.add('expanded');
}

function clearTerminal() {
    const content = document.getElementById('terminal-content');
    content.innerHTML = '<p class="terminal-welcome">Terminal effacé</p>';
}

// ============================================
// Activité
// ============================================

function addActivityLog(level, message) {
    const container = document.getElementById('activity-log');
    
    // Retirer le message vide
    const emptyState = container.querySelector('.empty-state');
    if (emptyState) emptyState.remove();
    
    const icons = {
        success: 'check-circle',
        error: 'times-circle',
        info: 'info-circle',
        warning: 'exclamation-triangle'
    };
    
    const item = document.createElement('div');
    item.className = `log-item ${level}`;
    item.innerHTML = `
        <i class="fas fa-${icons[level] || 'circle'}"></i>
        <span>${message}</span>
        <small style="margin-left: auto; color: var(--text-muted);">${new Date().toLocaleTimeString()}</small>
    `;
    
    container.insertBefore(item, container.firstChild);
    
    // Garder seulement les 20 derniers
    while (container.children.length > 20) {
        container.removeChild(container.lastChild);
    }
}

// ============================================
// Stats
// ============================================

function updateStats() {
    document.getElementById('stat-targets').textContent = targets.length;
    
    let actionCount = 0;
    let vulnCount = 0;
    
    for (const targetResults of Object.values(results)) {
        actionCount += Object.keys(targetResults || {}).length;
        
        for (const result of Object.values(targetResults || {})) {
            if (result.parsed_data) {
                if (result.parsed_data.findings) {
                    vulnCount += result.parsed_data.findings.length;
                }
                if (result.parsed_data.vulnerabilities) {
                    vulnCount += result.parsed_data.vulnerabilities.length;
                }
            }
        }
    }
    
    document.getElementById('stat-actions').textContent = actionCount;
    document.getElementById('stat-vulns').textContent = vulnCount;
}

// ============================================
// Utilitaires
// ============================================

function notify(type, message) {
    const container = document.getElementById('notifications');
    
    const icons = {
        success: 'check-circle',
        error: 'times-circle',
        info: 'info-circle',
        warning: 'exclamation-triangle'
    };
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${icons[type]}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

function showLoading() {
    document.getElementById('loading-overlay').classList.add('visible');
}

function hideLoading() {
    document.getElementById('loading-overlay').classList.remove('visible');
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================
// Chargement initial
// ============================================

async function loadInitialData() {
    await Promise.all([
        loadTargets(),
        loadActions(),
        loadWorkflows(),
        loadResults(),
        loadReports(),
        updateVpnStatus(),
        loadSessions(),
        initCharts()
    ]);
    
    document.getElementById('tools-status').innerHTML = 
        '<span class="status-badge success">Système prêt</span>';
}

// ============================================
// Chart.js - Graphiques statistiques
// ============================================

async function initCharts() {
    // Couleurs du thème
    const colors = {
        critical: '#ff4757',
        high: '#ff6b6b',
        medium: '#ffa502',
        low: '#2ed573',
        info: '#5dade2',
        background: '#1a1d29',
        text: '#e0e0e0'
    };

    // Graphique des vulnérabilités par sévérité
    const vulnCtx = document.getElementById('vuln-severity-chart')?.getContext('2d');
    if (vulnCtx) {
        vulnSeverityChart = new Chart(vulnCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critique', 'Élevée', 'Moyenne', 'Faible', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [colors.critical, colors.high, colors.medium, colors.low, colors.info],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: colors.text }
                    }
                }
            }
        });
    }

    // Graphique des ports
    const portsCtx = document.getElementById('ports-chart')?.getContext('2d');
    if (portsCtx) {
        portsChart = new Chart(portsCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Ports découverts',
                    data: [],
                    backgroundColor: '#00d9ff',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: { color: colors.text },
                        grid: { color: 'rgba(255,255,255,0.1)' }
                    },
                    y: {
                        ticks: { color: colors.text },
                        grid: { color: 'rgba(255,255,255,0.1)' }
                    }
                }
            }
        });
    }

    // Graphique des découvertes par type
    const discoveryCtx = document.getElementById('discovery-chart')?.getContext('2d');
    if (discoveryCtx) {
        discoveryChart = new Chart(discoveryCtx, {
            type: 'pie',
            data: {
                labels: ['Ports', 'Sous-domaines', 'Emails', 'Utilisateurs', 'Vulnérabilités'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: ['#00d9ff', '#2ed573', '#ffa502', '#ff6b6b', '#ff4757'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: colors.text }
                    }
                }
            }
        });
    }
}

function updateCharts(stats) {
    // Mettre à jour le graphique des vulnérabilités
    if (vulnSeverityChart && stats.vulnerability_stats) {
        const vulnData = stats.vulnerability_stats;
        vulnSeverityChart.data.datasets[0].data = [
            vulnData.critical || 0,
            vulnData.high || 0,
            vulnData.medium || 0,
            vulnData.low || 0,
            vulnData.info || 0
        ];
        vulnSeverityChart.update();
    }

    // Mettre à jour le graphique des découvertes
    if (discoveryChart && stats.discovery_stats) {
        const discData = stats.discovery_stats;
        discoveryChart.data.datasets[0].data = [
            discData.port || 0,
            discData.subdomain || 0,
            discData.email || 0,
            discData.user || 0,
            discData.vulnerability || 0
        ];
        discoveryChart.update();
    }
}

function updatePortsChart(ports) {
    if (!portsChart || !ports || ports.length === 0) return;

    // Grouper les ports par service
    const portCounts = {};
    ports.forEach(p => {
        const port = p.port || p;
        const service = p.service || `Port ${port}`;
        portCounts[service] = (portCounts[service] || 0) + 1;
    });

    const labels = Object.keys(portCounts).slice(0, 10); // Top 10
    const data = labels.map(l => portCounts[l]);

    portsChart.data.labels = labels;
    portsChart.data.datasets[0].data = data;
    portsChart.update();
}

// ============================================
// Sessions persistantes
// ============================================

async function loadSessions() {
    try {
        const response = await fetch(`${API_BASE}/api/sessions`);
        const sessions = await response.json();
        renderSessionsList(sessions);
    } catch (error) {
        console.error('Erreur chargement sessions:', error);
    }
}

function renderSessionsList(sessions) {
    const container = document.getElementById('sessions-list');
    if (!container) return;

    if (!sessions || sessions.length === 0) {
        container.innerHTML = '<p class="empty-state">Aucune session sauvegardée</p>';
        return;
    }

    container.innerHTML = sessions.map(session => `
        <div class="session-item ${currentSessionId === session.id ? 'active' : ''}" data-id="${session.id}">
            <div class="session-info">
                <strong>${escapeHtml(session.name)}</strong>
                <span class="session-meta">
                    ${session.target_count || 0} cibles · ${session.result_count || 0} résultats
                </span>
                <span class="session-date">${new Date(session.updated_at).toLocaleDateString('fr-FR')}</span>
            </div>
            <div class="session-actions">
                <button class="btn btn-small btn-primary" onclick="loadSession(${session.id})" title="Charger">
                    <i class="fas fa-folder-open"></i>
                </button>
                <button class="btn btn-small btn-secondary" onclick="exportSession(${session.id})" title="Exporter">
                    <i class="fas fa-download"></i>
                </button>
                <button class="btn btn-small btn-danger" onclick="deleteSession(${session.id})" title="Supprimer">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `).join('');
}

async function createNewSession() {
    const name = prompt('Nom de la session:', `Session ${new Date().toLocaleDateString('fr-FR')}`);
    if (!name) return;

    try {
        const response = await fetch(`${API_BASE}/api/sessions?name=${encodeURIComponent(name)}`, {
            method: 'POST'
        });
        const data = await response.json();
        currentSessionId = data.session_id;
        notify('success', `Session "${name}" créée`);
        loadSessions();
    } catch (error) {
        notify('error', 'Erreur création session');
    }
}

async function loadSession(sessionId) {
    try {
        showLoading();
        const response = await fetch(`${API_BASE}/api/sessions/${sessionId}/load`, { method: 'POST' });
        const data = await response.json();
        currentSessionId = sessionId;
        
        // Recharger les données
        await Promise.all([loadTargets(), loadResults()]);
        
        // Charger les stats pour les graphiques
        const statsResponse = await fetch(`${API_BASE}/api/sessions/${sessionId}/stats`);
        const stats = await statsResponse.json();
        updateCharts(stats);
        
        notify('success', data.message);
        loadSessions();
    } catch (error) {
        notify('error', 'Erreur chargement session');
    } finally {
        hideLoading();
    }
}

async function deleteSession(sessionId) {
    if (!confirm('Supprimer cette session et toutes ses données ?')) return;

    try {
        await fetch(`${API_BASE}/api/sessions/${sessionId}`, { method: 'DELETE' });
        if (currentSessionId === sessionId) {
            currentSessionId = null;
        }
        notify('success', 'Session supprimée');
        loadSessions();
    } catch (error) {
        notify('error', 'Erreur suppression session');
    }
}

async function exportSession(sessionId) {
    try {
        const response = await fetch(`${API_BASE}/api/sessions/${sessionId}/export`);
        const data = await response.json();
        downloadJSON(data, `session_${sessionId}_export.json`);
        notify('success', 'Session exportée');
    } catch (error) {
        notify('error', 'Erreur export session');
    }
}

async function exportCurrentSession() {
    try {
        const response = await fetch(`${API_BASE}/api/session/export`);
        const data = await response.json();
        downloadJSON(data, `session_export_${Date.now()}.json`);
        notify('success', 'Session courante exportée');
    } catch (error) {
        notify('error', 'Erreur export');
    }
}

function downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function triggerImportSession() {
    document.getElementById('import-session-file').click();
}

document.addEventListener('DOMContentLoaded', () => {
    const importInput = document.getElementById('import-session-file');
    if (importInput) {
        importInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            try {
                const text = await file.text();
                const data = JSON.parse(text);
                
                const response = await fetch(`${API_BASE}/api/session/import`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                notify('success', `Session importée (ID: ${result.session_id})`);
                loadSessions();
            } catch (error) {
                notify('error', 'Erreur import: fichier invalide');
            }
            
            e.target.value = '';
        });
    }
});

// ============================================
// PWA - Progressive Web App Support
// ============================================

class PWAManager {
    constructor() {
        this.deferredPrompt = null;
        this.isInstalled = false;
        this.isOnline = navigator.onLine;
        this.init();
    }
    
    async init() {
        // Enregistrer le Service Worker
        if ('serviceWorker' in navigator) {
            try {
                const registration = await navigator.serviceWorker.register('/sw.js', {
                    scope: '/'
                });
                
                console.log('[PWA] Service Worker enregistré:', registration.scope);
                
                // Vérifier les mises à jour
                registration.addEventListener('updatefound', () => {
                    const newWorker = registration.installing;
                    newWorker.addEventListener('statechange', () => {
                        if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                            this.showUpdateNotification();
                        }
                    });
                });
                
                // Écouter les messages du Service Worker
                navigator.serviceWorker.addEventListener('message', (event) => {
                    this.handleServiceWorkerMessage(event.data);
                });
                
            } catch (error) {
                console.error('[PWA] Erreur enregistrement SW:', error);
            }
        }
        
        // Écouter l'événement beforeinstallprompt
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            this.deferredPrompt = e;
            this.showInstallBanner();
        });
        
        // Détecter si déjà installé
        window.addEventListener('appinstalled', () => {
            this.isInstalled = true;
            this.hideInstallBanner();
            notify('success', 'HackInterface installé avec succès!');
        });
        
        // Gérer le mode hors-ligne
        window.addEventListener('online', () => this.updateOnlineStatus(true));
        window.addEventListener('offline', () => this.updateOnlineStatus(false));
        
        // Configurer les boutons
        this.setupInstallButtons();
    }
    
    showInstallBanner() {
        const banner = document.getElementById('pwa-install-banner');
        if (banner && !this.isInstalled) {
            // Attendre un peu avant d'afficher
            setTimeout(() => {
                banner.classList.add('show');
            }, 3000);
        }
    }
    
    hideInstallBanner() {
        const banner = document.getElementById('pwa-install-banner');
        if (banner) {
            banner.classList.remove('show');
        }
    }
    
    setupInstallButtons() {
        const installBtn = document.getElementById('pwa-install-btn');
        const closeBtn = document.getElementById('pwa-close-btn');
        
        if (installBtn) {
            installBtn.addEventListener('click', () => this.installPWA());
        }
        
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                this.hideInstallBanner();
                // Ne plus afficher pendant cette session
                sessionStorage.setItem('pwa-banner-dismissed', 'true');
            });
        }
    }
    
    async installPWA() {
        if (!this.deferredPrompt) {
            console.log('[PWA] Pas de prompt disponible');
            return;
        }
        
        this.hideInstallBanner();
        
        // Afficher le prompt d'installation
        this.deferredPrompt.prompt();
        
        const { outcome } = await this.deferredPrompt.userChoice;
        console.log('[PWA] Choix utilisateur:', outcome);
        
        this.deferredPrompt = null;
        
        if (outcome === 'accepted') {
            notify('success', 'Installation en cours...');
        }
    }
    
    updateOnlineStatus(online) {
        this.isOnline = online;
        const indicator = document.getElementById('offline-indicator');
        
        if (indicator) {
            if (online) {
                indicator.classList.remove('show');
                notify('success', 'Connexion rétablie');
                // Synchroniser les données en attente
                this.syncPendingData();
            } else {
                indicator.classList.add('show');
                notify('warning', 'Mode hors-ligne activé');
            }
        }
    }
    
    async syncPendingData() {
        if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({
                type: 'SYNC_NOW'
            });
        }
    }
    
    handleServiceWorkerMessage(data) {
        switch (data.type) {
            case 'sync-success':
                notify('success', `Synchronisation réussie: ${data.url}`);
                break;
            
            case 'CACHE_STATUS':
                console.log('[PWA] Status cache:', data.data);
                break;
        }
    }
    
    showUpdateNotification() {
        if (confirm('Une nouvelle version de HackInterface est disponible. Mettre à jour?')) {
            if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
                navigator.serviceWorker.controller.postMessage({
                    type: 'SKIP_WAITING'
                });
                window.location.reload();
            }
        }
    }
    
    async getCacheStatus() {
        return new Promise((resolve) => {
            if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
                const channel = new MessageChannel();
                channel.port1.onmessage = (event) => {
                    resolve(event.data);
                };
                navigator.serviceWorker.controller.postMessage(
                    { type: 'GET_CACHE_STATUS' },
                    [channel.port2]
                );
            } else {
                resolve(null);
            }
        });
    }
    
    async clearCache() {
        if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({
                type: 'CLEAR_CACHE'
            });
            notify('info', 'Cache vidé');
        }
    }
    
    async cacheUrls(urls) {
        if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({
                type: 'CACHE_URLS',
                data: { urls }
            });
        }
    }
}

// Initialiser le PWA Manager
const pwaManager = new PWAManager();

// Fonction utilitaire pour vérifier le mode hors-ligne
function isOffline() {
    return !navigator.onLine;
}

// Fonction pour mettre en cache les données importantes
async function cacheImportantData() {
    const urlsToCache = [
        '/api/workflows',
        '/api/templates/popular',
        '/api/tools/status'
    ];
    
    pwaManager.cacheUrls(urlsToCache);
}

// Appeler au chargement initial
document.addEventListener('DOMContentLoaded', () => {
    // Mettre en cache les données importantes après connexion
    if (navigator.onLine) {
        setTimeout(cacheImportantData, 5000);
    }
});
