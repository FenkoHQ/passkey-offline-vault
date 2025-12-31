import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const RECONNECT_DELAY = 5000;
const HEARTBEAT_INTERVAL = 300000; // 5 minutes - relays rate limit aggressively
const MIN_BROADCAST_INTERVAL = 10000; // Minimum 10s between broadcasts
const PASSKEY_STORAGE_KEY = 'passkeys';
const SYNC_DEVICES_KEY = 'sync_devices';
const MAX_DEBUG_LOGS = 200;

const NOSTR_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.nostr.band'];

export interface DebugLogEntry {
  timestamp: number;
  level: 'info' | 'warn' | 'error' | 'debug';
  category: string;
  message: string;
  data?: any;
}

export interface SyncMessage {
  type: 'announce' | 'request' | 'response' | 'update' | 'device_info';
  chainId: string;
  deviceId: string;
  deviceName?: string;
  deviceType?: string;
  timestamp: number;
  payload: any;
}

export interface EncryptedPasskeyBundle {
  version: string;
  deviceId: string;
  timestamp: number;
  nonce: string;
  ciphertext: string;
  passkeyIds: string[];
}

export class SyncService {
  private ws: WebSocket | null = null;
  private chainId: string | null = null;
  private deviceId: string | null = null;
  private deviceName: string | null = null;
  private seedHash: string | null = null;
  private encryptionKey: CryptoKey | null = null;
  private nostrPrivateKey: Uint8Array | null = null;
  private nostrPublicKey: string | null = null;
  private isConnected = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private currentRelayIndex = 0;
  private subId: string | null = null;
  private connectionPromise: Promise<void> | null = null;
  private debugLogs: DebugLogEntry[] = [];
  private lastBroadcastTime = 0;
  private knownDevices = new Set<string>(); // Track devices we've already seen

  private log(level: DebugLogEntry['level'], category: string, message: string, data?: any): void {
    const entry: DebugLogEntry = {
      timestamp: Date.now(),
      level,
      category,
      message,
      data,
    };
    this.debugLogs.push(entry);
    if (this.debugLogs.length > MAX_DEBUG_LOGS) {
      this.debugLogs = this.debugLogs.slice(-MAX_DEBUG_LOGS);
    }
    const prefix = `[SyncService:${category}]`;
    if (level === 'error') {
      console.error(prefix, message, data || '');
    } else if (level === 'warn') {
      console.warn(prefix, message, data || '');
    } else {
      console.log(prefix, message, data || '');
    }
  }

  getDebugLogs(): DebugLogEntry[] {
    return [...this.debugLogs];
  }

  clearDebugLogs(): void {
    this.debugLogs = [];
  }

  getDebugInfo(): any {
    return {
      chainId: this.chainId,
      deviceId: this.deviceId,
      deviceName: this.deviceName,
      seedHashPrefix: this.seedHash ? this.seedHash.substring(0, 16) + '...' : null,
      isConnected: this.isConnected,
      currentRelay: NOSTR_RELAYS[this.currentRelayIndex],
      currentRelayIndex: this.currentRelayIndex,
      subId: this.subId,
      wsReadyState: this.ws?.readyState,
      hasEncryptionKey: !!this.encryptionKey,
      hasNostrKeys: !!this.nostrPrivateKey && !!this.nostrPublicKey,
      nostrPubkey: this.nostrPublicKey ? this.nostrPublicKey.substring(0, 16) + '...' : null,
      logsCount: this.debugLogs.length,
    };
  }

  async initialize(
    chainId: string,
    deviceId: string,
    seedHash: string,
    deviceName?: string
  ): Promise<void> {
    if (this.chainId === chainId && this.isConnected) {
      this.log('info', 'init', 'Already initialized for this chain');
      return;
    }

    this.chainId = chainId;
    this.deviceId = deviceId;
    this.seedHash = seedHash;
    this.deviceName = deviceName || 'Unknown Device';

    this.log('info', 'init', 'Initializing sync service', {
      chainId,
      deviceId: deviceId.substring(0, 8) + '...',
      deviceName: this.deviceName,
      seedHashPrefix: seedHash.substring(0, 16) + '...',
    });

    await this.deriveKeys(seedHash);
    this.log('info', 'crypto', 'Derived encryption and signing keys');

    await this.connectWithRetry();

    this.log('info', 'init', 'Initialized for chain', { chainId });
  }

  private async deriveKeys(seedHash: string): Promise<void> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(seedHash),
      'PBKDF2',
      false,
      ['deriveKey', 'deriveBits']
    );

    // Derive AES encryption key for message encryption
    this.encryptionKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('passkey-vault-sync-v1'),
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // Derive secp256k1 private key for Nostr signing
    // Use PBKDF2 to derive 32 bytes for the private key
    const nostrKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: encoder.encode('passkey-vault-nostr-v1'),
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      256
    );

    this.nostrPrivateKey = new Uint8Array(nostrKeyBits);

    // Use schnorr.getPublicKey for x-only pubkey (32 bytes, required by Nostr/BIP340)
    const xOnlyPubKey = secp256k1.schnorr.getPublicKey(this.nostrPrivateKey);
    this.nostrPublicKey = bytesToHex(xOnlyPubKey);

    this.log('info', 'crypto', 'Derived Nostr keypair', {
      pubkey: this.nostrPublicKey.substring(0, 16) + '...',
    });
  }

  private async connectWithRetry(): Promise<void> {
    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    this.connectionPromise = new Promise((resolve) => {
      const tryConnect = () => {
        this.connectWebSocket()
          .then(() => {
            this.connectionPromise = null;
            resolve();
          })
          .catch((err) => {
            this.log('warn', 'ws', 'Connection failed, trying next relay', { error: err.message });
            this.currentRelayIndex = (this.currentRelayIndex + 1) % NOSTR_RELAYS.length;
            setTimeout(tryConnect, RECONNECT_DELAY);
          });
      };
      tryConnect();
    });

    return this.connectionPromise;
  }

  private connectWebSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      if (this.ws) {
        this.ws.close();
        this.ws = null;
      }

      const relayUrl = NOSTR_RELAYS[this.currentRelayIndex];
      this.log('info', 'ws', 'Connecting to relay', {
        relay: relayUrl,
        index: this.currentRelayIndex,
      });

      const timeoutId = setTimeout(() => {
        this.log('warn', 'ws', 'Connection timeout after 10s', { relay: relayUrl });
        if (this.ws) {
          this.ws.close();
        }
        reject(new Error('Connection timeout'));
      }, 10000);

      try {
        this.ws = new WebSocket(relayUrl);

        this.ws.onopen = () => {
          clearTimeout(timeoutId);
          this.log('info', 'ws', 'WebSocket connected', { relay: relayUrl });
          this.isConnected = true;
          this.subscribeToChain();
          this.announcePresence();
          this.startHeartbeat();
          resolve();
        };

        this.ws.onmessage = (event) => {
          this.handleWebSocketMessage(event.data);
        };

        this.ws.onclose = (event) => {
          clearTimeout(timeoutId);
          this.log('warn', 'ws', 'WebSocket disconnected', {
            code: event.code,
            reason: event.reason,
          });
          this.isConnected = false;
          this.stopHeartbeat();
          if (this.chainId) {
            this.scheduleReconnect();
          }
        };

        this.ws.onerror = (error) => {
          clearTimeout(timeoutId);
          this.log('error', 'ws', 'WebSocket error', { error: String(error) });
          reject(error);
        };
      } catch (error: any) {
        clearTimeout(timeoutId);
        this.log('error', 'ws', 'Failed to create WebSocket', { error: error.message });
        reject(error);
      }
    });
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.log('debug', 'heartbeat', 'Sending presence announcement');
        this.announcePresence();
      }
    }, HEARTBEAT_INTERVAL);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    this.log('info', 'ws', 'Scheduling reconnect in 5s');
    this.reconnectTimer = setTimeout(() => {
      this.log('info', 'ws', 'Attempting reconnect...');
      this.currentRelayIndex = (this.currentRelayIndex + 1) % NOSTR_RELAYS.length;
      this.connectWithRetry();
    }, RECONNECT_DELAY);
  }

  private subscribeToChain(): void {
    if (!this.ws || !this.chainId) return;

    this.subId = `pk_${this.chainId.substring(0, 8)}_${Date.now()}`;

    const filter = {
      kinds: [30078],
      '#d': [`pksync-${this.chainId}`],
      since: Math.floor(Date.now() / 1000) - 3600,
      limit: 50,
    };

    const subscribeMsg = JSON.stringify(['REQ', this.subId, filter]);

    this.ws.send(subscribeMsg);
    this.log('info', 'nostr', 'Subscribed to chain events', {
      subId: this.subId,
      filter,
      chainId: this.chainId,
    });
  }

  private async announcePresence(): Promise<void> {
    const announcement: SyncMessage = {
      type: 'announce',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      deviceName: this.deviceName || undefined,
      deviceType: this.getDeviceType(),
      timestamp: Date.now(),
      payload: {
        action: 'online',
      },
    };

    this.log('debug', 'msg', 'Broadcasting presence announcement', {
      deviceId: this.deviceId?.substring(0, 8),
      deviceName: this.deviceName,
    });

    await this.broadcastMessage(announcement);
  }

  private getDeviceType(): string {
    if (typeof navigator === 'undefined') return 'Desktop';
    const platform = navigator.platform?.toLowerCase() || '';
    if (platform.includes('mac')) return 'Desktop (macOS)';
    if (platform.includes('win')) return 'Desktop (Windows)';
    if (platform.includes('linux')) return 'Desktop (Linux)';
    return 'Desktop';
  }

  private async handleWebSocketMessage(data: string): Promise<void> {
    try {
      const parsed = JSON.parse(data);
      const msgType = parsed[0];

      if (msgType === 'EVENT' && parsed[2]) {
        const event = parsed[2];
        this.log('debug', 'nostr', 'Received EVENT', {
          eventId: event.id?.substring(0, 8),
          pubkey: event.pubkey?.substring(0, 8),
          kind: event.kind,
        });

        if (event?.content) {
          const syncMsg = await this.decryptMessage(event.content);
          if (syncMsg) {
            if (syncMsg.deviceId === this.deviceId) {
              this.log('debug', 'msg', 'Ignoring own message');
            } else if (syncMsg.chainId !== this.chainId) {
              this.log('debug', 'msg', 'Ignoring message from different chain');
            } else {
              this.log('info', 'msg', 'Received sync message', {
                type: syncMsg.type,
                fromDevice: syncMsg.deviceId?.substring(0, 8),
                deviceName: syncMsg.deviceName,
              });
              await this.processSyncMessage(syncMsg);
            }
          } else {
            this.log('debug', 'crypto', 'Failed to decrypt message (wrong key or not our message)');
          }
        }
      } else if (msgType === 'OK') {
        const [, eventId, success, message] = parsed;
        if (success) {
          this.log('info', 'nostr', 'Event published successfully', {
            eventId: eventId?.substring(0, 8),
          });
        } else {
          this.log('warn', 'nostr', 'Event rejected by relay', {
            eventId: eventId?.substring(0, 8),
            message,
          });
        }
      } else if (msgType === 'EOSE') {
        this.log('info', 'nostr', 'End of stored events');
        // Don't auto-request sync - our presence announcement will trigger peers to share
      } else if (msgType === 'NOTICE') {
        this.log('info', 'nostr', 'Relay notice', { notice: parsed[1] });
      } else {
        this.log('debug', 'nostr', 'Unknown message type', {
          msgType,
          data: data.substring(0, 100),
        });
      }
    } catch (error) {
      // Silently ignore parse errors for non-JSON messages
    }
  }

  private async processSyncMessage(msg: SyncMessage): Promise<void> {
    this.log('info', 'sync', 'Processing message', {
      type: msg.type,
      from: msg.deviceId?.substring(0, 8),
      deviceName: msg.deviceName,
    });

    await this.updateRemoteDevice(msg);

    switch (msg.type) {
      case 'announce':
        if (msg.payload.action === 'online') {
          await this.handlePeerOnline(msg);
        }
        break;

      case 'request':
        if (msg.payload.action === 'sync') {
          await this.handleSyncRequest(msg);
        }
        break;

      case 'response':
      case 'update':
        await this.handlePasskeyUpdate(msg);
        break;
    }
  }

  private async updateRemoteDevice(msg: SyncMessage): Promise<void> {
    try {
      const result = await chrome.storage.local.get(SYNC_DEVICES_KEY);
      const chain = result[SYNC_DEVICES_KEY];
      if (!chain) {
        this.log('warn', 'device', 'No chain found in storage');
        return;
      }

      const existingIndex = chain.devices.findIndex((d: any) => d.id === msg.deviceId);

      const deviceInfo = {
        id: msg.deviceId,
        name: msg.deviceName || `Device ${msg.deviceId.substring(0, 8)}`,
        deviceType: msg.deviceType || 'Desktop',
        publicKey: '',
        createdAt: existingIndex >= 0 ? chain.devices[existingIndex].createdAt : msg.timestamp,
        lastSeen: msg.timestamp,
        isThisDevice: msg.deviceId === this.deviceId,
      };

      if (existingIndex >= 0) {
        chain.devices[existingIndex] = {
          ...chain.devices[existingIndex],
          ...deviceInfo,
          lastSeen: msg.timestamp,
        };
        this.log('debug', 'device', 'Updated existing device', {
          deviceId: msg.deviceId.substring(0, 8),
        });
      } else if (msg.deviceId !== this.deviceId) {
        chain.devices.push(deviceInfo);
        this.log('info', 'device', 'Discovered NEW device!', {
          deviceId: msg.deviceId.substring(0, 8),
          deviceName: msg.deviceName,
          deviceType: msg.deviceType,
        });
      }

      await chrome.storage.local.set({ [SYNC_DEVICES_KEY]: chain });
      this.log('debug', 'device', 'Saved device list', { deviceCount: chain.devices.length });
    } catch (error: any) {
      this.log('error', 'device', 'Failed to update remote device', { error: error.message });
    }
  }

  private async handlePeerOnline(msg: SyncMessage): Promise<void> {
    // Only share passkeys with NEW devices we haven't seen before
    // This prevents broadcast storms when multiple devices are online
    if (this.knownDevices.has(msg.deviceId)) {
      this.log('debug', 'sync', 'Peer already known, skipping passkey share', {
        peer: msg.deviceId?.substring(0, 8),
      });
      return;
    }

    this.knownDevices.add(msg.deviceId);
    this.log('info', 'sync', 'New peer discovered, sharing passkeys', {
      peer: msg.deviceId?.substring(0, 8),
      peerName: msg.deviceName,
    });

    const passkeys = await this.getLocalPasskeys();
    if (passkeys.length > 0) {
      await this.broadcastPasskeyUpdate(passkeys);
    } else {
      this.log('info', 'sync', 'No passkeys to share with peer');
    }
  }

  private async handleSyncRequest(msg: SyncMessage): Promise<void> {
    this.log('info', 'sync', 'Sync requested by peer', {
      peer: msg.deviceId?.substring(0, 8),
      requestId: msg.payload.requestId,
    });

    const passkeys = await this.getLocalPasskeys();
    if (passkeys.length === 0) {
      this.log('info', 'sync', 'No passkeys to share');
      return;
    }

    const bundle = await this.createEncryptedBundle(passkeys);

    const response: SyncMessage = {
      type: 'response',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      deviceName: this.deviceName || undefined,
      deviceType: this.getDeviceType(),
      timestamp: Date.now(),
      payload: {
        requestId: msg.payload.requestId,
        bundle,
      },
    };

    this.log('info', 'sync', 'Sending passkeys in response', { passkeyCount: passkeys.length });
    await this.broadcastMessage(response);
  }

  private async handlePasskeyUpdate(msg: SyncMessage): Promise<void> {
    const { bundle } = msg.payload;
    if (bundle) {
      try {
        this.log('info', 'sync', 'Received passkey bundle', {
          from: msg.deviceId?.substring(0, 8),
          passkeyIds: bundle.passkeyIds,
        });
        const remotePasskeys = await this.decryptBundle(bundle);
        await this.mergePasskeys(remotePasskeys);
      } catch (error: any) {
        this.log('error', 'sync', 'Failed to decrypt/merge bundle', { error: error.message });
      }
    }
  }

  async requestSync(): Promise<void> {
    if (!this.isConnected) {
      this.log('warn', 'sync', 'Not connected, cannot request sync');
      return;
    }

    const request: SyncMessage = {
      type: 'request',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      deviceName: this.deviceName || undefined,
      deviceType: this.getDeviceType(),
      timestamp: Date.now(),
      payload: {
        action: 'sync',
        requestId: crypto.randomUUID(),
      },
    };

    this.log('info', 'sync', 'Requesting sync from peers', {
      requestId: request.payload.requestId,
    });
    await this.broadcastMessage(request);
  }

  async broadcastPasskeyUpdate(passkeys: any[]): Promise<void> {
    if (!this.isConnected || !this.chainId) {
      this.log('warn', 'sync', 'Not connected, skipping passkey broadcast');
      return;
    }

    if (passkeys.length === 0) {
      this.log('info', 'sync', 'No passkeys to broadcast');
      return;
    }

    const bundle = await this.createEncryptedBundle(passkeys);

    const update: SyncMessage = {
      type: 'update',
      chainId: this.chainId,
      deviceId: this.deviceId!,
      deviceName: this.deviceName || undefined,
      deviceType: this.getDeviceType(),
      timestamp: Date.now(),
      payload: { bundle },
    };

    await this.broadcastMessage(update);
    this.log('info', 'sync', 'Broadcasted passkey update', { passkeyCount: passkeys.length });
  }

  private async broadcastMessage(msg: SyncMessage, bypassRateLimit = false): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.log('warn', 'ws', 'WebSocket not ready for broadcast', {
        readyState: this.ws?.readyState,
      });
      return;
    }

    // Rate limiting - prevent broadcast storms
    const now = Date.now();
    if (!bypassRateLimit && now - this.lastBroadcastTime < MIN_BROADCAST_INTERVAL) {
      this.log('debug', 'nostr', 'Rate limited, skipping broadcast', {
        msgType: msg.type,
        timeSinceLastMs: now - this.lastBroadcastTime,
      });
      return;
    }
    this.lastBroadcastTime = now;

    try {
      const encrypted = await this.encryptMessage(msg);
      const event = await this.createNostrEvent(encrypted);
      this.log('debug', 'nostr', 'Sending Nostr event', {
        eventId: event.id?.substring(0, 8),
        pubkey: event.pubkey?.substring(0, 8),
        msgType: msg.type,
      });
      this.ws.send(JSON.stringify(['EVENT', event]));
    } catch (error: any) {
      this.log('error', 'nostr', 'Failed to broadcast message', {
        error: error?.message || String(error),
        stack: error?.stack,
      });
    }
  }

  private async createNostrEvent(content: string): Promise<any> {
    if (!this.nostrPrivateKey || !this.nostrPublicKey) {
      throw new Error('Nostr keys not initialized');
    }

    const created_at = Math.floor(Date.now() / 1000);
    const pubkey = this.nostrPublicKey;
    const tags = [['d', `pksync-${this.chainId}`]];

    // Create the event data for hashing (NIP-01 format)
    const eventData = [0, pubkey, created_at, 30078, tags, content];
    const eventJson = JSON.stringify(eventData);

    // Hash the serialized event to get the event ID
    const eventHash = sha256(new TextEncoder().encode(eventJson));
    const id = bytesToHex(eventHash);

    // Sign the event ID with BIP340 Schnorr signature (required by Nostr)
    // Use signAsync for better browser compatibility
    const sig = await secp256k1.schnorr.signAsync(eventHash, this.nostrPrivateKey);
    const sigHex = bytesToHex(sig);

    this.log('debug', 'nostr', 'Created signed event', {
      id: id.substring(0, 8),
      pubkey: pubkey.substring(0, 8),
      sigLen: sigHex.length,
    });

    return {
      id,
      pubkey,
      created_at,
      kind: 30078,
      tags,
      content,
      sig: sigHex,
    };
  }

  private async encryptMessage(msg: SyncMessage): Promise<string> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(msg));
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      this.encryptionKey,
      data
    );

    return JSON.stringify({
      n: this.arrayBufferToBase64(nonce),
      c: this.arrayBufferToBase64(ciphertext),
    });
  }

  private async decryptMessage(encrypted: string): Promise<SyncMessage | null> {
    if (!this.encryptionKey) {
      return null;
    }

    try {
      const { n, c } = JSON.parse(encrypted);
      const nonce = this.base64ToArrayBuffer(n);
      const ciphertext = this.base64ToArrayBuffer(c);

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce.buffer as ArrayBuffer },
        this.encryptionKey,
        ciphertext.buffer as ArrayBuffer
      );

      const decoder = new TextDecoder();
      return JSON.parse(decoder.decode(decrypted));
    } catch {
      return null;
    }
  }

  private async createEncryptedBundle(passkeys: any[]): Promise<EncryptedPasskeyBundle> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(passkeys));
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      this.encryptionKey,
      data
    );

    return {
      version: '1.0',
      deviceId: this.deviceId!,
      timestamp: Date.now(),
      nonce: this.arrayBufferToBase64(nonce),
      ciphertext: this.arrayBufferToBase64(ciphertext),
      passkeyIds: passkeys.map((p) => p.id),
    };
  }

  private async decryptBundle(bundle: EncryptedPasskeyBundle): Promise<any[]> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const nonce = this.base64ToArrayBuffer(bundle.nonce);
    const ciphertext = this.base64ToArrayBuffer(bundle.ciphertext);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce.buffer as ArrayBuffer },
      this.encryptionKey,
      ciphertext.buffer as ArrayBuffer
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
  }

  private async getLocalPasskeys(): Promise<any[]> {
    const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
    return result[PASSKEY_STORAGE_KEY] || [];
  }

  private async mergePasskeys(remotePasskeys: any[]): Promise<void> {
    const localPasskeys = await this.getLocalPasskeys();
    const localMap = new Map(localPasskeys.map((p) => [p.id, p]));

    let addedCount = 0;
    let updatedCount = 0;

    this.log('info', 'merge', 'Merging passkeys', {
      localCount: localPasskeys.length,
      remoteCount: remotePasskeys.length,
    });

    for (const remote of remotePasskeys) {
      const local = localMap.get(remote.id);

      if (!local) {
        localMap.set(remote.id, remote);
        addedCount++;
        this.log('info', 'merge', 'Added new passkey', {
          id: remote.id?.substring(0, 8),
          rpId: remote.rpId,
        });
      } else if (remote.createdAt > local.createdAt) {
        localMap.set(remote.id, remote);
        updatedCount++;
        this.log('info', 'merge', 'Updated passkey (newer)', {
          id: remote.id?.substring(0, 8),
          rpId: remote.rpId,
        });
      }
    }

    if (addedCount > 0 || updatedCount > 0) {
      const merged = Array.from(localMap.values());
      await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: merged });
      this.log('info', 'merge', 'Merge complete', {
        added: addedCount,
        updated: updatedCount,
        total: merged.length,
      });
    } else {
      this.log('info', 'merge', 'No changes needed');
    }
  }

  private arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  getStatus(): { connected: boolean; chainId: string | null; deviceId: string | null } {
    return {
      connected: this.isConnected,
      chainId: this.chainId,
      deviceId: this.deviceId,
    };
  }

  async disconnect(): Promise<void> {
    this.log('info', 'ws', 'Disconnecting...');
    this.stopHeartbeat();

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      if (this.subId && this.ws.readyState === WebSocket.OPEN) {
        try {
          this.ws.send(JSON.stringify(['CLOSE', this.subId]));
        } catch {}
      }
      this.ws.close();
      this.ws = null;
    }

    this.chainId = null;
    this.deviceId = null;
    this.isConnected = false;
    this.connectionPromise = null;
    this.log('info', 'ws', 'Disconnected');
  }
}

export const syncService = new SyncService();
