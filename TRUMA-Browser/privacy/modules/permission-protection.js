/**
 * TRUMA Browser - Permission Protection Module
 * Blocks sensitive permissions by default, requires manual approval
 */

class PermissionProtection {
    constructor(config, manager) {
        this.config = config;
        this.manager = manager;
        this.enabled = config.enabled !== false;
        this.blockedPermissions = new Set(config.autoBlock || []);
        this.allowedPermissions = new Map(); // Per-origin allowlist
        this.pendingRequests = [];
    }

    /**
     * Initialize permission protection
     */
    async initialize(sess, mainWindow) {
        this.session = sess;
        this.mainWindow = mainWindow;

        // Set permission request handler
        sess.setPermissionRequestHandler((webContents, permission, callback, details) => {
            if (!this.enabled) {
                return callback(true);
            }

            const origin = this.getOrigin(webContents);
            
            // Check if permission is auto-blocked
            if (this.blockedPermissions.has(permission)) {
                // Check if this origin has been granted permission
                if (this.isPermissionAllowed(origin, permission)) {
                    console.log(`[PermissionProtection] Allowed ${permission} for ${origin}`);
                    return callback(true);
                }

                console.log(`[PermissionProtection] Blocked ${permission} for ${origin}`);
                this.manager.updateStat('permissionsBlocked');

                // Prompt user if configured
                if (this.config.promptOnBlock) {
                    this.promptPermission(permission, origin, details, callback);
                    return; // Don't call callback yet
                }

                return callback(false);
            }

            // Permission not in auto-block list, allow
            return callback(true);
        });

        // Set permission check handler
        sess.setPermissionCheckHandler((webContents, permission, requestingOrigin, details) => {
            if (!this.enabled) {
                return true;
            }

            const origin = requestingOrigin || this.getOrigin(webContents);
            
            if (this.blockedPermissions.has(permission)) {
                return this.isPermissionAllowed(origin, permission);
            }

            return true;
        });

        console.log('[PermissionProtection] Initialized with blocked permissions:', [...this.blockedPermissions]);
    }

    /**
     * Get origin from web contents
     */
    getOrigin(webContents) {
        try {
            const url = webContents.getURL();
            return new URL(url).origin;
        } catch (e) {
            return 'unknown';
        }
    }

    /**
     * Check if permission is allowed for origin
     */
    isPermissionAllowed(origin, permission) {
        const allowed = this.allowedPermissions.get(origin);
        return allowed && allowed.has(permission);
    }

    /**
     * Grant permission for origin
     */
    grantPermission(origin, permission) {
        if (!this.allowedPermissions.has(origin)) {
            this.allowedPermissions.set(origin, new Set());
        }
        this.allowedPermissions.get(origin).add(permission);
    }

    /**
     * Revoke permission for origin
     */
    revokePermission(origin, permission) {
        const allowed = this.allowedPermissions.get(origin);
        if (allowed) {
            allowed.delete(permission);
        }
    }

    /**
     * Prompt user for permission
     */
    promptPermission(permission, origin, details, callback) {
        const requestId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        this.pendingRequests.push({
            id: requestId,
            permission,
            origin,
            details,
            callback
        });

        // Send prompt to UI
        if (this.mainWindow && !this.mainWindow.isDestroyed()) {
            this.mainWindow.webContents.send('permission-request', {
                id: requestId,
                permission,
                origin,
                message: this.getPermissionMessage(permission)
            });
        }
    }

    /**
     * Get user-friendly message for permission
     */
    getPermissionMessage(permission) {
        const messages = {
            camera: 'This site wants to use your camera',
            microphone: 'This site wants to use your microphone',
            location: 'This site wants to know your location',
            notifications: 'This site wants to send you notifications',
            geolocation: 'This site wants to access your location',
            midi: 'This site wants to access MIDI devices',
            hid: 'This site wants to access HID devices',
            serial: 'This site wants to access serial ports',
            usb: 'This site wants to access USB devices',
            media: 'This site wants to access media devices',
            pointerLock: 'This site wants to lock your pointer',
            fullscreen: 'This site wants to enter fullscreen mode',
            openExternal: 'This site wants to open an external application',
            clipboardRead: 'This site wants to read your clipboard',
            clipboardWrite: 'This site wants to write to your clipboard'
        };

        return messages[permission] || `This site wants to access: ${permission}`;
    }

    /**
     * Handle user response to permission prompt
     */
    handlePermissionResponse(requestId, granted) {
        const index = this.pendingRequests.findIndex(r => r.id === requestId);
        
        if (index !== -1) {
            const request = this.pendingRequests[index];
            this.pendingRequests.splice(index, 1);

            if (granted) {
                this.grantPermission(request.origin, request.permission);
            }

            if (request.callback) {
                request.callback(granted);
            }
        }
    }

    /**
     * Get all granted permissions
     */
    getGrantedPermissions() {
        const result = {};
        
        this.allowedPermissions.forEach((permissions, origin) => {
            result[origin] = [...permissions];
        });

        return result;
    }

    /**
     * Clear all granted permissions
     */
    clearAllPermissions() {
        this.allowedPermissions.clear();
    }

    /**
     * Clear permissions for specific origin
     */
    clearPermissionsForOrigin(origin) {
        this.allowedPermissions.delete(origin);
    }

    /**
     * Add permission to auto-block list
     */
    blockPermission(permission) {
        this.blockedPermissions.add(permission);
        if (!this.config.autoBlock.includes(permission)) {
            this.config.autoBlock.push(permission);
        }
    }

    /**
     * Remove permission from auto-block list
     */
    unblockPermission(permission) {
        this.blockedPermissions.delete(permission);
        const index = this.config.autoBlock.indexOf(permission);
        if (index !== -1) {
            this.config.autoBlock.splice(index, 1);
        }
    }

    /**
     * Get current permission settings
     */
    getPermissionSettings() {
        return {
            autoBlocked: [...this.blockedPermissions],
            promptOnBlock: this.config.promptOnBlock
        };
    }

    /**
     * Update configuration
     */
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        this.enabled = this.config.enabled !== false;
        this.blockedPermissions = new Set(this.config.autoBlock || []);
    }

    /**
     * Cleanup
     */
    async cleanup() {
        this.allowedPermissions.clear();
        this.pendingRequests = [];
    }
}

module.exports = PermissionProtection;
