import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, ScrollView, Switch, TouchableOpacity, Alert } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

const API_URL = 'http://localhost:10000';

export default function SecurityScreen() {
  const [settings, setSettings] = useState({
    enabled: true,
    autoBlock: true,
    botDetection: true,
    rateLimitEnabled: true,
    autoBlockThreshold: 5,
    blockDuration: 24
  });

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      const res = await axios.get(`${API_URL}/api/security/settings`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSettings(res.data.settings);
    } catch (error) {
      console.error('Failed to load settings');
    }
  }

  async function updateSetting(key, value) {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      await axios.put(`${API_URL}/api/security/settings`, 
        { [key]: value },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setSettings({ ...settings, [key]: value });
    } catch (error) {
      Alert.alert('Error', 'Failed to update setting');
    }
  }

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView style={styles.scrollView}>
        <Text style={styles.headerTitle}>🛡️ Security Settings</Text>

        <View style={styles.panel}>
          <Text style={styles.panelTitle}>Protection Controls</Text>
          
          <View style={styles.toggleRow}>
            <Text style={styles.toggleLabel}>TRUMA NET Enabled</Text>
            <Switch
              value={settings.enabled}
              onValueChange={(value) => updateSetting('enabled', value)}
              trackColor={{ false: '#333', true: '#dc143c' }}
              thumbColor={settings.enabled ? '#fff' : '#888'}
            />
          </View>

          <View style={styles.toggleRow}>
            <Text style={styles.toggleLabel}>Auto-Block Threats</Text>
            <Switch
              value={settings.autoBlock}
              onValueChange={(value) => updateSetting('autoBlock', value)}
              trackColor={{ false: '#333', true: '#dc143c' }}
              thumbColor={settings.autoBlock ? '#fff' : '#888'}
            />
          </View>

          <View style={styles.toggleRow}>
            <Text style={styles.toggleLabel}>Bot Detection</Text>
            <Switch
              value={settings.botDetection}
              onValueChange={(value) => updateSetting('botDetection', value)}
              trackColor={{ false: '#333', true: '#dc143c' }}
              thumbColor={settings.botDetection ? '#fff' : '#888'}
            />
          </View>

          <View style={styles.toggleRow}>
            <Text style={styles.toggleLabel}>Rate Limiting</Text>
            <Switch
              value={settings.rateLimitEnabled}
              onValueChange={(value) => updateSetting('rateLimitEnabled', value)}
              trackColor={{ false: '#333', true: '#dc143c' }}
              thumbColor={settings.rateLimitEnabled ? '#fff' : '#888'}
            />
          </View>
        </View>

        <View style={styles.panel}>
          <Text style={styles.panelTitle}>Auto-Block Settings</Text>
          
          <View style={styles.infoRow}>
            <Text style={styles.infoLabel}>Threats before block</Text>
            <Text style={styles.infoValue}>{settings.autoBlockThreshold}</Text>
          </View>

          <View style={styles.infoRow}>
            <Text style={styles.infoLabel}>Block duration (hours)</Text>
            <Text style={styles.infoValue}>{settings.blockDuration}</Text>
          </View>
        </View>

        <TouchableOpacity 
          style={styles.emergencyButton}
          onPress={() => Alert.alert(
            'Emergency Mode',
            'Block ALL new visitors?',
            [
              { text: 'Cancel', style: 'cancel' },
              { text: 'Activate', style: 'destructive', onPress: () => activateEmergency() }
            ]
          )}
        >
          <Text style={styles.emergencyButtonText}>🚨 ACTIVATE EMERGENCY MODE</Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );

  async function activateEmergency() {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      await axios.post(`${API_URL}/api/security/emergency-mode`, 
        { enabled: true },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      Alert.alert('Emergency Mode', 'Activated successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to activate');
    }
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  scrollView: {
    flex: 1,
    padding: 16,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#fff',
    marginBottom: 20,
  },
  panel: {
    backgroundColor: '#1a1a1a',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
  },
  panelTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#fff',
    marginBottom: 16,
  },
  toggleRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#333',
  },
  toggleLabel: {
    color: '#888',
    fontSize: 14,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#333',
  },
  infoLabel: {
    color: '#888',
    fontSize: 14,
  },
  infoValue: {
    color: '#dc143c',
    fontSize: 16,
    fontWeight: '700',
    fontFamily: 'monospace',
  },
  emergencyButton: {
    backgroundColor: '#ff4444',
    borderRadius: 12,
    padding: 20,
    alignItems: 'center',
    marginTop: 8,
  },
  emergencyButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '700',
  },
});
