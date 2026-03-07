import React, { useState } from 'react';
import { View, Text, ScrollView, StyleSheet, TextInput, TouchableOpacity, Alert } from 'react-native';
import { useApp } from '../context/AppContext';

export default function SettingsScreen() {
  const { apiKey, serverUrl, logout, apiCall } = useApp();
  const [newServerUrl, setNewServerUrl] = useState(serverUrl);

  const handleLogout = () => {
    Alert.alert(
      'Logout',
      'Are you sure you want to logout?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Logout',
          style: 'destructive',
          onPress: () => logout()
        }
      ]
    );
  };

  const exportData = async () => {
    const licenses = await apiCall('/api/admin/licenses');
    const pools = await apiCall('/api/admin/pools');
    const audit = await apiCall('/api/admin/audit');
    
    const data = JSON.stringify({ licenses, pools, audit }, null, 2);
    Alert.alert('Export', `Data exported (${data.length} bytes)\n\nCheck console for full data.`);
    console.log('Exported Data:', data);
  };

  return (
    <ScrollView style={styles.container}>
      <Text style={styles.header}>Settings</Text>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Connection</Text>
        
        <Text style={styles.label}>Server URL</Text>
        <TextInput
          style={styles.input}
          value={newServerUrl}
          onChangeText={setNewServerUrl}
          placeholder="http://localhost:3001"
          placeholderTextColor="#666"
          autoCapitalize="none"
        />

        <Text style={styles.label}>API Key</Text>
        <TextInput
          style={styles.input}
          value={apiKey ? '••••••••••••••••' : ''}
          editable={false}
          placeholderTextColor="#666"
        />
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Data</Text>
        
        <TouchableOpacity style={styles.menuItem} onPress={exportData}>
          <Text style={styles.menuIcon}>📤</Text>
          <Text style={styles.menuText}>Export All Data</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>About</Text>
        
        <View style={styles.aboutCard}>
          <Text style={styles.appName}>TRAUMA License Manager</Text>
          <Text style={styles.version}>Version 1.0.0</Text>
          <Text style={styles.description}>
            Mobile app for managing TRAUMA licenses, pools, and user access.
          </Text>
        </View>
      </View>

      <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
        <Text style={styles.logoutText}>Logout</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
    padding: 16,
  },
  header: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 24,
  },
  section: {
    marginBottom: 24,
  },
  sectionTitle: {
    fontSize: 14,
    color: '#888',
    marginBottom: 12,
    textTransform: 'uppercase',
  },
  label: {
    color: '#666',
    fontSize: 12,
    marginTop: 12,
    marginBottom: 8,
  },
  input: {
    backgroundColor: '#111',
    borderWidth: 1,
    borderColor: '#222',
    borderRadius: 8,
    padding: 14,
    color: '#fff',
    fontSize: 16,
  },
  menuItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#111',
    borderRadius: 8,
    padding: 16,
    marginTop: 8,
  },
  menuIcon: {
    fontSize: 20,
    marginRight: 12,
  },
  menuText: {
    color: '#fff',
    fontSize: 16,
  },
  aboutCard: {
    backgroundColor: '#111',
    borderRadius: 12,
    padding: 20,
    alignItems: 'center',
  },
  appName: {
    color: '#fff',
    fontSize: 18,
    fontWeight: 'bold',
  },
  version: {
    color: '#dc143c',
    fontSize: 12,
    marginTop: 4,
  },
  description: {
    color: '#666',
    fontSize: 14,
    textAlign: 'center',
    marginTop: 12,
  },
  logoutButton: {
    backgroundColor: '#331111',
    borderRadius: 8,
    padding: 16,
    alignItems: 'center',
    marginTop: 20,
    marginBottom: 40,
  },
  logoutText: {
    color: '#ff4444',
    fontSize: 16,
    fontWeight: 'bold',
  },
});
