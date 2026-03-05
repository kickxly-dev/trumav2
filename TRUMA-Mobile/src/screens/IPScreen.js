import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, FlatList, TextInput, TouchableOpacity, Alert } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

const API_URL = 'http://localhost:10000';

export default function IPScreen() {
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [blockIPInput, setBlockIPInput] = useState('');
  const [blockReason, setBlockReason] = useState('');

  useEffect(() => {
    loadBlockedIPs();
  }, []);

  async function loadBlockedIPs() {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      const res = await axios.get(`${API_URL}/api/security/blocked-ips`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setBlockedIPs(res.data.blockedIPs || []);
    } catch (error) {
      console.error('Failed to load blocked IPs');
    }
  }

  async function blockIP() {
    if (!blockIPInput.trim()) {
      Alert.alert('Error', 'Enter an IP address');
      return;
    }

    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      await axios.post(`${API_URL}/api/security/block-ip`, 
        { ip: blockIPInput, reason: blockReason || 'Manual block', durationHours: 24 },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setBlockIPInput('');
      setBlockReason('');
      loadBlockedIPs();
      Alert.alert('Success', 'IP blocked successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to block IP');
    }
  }

  async function unblockIP(ip) {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      await axios.delete(`${API_URL}/api/security/block-ip/${ip}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      loadBlockedIPs();
    } catch (error) {
      Alert.alert('Error', 'Failed to unblock IP');
    }
  }

  function renderBlockedIP({ item }) {
    return (
      <View style={styles.ipCard}>
        <View style={styles.ipHeader}>
          <Text style={styles.ipAddress}>{item.ip_address}</Text>
          <TouchableOpacity 
            style={styles.unblockButton}
            onPress={() => unblockIP(item.ip_address)}
          >
            <Text style={styles.unblockButtonText}>Unblock</Text>
          </TouchableOpacity>
        </View>
        <Text style={styles.ipReason}>{item.reason}</Text>
        <View style={styles.ipFooter}>
          <Text style={styles.ipTime}>Blocked: {new Date(item.blocked_at).toLocaleDateString()}</Text>
          <Text style={styles.ipExpires}>Expires: {item.expires_at ? new Date(item.expires_at).toLocaleDateString() : 'Never'}</Text>
        </View>
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>🔒 IP Control</Text>
      </View>

      <View style={styles.blockForm}>
        <Text style={styles.formLabel}>Block New IP</Text>
        <TextInput
          style={styles.input}
          placeholder="IP Address"
          placeholderTextColor="#666"
          value={blockIPInput}
          onChangeText={setBlockIPInput}
        />
        <TextInput
          style={styles.input}
          placeholder="Reason (optional)"
          placeholderTextColor="#666"
          value={blockReason}
          onChangeText={setBlockReason}
        />
        <TouchableOpacity style={styles.blockButton} onPress={blockIP}>
          <Text style={styles.blockButtonText}>Block IP</Text>
        </TouchableOpacity>
      </View>

      <Text style={styles.sectionTitle}>Currently Blocked</Text>

      <FlatList
        data={blockedIPs}
        renderItem={renderBlockedIP}
        keyExtractor={(item, index) => index.toString()}
        contentContainerStyle={styles.list}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyText}>No blocked IPs</Text>
          </View>
        }
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  header: {
    padding: 16,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#fff',
  },
  blockForm: {
    backgroundColor: '#1a1a1a',
    margin: 16,
    marginTop: 0,
    borderRadius: 12,
    padding: 16,
  },
  formLabel: {
    color: '#888',
    fontSize: 14,
    marginBottom: 12,
  },
  input: {
    backgroundColor: '#111',
    borderColor: '#333',
    borderWidth: 1,
    borderRadius: 8,
    padding: 12,
    color: '#fff',
    fontSize: 14,
    marginBottom: 12,
  },
  blockButton: {
    backgroundColor: '#ff4444',
    borderRadius: 8,
    padding: 14,
    alignItems: 'center',
  },
  blockButtonText: {
    color: '#fff',
    fontSize: 14,
    fontWeight: '600',
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#888',
    paddingHorizontal: 16,
    marginBottom: 12,
  },
  list: {
    padding: 16,
    paddingTop: 0,
  },
  ipCard: {
    backgroundColor: '#1a1a1a',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  ipHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  ipAddress: {
    color: '#fff',
    fontSize: 14,
    fontFamily: 'monospace',
    fontWeight: '600',
  },
  unblockButton: {
    backgroundColor: 'transparent',
    borderColor: '#dc143c',
    borderWidth: 1,
    paddingHorizontal: 14,
    paddingVertical: 6,
    borderRadius: 6,
  },
  unblockButtonText: {
    color: '#dc143c',
    fontSize: 12,
    fontWeight: '600',
  },
  ipReason: {
    color: '#888',
    fontSize: 13,
    marginBottom: 12,
  },
  ipFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  ipTime: {
    color: '#555',
    fontSize: 11,
  },
  ipExpires: {
    color: '#555',
    fontSize: 11,
  },
  empty: {
    alignItems: 'center',
    paddingVertical: 40,
  },
  emptyText: {
    color: '#555',
    fontSize: 14,
  },
});
