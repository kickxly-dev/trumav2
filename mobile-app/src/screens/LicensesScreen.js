import React, { useState, useEffect } from 'react';
import { View, Text, ScrollView, StyleSheet, RefreshControl, TouchableOpacity, Modal, TextInput, Alert } from 'react-native';
import { useApp } from '../context/AppContext';

export default function LicensesScreen() {
  const { apiCall } = useApp();
  const [licenses, setLicenses] = useState([]);
  const [refreshing, setRefreshing] = useState(false);
  const [showGenerate, setShowGenerate] = useState(false);
  const [genUser, setGenUser] = useState('');
  const [genDays, setGenDays] = useState('365');
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    loadLicenses();
  }, []);

  const loadLicenses = async () => {
    const result = await apiCall('/api/admin/licenses');
    if (result.licenses) {
      setLicenses(result.licenses);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadLicenses();
    setRefreshing(false);
  };

  const generateLicense = async () => {
    if (!genUser.trim()) {
      Alert.alert('Error', 'Please enter a user');
      return;
    }

    setGenerating(true);
    const result = await apiCall('/api/admin/license/generate', 'POST', {
      user: genUser,
      expiryDays: parseInt(genDays)
    });

    if (result.success) {
      Alert.alert('Success', `License generated:\n${result.license.key}`);
      setShowGenerate(false);
      setGenUser('');
      loadLicenses();
    } else {
      Alert.alert('Error', result.error || 'Failed to generate');
    }
    setGenerating(false);
  };

  const revokeLicense = async (key) => {
    Alert.alert(
      'Revoke License',
      'Are you sure you want to revoke this license?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Revoke',
          style: 'destructive',
          onPress: async () => {
            const result = await apiCall('/api/admin/license/revoke', 'POST', { key });
            if (result.success) {
              Alert.alert('Success', 'License revoked');
              loadLicenses();
            } else {
              Alert.alert('Error', result.error || 'Failed to revoke');
            }
          }
        }
      ]
    );
  };

  const getStatus = (license) => {
    if (license.revoked) return { text: 'REVOKED', color: '#ff4444' };
    if (new Date(license.expiry) < new Date()) return { text: 'EXPIRED', color: '#ffaa00' };
    return { text: 'ACTIVE', color: '#00ff88' };
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Licenses</Text>
        <TouchableOpacity style={styles.addButton} onPress={() => setShowGenerate(true)}>
          <Text style={styles.addButtonText}>+ Generate</Text>
        </TouchableOpacity>
      </View>

      <ScrollView 
        style={styles.list}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#dc143c" />}
      >
        {licenses.map((license, i) => {
          const status = getStatus(license);
          return (
            <View key={i} style={styles.licenseCard}>
              <View style={styles.licenseHeader}>
                <Text style={styles.licenseUser}>{license.user}</Text>
                <Text style={[styles.statusBadge, { backgroundColor: status.color + '22', color: status.color }]}>
                  {status.text}
                </Text>
              </View>
              <Text style={styles.licenseKey}>{license.key.substring(0, 25)}...</Text>
              <View style={styles.licenseFooter}>
                <Text style={styles.licenseExpiry}>
                  Expires: {new Date(license.expiry).toLocaleDateString()}
                </Text>
                {!license.revoked && (
                  <TouchableOpacity onPress={() => revokeLicense(license.key)}>
                    <Text style={styles.revokeButton}>Revoke</Text>
                  </TouchableOpacity>
                )}
              </View>
            </View>
          );
        })}
        {licenses.length === 0 && (
          <Text style={styles.empty}>No licenses found</Text>
        )}
      </ScrollView>

      <Modal visible={showGenerate} transparent animationType="slide">
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>Generate License</Text>
            
            <Text style={styles.label}>User (Discord ID or name)</Text>
            <TextInput
              style={styles.input}
              value={genUser}
              onChangeText={setGenUser}
              placeholder="Enter user"
              placeholderTextColor="#666"
            />

            <Text style={styles.label}>Duration (days)</Text>
            <TextInput
              style={styles.input}
              value={genDays}
              onChangeText={setGenDays}
              placeholder="365"
              placeholderTextColor="#666"
              keyboardType="numeric"
            />

            <View style={styles.modalButtons}>
              <TouchableOpacity 
                style={[styles.modalButton, styles.cancelButton]} 
                onPress={() => setShowGenerate(false)}
              >
                <Text style={styles.cancelButtonText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity 
                style={[styles.modalButton, styles.generateButton]} 
                onPress={generateLicense}
                disabled={generating}
              >
                <Text style={styles.generateButtonText}>
                  {generating ? 'Generating...' : 'Generate'}
                </Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#222',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#fff',
  },
  addButton: {
    backgroundColor: '#dc143c',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 8,
  },
  addButtonText: {
    color: '#fff',
    fontWeight: 'bold',
  },
  list: {
    flex: 1,
    padding: 16,
  },
  licenseCard: {
    backgroundColor: '#111',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  licenseHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  licenseUser: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
    flex: 1,
  },
  statusBadge: {
    fontSize: 11,
    fontWeight: 'bold',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
  },
  licenseKey: {
    color: '#888',
    fontSize: 12,
    fontFamily: 'monospace',
    marginBottom: 8,
  },
  licenseFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  licenseExpiry: {
    color: '#666',
    fontSize: 12,
  },
  revokeButton: {
    color: '#ff4444',
    fontSize: 14,
  },
  empty: {
    color: '#444',
    textAlign: 'center',
    marginTop: 40,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.8)',
    justifyContent: 'center',
    padding: 20,
  },
  modalContent: {
    backgroundColor: '#111',
    borderRadius: 16,
    padding: 24,
  },
  modalTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 20,
  },
  label: {
    color: '#888',
    fontSize: 14,
    marginTop: 12,
    marginBottom: 8,
  },
  input: {
    backgroundColor: '#0a0a0a',
    borderWidth: 1,
    borderColor: '#222',
    borderRadius: 8,
    padding: 14,
    color: '#fff',
    fontSize: 16,
  },
  modalButtons: {
    flexDirection: 'row',
    marginTop: 24,
    gap: 12,
  },
  modalButton: {
    flex: 1,
    padding: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  cancelButton: {
    backgroundColor: '#222',
  },
  cancelButtonText: {
    color: '#888',
    fontWeight: 'bold',
  },
  generateButton: {
    backgroundColor: '#dc143c',
  },
  generateButtonText: {
    color: '#fff',
    fontWeight: 'bold',
  },
});
