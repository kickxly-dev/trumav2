import React, { useState, useEffect } from 'react';
import { View, Text, ScrollView, StyleSheet, RefreshControl, TouchableOpacity, Modal, TextInput, Alert } from 'react-native';
import { useApp } from '../context/AppContext';

export default function PoolsScreen() {
  const { apiCall } = useApp();
  const [pools, setPools] = useState([]);
  const [refreshing, setRefreshing] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [poolName, setPoolName] = useState('');
  const [poolCount, setPoolCount] = useState('10');
  const [poolDays, setPoolDays] = useState('365');
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    loadPools();
  }, []);

  const loadPools = async () => {
    const result = await apiCall('/api/admin/pools');
    if (result.pools) {
      setPools(result.pools);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadPools();
    setRefreshing(false);
  };

  const createPool = async () => {
    if (!poolName.trim()) {
      Alert.alert('Error', 'Please enter a pool name');
      return;
    }

    setCreating(true);
    const result = await apiCall('/api/admin/pool/create', 'POST', {
      name: poolName,
      count: parseInt(poolCount),
      expiryDays: parseInt(poolDays)
    });

    if (result.success) {
      Alert.alert('Success', `Pool created with ${poolCount} keys\nID: ${result.pool.id}`);
      setShowCreate(false);
      setPoolName('');
      loadPools();
    } else {
      Alert.alert('Error', result.error || 'Failed to create pool');
    }
    setCreating(false);
  };

  const deletePool = async (id) => {
    Alert.alert(
      'Delete Pool',
      'Are you sure? Unclaimed keys will be lost.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            const result = await apiCall(`/api/admin/pool/${id}`, 'DELETE');
            if (result.success) {
              Alert.alert('Success', 'Pool deleted');
              loadPools();
            } else {
              Alert.alert('Error', result.error || 'Failed to delete');
            }
          }
        }
      ]
    );
  };

  const copyPoolId = (id) => {
    // In a real app, use Clipboard API
    Alert.alert('Pool ID', id);
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>License Pools</Text>
        <TouchableOpacity style={styles.addButton} onPress={() => setShowCreate(true)}>
          <Text style={styles.addButtonText}>+ Create</Text>
        </TouchableOpacity>
      </View>

      <ScrollView 
        style={styles.list}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#dc143c" />}
      >
        {pools.map((pool, i) => (
          <View key={i} style={styles.poolCard}>
            <View style={styles.poolHeader}>
              <View>
                <Text style={styles.poolName}>{pool.name}</Text>
                <Text style={styles.poolId}>ID: {pool.id}</Text>
              </View>
              <View style={styles.poolStats}>
                <Text style={styles.poolClaimed}>{pool.claimed}/{pool.total}</Text>
                <Text style={styles.poolRemaining}>{pool.remaining} left</Text>
              </View>
            </View>

            <View style={styles.progressBar}>
              <View 
                style={[
                  styles.progressFill, 
                  { width: `${(pool.claimed / pool.total) * 100}%` }
                ]} 
              />
            </View>

            <View style={styles.poolActions}>
              <TouchableOpacity 
                style={styles.actionButton} 
                onPress={() => copyPoolId(pool.id)}
              >
                <Text style={styles.actionButtonText}>Copy ID</Text>
              </TouchableOpacity>
              <TouchableOpacity 
                style={[styles.actionButton, styles.deleteButton]} 
                onPress={() => deletePool(pool.id)}
              >
                <Text style={styles.deleteButtonText}>Delete</Text>
              </TouchableOpacity>
            </View>
          </View>
        ))}
        {pools.length === 0 && (
          <Text style={styles.empty}>No pools created yet</Text>
        )}
      </ScrollView>

      <Modal visible={showCreate} transparent animationType="slide">
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>Create Pool</Text>
            
            <Text style={styles.label}>Pool Name</Text>
            <TextInput
              style={styles.input}
              value={poolName}
              onChangeText={setPoolName}
              placeholder="e.g., Giveaway 2024"
              placeholderTextColor="#666"
            />

            <Text style={styles.label}>Number of Keys (1-100)</Text>
            <TextInput
              style={styles.input}
              value={poolCount}
              onChangeText={setPoolCount}
              placeholder="10"
              placeholderTextColor="#666"
              keyboardType="numeric"
            />

            <Text style={styles.label}>Duration (days)</Text>
            <TextInput
              style={styles.input}
              value={poolDays}
              onChangeText={setPoolDays}
              placeholder="365"
              placeholderTextColor="#666"
              keyboardType="numeric"
            />

            <View style={styles.modalButtons}>
              <TouchableOpacity 
                style={[styles.modalButton, styles.cancelButton]} 
                onPress={() => setShowCreate(false)}
              >
                <Text style={styles.cancelButtonText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity 
                style={[styles.modalButton, styles.createButton]} 
                onPress={createPool}
                disabled={creating}
              >
                <Text style={styles.createButtonText}>
                  {creating ? 'Creating...' : 'Create'}
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
  poolCard: {
    backgroundColor: '#111',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  poolHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  poolName: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  poolId: {
    color: '#666',
    fontSize: 11,
    marginTop: 4,
  },
  poolStats: {
    alignItems: 'flex-end',
  },
  poolClaimed: {
    color: '#fff',
    fontSize: 18,
    fontWeight: 'bold',
  },
  poolRemaining: {
    color: '#00ff88',
    fontSize: 12,
  },
  progressBar: {
    height: 6,
    backgroundColor: '#222',
    borderRadius: 3,
    marginBottom: 12,
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#00ff88',
    borderRadius: 3,
  },
  poolActions: {
    flexDirection: 'row',
    gap: 8,
  },
  actionButton: {
    flex: 1,
    backgroundColor: '#222',
    padding: 10,
    borderRadius: 6,
    alignItems: 'center',
  },
  actionButtonText: {
    color: '#888',
    fontWeight: 'bold',
  },
  deleteButton: {
    backgroundColor: '#331111',
  },
  deleteButtonText: {
    color: '#ff4444',
    fontWeight: 'bold',
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
  createButton: {
    backgroundColor: '#dc143c',
  },
  createButtonText: {
    color: '#fff',
    fontWeight: 'bold',
  },
});
