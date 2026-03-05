import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, FlatList, TouchableOpacity, RefreshControl } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

const API_URL = 'http://localhost:10000';

export default function ThreatsScreen() {
  const [threats, setThreats] = useState([]);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadThreats();
  }, []);

  async function loadThreats() {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      const res = await axios.get(`${API_URL}/api/security/threats`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setThreats(res.data.threats || []);
    } catch (error) {
      console.error('Failed to load threats');
    }
    setRefreshing(false);
  }

  async function blockIP(ip, threatType) {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      await axios.post(`${API_URL}/api/security/block-ip`, 
        { ip, reason: `Threat: ${threatType}`, durationHours: 24 },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      loadThreats();
    } catch (error) {
      console.error('Failed to block IP');
    }
  }

  function renderThreat({ item }) {
    return (
      <View style={styles.threatCard}>
        <View style={styles.threatHeader}>
          <Text style={styles.threatIP}>{item.ip_address}</Text>
          <View style={styles.threatBadge}>
            <Text style={styles.threatBadgeText}>{item.threat_type}</Text>
          </View>
        </View>
        <Text style={styles.threatPath}>{item.path}</Text>
        <View style={styles.threatFooter}>
          <Text style={styles.threatTime}>
            {new Date(item.timestamp).toLocaleString()}
          </Text>
          <TouchableOpacity 
            style={styles.blockButton}
            onPress={() => blockIP(item.ip_address, item.threat_type)}
          >
            <Text style={styles.blockButtonText}>Block</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>⚠️ Recent Threats</Text>
        <TouchableOpacity onPress={loadThreats}>
          <Text style={styles.refreshText}>Refresh</Text>
        </TouchableOpacity>
      </View>

      <FlatList
        data={threats.slice(0, 50)}
        renderItem={renderThreat}
        keyExtractor={(item, index) => index.toString()}
        contentContainerStyle={styles.list}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); loadThreats(); }} tintColor="#dc143c" />
        }
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyText}>No threats detected</Text>
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
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#fff',
  },
  refreshText: {
    color: '#dc143c',
    fontSize: 14,
  },
  list: {
    padding: 16,
    paddingTop: 0,
  },
  threatCard: {
    backgroundColor: '#1a1a1a',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  threatHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  threatIP: {
    color: '#fff',
    fontSize: 14,
    fontFamily: 'monospace',
    fontWeight: '600',
  },
  threatBadge: {
    backgroundColor: 'rgba(255, 68, 68, 0.2)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 12,
  },
  threatBadgeText: {
    color: '#ff4444',
    fontSize: 11,
    fontWeight: '600',
  },
  threatPath: {
    color: '#888',
    fontSize: 13,
    marginBottom: 12,
  },
  threatFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  threatTime: {
    color: '#555',
    fontSize: 12,
  },
  blockButton: {
    backgroundColor: '#ff4444',
    paddingHorizontal: 16,
    paddingVertical: 6,
    borderRadius: 6,
  },
  blockButtonText: {
    color: '#fff',
    fontSize: 12,
    fontWeight: '600',
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
