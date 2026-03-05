import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, ScrollView, RefreshControl } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

const API_URL = 'http://localhost:10000';

export default function DashboardScreen() {
  const [stats, setStats] = useState({
    visitors1h: 0,
    threats1h: 0,
    totalBlocked: 0,
    uniqueIPs1h: 0
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 30000);
    return () => clearInterval(interval);
  }, []);

  async function loadStats() {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      const res = await axios.get(`${API_URL}/api/security/realtime-stats`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStats(res.data.stats);
    } catch (error) {
      console.error('Failed to load stats');
    }
    setLoading(false);
    setRefreshing(false);
  }

  function onRefresh() {
    setRefreshing(true);
    loadStats();
  }

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView 
        style={styles.scrollView}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#dc143c" />}
      >
        <View style={styles.header}>
          <Text style={styles.headerTitle}>📊 Real-Time Overview</Text>
          <View style={styles.liveIndicator}>
            <View style={styles.liveDot} />
            <Text style={styles.liveText}>LIVE</Text>
          </View>
        </View>

        <View style={styles.statsGrid}>
          <View style={[styles.statCard, { borderLeftColor: '#dc143c' }]}>
            <Text style={styles.statValue}>{stats.visitors1h}</Text>
            <Text style={styles.statLabel}>Visitors (1h)</Text>
          </View>

          <View style={[styles.statCard, { borderLeftColor: '#ff4444' }]}>
            <Text style={[styles.statValue, { color: '#ff4444' }]}>{stats.threats1h}</Text>
            <Text style={styles.statLabel}>Threats (1h)</Text>
          </View>

          <View style={[styles.statCard, { borderLeftColor: '#ffaa00' }]}>
            <Text style={[styles.statValue, { color: '#ffaa00' }]}>{stats.totalBlocked}</Text>
            <Text style={styles.statLabel}>Blocked IPs</Text>
          </View>

          <View style={[styles.statCard, { borderLeftColor: '#00ff88' }]}>
            <Text style={[styles.statValue, { color: '#00ff88' }]}>{stats.uniqueIPs1h}</Text>
            <Text style={styles.statLabel}>Unique IPs</Text>
          </View>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>System Status</Text>
          <View style={styles.statusRow}>
            <Text style={styles.statusLabel}>TRUMA NET</Text>
            <View style={styles.statusBadge}>
              <Text style={styles.statusBadgeText}>ACTIVE</Text>
            </View>
          </View>
          <View style={styles.statusRow}>
            <Text style={styles.statusLabel}>Auto-Block</Text>
            <View style={styles.statusBadge}>
              <Text style={styles.statusBadgeText}>ENABLED</Text>
            </View>
          </View>
          <View style={styles.statusRow}>
            <Text style={styles.statusLabel}>Bot Detection</Text>
            <View style={styles.statusBadge}>
              <Text style={styles.statusBadgeText}>ACTIVE</Text>
            </View>
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
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
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#fff',
  },
  liveIndicator: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  liveDot: {
    width: 8,
    height: 8,
    backgroundColor: '#00ff88',
    borderRadius: 4,
    marginRight: 6,
  },
  liveText: {
    color: '#00ff88',
    fontSize: 12,
    fontWeight: '600',
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: 24,
  },
  statCard: {
    width: '48%',
    backgroundColor: '#1a1a1a',
    borderLeftWidth: 4,
    borderRadius: 8,
    padding: 16,
    marginBottom: 12,
  },
  statValue: {
    fontSize: 28,
    fontWeight: '800',
    color: '#dc143c',
    fontFamily: 'monospace',
  },
  statLabel: {
    fontSize: 12,
    color: '#888',
    marginTop: 4,
  },
  section: {
    backgroundColor: '#1a1a1a',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#fff',
    marginBottom: 16,
  },
  statusRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#333',
  },
  statusLabel: {
    color: '#888',
    fontSize: 14,
  },
  statusBadge: {
    backgroundColor: 'rgba(0, 255, 136, 0.1)',
    paddingHorizontal: 12,
    paddingVertical: 4,
    borderRadius: 12,
  },
  statusBadgeText: {
    color: '#00ff88',
    fontSize: 12,
    fontWeight: '600',
  },
});
