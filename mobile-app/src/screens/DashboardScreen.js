import React, { useState, useEffect } from 'react';
import { View, Text, ScrollView, StyleSheet, RefreshControl, TouchableOpacity } from 'react-native';
import { useApp } from '../context/AppContext';

export default function DashboardScreen() {
  const { apiCall } = useApp();
  const [stats, setStats] = useState({
    totalLicenses: 0,
    activeLicenses: 0,
    totalPools: 0,
    totalValidations: 0
  });
  const [recentActivity, setRecentActivity] = useState([]);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    const licenses = await apiCall('/api/admin/licenses');
    const pools = await apiCall('/api/admin/pools');
    const audit = await apiCall('/api/admin/audit?limit=10');

    if (licenses.licenses) {
      const active = licenses.licenses.filter(l => !l.revoked).length;
      setStats(prev => ({
        ...prev,
        totalLicenses: licenses.licenses.length,
        activeLicenses: active
      }));
    }

    if (pools.pools) {
      setStats(prev => ({ ...prev, totalPools: pools.pools.length }));
    }

    if (audit.logs) {
      setStats(prev => ({ ...prev, totalValidations: audit.total || 0 }));
      setRecentActivity(audit.logs.slice(-5).reverse());
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };

  return (
    <ScrollView 
      style={styles.container}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#dc143c" />}
    >
      <Text style={styles.header}>Dashboard</Text>

      <View style={styles.statsGrid}>
        <View style={styles.statCard}>
          <Text style={styles.statValue}>{stats.totalLicenses}</Text>
          <Text style={styles.statLabel}>Total Licenses</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={styles.statValue}>{stats.activeLicenses}</Text>
          <Text style={styles.statLabel}>Active</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={styles.statValue}>{stats.totalPools}</Text>
          <Text style={styles.statLabel}>Pools</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={styles.statValue}>{stats.totalValidations}</Text>
          <Text style={styles.statLabel}>Validations</Text>
        </View>
      </View>

      <Text style={styles.sectionTitle}>Recent Activity</Text>
      {recentActivity.map((log, i) => (
        <View key={i} style={styles.activityItem}>
          <Text style={styles.activityAction}>{log.action}</Text>
          <Text style={styles.activityActor}>by {log.details.actor}</Text>
          <Text style={styles.activityTime}>
            {new Date(log.timestamp).toLocaleDateString()}
          </Text>
        </View>
      ))}
      {recentActivity.length === 0 && (
        <Text style={styles.empty}>No recent activity</Text>
      )}
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
    marginBottom: 20,
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: 24,
  },
  statCard: {
    width: '48%',
    backgroundColor: '#111',
    borderRadius: 12,
    padding: 20,
    marginBottom: 12,
    alignItems: 'center',
  },
  statValue: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#dc143c',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 12,
  },
  activityItem: {
    backgroundColor: '#111',
    borderRadius: 8,
    padding: 16,
    marginBottom: 8,
  },
  activityAction: {
    color: '#dc143c',
    fontWeight: 'bold',
    fontSize: 14,
  },
  activityActor: {
    color: '#888',
    fontSize: 12,
    marginTop: 4,
  },
  activityTime: {
    color: '#444',
    fontSize: 11,
    marginTop: 4,
  },
  empty: {
    color: '#444',
    textAlign: 'center',
    marginTop: 20,
  },
});
