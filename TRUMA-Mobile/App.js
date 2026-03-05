import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert, ScrollView } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import axios from 'axios';

const API_URL = 'http://localhost:10000';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState(null);
  const [ownerCode, setOwnerCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({ visitors1h: 0, threats1h: 0, totalBlocked: 0, uniqueIPs1h: 0 });

  async function handleLogin() {
    if (!ownerCode.trim()) {
      Alert.alert('Error', 'Enter owner code');
      return;
    }

    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/api/auth/owner-login`, { ownerCode });
      if (res.data.token) {
        setToken(res.data.token);
        setIsAuthenticated(true);
        loadStats(res.data.token);
      }
    } catch (error) {
      Alert.alert('Authentication Failed', error.response?.data?.error || 'Connection failed');
    }
    setLoading(false);
  }

  async function loadStats(authToken) {
    try {
      const res = await axios.get(`${API_URL}/api/security/realtime-stats`, {
        headers: { Authorization: `Bearer ${authToken || token}` }
      });
      setStats(res.data.stats);
    } catch (error) {
      console.error('Failed to load stats');
    }
  }

  function handleLogout() {
    setToken(null);
    setIsAuthenticated(false);
    setOwnerCode('');
  }

  if (!isAuthenticated) {
    return (
      <SafeAreaProvider>
        <StatusBar style="light" />
        <SafeAreaView style={styles.container}>
          <View style={styles.loginContent}>
            <Text style={styles.logo}>🛡️</Text>
            <Text style={styles.title}>TRUMA NET</Text>
            <Text style={styles.subtitle}>V2 Mobile Control</Text>
            
            <View style={styles.badge}>
              <Text style={styles.badgeText}>OWNER ACCESS ONLY</Text>
            </View>

            <View style={styles.form}>
              <Text style={styles.label}>Owner Access Code</Text>
              <TextInput
                style={styles.input}
                placeholder="Enter code..."
                placeholderTextColor="#666"
                value={ownerCode}
                onChangeText={setOwnerCode}
                secureTextEntry
              />

              <TouchableOpacity style={styles.button} onPress={handleLogin} disabled={loading}>
                <Text style={styles.buttonText}>
                  {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE'}
                </Text>
              </TouchableOpacity>
            </View>

            <Text style={styles.footer}>Protected by TRUMA NET V2</Text>
          </View>
        </SafeAreaView>
      </SafeAreaProvider>
    );
  }

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <SafeAreaView style={styles.container}>
        <ScrollView style={styles.scrollView}>
          <View style={styles.header}>
            <Text style={styles.headerTitle}>📊 TRUMA NET V2</Text>
            <TouchableOpacity onPress={handleLogout}>
              <Text style={styles.logoutText}>Logout</Text>
            </TouchableOpacity>
          </View>

          <View style={styles.liveIndicator}>
            <View style={styles.liveDot} />
            <Text style={styles.liveText}>LIVE</Text>
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

          <TouchableOpacity style={styles.refreshButton} onPress={() => loadStats()}>
            <Text style={styles.refreshButtonText}>🔄 Refresh Stats</Text>
          </TouchableOpacity>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>System Status</Text>
            <View style={styles.statusRow}>
              <Text style={styles.statusLabel}>TRUMA NET</Text>
              <Text style={styles.statusActive}>ACTIVE</Text>
            </View>
            <View style={styles.statusRow}>
              <Text style={styles.statusLabel}>Auto-Block</Text>
              <Text style={styles.statusActive}>ENABLED</Text>
            </View>
            <View style={styles.statusRow}>
              <Text style={styles.statusLabel}>Bot Detection</Text>
              <Text style={styles.statusActive}>ACTIVE</Text>
            </View>
          </View>
        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  loginContent: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  logo: {
    fontSize: 64,
    marginBottom: 10,
  },
  title: {
    fontSize: 32,
    fontWeight: '800',
    color: '#dc143c',
  },
  subtitle: {
    fontSize: 16,
    color: '#888',
    marginTop: 5,
  },
  badge: {
    backgroundColor: 'rgba(0, 255, 136, 0.1)',
    borderColor: '#00ff88',
    borderWidth: 1,
    paddingHorizontal: 16,
    paddingVertical: 6,
    borderRadius: 20,
    marginTop: 16,
    marginBottom: 40,
  },
  badgeText: {
    color: '#00ff88',
    fontSize: 12,
    fontWeight: '600',
  },
  form: {
    width: '100%',
    maxWidth: 300,
  },
  label: {
    color: '#888',
    fontSize: 14,
    marginBottom: 8,
  },
  input: {
    backgroundColor: '#111',
    borderColor: '#333',
    borderWidth: 1,
    borderRadius: 8,
    padding: 16,
    color: '#fff',
    fontSize: 16,
    marginBottom: 16,
  },
  button: {
    backgroundColor: '#dc143c',
    borderRadius: 8,
    padding: 16,
    alignItems: 'center',
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '700',
  },
  footer: {
    color: '#555',
    fontSize: 12,
    marginTop: 40,
  },
  scrollView: {
    flex: 1,
    padding: 16,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#fff',
  },
  logoutText: {
    color: '#dc143c',
    fontSize: 14,
  },
  liveIndicator: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 20,
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
    marginBottom: 20,
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
  },
  statLabel: {
    fontSize: 12,
    color: '#888',
    marginTop: 4,
  },
  refreshButton: {
    backgroundColor: '#1a1a1a',
    borderRadius: 8,
    padding: 14,
    alignItems: 'center',
    marginBottom: 20,
  },
  refreshButtonText: {
    color: '#fff',
    fontSize: 14,
  },
  section: {
    backgroundColor: '#1a1a1a',
    borderRadius: 12,
    padding: 16,
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
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#333',
  },
  statusLabel: {
    color: '#888',
    fontSize: 14,
  },
  statusActive: {
    color: '#00ff88',
    fontSize: 12,
    fontWeight: '600',
  },
});
