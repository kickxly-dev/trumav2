import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, FlatList, TextInput, TouchableOpacity, Alert } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

const API_URL = 'http://localhost:10000';

export default function SitesScreen() {
  const [sites, setSites] = useState([]);
  const [siteId, setSiteId] = useState('');
  const [siteName, setSiteName] = useState('');
  const [siteUrl, setSiteUrl] = useState('');

  useEffect(() => {
    loadSites();
  }, []);

  async function loadSites() {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      const res = await axios.get(`${API_URL}/api/truma-net/sites`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSites(res.data.sites || []);
    } catch (error) {
      console.error('Failed to load sites');
    }
  }

  async function addSite() {
    if (!siteId.trim() || !siteName.trim()) {
      Alert.alert('Error', 'Site ID and Name required');
      return;
    }

    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      const res = await axios.post(`${API_URL}/api/truma-net/sites`, 
        { siteId, siteName, siteUrl },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      Alert.alert('Site Added!', `Embed code:\n${res.data.embedCode}`);
      setSiteId('');
      setSiteName('');
      setSiteUrl('');
      loadSites();
    } catch (error) {
      Alert.alert('Error', 'Failed to add site');
    }
  }

  async function removeSite(siteIdToRemove) {
    try {
      const token = await SecureStore.getItemAsync('ownerToken');
      await axios.delete(`${API_URL}/api/truma-net/sites/${siteIdToRemove}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      loadSites();
    } catch (error) {
      Alert.alert('Error', 'Failed to remove site');
    }
  }

  function renderSite({ item }) {
    return (
      <View style={styles.siteCard}>
        <View style={styles.siteHeader}>
          <Text style={styles.siteName}>{item.site_name}</Text>
          <TouchableOpacity 
            style={styles.removeButton}
            onPress={() => Alert.alert(
              'Remove Site',
              `Remove ${item.site_name}?`,
              [
                { text: 'Cancel', style: 'cancel' },
                { text: 'Remove', style: 'destructive', onPress: () => removeSite(item.site_id) }
              ]
            )}
          >
            <Text style={styles.removeButtonText}>Remove</Text>
          </TouchableOpacity>
        </View>
        <Text style={styles.siteUrl}>{item.site_url || 'No URL'}</Text>
        <View style={styles.embedCode}>
          <Text style={styles.embedText}>data-site-id="{item.site_id}"</Text>
        </View>
        <Text style={styles.visitorCount}>
          {item.visitor_count || 0} visitors
        </Text>
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>🌐 Protected Sites</Text>
      </View>

      <View style={styles.addForm}>
        <Text style={styles.formLabel}>Add New Site</Text>
        <TextInput
          style={styles.input}
          placeholder="Site ID (e.g., mysite)"
          placeholderTextColor="#666"
          value={siteId}
          onChangeText={setSiteId}
          autoCapitalize="none"
        />
        <TextInput
          style={styles.input}
          placeholder="Site Name"
          placeholderTextColor="#666"
          value={siteName}
          onChangeText={setSiteName}
        />
        <TextInput
          style={styles.input}
          placeholder="Site URL (optional)"
          placeholderTextColor="#666"
          value={siteUrl}
          onChangeText={setSiteUrl}
          autoCapitalize="none"
        />
        <TouchableOpacity style={styles.addButton} onPress={addSite}>
          <Text style={styles.addButtonText}>Add Site</Text>
        </TouchableOpacity>
      </View>

      <Text style={styles.sectionTitle}>Your Sites</Text>

      <FlatList
        data={sites}
        renderItem={renderSite}
        keyExtractor={(item, index) => index.toString()}
        contentContainerStyle={styles.list}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyText}>No sites registered</Text>
            <Text style={styles.emptySubtext}>Add a site above to start protecting it</Text>
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
  addForm: {
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
  addButton: {
    backgroundColor: '#dc143c',
    borderRadius: 8,
    padding: 14,
    alignItems: 'center',
  },
  addButtonText: {
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
  siteCard: {
    backgroundColor: '#1a1a1a',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  siteHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  siteName: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  removeButton: {
    backgroundColor: 'transparent',
    borderColor: '#ff4444',
    borderWidth: 1,
    paddingHorizontal: 12,
    paddingVertical: 5,
    borderRadius: 6,
  },
  removeButtonText: {
    color: '#ff4444',
    fontSize: 12,
  },
  siteUrl: {
    color: '#888',
    fontSize: 13,
    marginBottom: 10,
  },
  embedCode: {
    backgroundColor: 'rgba(0, 255, 136, 0.1)',
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 6,
    alignSelf: 'flex-start',
    marginBottom: 10,
  },
  embedText: {
    color: '#00ff88',
    fontSize: 11,
    fontFamily: 'monospace',
  },
  visitorCount: {
    color: '#555',
    fontSize: 12,
  },
  empty: {
    alignItems: 'center',
    paddingVertical: 40,
  },
  emptyText: {
    color: '#555',
    fontSize: 14,
  },
  emptySubtext: {
    color: '#444',
    fontSize: 12,
    marginTop: 4,
  },
});
