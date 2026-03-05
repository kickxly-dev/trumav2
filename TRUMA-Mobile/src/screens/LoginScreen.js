import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

export default function LoginScreen({ onLogin }) {
  const [ownerCode, setOwnerCode] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleLogin() {
    if (!ownerCode.trim()) {
      Alert.alert('Error', 'Enter owner code');
      return;
    }

    setLoading(true);
    const result = await onLogin(ownerCode);
    setLoading(false);

    if (!result.success) {
      Alert.alert('Authentication Failed', result.error);
    }
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <View style={styles.logoContainer}>
          <Text style={styles.logo}>🛡️</Text>
          <Text style={styles.title}>TRUMA NET</Text>
          <Text style={styles.subtitle}>V2 Mobile Control</Text>
          <View style={styles.badge}>
            <Text style={styles.badgeText}>OWNER ACCESS ONLY</Text>
          </View>
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
            autoCapitalize="none"
          />

          <TouchableOpacity 
            style={styles.button} 
            onPress={handleLogin}
            disabled={loading}
          >
            <Text style={styles.buttonText}>
              {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE'}
            </Text>
          </TouchableOpacity>
        </View>

        <Text style={styles.footer}>Protected by TRUMA NET V2</Text>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  content: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  logoContainer: {
    alignItems: 'center',
    marginBottom: 40,
  },
  logo: {
    fontSize: 64,
    marginBottom: 10,
  },
  title: {
    fontSize: 32,
    fontWeight: '800',
    color: '#dc143c',
    fontFamily: 'monospace',
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
  },
  badgeText: {
    color: '#00ff88',
    fontSize: 12,
    fontWeight: '600',
    fontFamily: 'monospace',
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
    fontFamily: 'monospace',
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
    fontFamily: 'monospace',
  },
  footer: {
    color: '#555',
    fontSize: 12,
    marginTop: 40,
  },
});
