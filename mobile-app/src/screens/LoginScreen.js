import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator } from 'react-native';
import { useApp } from '../context/AppContext';

export default function LoginScreen({ navigation }) {
  const { login, isAuthenticated, loading } = useApp();
  const [apiKey, setApiKey] = useState('');
  const [serverUrl, setServerUrl] = useState('http://localhost:3001');
  const [error, setError] = useState('');
  const [loggingIn, setLoggingIn] = useState(false);

  useEffect(() => {
    if (isAuthenticated) {
      navigation.replace('Main');
    }
  }, [isAuthenticated]);

  const handleLogin = async () => {
    if (!apiKey.trim()) {
      setError('Please enter your API key');
      return;
    }

    setLoggingIn(true);
    setError('');
    
    try {
      await login(apiKey, serverUrl);
      navigation.replace('Main');
    } catch (e) {
      setError('Failed to connect to server');
    }
    setLoggingIn(false);
  };

  if (loading) {
    return (
      <View style={styles.container}>
        <ActivityIndicator size="large" color="#dc143c" />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.logo}>🛡️ TRAUMA</Text>
      <Text style={styles.subtitle}>License Manager</Text>

      <View style={styles.form}>
        <Text style={styles.label}>Server URL</Text>
        <TextInput
          style={styles.input}
          value={serverUrl}
          onChangeText={setServerUrl}
          placeholder="http://localhost:3001"
          placeholderTextColor="#666"
          autoCapitalize="none"
        />

        <Text style={styles.label}>API Key</Text>
        <TextInput
          style={styles.input}
          value={apiKey}
          onChangeText={setApiKey}
          placeholder="Enter your API key"
          placeholderTextColor="#666"
          secureTextEntry
          autoCapitalize="none"
        />

        {error ? <Text style={styles.error}>{error}</Text> : null}

        <TouchableOpacity 
          style={styles.button} 
          onPress={handleLogin}
          disabled={loggingIn}
        >
          {loggingIn ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>Connect</Text>
          )}
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
  },
  logo: {
    fontSize: 40,
    fontWeight: 'bold',
    color: '#dc143c',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 18,
    color: '#666',
    marginBottom: 40,
  },
  form: {
    width: '100%',
    maxWidth: 400,
  },
  label: {
    color: '#888',
    fontSize: 14,
    marginBottom: 8,
    marginTop: 16,
  },
  input: {
    backgroundColor: '#111',
    borderWidth: 1,
    borderColor: '#222',
    borderRadius: 8,
    padding: 16,
    color: '#fff',
    fontSize: 16,
  },
  button: {
    backgroundColor: '#dc143c',
    borderRadius: 8,
    padding: 16,
    alignItems: 'center',
    marginTop: 24,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  error: {
    color: '#ff4444',
    marginTop: 12,
    textAlign: 'center',
  },
});
