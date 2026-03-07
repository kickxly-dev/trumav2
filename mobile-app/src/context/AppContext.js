import React, { createContext, useContext, useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';

const AppContext = createContext();

export function AppProvider({ children }) {
  const [apiKey, setApiKey] = useState(null);
  const [serverUrl, setServerUrl] = useState('http://localhost:3001');
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    loadStoredData();
  }, []);

  const loadStoredData = async () => {
    try {
      const storedKey = await AsyncStorage.getItem('api_key');
      const storedUrl = await AsyncStorage.getItem('server_url');
      
      if (storedKey) {
        setApiKey(storedKey);
        setIsAuthenticated(true);
      }
      if (storedUrl) {
        setServerUrl(storedUrl);
      }
    } catch (e) {
      console.error('Failed to load stored data', e);
    }
    setLoading(false);
  };

  const login = async (key, url) => {
    await AsyncStorage.setItem('api_key', key);
    await AsyncStorage.setItem('server_url', url);
    setApiKey(key);
    setServerUrl(url);
    setIsAuthenticated(true);
  };

  const logout = async () => {
    await AsyncStorage.removeItem('api_key');
    setApiKey(null);
    setIsAuthenticated(false);
  };

  const apiCall = async (endpoint, method = 'GET', body = null) => {
    try {
      const res = await fetch(`${serverUrl}${endpoint}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey
        },
        body: body ? JSON.stringify(body) : null
      });
      return await res.json();
    } catch (e) {
      return { error: e.message };
    }
  };

  return (
    <AppContext.Provider value={{
      apiKey,
      serverUrl,
      loading,
      isAuthenticated,
      login,
      logout,
      apiCall
    }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  return useContext(AppContext);
}
