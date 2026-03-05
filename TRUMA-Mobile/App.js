import React, { useState, useEffect } from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createStackNavigator } from '@react-navigation/stack';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import * as SecureStore from 'expo-secure-store';
import axios from 'axios';

// Screens
import LoginScreen from './src/screens/LoginScreen';
import DashboardScreen from './src/screens/DashboardScreen';
import SecurityScreen from './src/screens/SecurityScreen';
import ThreatsScreen from './src/screens/ThreatsScreen';
import IPScreen from './src/screens/IPScreen';
import SitesScreen from './src/screens/SitesScreen';

const Tab = createBottomTabNavigator();
const Stack = createStackNavigator();

const API_URL = 'http://localhost:10000';

function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={{
        tabBarStyle: { backgroundColor: '#0a0a0a', borderTopColor: '#333' },
        tabBarActiveTintColor: '#dc143c',
        tabBarInactiveTintColor: '#888',
        headerStyle: { backgroundColor: '#0a0a0a' },
        headerTintColor: '#fff',
      }}
    >
      <Tab.Screen 
        name="Dashboard" 
        component={DashboardScreen}
        options={{ tabBarIcon: ({ color }) => <Text style={{ color, fontSize: 20 }}>📊</Text> }}
      />
      <Tab.Screen 
        name="Security" 
        component={SecurityScreen}
        options={{ tabBarIcon: ({ color }) => <Text style={{ color, fontSize: 20 }}>🛡️</Text> }}
      />
      <Tab.Screen 
        name="Threats" 
        component={ThreatsScreen}
        options={{ tabBarIcon: ({ color }) => <Text style={{ color, fontSize: 20 }}>⚠️</Text> }}
      />
      <Tab.Screen 
        name="IPs" 
        component={IPScreen}
        options={{ tabBarIcon: ({ color }) => <Text style={{ color, fontSize: 20 }}>🔒</Text> }}
      />
      <Tab.Screen 
        name="Sites" 
        component={SitesScreen}
        options={{ tabBarIcon: ({ color }) => <Text style={{ color, fontSize: 20 }}>🌐</Text> }}
      />
    </Tab.Navigator>
  );
}

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  async function checkAuth() {
    try {
      const savedToken = await SecureStore.getItemAsync('ownerToken');
      if (savedToken) {
        // Verify token
        const res = await axios.get(`${API_URL}/api/security/settings`, {
          headers: { Authorization: `Bearer ${savedToken}` }
        });
        if (res.data) {
          setToken(savedToken);
          setIsAuthenticated(true);
        }
      }
    } catch (error) {
      await SecureStore.deleteItemAsync('ownerToken');
    }
    setLoading(false);
  }

  async function login(ownerCode) {
    try {
      const res = await axios.post(`${API_URL}/api/auth/owner-login`, { ownerCode });
      if (res.data.token) {
        await SecureStore.setItemAsync('ownerToken', res.data.token);
        setToken(res.data.token);
        setIsAuthenticated(true);
        return { success: true };
      }
    } catch (error) {
      return { success: false, error: error.response?.data?.error || 'Connection failed' };
    }
  }

  async function logout() {
    await SecureStore.deleteItemAsync('ownerToken');
    setToken(null);
    setIsAuthenticated(false);
  }

  if (loading) {
    return (
      <SafeAreaProvider>
        <StatusBar style="light" />
        <View style={{ flex: 1, backgroundColor: '#0a0a0a', justifyContent: 'center', alignItems: 'center' }}>
          <Text style={{ color: '#dc143c', fontSize: 24, fontFamily: 'monospace' }}>TRUMA NET V2</Text>
          <Text style={{ color: '#888', marginTop: 10 }}>Loading...</Text>
        </View>
      </SafeAreaProvider>
    );
  }

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <NavigationContainer>
        <Stack.Navigator screenOptions={{ headerShown: false }}>
          {isAuthenticated ? (
            <Stack.Screen name="Main">
              {() => <MainTabs />}
            </Stack.Screen>
          ) : (
            <Stack.Screen name="Login">
              {() => <LoginScreen onLogin={login} />}
            </Stack.Screen>
          )}
        </Stack.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
