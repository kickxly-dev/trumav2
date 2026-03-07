import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { StatusBar } from 'expo-status-bar';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Screens
import DashboardScreen from './src/screens/DashboardScreen';
import LicensesScreen from './src/screens/LicensesScreen';
import PoolsScreen from './src/screens/PoolsScreen';
import SettingsScreen from './src/screens/SettingsScreen';
import LoginScreen from './src/screens/LoginScreen';

// Context
import { AppProvider } from './src/context/AppContext';

const Tab = createBottomTabNavigator();
const Stack = createNativeStackNavigator();

function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={{
        tabBarStyle: { backgroundColor: '#111', borderTopColor: '#222' },
        tabBarActiveTintColor: '#dc143c',
        tabBarInactiveTintColor: '#666',
        headerStyle: { backgroundColor: '#111' },
        headerTintColor: '#fff',
      }}
    >
      <Tab.Screen 
        name="Dashboard" 
        component={DashboardScreen}
        options={{ tabBarIcon: ({ color }) => <TabIcon icon="📊" color={color} /> }}
      />
      <Tab.Screen 
        name="Licenses" 
        component={LicensesScreen}
        options={{ tabBarIcon: ({ color }) => <TabIcon icon="🔑" color={color} /> }}
      />
      <Tab.Screen 
        name="Pools" 
        component={PoolsScreen}
        options={{ tabBarIcon: ({ color }) => <TabIcon icon="📦" color={color} /> }}
      />
      <Tab.Screen 
        name="Settings" 
        component={SettingsScreen}
        options={{ tabBarIcon: ({ color }) => <TabIcon icon="⚙️" color={color} /> }}
      />
    </Tab.Navigator>
  );
}

function TabIcon({ icon, color }) {
  return <span style={{ fontSize: 20, color }}>{icon}</span>;
}

export default function App() {
  return (
    <AppProvider>
      <NavigationContainer>
        <StatusBar style="light" />
        <Stack.Navigator screenOptions={{ headerShown: false }}>
          <Stack.Screen name="Login" component={LoginScreen} />
          <Stack.Screen name="Main" component={MainTabs} />
        </Stack.Navigator>
      </NavigationContainer>
    </AppProvider>
  );
}
