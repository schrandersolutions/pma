// File: frontend/src/context/AuthContext.jsx
import React, { createContext } from 'react'

export const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  return (
    <AuthContext.Provider value={{ isAuthenticated: false }}>
      {children}
    </AuthContext.Provider>
  )
}
