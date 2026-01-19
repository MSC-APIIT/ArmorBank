import type { User } from './definitions';

// In a real application, you would fetch this data from a database.
// Passwords would be hashed and not stored in plaintext.
export const users: User[] = [
  {
    id: '1',
    email: 'customer@example.com',
    name: 'John Customer',
    password: 'password123',
    role: 'customer',
    failedLoginAttempts: 0,
  },
  {
    id: '2',
    email: 'staff@example.com',
    name: 'Jane Staff',
    password: 'password123',
    role: 'staff',
    failedLoginAttempts: 2, // Pre-seeded failed attempts for risk engine demo
  },
  {
    id: '3',
    email: 'admin@example.com',
    name: 'Super Admin',
    password: 'password123',
    role: 'admin',
    failedLoginAttempts: 0,
  },
];
