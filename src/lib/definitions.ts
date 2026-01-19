export type UserRole = 'customer' | 'staff' | 'admin';

export type User = {
  id: string;
  email: string;
  name: string;
  // In a real app, this would be a securely hashed password.
  // For this demo, we'll store it as plain text to compare against.
  password: string; 
  role: UserRole;
  // A mock for failed login attempts to feed the risk engine
  failedLoginAttempts: number;
};

export type SessionPayload = {
  user: {
    id: string;
    role: UserRole;
    name: string;
  };
  isMfaPending: boolean;
  // We'll use a simple UNIX timestamp for expiration
  expires: number; 
};
