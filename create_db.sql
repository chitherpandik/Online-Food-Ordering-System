-- Run this in your Supabase SQL Editor to set up the schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  fullname VARCHAR(200) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  verification_token VARCHAR(255) DEFAULT NULL,
  reset_token VARCHAR(255) DEFAULT NULL,
  reset_expires TIMESTAMPTZ DEFAULT NULL,
  last_login TIMESTAMPTZ DEFAULT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  fullname VARCHAR(200) NOT NULL,
  email VARCHAR(255) NOT NULL,
  total NUMERIC(10,2) NOT NULL DEFAULT 0,
  payment_method VARCHAR(50) DEFAULT NULL,
  address TEXT DEFAULT NULL,
  phone VARCHAR(10) DEFAULT NULL CHECK (phone ~ '^\d{10}$' OR phone IS NULL),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Order items table
CREATE TABLE IF NOT EXISTS order_items (
  id BIGSERIAL PRIMARY KEY,
  order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  price NUMERIC(10,2) NOT NULL DEFAULT 0,
  qty INT NOT NULL DEFAULT 1,
  img VARCHAR(1024) DEFAULT NULL,
  description TEXT DEFAULT NULL
);

-- Indexes for token lookups
CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users (verification_token);
CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users (reset_token);
CREATE INDEX IF NOT EXISTS idx_orders_email ON orders (email);
