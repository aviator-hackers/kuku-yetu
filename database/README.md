# Kuku Yetu Database Schema

This directory contains the PostgreSQL database schema and seed data for the Kuku Yetu poultry e-commerce platform.

## 🗄️ Database Setup on Neon

### Step 1: Create Neon Database
1. Go to [neon.tech](https://neon.tech)
2. Create a new project
3. Copy your connection string from the dashboard

### Step 2: Run Schema Setup
1. Copy the contents of `schema.sql`
2. Paste into Neon SQL Editor
3. Execute the SQL

### Step 3: Seed Initial Data
1. Copy the contents of `seed.sql`
2. Paste into Neon SQL Editor
3. Execute the SQL

### Step 4: Create Admin User
```sql
INSERT INTO admin_users (username, email, password_hash, role) 
VALUES ('Admin', 'admin@kukuyetu.co.ke', 
        crypt('ChangeThisPassword123!', gen_salt('bf')), 
        'admin');