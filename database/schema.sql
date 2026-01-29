-- Kuku Yetu Database Schema
-- PostgreSQL 15+ for Neon

-- Create enum types (must be first)
CREATE TYPE order_status AS ENUM ('pending', 'paid', 'processing', 'delivered', 'cancelled');
CREATE TYPE payment_status AS ENUM ('pending', 'completed', 'failed', 'refunded');
CREATE TYPE product_type AS ENUM ('broiler', 'kienyeji', 'turkey', 'other');

-- Products table
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    type product_type NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 0,
    images TEXT[],
    in_stock BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Orders table
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(50) UNIQUE NOT NULL,
    customer_name VARCHAR(255) NOT NULL,
    customer_email VARCHAR(255) NOT NULL,
    customer_phone VARCHAR(20) NOT NULL,
    delivery_lat DECIMAL(10, 8),
    delivery_lng DECIMAL(11, 8),
    delivery_address TEXT,
    total_amount DECIMAL(10, 2) NOT NULL,
    status order_status DEFAULT 'pending',
    payment_status payment_status DEFAULT 'pending',
    transaction_id VARCHAR(100),
    estimated_delivery TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Order items table
CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Admin users table
CREATE TABLE admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'admin',
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table (for admin auth)
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES admin_users(id),
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Notifications table
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES admin_users(id),
    message TEXT NOT NULL,
    type VARCHAR(50),
    read BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Payments table (for tracking payment records separately)
CREATE TABLE payments (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(50) REFERENCES orders(order_id),
    transaction_id VARCHAR(100) UNIQUE NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    status payment_status DEFAULT 'pending',
    payment_method VARCHAR(50),
    failure_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Blacklisted tokens table (for logout functionality)
CREATE TABLE blacklisted_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_created_at ON orders(created_at DESC);
CREATE INDEX idx_orders_customer_email ON orders(customer_email);
CREATE INDEX idx_orders_payment_status ON orders(payment_status);
CREATE INDEX idx_products_type ON products(type);
CREATE INDEX idx_products_in_stock ON products(in_stock);
CREATE INDEX idx_products_price ON products(price);
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
CREATE INDEX idx_order_items_product_id ON order_items(product_id);
CREATE INDEX idx_admin_users_email ON admin_users(email);
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_payments_transaction_id ON payments(transaction_id);
CREATE INDEX idx_payments_order_id ON payments(order_id);
CREATE INDEX idx_blacklisted_tokens_token ON blacklisted_tokens(token);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON products
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_orders_updated_at BEFORE UPDATE ON orders
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_admin_users_updated_at BEFORE UPDATE ON admin_users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_payments_updated_at BEFORE UPDATE ON payments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to auto-update product stock status
CREATE OR REPLACE FUNCTION update_product_stock_status()
RETURNS TRIGGER AS $$
BEGIN
    -- Update in_stock based on quantity
    IF NEW.quantity <= 0 THEN
        NEW.in_stock = false;
    ELSE
        NEW.in_stock = true;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to update product stock status
CREATE TRIGGER update_product_stock_trigger BEFORE INSERT OR UPDATE ON products
    FOR EACH ROW EXECUTE FUNCTION update_product_stock_status();

-- Function to generate order ID
CREATE OR REPLACE FUNCTION generate_order_id()
RETURNS TRIGGER AS $$
DECLARE
    order_prefix VARCHAR(10) := 'ORD-';
    date_part VARCHAR(20);
    random_part VARCHAR(10);
    new_order_id VARCHAR(50);
BEGIN
    -- Generate date part: YYYYMMDD
    date_part := TO_CHAR(CURRENT_DATE, 'YYYYMMDD');
    
    -- Generate random part: 6 digits
    random_part := LPAD(FLOOR(RANDOM() * 1000000)::TEXT, 6, '0');
    
    -- Combine
    new_order_id := order_prefix || date_part || '-' || random_part;
    
    -- Ensure uniqueness
    WHILE EXISTS (SELECT 1 FROM orders WHERE order_id = new_order_id) LOOP
        random_part := LPAD(FLOOR(RANDOM() * 1000000)::TEXT, 6, '0');
        new_order_id := order_prefix || date_part || '-' || random_part;
    END LOOP;
    
    NEW.order_id := new_order_id;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-generate order ID
CREATE TRIGGER generate_order_id_trigger BEFORE INSERT ON orders
    FOR EACH ROW EXECUTE FUNCTION generate_order_id();

-- Function to update product quantity when order item is added
CREATE OR REPLACE FUNCTION update_product_quantity_on_order()
RETURNS TRIGGER AS $$
BEGIN
    -- Decrease product quantity
    UPDATE products 
    SET quantity = quantity - NEW.quantity,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = NEW.product_id;
    
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to update product quantity
CREATE TRIGGER update_product_quantity_trigger AFTER INSERT ON order_items
    FOR EACH ROW EXECUTE FUNCTION update_product_quantity_on_order();

-- Function to restore product quantity when order is cancelled
CREATE OR REPLACE FUNCTION restore_product_quantity_on_cancellation()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'cancelled' AND OLD.status != 'cancelled' THEN
        -- Restore quantities for all items in the order
        UPDATE products p
        SET quantity = p.quantity + oi.quantity,
            updated_at = CURRENT_TIMESTAMP
        FROM order_items oi
        WHERE oi.order_id = NEW.id
          AND p.id = oi.product_id;
    END IF;
    
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to restore product quantity
CREATE TRIGGER restore_product_quantity_trigger AFTER UPDATE OF status ON orders
    FOR EACH ROW EXECUTE FUNCTION restore_product_quantity_on_cancellation();

-- Create a view for order summaries
CREATE OR REPLACE VIEW order_summary AS
SELECT 
    o.id,
    o.order_id,
    o.customer_name,
    o.customer_email,
    o.customer_phone,
    o.total_amount,
    o.status,
    o.payment_status,
    o.created_at,
    COUNT(oi.id) as item_count,
    SUM(oi.quantity) as total_items,
    o.delivery_address
FROM orders o
LEFT JOIN order_items oi ON o.id = oi.order_id
GROUP BY o.id, o.order_id, o.customer_name, o.customer_email, o.customer_phone, 
         o.total_amount, o.status, o.payment_status, o.created_at, o.delivery_address;

-- Print completion message
DO $$
BEGIN
    RAISE NOTICE '✅ Database schema created successfully!';
    RAISE NOTICE '📊 Tables created: 8 tables with all relationships';
    RAISE NOTICE '🔑 Indexes: 14 indexes for optimal performance';
    RAISE NOTICE '⚡ Triggers: 7 triggers for automated operations';
    RAISE NOTICE '👁️ View: order_summary view created';
    RAISE NOTICE '';
    RAISE NOTICE '📝 Next steps:';
    RAISE NOTICE '   1. Run seed.sql to populate initial data';
    RAISE NOTICE '   2. Update admin password in seed.sql';
    RAISE NOTICE '   3. Test the database connection from your backend';
END $$;