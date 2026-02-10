require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const axios = require('axios');

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      scriptSrc: ["'self'", "https://unpkg.com", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Lipia Online Configuration
const LIPIA_API = 'https://lipia-api.kreativelabske.com/api/v2';
const LIPIA_API_KEY = process.env.LIPIA_API_KEY;

// Initialize Database
const initializeDB = async () => {
  const client = await pool.connect();
  try {
    // Products table
    await client.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        type VARCHAR(100),
        price DECIMAL(10,2) NOT NULL,
        quantity INTEGER DEFAULT 0,
        availability BOOLEAN DEFAULT true,
        image_urls TEXT[] DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Orders table
    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        order_id VARCHAR(50) UNIQUE NOT NULL,
        customer_name VARCHAR(255) NOT NULL,
        customer_phone VARCHAR(20) NOT NULL,
        customer_email VARCHAR(255),
        delivery_address TEXT NOT NULL,
        items JSONB NOT NULL,
        total_amount DECIMAL(10,2) NOT NULL,
        payment_reference VARCHAR(100),
        mpesa_receipt VARCHAR(50),
        payment_status VARCHAR(20) DEFAULT 'pending',
        order_status VARCHAR(20) DEFAULT 'pending',
        estimated_delivery TIMESTAMP,
        receipt_number VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Admin users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create default admin if not exists
    const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 10);
    await client.query(`
      INSERT INTO admin_users (email, password_hash)
      VALUES ($1, $2)
      ON CONFLICT (email) DO NOTHING
    `, [process.env.ADMIN_EMAIL || 'admin@kukuyetu.com', hashedPassword]);

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  } finally {
    client.release();
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});


// Admin authentication middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const result = await pool.query('SELECT * FROM admin_users WHERE id = $1', [decoded.userId]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ========== ADMIN ROUTES ==========

// Admin login
app.post('/api/admin/login', async (req, res) => {
  console.log('ENV JWT_SECRET:', JSON.stringify(process.env.JWT_SECRET));
  console.log('ENV JWT_SECRET length:', process.env.JWT_SECRET?.length);
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM admin_users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const admin = result.rows[0];
    const validPassword = await bcrypt.compare(password, admin.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: admin.id, email: admin.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '8h' }
    );

    res.json({ token, email: admin.email });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all products (admin)
app.get('/api/admin/products', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create product
app.post('/api/admin/products', authenticateAdmin, async (req, res) => {
  const { title, description, type, price, quantity, availability, image_urls } = req.body;

  try {
    const result = await pool.query(
      `INSERT INTO products (title, description, type, price, quantity, availability, image_urls)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [title, description, type, parseFloat(price), parseInt(quantity), availability, image_urls || []]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update product
app.put('/api/admin/products/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, description, type, price, quantity, availability, image_urls } = req.body;

  try {
    const result = await pool.query(
      `UPDATE products 
       SET title = $1, description = $2, type = $3, price = $4, 
           quantity = $5, availability = $6, image_urls = $7
       WHERE id = $8
       RETURNING *`,
      [title, description, type, price, quantity, availability, image_urls, id]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete product
app.delete('/api/admin/products/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query('DELETE FROM products WHERE id = $1', [id]);
    res.json({ message: 'Product deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all orders (admin)
app.get('/api/admin/orders', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update order status
app.put('/api/admin/orders/:orderId/confirm', authenticateAdmin, async (req, res) => {
  const { orderId } = req.params;
  const { estimated_delivery } = req.body;

  try {
    const result = await pool.query(
      `UPDATE orders 
       SET order_status = 'confirmed', estimated_delivery = $1
       WHERE order_id = $2
       RETURNING *`,
      [estimated_delivery, orderId]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ========== PUBLIC ROUTES ==========

// Get all products (public)
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM products WHERE availability = true ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get address from coordinates
app.get('/api/location/address', async (req, res) => {
  const { lat, lon } = req.query;

  try {
    const response = await axios.get(
      `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`
    );

    const address = response.data;
    let readableAddress = '';
    
    if (address.address) {
      const addr = address.address;
      readableAddress = [
        addr.road,
        addr.suburb,
        addr.city_district,
        addr.city,
        addr.county
      ].filter(Boolean).join(', ');
    } else {
      readableAddress = address.display_name;
    }

    res.json({ address: readableAddress });
  } catch (error) {
    console.error('Geocoding error:', error);
    res.status(500).json({ error: 'Failed to get address' });
  }
});

// ========== PAYMENT ROUTES ==========

// Initialize STK Push
app.post('/api/payments/initiate', async (req, res) => {
  const { phone_number, amount, external_reference, customer_name, items, delivery_address } = req.body;

  try {
    // Save order first
    const orderResult = await pool.query(
      `INSERT INTO orders (order_id, customer_name, customer_phone, delivery_address, items, total_amount, payment_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        external_reference,
        customer_name,
        phone_number,
        delivery_address,
        JSON.stringify(items),
        amount,
        'pending'
      ]
    );

    // Call Lipia Online API
    const lipiaResponse = await axios.post(
      `${LIPIA_API}/payments/stk-push`,
      {
        phone_number: phone_number.replace(/^0/, '254'),
        amount: amount.toString(),
        external_reference,
        callback_url: `${process.env.BACKEND_URL}/api/payments/callback`,
        metadata: {
          order_id: external_reference,
          customer_name
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${LIPIA_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (lipiaResponse.data.ResponseCode === 0) {
      // Update order with payment reference
      await pool.query(
        'UPDATE orders SET payment_reference = $1 WHERE order_id = $2',
        [lipiaResponse.data.TransactionReference, external_reference]
      );

      res.json({
        success: true,
        transaction_reference: lipiaResponse.data.TransactionReference,
        order_id: external_reference
      });
    } else {
      throw new Error('STK Push failed');
    }
  } catch (error) {
    console.error('Payment initiation error:', error);
    res.status(500).json({ error: 'Payment initiation failed' });
  }
});

// Check payment status
app.get('/api/payments/status/:reference', async (req, res) => {
  const { reference } = req.params;

  try {
    // First check our database
    const orderResult = await pool.query(
      'SELECT * FROM orders WHERE payment_reference = $1',
      [reference]
    );

    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    const order = orderResult.rows[0];

    // If already marked as success in our DB, return immediately
    if (order.payment_status === 'success') {
      return res.json({
        status: 'success',
        order: order
      });
    }

    // Query Lipia Online API for current status
    const lipiaResponse = await axios.get(
      `${LIPIA_API}/payments/status?reference=${reference}`,
      {
        headers: {
          'Authorization': `Bearer ${LIPIA_API_KEY}`
        }
      }
    );

    const paymentStatus = lipiaResponse.data.Status || 'pending';

    // Update our database if status changed
    if (paymentStatus === 'SUCCESS' && order.payment_status !== 'success') {
      await pool.query(
        `UPDATE orders 
         SET payment_status = 'success', 
             mpesa_receipt = $1,
             order_status = 'confirmed',
             receipt_number = 'KUKU-${Date.now()}'
         WHERE payment_reference = $2`,
        [lipiaResponse.data.MpesaReceiptNumber || 'N/A', reference]
      );
    }

    res.json({
      status: paymentStatus.toLowerCase(),
      order: order
    });
  } catch (error) {
    console.error('Status check error:', error);
    res.status(500).json({ error: 'Failed to check payment status' });
  }
});

// Payment callback (webhook) from Lipia
app.post('/api/payments/callback', async (req, res) => {
  try {
    const callbackData = req.body;
    
    // Verify the callback (in production, verify signature)
    if (!callbackData.ExternalReference || !callbackData.Status) {
      return res.status(400).send('Invalid callback data');
    }

    const { ExternalReference, Status, MpesaReceiptNumber, ResultCode } = callbackData;

    // Update order based on callback
    if (Status === 'SUCCESS' && ResultCode === 0) {
      await pool.query(
        `UPDATE orders 
         SET payment_status = 'success', 
             mpesa_receipt = $1,
             order_status = 'paid',
             receipt_number = 'KUKU-${Date.now()}'
         WHERE order_id = $2`,
        [MpesaReceiptNumber, ExternalReference]
      );
    } else {
      await pool.query(
        'UPDATE orders SET payment_status = $1 WHERE order_id = $2',
        ['failed', ExternalReference]
      );
    }

    // Always return 200 OK to Lipia
    res.status(200).send('ok');
  } catch (error) {
    console.error('Callback error:', error);
    res.status(200).send('ok'); // Still return 200 to prevent retries
  }
});

// Get order details
app.get('/api/orders/:orderId', async (req, res) => {
  const { orderId } = req.params;

  try {
    const result = await pool.query('SELECT * FROM orders WHERE order_id = $1', [orderId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize and start server
const PORT = process.env.PORT || 3001;

initializeDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Health check: http://localhost:${PORT}/health`);
  });
}).catch(error => {
  console.error('Failed to initialize:', error);
  process.exit(1);
});
