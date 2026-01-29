const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { validateAdminLogin, validate, sanitizeInput } = require('../middleware/validation');
const { auth, adminAuth } = require('../middleware/auth');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Admin login
router.post('/login',
  sanitizeInput,
  validateAdminLogin,
  validate,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      // Find admin user
      const result = await pool.query(
        'SELECT * FROM admin_users WHERE email = $1',
        [email]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      const user = result.rows[0];

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password_hash);
      
      if (!isValidPassword) {
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      // Check if user is active
      if (!user.is_active) {
        return res.status(403).json({
          success: false,
          error: 'Account is deactivated'
        });
      }

      // Generate JWT token
      const token = jwt.sign(
        { 
          userId: user.id, 
          email: user.email,
          role: user.role,
          username: user.username 
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
      );

      // Update last login
      await pool.query(
        'UPDATE admin_users SET last_login = NOW() WHERE id = $1',
        [user.id]
      );

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role,
          last_login: user.last_login
        }
      });

    } catch (error) {
      console.error('Admin login error:', error);
      res.status(500).json({
        success: false,
        error: 'Login failed'
      });
    }
  }
);

// Verify token
router.get('/verify',
  auth,
  adminAuth,
  (req, res) => {
    res.json({
      success: true,
      user: req.user
    });
  }
);

// Logout
router.post('/logout',
  auth,
  async (req, res) => {
    try {
      // Add token to blacklist
      await pool.query(
        'INSERT INTO blacklisted_tokens (token, expires_at) VALUES ($1, NOW() + INTERVAL \'8 hours\')',
        [req.token]
      );

      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        error: 'Logout failed'
      });
    }
  }
);

// Get dashboard stats
router.get('/stats',
  auth,
  adminAuth,
  async (req, res) => {
    try {
      // Get today's date
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const yesterday = new Date(today);
      yesterday.setDate(yesterday.getDate() - 1);
      const lastWeek = new Date(today);
      lastWeek.setDate(lastWeek.getDate() - 7);

      // Execute all queries in parallel
      const [
        ordersCount,
        revenueStats,
        customerStats,
        productStats,
        recentOrders,
        topProducts
      ] = await Promise.all([
        // Total and today's orders
        pool.query(`
          SELECT 
            COUNT(*) as total_orders,
            COUNT(CASE WHEN DATE(created_at) = CURRENT_DATE THEN 1 END) as today_orders,
            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_orders,
            COUNT(CASE WHEN status = 'processing' THEN 1 END) as processing_orders
          FROM orders
        `),

        // Revenue statistics
        pool.query(`
          SELECT 
            COALESCE(SUM(total_amount), 0) as total_revenue,
            COALESCE(SUM(CASE WHEN DATE(created_at) = CURRENT_DATE THEN total_amount ELSE 0 END), 0) as today_revenue,
            COALESCE(SUM(CASE WHEN DATE(created_at) = CURRENT_DATE - INTERVAL '1 day' THEN total_amount ELSE 0 END), 0) as yesterday_revenue,
            COALESCE(SUM(CASE WHEN created_at >= $1 THEN total_amount ELSE 0 END), 0) as weekly_revenue
          FROM orders
          WHERE status != 'cancelled'
        `, [lastWeek]),

        // Customer statistics
        pool.query(`
          SELECT 
            COUNT(DISTINCT customer_email) as total_customers,
            COUNT(DISTINCT CASE WHEN DATE(created_at) = CURRENT_DATE THEN customer_email END) as today_customers
          FROM orders
        `),

        // Product statistics
        pool.query(`
          SELECT 
            COUNT(*) as total_products,
            COUNT(CASE WHEN quantity = 0 THEN 1 END) as out_of_stock,
            COUNT(CASE WHEN quantity < 10 THEN 1 END) as low_stock
          FROM products
        `),

        // Recent orders
        pool.query(`
          SELECT o.*, 
                 json_agg(
                   json_build_object(
                     'id', oi.id,
                     'product_id', oi.product_id,
                     'title', p.title,
                     'quantity', oi.quantity,
                     'price', oi.price
                   )
                 ) as items
          FROM orders o
          LEFT JOIN order_items oi ON o.id = oi.order_id
          LEFT JOIN products p ON oi.product_id = p.id
          WHERE o.created_at >= CURRENT_DATE - INTERVAL '7 days'
          GROUP BY o.id
          ORDER BY o.created_at DESC
          LIMIT 10
        `),

        // Top selling products
        pool.query(`
          SELECT p.id, p.title, p.type, p.price,
                 SUM(oi.quantity) as total_sold,
                 SUM(oi.quantity * oi.price) as total_revenue
          FROM order_items oi
          JOIN products p ON oi.product_id = p.id
          JOIN orders o ON oi.order_id = o.id
          WHERE o.created_at >= CURRENT_DATE - INTERVAL '30 days'
            AND o.status != 'cancelled'
          GROUP BY p.id, p.title, p.type, p.price
          ORDER BY total_sold DESC
          LIMIT 10
        `)
      ]);

      // Calculate revenue change
      const todayRevenue = parseFloat(revenueStats.rows[0].today_revenue) || 0;
      const yesterdayRevenue = parseFloat(revenueStats.rows[0].yesterday_revenue) || 0;
      const revenueChange = yesterdayRevenue > 0 
        ? ((todayRevenue - yesterdayRevenue) / yesterdayRevenue * 100).toFixed(2)
        : 0;

      res.json({
        success: true,
        data: {
          orders: {
            total: parseInt(ordersCount.rows[0].total_orders) || 0,
            today: parseInt(ordersCount.rows[0].today_orders) || 0,
            pending: parseInt(ordersCount.rows[0].pending_orders) || 0,
            processing: parseInt(ordersCount.rows[0].processing_orders) || 0
          },
          revenue: {
            total: parseFloat(revenueStats.rows[0].total_revenue) || 0,
            today: todayRevenue,
            weekly: parseFloat(revenueStats.rows[0].weekly_revenue) || 0,
            change: parseFloat(revenueChange)
          },
          customers: {
            total: parseInt(customerStats.rows[0].total_customers) || 0,
            today: parseInt(customerStats.rows[0].today_customers) || 0
          },
          products: {
            total: parseInt(productStats.rows[0].total_products) || 0,
            out_of_stock: parseInt(productStats.rows[0].out_of_stock) || 0,
            low_stock: parseInt(productStats.rows[0].low_stock) || 0
          },
          recent_orders: recentOrders.rows,
          top_products: topProducts.rows
        }
      });

    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch dashboard statistics'
      });
    }
  }
);

// Get all orders for admin
router.get('/orders',
  auth,
  adminAuth,
  async (req, res) => {
    try {
      const { page = 1, limit = 20, status, search } = req.query;
      const offset = (page - 1) * limit;
      
      let query = `
        SELECT o.*, 
               json_agg(
                 json_build_object(
                   'id', oi.id,
                   'product_id', oi.product_id,
                   'title', p.title,
                   'quantity', oi.quantity,
                   'price', oi.price
                 )
               ) as items
        FROM orders o
        LEFT JOIN order_items oi ON o.id = oi.order_id
        LEFT JOIN products p ON oi.product_id = p.id
        WHERE 1=1
      `;
      
      let params = [];
      let paramCount = 1;

      if (status && status !== 'all') {
        query += ` AND o.status = $${paramCount}`;
        params.push(status);
        paramCount++;
      }

      if (search) {
        query += ` AND (
          o.order_id ILIKE $${paramCount} OR 
          o.customer_name ILIKE $${paramCount} OR 
          o.customer_email ILIKE $${paramCount} OR
          o.customer_phone ILIKE $${paramCount}
        )`;
        params.push(`%${search}%`);
        paramCount++;
      }

      query += ` GROUP BY o.id ORDER BY o.created_at DESC`;

      // Get total count
      const countQuery = query.replace(
        'SELECT o.*, json_agg(json_build_object(\'id\', oi.id, \'product_id\', oi.product_id, \'title\', p.title, \'quantity\', oi.quantity, \'price\', oi.price)) as items',
        'SELECT COUNT(DISTINCT o.id) as total'
      ).split(' GROUP BY')[0];
      
      const countResult = await pool.query(countQuery, params);
      const total = parseInt(countResult.rows[0].total);

      // Add pagination
      query += ` LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
      params.push(limit, offset);

      const result = await pool.query(query, params);

      res.json({
        success: true,
        data: result.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      });

    } catch (error) {
      console.error('Error fetching admin orders:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch orders'
      });
    }
  }
);

// Update order status
router.put('/orders/:orderId/status',
  auth,
  adminAuth,
  sanitizeInput,
  async (req, res) => {
    try {
      const { orderId } = req.params;
      const { status, notes } = req.body;

      const validStatuses = ['pending', 'paid', 'processing', 'delivered', 'cancelled'];
      
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid order status'
        });
      }

      const result = await pool.query(
        `UPDATE orders 
         SET status = $1, 
             updated_at = NOW(),
             admin_notes = COALESCE($2, admin_notes)
         WHERE order_id = $3
         RETURNING *`,
        [status, notes, orderId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'Order not found'
        });
      }

      // If order is cancelled, restore product quantities
      if (status === 'cancelled') {
        await restoreProductQuantities(orderId);
      }

      res.json({
        success: true,
        message: 'Order status updated successfully',
        data: result.rows[0]
      });

    } catch (error) {
      console.error('Error updating order status:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to update order status'
      });
    }
  }
);

// Helper function to restore product quantities
async function restoreProductQuantities(orderId) {
  try {
    const itemsResult = await pool.query(
      `SELECT oi.product_id, oi.quantity
       FROM orders o
       JOIN order_items oi ON o.id = oi.order_id
       WHERE o.order_id = $1`,
      [orderId]
    );

    for (const item of itemsResult.rows) {
      await pool.query(
        `UPDATE products 
         SET quantity = quantity + $1,
             in_stock = true,
             updated_at = NOW()
         WHERE id = $2`,
        [item.quantity, item.product_id]
      );
    }
  } catch (error) {
    console.error('Error restoring product quantities:', error);
  }
}

module.exports = router;