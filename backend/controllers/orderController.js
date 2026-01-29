const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

class OrderController {
  // Create new order
  static async createOrder(req, res) {
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');
      
      const { 
        customer_name, 
        customer_email, 
        customer_phone, 
        delivery_lat, 
        delivery_lng,
        delivery_address,
        items,
        total_amount
      } = req.body;

      // Generate unique order ID
      const orderId = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();

      // Create order
      const orderResult = await client.query(
        `INSERT INTO orders (
          order_id, customer_name, customer_email, customer_phone,
          delivery_lat, delivery_lng, delivery_address, total_amount,
          status, payment_status, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', 'pending', NOW(), NOW())
        RETURNING id, order_id`,
        [orderId, customer_name, customer_email, customer_phone,
         delivery_lat, delivery_lng, delivery_address, total_amount]
      );

      const order = orderResult.rows[0];

      // Add order items and update product quantities
      for (const item of items) {
        // Add order item
        await client.query(
          `INSERT INTO order_items (order_id, product_id, quantity, price)
           VALUES ($1, $2, $3, $4)`,
          [order.id, item.product_id, item.quantity, item.price]
        );

        // Update product quantity
        await client.query(
          `UPDATE products 
           SET quantity = quantity - $1,
               in_stock = quantity - $1 > 0,
               updated_at = NOW()
           WHERE id = $2`,
          [item.quantity, item.product_id]
        );
      }

      await client.query('COMMIT');

      // Send order confirmation email (optional)
      await OrderController.sendOrderConfirmation(orderId, customer_email, customer_name);

      res.status(201).json({
        success: true,
        message: 'Order created successfully',
        data: {
          order_id: order.order_id,
          customer_name,
          customer_email,
          total_amount,
          estimated_delivery: new Date(Date.now() + 3 * 60 * 60 * 1000).toISOString() // 3 hours
        }
      });

    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Error creating order:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to create order' 
      });
    } finally {
      client.release();
    }
  }

  // Get order by ID
  static async getOrderById(req, res) {
    try {
      const { orderId } = req.params;

      // Get order with items
      const orderResult = await pool.query(
        `SELECT o.*, 
                json_agg(
                  json_build_object(
                    'id', oi.id,
                    'product_id', oi.product_id,
                    'title', p.title,
                    'quantity', oi.quantity,
                    'price', oi.price,
                    'total', oi.quantity * oi.price
                  )
                ) as items
         FROM orders o
         LEFT JOIN order_items oi ON o.id = oi.order_id
         LEFT JOIN products p ON oi.product_id = p.id
         WHERE o.order_id = $1
         GROUP BY o.id`,
        [orderId]
      );

      if (orderResult.rows.length === 0) {
        return res.status(404).json({ 
          success: false, 
          error: 'Order not found' 
        });
      }

      res.json({
        success: true,
        data: orderResult.rows[0]
      });
    } catch (error) {
      console.error('Error fetching order:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to fetch order' 
      });
    }
  }

  // Get orders by customer email
  static async getOrdersByCustomer(req, res) {
    try {
      const { email } = req.params;
      const { page = 1, limit = 10 } = req.query;
      const offset = (page - 1) * limit;

      // Get total count
      const countResult = await pool.query(
        'SELECT COUNT(*) as total FROM orders WHERE customer_email = $1',
        [email]
      );
      const total = parseInt(countResult.rows[0].total);

      // Get paginated orders
      const ordersResult = await pool.query(
        `SELECT * FROM orders 
         WHERE customer_email = $1
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3`,
        [email, limit, offset]
      );

      res.json({
        success: true,
        data: ordersResult.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      });
    } catch (error) {
      console.error('Error fetching customer orders:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to fetch orders' 
      });
    }
  }

  // Update order status
  static async updateOrderStatus(req, res) {
    try {
      const { orderId } = req.params;
      const { status } = req.body;

      const validStatuses = ['pending', 'paid', 'processing', 'delivered', 'cancelled'];
      
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid order status' 
        });
      }

      const result = await pool.query(
        `UPDATE orders 
         SET status = $1, updated_at = NOW()
         WHERE order_id = $2
         RETURNING *`,
        [status, orderId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ 
          success: false, 
          error: 'Order not found' 
        });
      }

      // If order is cancelled, restore product quantities
      if (status === 'cancelled') {
        await OrderController.restoreProductQuantities(orderId);
      }

      // If order is delivered, send delivery confirmation
      if (status === 'delivered') {
        await OrderController.sendDeliveryConfirmation(orderId);
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

  // Helper: Restore product quantities when order is cancelled
  static async restoreProductQuantities(orderId) {
    try {
      // Get order items
      const itemsResult = await pool.query(
        `SELECT oi.product_id, oi.quantity
         FROM orders o
         JOIN order_items oi ON o.id = oi.order_id
         WHERE o.order_id = $1`,
        [orderId]
      );

      // Restore quantities for each product
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

  // Helper: Send order confirmation email
  static async sendOrderConfirmation(orderId, customerEmail, customerName) {
    try {
      // In production, implement email sending with nodemailer
      console.log(`Order confirmation sent for ${orderId} to ${customerEmail}`);
      return true;
    } catch (error) {
      console.error('Error sending order confirmation:', error);
      return false;
    }
  }

  // Helper: Send delivery confirmation
  static async sendDeliveryConfirmation(orderId) {
    try {
      // Get order details for email
      const orderResult = await pool.query(
        'SELECT customer_email, customer_name FROM orders WHERE order_id = $1',
        [orderId]
      );

      if (orderResult.rows.length > 0) {
        const { customer_email, customer_name } = orderResult.rows[0];
        console.log(`Delivery confirmation sent for ${orderId} to ${customer_email}`);
      }
    } catch (error) {
      console.error('Error sending delivery confirmation:', error);
    }
  }
}

module.exports = OrderController;