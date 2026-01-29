const { Pool } = require('pg');
const crypto = require('crypto');
const axios = require('axios');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

class PaymentController {
  // Verify payment with Lipiana
  static async verifyPayment(req, res) {
    try {
      const { transaction_id, order_id, amount } = req.body;

      if (!transaction_id || !order_id || !amount) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: transaction_id, order_id, amount'
        });
      }

      // Verify payment with Lipiana API
      const lipianaResponse = await axios.post(
        'https://api.lipiana.dev/v1/payments/verify',
        {
          transaction_id,
          order_id,
          amount,
          merchant_id: process.env.LIPIANA_MERCHANT_ID
        },
        {
          headers: {
            'Authorization': `Bearer ${process.env.LIPIANA_API_KEY}`,
            'Content-Type': 'application/json',
            'X-Merchant-ID': process.env.LIPIANA_MERCHANT_ID
          },
          timeout: 10000 // 10 second timeout
        }
      );

      if (lipianaResponse.data.success) {
        // Payment verified successfully
        await PaymentController.updateOrderPayment(order_id, transaction_id, amount);
        
        return res.json({
          success: true,
          data: {
            verified: true,
            transaction_id,
            verified_at: new Date().toISOString(),
            order_id,
            amount
          }
        });
      } else {
        return res.status(400).json({
          success: false,
          error: 'Payment verification failed',
          details: lipianaResponse.data
        });
      }

    } catch (error) {
      console.error('Payment verification error:', error.response?.data || error.message);
      
      // Check if it's an Axios error
      if (error.response) {
        return res.status(error.response.status).json({
          success: false,
          error: 'Payment gateway error',
          details: error.response.data
        });
      } else if (error.request) {
        return res.status(504).json({
          success: false,
          error: 'Payment gateway timeout'
        });
      }

      res.status(500).json({
        success: false,
        error: 'Payment verification failed'
      });
    }
  }

  // Process payment webhook from Lipiana
  static async processWebhook(req, res) {
    try {
      const signature = req.headers['x-lipiana-signature'];
      const payload = JSON.stringify(req.body);

      // Verify webhook signature
      const expectedSignature = crypto
        .createHmac('sha256', process.env.LIPIANA_WEBHOOK_SECRET)
        .update(payload)
        .digest('hex');

      if (signature !== expectedSignature) {
        console.error('Invalid webhook signature');
        return res.status(401).json({ 
          success: false, 
          error: 'Invalid signature' 
        });
      }

      const { event, data } = req.body;
      console.log(`Processing webhook event: ${event}`, data);

      switch (event) {
        case 'payment.completed':
          await PaymentController.handlePaymentCompleted(data);
          break;
          
        case 'payment.failed':
          await PaymentController.handlePaymentFailed(data);
          break;
          
        case 'payment.refunded':
          await PaymentController.handlePaymentRefunded(data);
          break;
          
        case 'payment.disputed':
          await PaymentController.handlePaymentDisputed(data);
          break;
          
        default:
          console.log(`Unhandled webhook event: ${event}`);
      }

      res.json({ 
        success: true, 
        received: true 
      });

    } catch (error) {
      console.error('Webhook processing error:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Webhook processing failed' 
      });
    }
  }

  // Initiate payment
  static async initiatePayment(req, res) {
    try {
      const { order_id, amount, customer_email, customer_phone, payment_method } = req.body;

      // Validate order exists and is pending
      const orderCheck = await pool.query(
        'SELECT * FROM orders WHERE order_id = $1 AND status = $2',
        [order_id, 'pending']
      );

      if (orderCheck.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'Order not found or already processed'
        });
      }

      // Create payment request to Lipiana
      const paymentRequest = {
        order_id,
        amount,
        currency: 'KES',
        customer: {
          email: customer_email,
          phone: customer_phone
        },
        payment_method,
        callback_url: `${process.env.BACKEND_URL}/api/payment/callback`,
        redirect_url: `${process.env.FRONTEND_URL}/payment-success`
      };

      const lipianaResponse = await axios.post(
        'https://api.lipiana.dev/v1/payments/create',
        paymentRequest,
        {
          headers: {
            'Authorization': `Bearer ${process.env.LIPIANA_API_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (lipianaResponse.data.success) {
        // Update order with payment initiation
        await pool.query(
          `UPDATE orders 
           SET payment_status = 'initiated',
               transaction_id = $1,
               updated_at = NOW()
           WHERE order_id = $2`,
          [lipianaResponse.data.transaction_id, order_id]
        );

        res.json({
          success: true,
          data: {
            payment_url: lipianaResponse.data.payment_url,
            transaction_id: lipianaResponse.data.transaction_id,
            expires_at: lipianaResponse.data.expires_at
          }
        });
      } else {
        throw new Error('Failed to initiate payment');
      }

    } catch (error) {
      console.error('Payment initiation error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to initiate payment'
      });
    }
  }

  // Check payment status
  static async checkPaymentStatus(req, res) {
    try {
      const { transaction_id } = req.params;

      const response = await axios.get(
        `https://api.lipiana.dev/v1/payments/${transaction_id}/status`,
        {
          headers: {
            'Authorization': `Bearer ${process.env.LIPIANA_API_KEY}`
          }
        }
      );

      res.json({
        success: true,
        data: response.data
      });
    } catch (error) {
      console.error('Payment status check error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to check payment status'
      });
    }
  }

  // Helper: Update order payment status
  static async updateOrderPayment(order_id, transaction_id, amount) {
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');

      // Update order payment status
      await client.query(
        `UPDATE orders 
         SET payment_status = 'completed',
             status = 'paid',
             transaction_id = $1,
             updated_at = NOW()
         WHERE order_id = $2`,
        [transaction_id, order_id]
      );

      // Create payment record
      await client.query(
        `INSERT INTO payments (
          order_id, transaction_id, amount, status, 
          payment_method, created_at
        ) VALUES ($1, $2, $3, 'completed', 'lipiana', NOW())`,
        [order_id, transaction_id, amount]
      );

      await client.query('COMMIT');

      console.log(`Payment updated for order ${order_id}`);
      
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Error updating order payment:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Helper: Handle completed payment
  static async handlePaymentCompleted(data) {
    try {
      const { transaction_id, order_id, amount } = data;
      await PaymentController.updateOrderPayment(order_id, transaction_id, amount);
      
      // Send payment confirmation
      await PaymentController.sendPaymentConfirmation(order_id);
      
      console.log(`Payment completed for order ${order_id}`);
    } catch (error) {
      console.error('Error handling payment completed:', error);
    }
  }

  // Helper: Handle failed payment
  static async handlePaymentFailed(data) {
    try {
      const { transaction_id, order_id, reason } = data;
      
      await pool.query(
        `UPDATE orders 
         SET payment_status = 'failed',
             updated_at = NOW()
         WHERE order_id = $1`,
        [order_id]
      );

      await pool.query(
        `INSERT INTO payments (
          order_id, transaction_id, amount, status, 
          failure_reason, created_at
        ) VALUES ($1, $2, $3, 'failed', $4, NOW())`,
        [order_id, transaction_id, data.amount || 0, reason]
      );

      console.log(`Payment failed for order ${order_id}: ${reason}`);
    } catch (error) {
      console.error('Error handling payment failed:', error);
    }
  }

  // Helper: Handle refund
  static async handlePaymentRefunded(data) {
    try {
      const { transaction_id, order_id, refund_amount } = data;
      
      await pool.query(
        `UPDATE orders 
         SET payment_status = 'refunded',
             updated_at = NOW()
         WHERE order_id = $1`,
        [order_id]
      );

      await pool.query(
        `INSERT INTO payments (
          order_id, transaction_id, amount, status, 
          payment_method, created_at
        ) VALUES ($1, $2, $3, 'refunded', 'refund', NOW())`,
        [order_id, transaction_id, refund_amount]
      );

      console.log(`Payment refunded for order ${order_id}: ${refund_amount}`);
    } catch (error) {
      console.error('Error handling payment refunded:', error);
    }
  }

  // Helper: Handle dispute
  static async handlePaymentDisputed(data) {
    try {
      const { transaction_id, order_id } = data;
      
      await pool.query(
        `UPDATE orders 
         SET payment_status = 'disputed',
             updated_at = NOW()
         WHERE order_id = $1`,
        [order_id]
      );

      console.log(`Payment disputed for order ${order_id}`);
    } catch (error) {
      console.error('Error handling payment disputed:', error);
    }
  }

  // Helper: Send payment confirmation
  static async sendPaymentConfirmation(order_id) {
    try {
      // Get order details for email
      const orderResult = await pool.query(
        `SELECT customer_email, customer_name, total_amount 
         FROM orders WHERE order_id = $1`,
        [order_id]
      );

      if (orderResult.rows.length > 0) {
        const { customer_email, customer_name, total_amount } = orderResult.rows[0];
        
        // In production, implement email sending
        console.log(`Payment confirmation sent to ${customer_email} for order ${order_id}`);
        
        // Here you would integrate with your email service
        // await sendEmail({
        //   to: customer_email,
        //   subject: 'Payment Confirmation - Kuku Yetu',
        //   template: 'payment-confirmation',
        //   data: { customer_name, order_id, total_amount }
        // });
      }
    } catch (error) {
      console.error('Error sending payment confirmation:', error);
    }
  }
}

module.exports = PaymentController;