const express = require('express');
const router = express.Router();
const PaymentController = require('../controllers/paymentController');
const { validatePayment, validate, sanitizeInput } = require('../middleware/validation');
const { auth } = require('../middleware/auth');

// Payment verification (called from frontend after payment)
router.post('/verify',
  sanitizeInput,
  validatePayment,
  validate,
  PaymentController.verifyPayment
);

// Webhook for payment notifications (from Lipiana)
router.post('/webhook',
  PaymentController.processWebhook
);

// Initiate payment
router.post('/initiate',
  sanitizeInput,
  auth,
  PaymentController.initiatePayment
);

// Check payment status
router.get('/status/:transaction_id',
  sanitizeInput,
  PaymentController.checkPaymentStatus
);

// Payment callback (redirect from payment gateway)
router.get('/callback', (req, res) => {
  const { transaction_id, status, order_id } = req.query;
  
  // Redirect to frontend with payment result
  const redirectUrl = `${process.env.FRONTEND_URL}/payment-result?transaction_id=${transaction_id}&status=${status}&order_id=${order_id}`;
  res.redirect(redirectUrl);
});

// Get payment history for user
router.get('/history',
  auth,
  async (req, res) => {
    try {
      const { Pool } = require('pg');
      const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
      });

      const result = await pool.query(
        `SELECT p.*, o.customer_name, o.total_amount
         FROM payments p
         JOIN orders o ON p.order_id = o.order_id
         WHERE o.customer_email = $1
         ORDER BY p.created_at DESC
         LIMIT 50`,
        [req.user.email]
      );

      res.json({
        success: true,
        data: result.rows
      });
    } catch (error) {
      console.error('Error fetching payment history:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch payment history'
      });
    }
  }
);

module.exports = router;