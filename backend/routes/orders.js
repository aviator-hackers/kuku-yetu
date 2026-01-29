const express = require('express');
const router = express.Router();
const OrderController = require('../controllers/orderController');
const { validateOrder, validate, sanitizeInput } = require('../middleware/validation');
const { auth, adminAuth } = require('../middleware/auth');

// Public routes (for customers)
router.post('/',
  sanitizeInput,
  validateOrder,
  validate,
  OrderController.createOrder
);

router.get('/customer/:email',
  sanitizeInput,
  OrderController.getOrdersByCustomer
);

router.get('/:orderId',
  sanitizeInput,
  OrderController.getOrderById
);

// Admin routes (protected)
router.put('/:orderId/status',
  auth,
  adminAuth,
  sanitizeInput,
  OrderController.updateOrderStatus
);

// Webhook for order updates (public but secured with signature)
router.post('/webhook', (req, res) => {
  // Implement webhook security with signature verification
  const signature = req.headers['x-webhook-signature'];
  
  if (!signature || !verifyWebhookSignature(req.body, signature)) {
    return res.status(401).json({ success: false, error: 'Invalid signature' });
  }
  
  // Process webhook
  res.json({ success: true, received: true });
});

// Helper function to verify webhook signature
function verifyWebhookSignature(payload, signature) {
  // Implement your signature verification logic
  // This is a placeholder - implement based on your webhook provider
  return true;
}

module.exports = router;