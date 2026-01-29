const { body, param, query, validationResult } = require('express-validator');

// Product validation rules
const validateProduct = [
  body('title')
    .trim()
    .notEmpty().withMessage('Product title is required')
    .isLength({ min: 3, max: 200 }).withMessage('Title must be between 3 and 200 characters'),
  
  body('description')
    .trim()
    .notEmpty().withMessage('Product description is required')
    .isLength({ min: 10, max: 1000 }).withMessage('Description must be between 10 and 1000 characters'),
  
  body('type')
    .trim()
    .notEmpty().withMessage('Product type is required')
    .isIn(['broiler', 'kienyeji', 'turkey', 'other']).withMessage('Invalid product type'),
  
  body('price')
    .isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  
  body('quantity')
    .isInt({ min: 0 }).withMessage('Quantity must be a non-negative integer'),
  
  body('in_stock')
    .optional()
    .isBoolean().withMessage('in_stock must be a boolean value'),
];

// Order validation rules
const validateOrder = [
  body('customer_name')
    .trim()
    .notEmpty().withMessage('Customer name is required')
    .isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters'),
  
  body('customer_email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email address')
    .normalizeEmail(),
  
  body('customer_phone')
    .trim()
    .notEmpty().withMessage('Phone number is required')
    .matches(/^[0-9+\-\s()]{10,15}$/).withMessage('Invalid phone number format'),
  
  body('delivery_lat')
    .optional()
    .isFloat({ min: -90, max: 90 }).withMessage('Invalid latitude'),
  
  body('delivery_lng')
    .optional()
    .isFloat({ min: -180, max: 180 }).withMessage('Invalid longitude'),
  
  body('items')
    .isArray({ min: 1 }).withMessage('Order must contain at least one item'),
  
  body('items.*.product_id')
    .isInt({ min: 1 }).withMessage('Invalid product ID'),
  
  body('items.*.quantity')
    .isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
];

// Payment validation rules
const validatePayment = [
  body('transaction_id')
    .trim()
    .notEmpty().withMessage('Transaction ID is required'),
  
  body('order_id')
    .trim()
    .notEmpty().withMessage('Order ID is required'),
  
  body('amount')
    .isFloat({ min: 0 }).withMessage('Amount must be a positive number'),
];

// Admin login validation
const validateAdminLogin = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email address')
    .normalizeEmail(),
  
  body('password')
    .trim()
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
];

// Validation result handler
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  }
  next();
};

// Sanitization middleware
const sanitizeInput = (req, res, next) => {
  // Sanitize string inputs
  const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str
      .replace(/[<>]/g, '') // Remove < and > to prevent HTML injection
      .trim();
  };

  // Sanitize request body
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = sanitizeString(req.body[key]);
      }
    });
  }

  // Sanitize query parameters
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (typeof req.query[key] === 'string') {
        req.query[key] = sanitizeString(req.query[key]);
      }
    });
  }

  // Sanitize URL parameters
  if (req.params) {
    Object.keys(req.params).forEach(key => {
      if (typeof req.params[key] === 'string') {
        req.params[key] = sanitizeString(req.params[key]);
      }
    });
  }

  next();
};

module.exports = {
  validateProduct,
  validateOrder,
  validatePayment,
  validateAdminLogin,
  validate,
  sanitizeInput
};