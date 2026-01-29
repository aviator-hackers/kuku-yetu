const express = require('express');
const router = express.Router();
const multer = require('multer');
const ProductController = require('../controllers/productController');
const { validateProduct, validate, sanitizeInput } = require('../middleware/validation');
const { auth, adminAuth } = require('../middleware/auth');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + '.' + file.originalname.split('.').pop());
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 5 // Maximum 5 files
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(file.originalname.toLowerCase().split('.').pop());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed (jpeg, jpg, png, gif, webp)'));
    }
  }
});

// Public routes
router.get('/', ProductController.getAllProducts);
router.get('/:id', ProductController.getProductById);

// Admin routes (protected)
router.post('/', 
  auth, 
  adminAuth,
  sanitizeInput,
  upload.array('images', 5),
  validateProduct,
  validate,
  ProductController.createProduct
);

router.put('/:id',
  auth,
  adminAuth,
  sanitizeInput,
  upload.array('images', 5),
  validateProduct,
  validate,
  ProductController.updateProduct
);

router.delete('/:id',
  auth,
  adminAuth,
  ProductController.deleteProduct
);

router.patch('/:id/stock',
  auth,
  adminAuth,
  sanitizeInput,
  ProductController.updateStock
);

// Error handling for multer
router.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: 'File too large. Maximum size is 5MB.'
      });
    }
    
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        error: 'Too many files. Maximum 5 images allowed.'
      });
    }
    
    return res.status(400).json({
      success: false,
      error: error.message
    });
  } else if (error) {
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }
  
  next();
});

module.exports = router;