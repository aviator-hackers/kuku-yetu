const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const auth = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false, 
        error: 'Access denied. No token provided.' 
      });
    }

    const token = authHeader.replace('Bearer ', '');
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if token is blacklisted (for logout functionality)
    const tokenCheck = await pool.query(
      'SELECT * FROM blacklisted_tokens WHERE token = $1',
      [token]
    );
    
    if (tokenCheck.rows.length > 0) {
      return res.status(401).json({ 
        success: false, 
        error: 'Token has been invalidated. Please login again.' 
      });
    }

    // Check if user still exists
    const userCheck = await pool.query(
      'SELECT id, email, username, role FROM admin_users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userCheck.rows.length === 0) {
      return res.status(401).json({ 
        success: false, 
        error: 'User no longer exists.' 
      });
    }

    // Attach user to request
    req.user = userCheck.rows[0];
    req.token = token;
    next();
    
  } catch (error) {
    console.error('Auth middleware error:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid token.' 
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Token has expired. Please login again.' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Authentication failed.' 
    });
  }
};

const adminAuth = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false, 
      error: 'Access denied. Admin privileges required.' 
    });
  }
  next();
};

module.exports = { auth, adminAuth };