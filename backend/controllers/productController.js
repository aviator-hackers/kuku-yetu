const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

class ProductController {
  // Get all products
  static async getAllProducts(req, res) {
    try {
      const { type, in_stock, page = 1, limit = 20 } = req.query;
      const offset = (page - 1) * limit;
      
      let query = 'SELECT * FROM products WHERE 1=1';
      let params = [];
      let paramCount = 1;

      if (type) {
        query += ` AND type = $${paramCount}`;
        params.push(type);
        paramCount++;
      }

      if (in_stock === 'true') {
        query += ' AND in_stock = true AND quantity > 0';
      } else if (in_stock === 'false') {
        query += ' AND (in_stock = false OR quantity = 0)';
      }

      // Get total count
      const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
      const countResult = await pool.query(countQuery, params);
      const total = parseInt(countResult.rows[0].total);

      // Get paginated results
      query += ` ORDER BY created_at DESC LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
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
      console.error('Error fetching products:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to fetch products' 
      });
    }
  }

  // Get single product
  static async getProductById(req, res) {
    try {
      const { id } = req.params;
      
      const result = await pool.query(
        'SELECT * FROM products WHERE id = $1',
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ 
          success: false, 
          error: 'Product not found' 
        });
      }

      res.json({
        success: true,
        data: result.rows[0]
      });
    } catch (error) {
      console.error('Error fetching product:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to fetch product' 
      });
    }
  }

  // Create product (Admin only)
  static async createProduct(req, res) {
    try {
      const { title, description, type, price, quantity, in_stock = true } = req.body;
      
      // Handle image uploads
      let imageUrls = [];
      if (req.files && req.files.images) {
        const files = Array.isArray(req.files.images) ? req.files.images : [req.files.images];
        
        for (const file of files) {
          const result = await cloudinary.uploader.upload(file.path, {
            folder: 'kuku-yetu/products',
            resource_type: 'auto'
          });
          imageUrls.push(result.secure_url);
        }
      }

      const result = await pool.query(
        `INSERT INTO products (
          title, description, type, price, quantity, 
          images, in_stock, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        RETURNING *`,
        [title, description, type, price, quantity, imageUrls, in_stock]
      );

      res.status(201).json({
        success: true,
        message: 'Product created successfully',
        data: result.rows[0]
      });
    } catch (error) {
      console.error('Error creating product:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to create product' 
      });
    }
  }

  // Update product (Admin only)
  static async updateProduct(req, res) {
    try {
      const { id } = req.params;
      const { title, description, type, price, quantity, in_stock } = req.body;
      
      // Check if product exists
      const checkResult = await pool.query(
        'SELECT * FROM products WHERE id = $1',
        [id]
      );

      if (checkResult.rows.length === 0) {
        return res.status(404).json({ 
          success: false, 
          error: 'Product not found' 
        });
      }

      const currentProduct = checkResult.rows[0];
      
      // Handle image uploads if new images provided
      let imageUrls = currentProduct.images;
      if (req.files && req.files.images) {
        // Delete old images from Cloudinary
        for (const imageUrl of imageUrls) {
          const publicId = imageUrl.split('/').pop().split('.')[0];
          await cloudinary.uploader.destroy(`kuku-yetu/products/${publicId}`);
        }

        // Upload new images
        const files = Array.isArray(req.files.images) ? req.files.images : [req.files.images];
        imageUrls = [];
        
        for (const file of files) {
          const result = await cloudinary.uploader.upload(file.path, {
            folder: 'kuku-yetu/products',
            resource_type: 'auto'
          });
          imageUrls.push(result.secure_url);
        }
      }

      const result = await pool.query(
        `UPDATE products 
         SET title = COALESCE($1, title),
             description = COALESCE($2, description),
             type = COALESCE($3, type),
             price = COALESCE($4, price),
             quantity = COALESCE($5, quantity),
             images = $6,
             in_stock = COALESCE($7, in_stock),
             updated_at = NOW()
         WHERE id = $8
         RETURNING *`,
        [title, description, type, price, quantity, imageUrls, in_stock, id]
      );

      res.json({
        success: true,
        message: 'Product updated successfully',
        data: result.rows[0]
      });
    } catch (error) {
      console.error('Error updating product:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to update product' 
      });
    }
  }

  // Delete product (Admin only)
  static async deleteProduct(req, res) {
    try {
      const { id } = req.params;
      
      // Check if product exists
      const checkResult = await pool.query(
        'SELECT * FROM products WHERE id = $1',
        [id]
      );

      if (checkResult.rows.length === 0) {
        return res.status(404).json({ 
          success: false, 
          error: 'Product not found' 
        });
      }

      const product = checkResult.rows[0];
      
      // Delete images from Cloudinary
      if (product.images && product.images.length > 0) {
        for (const imageUrl of product.images) {
          const publicId = imageUrl.split('/').pop().split('.')[0];
          await cloudinary.uploader.destroy(`kuku-yetu/products/${publicId}`);
        }
      }

      // Delete product from database
      await pool.query('DELETE FROM products WHERE id = $1', [id]);

      res.json({
        success: true,
        message: 'Product deleted successfully'
      });
    } catch (error) {
      console.error('Error deleting product:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to delete product' 
      });
    }
  }

  // Update product stock
  static async updateStock(req, res) {
    try {
      const { id } = req.params;
      const { quantity, action = 'set' } = req.body; // action: 'set', 'add', 'subtract'

      const checkResult = await pool.query(
        'SELECT quantity FROM products WHERE id = $1',
        [id]
      );

      if (checkResult.rows.length === 0) {
        return res.status(404).json({ 
          success: false, 
          error: 'Product not found' 
        });
      }

      const currentQuantity = checkResult.rows[0].quantity;
      let newQuantity;

      switch (action) {
        case 'add':
          newQuantity = currentQuantity + quantity;
          break;
        case 'subtract':
          newQuantity = Math.max(0, currentQuantity - quantity);
          break;
        case 'set':
        default:
          newQuantity = quantity;
      }

      const result = await pool.query(
        `UPDATE products 
         SET quantity = $1, 
             in_stock = $1 > 0,
             updated_at = NOW()
         WHERE id = $2
         RETURNING *`,
        [newQuantity, id]
      );

      res.json({
        success: true,
        message: 'Stock updated successfully',
        data: result.rows[0]
      });
    } catch (error) {
      console.error('Error updating stock:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to update stock' 
      });
    }
  }
}

module.exports = ProductController;