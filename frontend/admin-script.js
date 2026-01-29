// Admin application state
const adminState = {
    token: localStorage.getItem('adminToken'),
    user: JSON.parse(localStorage.getItem('adminUser')),
    orders: [],
    products: [],
    customers: [],
    stats: {},
    notifications: []
};

// Backend base URL - define once, use everywhere
const BACKEND_URL = 'https://kuku-yetu.onrender.com';

// Global variable for Google Maps initialization
window.initAdminMap = function() {
    // This function will be called by Google Maps API
    console.log('Google Maps initialized');
    // You can initialize map here if needed
};

// Initialize admin panel
document.addEventListener('DOMContentLoaded', function() {
    checkAdminAuth();
    setupEventListeners();
    
    if (adminState.token) {
        loadDashboardData();
        loadNotifications();
    }
});

// Authentication
function checkAdminAuth() {
    const loginScreen = document.getElementById('loginScreen');
    const adminDashboard = document.getElementById('adminDashboard');
    
    if (adminState.token && adminState.user) {
        // Verify token with backend
        verifyToken().then(isValid => {
            if (isValid) {
                loginScreen.style.display = 'none';
                adminDashboard.style.display = 'flex';
                updateAdminInfo();
                loadSection('dashboard');
            } else {
                logout();
            }
        }).catch(() => {
            logout();
        });
    } else {
        loginScreen.style.display = 'flex';
        adminDashboard.style.display = 'none';
    }
}

async function verifyToken() {
    try {
        const response = await fetch(`${BACKEND_URL}/api/admin/verify`, {
            headers: {
                'Authorization': `Bearer ${adminState.token}`
            }
        });
        return response.ok;
    } catch (error) {
        console.error('Token verification failed:', error);
        return false;
    }
}

// Login form submission - FIXED VERSION
document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const email = document.getElementById('adminEmail').value;
    const password = document.getElementById('adminPassword').value;
    
    // Clear any previous error messages
    const errorElement = document.getElementById('loginError');
    if (errorElement) errorElement.remove();
    
    // Show loading state
    const submitBtn = this.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';
    submitBtn.disabled = true;
    
    try {
        const response = await fetch(`${BACKEND_URL}/api/admin/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                email: email.trim(),
                password: password 
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.token) {
            // Save token and user info
            adminState.token = data.token;
            adminState.user = data.admin || data.user;
            
            localStorage.setItem('adminToken', data.token);
            localStorage.setItem('adminUser', JSON.stringify(adminState.user));
            
            // Switch to dashboard
            checkAdminAuth();
            showNotification('Login successful!', 'success');
        } else {
            // Handle different error responses
            let errorMessage = 'Invalid credentials';
            
            if (response.status === 400) {
                errorMessage = data.message || 'Invalid email or password format';
            } else if (response.status === 401) {
                errorMessage = data.message || 'Invalid credentials';
            } else if (response.status === 404) {
                errorMessage = 'Admin account not found';
            } else if (data.message) {
                errorMessage = data.message;
            }
            
            // Display error message
            const errorDiv = document.createElement('div');
            errorDiv.id = 'loginError';
            errorDiv.style.cssText = `
                background-color: #fee;
                color: #c33;
                padding: 10px;
                border-radius: 5px;
                margin-top: 10px;
                border: 1px solid #fcc;
                font-size: 14px;
            `;
            errorDiv.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${errorMessage}`;
            
            this.appendChild(errorDiv);
            
            // Clear password field
            document.getElementById('adminPassword').value = '';
        }
    } catch (error) {
        console.error('Login error:', error);
        
        const errorDiv = document.createElement('div');
        errorDiv.id = 'loginError';
        errorDiv.style.cssText = `
            background-color: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            border: 1px solid #fcc;
            font-size: 14px;
        `;
        errorDiv.innerHTML = '<i class="fas fa-exclamation-circle"></i> Network error. Please try again.';
        
        this.appendChild(errorDiv);
    } finally {
        // Reset button state
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
});

// Logout
document.getElementById('logoutBtn').addEventListener('click', logout);

function logout() {
    localStorage.removeItem('adminToken');
    localStorage.removeItem('adminUser');
    adminState.token = null;
    adminState.user = null;
    checkAdminAuth();
    showNotification('Logged out successfully', 'info');
}

function updateAdminInfo() {
    if (adminState.user) {
        document.getElementById('adminName').textContent = adminState.user.name || adminState.user.email;
    }
}

// Navigation
function setupEventListeners() {
    // Navigation links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const section = this.dataset.section;
            
            // Update active link
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            
            // Load section
            loadSection(section);
        });
    });
}

async function loadSection(section) {
    const contentArea = document.getElementById('contentArea');
    const pageTitle = document.getElementById('pageTitle');
    
    switch(section) {
        case 'dashboard':
            pageTitle.textContent = 'Dashboard Overview';
            contentArea.innerHTML = await loadDashboardContent();
            renderDashboardCharts();
            break;
            
        case 'products':
            pageTitle.textContent = 'Product Management';
            contentArea.innerHTML = await loadProductsContent();
            break;
            
        case 'orders':
            pageTitle.textContent = 'Order Management';
            contentArea.innerHTML = await loadOrdersContent();
            break;
            
        case 'add-product':
            pageTitle.textContent = 'Add New Product';
            contentArea.innerHTML = loadAddProductContent();
            break;
            
        case 'customers':
            pageTitle.textContent = 'Customer Management';
            contentArea.innerHTML = await loadCustomersContent();
            break;
            
        case 'analytics':
            pageTitle.textContent = 'Analytics & Reports';
            contentArea.innerHTML = loadAnalyticsContent();
            break;
            
        case 'settings':
            pageTitle.textContent = 'Settings';
            contentArea.innerHTML = loadSettingsContent();
            break;
    }
}

// Load dashboard data
async function loadDashboardData() {
    try {
        const [ordersRes, productsRes, statsRes] = await Promise.all([
            fetch(`${BACKEND_URL}/api/admin/orders`, {
                headers: { 'Authorization': `Bearer ${adminState.token}` }
            }),
            fetch(`${BACKEND_URL}/api/admin/products`, {
                headers: { 'Authorization': `Bearer ${adminState.token}` }
            }),
            fetch(`${BACKEND_URL}/api/admin/stats`, {
                headers: { 'Authorization': `Bearer ${adminState.token}` }
            })
        ]);

        // Check if responses are OK
        if (!ordersRes.ok) throw new Error('Failed to load orders');
        if (!productsRes.ok) throw new Error('Failed to load products');
        if (!statsRes.ok) throw new Error('Failed to load stats');

        adminState.orders = await ordersRes.json();
        adminState.products = await productsRes.json();
        adminState.stats = await statsRes.json();
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showNotification('Failed to load dashboard data', 'error');
    }
}

// Dashboard Content
async function loadDashboardContent() {
    await loadDashboardData();
    
    const pendingOrders = adminState.orders.filter(o => o.status === 'pending').length;
    const todayRevenue = adminState.stats.todayRevenue || 0;
    const totalProducts = adminState.products.length;
    const totalCustomers = adminState.stats.totalCustomers || 0;
    
    return `
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon icon-orders">
                    <i class="fas fa-shopping-cart"></i>
                </div>
                <div class="stat-info">
                    <h3>Pending Orders</h3>
                    <div class="stat-value">${pendingOrders}</div>
                    <div class="stat-change positive">
                        <i class="fas fa-arrow-up"></i> 12% from yesterday
                    </div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon icon-revenue">
                    <i class="fas fa-money-bill-wave"></i>
                </div>
                <div class="stat-info">
                    <h3>Today's Revenue</h3>
                    <div class="stat-value">KSh ${todayRevenue.toLocaleString()}</div>
                    <div class="stat-change positive">
                        <i class="fas fa-arrow-up"></i> 8% from yesterday
                    </div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon icon-products">
                    <i class="fas fa-box"></i>
                </div>
                <div class="stat-info">
                    <h3>Total Products</h3>
                    <div class="stat-value">${totalProducts}</div>
                    <div class="stat-change negative">
                        <i class="fas fa-arrow-down"></i> 2 low in stock
                    </div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon icon-pending">
                    <i class="fas fa-users"></i>
                </div>
                <div class="stat-info">
                    <h3>Total Customers</h3>
                    <div class="stat-value">${totalCustomers}</div>
                    <div class="stat-change positive">
                        <i class="fas fa-arrow-up"></i> 5 new today
                    </div>
                </div>
            </div>
        </div>
        
        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 2rem; margin-bottom: 2rem;">
            <div class="chart-container">
                <h3 style="margin-bottom: 1rem;">Revenue Overview</h3>
                <div id="revenueChart" style="height: 300px;"></div>
            </div>
            
            <div class="chart-container">
                <h3 style="margin-bottom: 1rem;">Top Products</h3>
                <div id="topProductsChart" style="height: 300px;"></div>
            </div>
        </div>
        
        <div class="table-container">
            <div class="table-header">
                <h3>Recent Orders</h3>
                <button class="btn btn-secondary" onclick="loadSection('orders')">
                    View All <i class="fas fa-arrow-right"></i>
                </button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Order ID</th>
                        <th>Customer</th>
                        <th>Amount</th>
                        <th>Status</th>
                        <th>Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${adminState.orders.slice(0, 5).map(order => `
                        <tr>
                            <td>${order.order_id}</td>
                            <td>${order.customer_name}</td>
                            <td>KSh ${order.total_amount.toLocaleString()}</td>
                            <td>
                                <span class="status-badge status-${order.status}">
                                    ${order.status.charAt(0).toUpperCase() + order.status.slice(1)}
                                </span>
                            </td>
                            <td>${new Date(order.created_at).toLocaleDateString()}</td>
                            <td>
                                <button class="btn btn-sm btn-secondary" onclick="viewOrderDetails('${order.order_id}')">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Orders Content
async function loadOrdersContent() {
    const orders = adminState.orders;
    
    return `
        <div class="table-container">
            <div class="table-header">
                <h3>All Orders (${orders.length})</h3>
                <div style="display: flex; gap: 0.5rem;">
                    <select id="orderFilter" class="form-control" style="width: auto;">
                        <option value="all">All Status</option>
                        <option value="pending">Pending</option>
                        <option value="paid">Paid</option>
                        <option value="processing">Processing</option>
                        <option value="delivered">Delivered</option>
                        <option value="cancelled">Cancelled</option>
                    </select>
                    <button class="btn btn-primary" onclick="exportOrders()">
                        <i class="fas fa-download"></i> Export
                    </button>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Order ID</th>
                        <th>Customer</th>
                        <th>Phone</th>
                        <th>Amount</th>
                        <th>Status</th>
                        <th>Payment</th>
                        <th>Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${orders.map(order => `
                        <tr>
                            <td>${order.order_id}</td>
                            <td>
                                <div>${order.customer_name}</div>
                                <small style="color: #64748b;">${order.customer_email}</small>
                            </td>
                            <td>${order.customer_phone}</td>
                            <td>KSh ${order.total_amount.toLocaleString()}</td>
                            <td>
                                <select class="status-select form-control" data-order-id="${order.order_id}" style="width: 120px; padding: 0.25rem;">
                                    <option value="pending" ${order.status === 'pending' ? 'selected' : ''}>Pending</option>
                                    <option value="paid" ${order.status === 'paid' ? 'selected' : ''}>Paid</option>
                                    <option value="processing" ${order.status === 'processing' ? 'selected' : ''}>Processing</option>
                                    <option value="delivered" ${order.status === 'delivered' ? 'selected' : ''}>Delivered</option>
                                    <option value="cancelled" ${order.status === 'cancelled' ? 'selected' : ''}>Cancelled</option>
                                </select>
                            </td>
                            <td>
                                <span class="status-badge ${order.payment_status === 'completed' ? 'status-paid' : 'status-pending'}">
                                    ${order.payment_status}
                                </span>
                            </td>
                            <td>${new Date(order.created_at).toLocaleString()}</td>
                            <td>
                                <div style="display: flex; gap: 0.25rem;">
                                    <button class="btn btn-sm btn-secondary" onclick="viewOrderDetails('${order.order_id}')" title="View Details">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                    <button class="btn btn-sm btn-success" onclick="confirmReceipt('${order.order_id}')" title="Confirm Receipt">
                                        <i class="fas fa-check"></i>
                                    </button>
                                    <button class="btn btn-sm btn-primary" onclick="showOrderLocation(${order.delivery_lat}, ${order.delivery_lng})" title="View Location">
                                        <i class="fas fa-map-marker-alt"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
        
        <div style="margin-top: 1rem; display: flex; justify-content: space-between; align-items: center;">
            <div style="color: #64748b;">
                Showing ${orders.length} orders
            </div>
            <div style="display: flex; gap: 0.5rem;">
                <button class="btn btn-secondary" disabled>Previous</button>
                <button class="btn btn-secondary">Next</button>
            </div>
        </div>
    `;
}

// Products Content
async function loadProductsContent() {
    const products = adminState.products;
    
    return `
        <div class="table-container">
            <div class="table-header">
                <h3>All Products (${products.length})</h3>
                <button class="btn btn-primary" onclick="loadSection('add-product')">
                    <i class="fas fa-plus"></i> Add Product
                </button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Product</th>
                        <th>Type</th>
                        <th>Price</th>
                        <th>Quantity</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${products.map(product => `
                        <tr>
                            <td>
                                <div style="display: flex; align-items: center; gap: 1rem;">
                                    <img src="${product.images[0] || 'https://via.placeholder.com/50x50?text=Product'}" 
                                         alt="${product.title}" 
                                         style="width: 50px; height: 50px; object-fit: cover; border-radius: 6px;">
                                    <div>
                                        <div style="font-weight: 500;">${product.title}</div>
                                        <small style="color: #64748b;">${product.description.substring(0, 50)}...</small>
                                    </div>
                                </div>
                            </td>
                            <td>
                                <span class="status-badge status-processing">
                                    ${product.type}
                                </span>
                            </td>
                            <td>KSh ${product.price.toLocaleString()}</td>
                            <td>
                                <div style="display: flex; align-items: center; gap: 0.5rem;">
                                    <span>${product.quantity}</span>
                                    ${product.quantity < 10 ? '<span style="color: var(--danger-color); font-size: 0.8rem;">Low!</span>' : ''}
                                </div>
                            </td>
                            <td>
                                <span class="status-badge ${product.in_stock ? 'status-delivered' : 'status-cancelled'}">
                                    ${product.in_stock ? 'In Stock' : 'Out of Stock'}
                                </span>
                            </td>
                            <td>
                                <div style="display: flex; gap: 0.25rem;">
                                    <button class="btn btn-sm btn-secondary" onclick="editProduct(${product.id})">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteProduct(${product.id})">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Add Product Content
function loadAddProductContent() {
    return `
        <div class="upload-container">
            <form id="productForm">
                <div class="form-group">
                    <label class="form-label">Product Title *</label>
                    <input type="text" class="form-control" id="productTitle" required 
                           placeholder="e.g., Premium Broiler Chicken">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Description *</label>
                    <textarea class="form-control" id="productDescription" rows="4" required
                              placeholder="Describe the product in detail..."></textarea>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem;">
                    <div class="form-group">
                        <label class="form-label">Product Type *</label>
                        <select class="form-control" id="productType" required>
                            <option value="">Select Type</option>
                            <option value="broiler">Broiler</option>
                            <option value="kienyeji">Kienyeji</option>
                            <option value="turkey">Turkey</option>
                            <option value="other">Other</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Price (KSh) *</label>
                        <input type="number" class="form-control" id="productPrice" required 
                               min="0" step="0.01" placeholder="850.00">
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem;">
                    <div class="form-group">
                        <label class="form-label">Quantity *</label>
                        <input type="number" class="form-control" id="productQuantity" required 
                               min="0" placeholder="50">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Availability</label>
                        <select class="form-control" id="productAvailability">
                            <option value="true">In Stock</option>
                            <option value="false">Out of Stock</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Product Images *</label>
                    <div class="image-upload-area" id="imageUploadArea">
                        <div style="margin-bottom: 1rem;">
                            <i class="fas fa-cloud-upload-alt" style="font-size: 3rem; color: #cbd5e1;"></i>
                        </div>
                        <p>Drag & drop images here or click to browse</p>
                        <p style="color: #64748b; font-size: 0.9rem; margin-top: 0.5rem;">
                            Maximum 5 images, each up to 5MB
                        </p>
                        <input type="file" id="imageInput" multiple accept="image/*" 
                               style="display: none;">
                    </div>
                    
                    <div class="image-preview" id="imagePreview">
                        <!-- Images will be previewed here -->
                    </div>
                </div>
                
                <div style="display: flex; gap: 1rem; margin-top: 2rem;">
                    <button type="button" class="btn btn-secondary" onclick="loadSection('products')">
                        Cancel
                    </button>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Product
                    </button>
                </div>
            </form>
        </div>
    `;
}

// Customers Content
async function loadCustomersContent() {
    // Try to load customers from API
    try {
        const response = await fetch(`${BACKEND_URL}/api/admin/customers`, {
            headers: { 'Authorization': `Bearer ${adminState.token}` }
        });
        
        if (response.ok) {
            adminState.customers = await response.json();
        }
    } catch (error) {
        console.error('Error loading customers:', error);
        adminState.customers = [];
    }
    
    const customers = adminState.customers;
    
    return `
        <div class="table-container">
            <div class="table-header">
                <h3>Customers (${customers.length})</h3>
                <input type="text" class="form-control" placeholder="Search customers..." 
                       style="width: 300px;">
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Customer</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Orders</th>
                        <th>Total Spent</th>
                        <th>Last Order</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${customers.map(customer => `
                        <tr>
                            <td>
                                <div style="font-weight: 500;">${customer.name}</div>
                            </td>
                            <td>${customer.email}</td>
                            <td>${customer.phone}</td>
                            <td>${customer.order_count || 0}</td>
                            <td>KSh ${(customer.total_spent || 0).toLocaleString()}</td>
                            <td>${customer.last_order ? new Date(customer.last_order).toLocaleDateString() : 'Never'}</td>
                            <td>
                                <button class="btn btn-sm btn-secondary">
                                    <i class="fas fa-envelope"></i> Email
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Order Functions
async function viewOrderDetails(orderId) {
    try {
        const response = await fetch(`${BACKEND_URL}/api/admin/orders/${orderId}`, {
            headers: { 'Authorization': `Bearer ${adminState.token}` }
        });
        
        if (!response.ok) {
            throw new Error('Failed to load order details');
        }
        
        const order = await response.json();
        
        const modal = document.getElementById('orderDetailModal');
        modal.querySelector('.modal-content').innerHTML = `
            <div style="padding: 2rem;">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 2rem;">
                    <div>
                        <h2>Order #${order.order_id}</h2>
                        <p style="color: #64748b;">Placed on ${new Date(order.created_at).toLocaleString()}</p>
                    </div>
                    <button class="btn btn-secondary" onclick="closeModal('orderDetailModal')">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                
                <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 2rem;">
                    <div>
                        <h3 style="margin-bottom: 1rem;">Order Items</h3>
                        <div style="background: #f8fafc; padding: 1.5rem; border-radius: 8px;">
                            ${order.items && order.items.map(item => `
                                <div style="display: flex; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid #e2e8f0;">
                                    <div>
                                        <div style="font-weight: 500;">${item.title}</div>
                                        <div style="color: #64748b; font-size: 0.9rem;">Qty: ${item.quantity}</div>
                                    </div>
                                    <div style="font-weight: 500;">
                                        KSh ${((item.price || 0) * (item.quantity || 0)).toLocaleString()}
                                    </div>
                                </div>
                            `).join('') || 'No items found'}
                            
                            <div style="padding-top: 1rem;">
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                                    <span>Subtotal:</span>
                                    <span>KSh ${((order.total_amount || 0) - 200).toLocaleString()}</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                                    <span>Delivery:</span>
                                    <span>KSh 200.00</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; font-size: 1.2rem; font-weight: bold; border-top: 2px solid #e2e8f0; padding-top: 0.5rem;">
                                    <span>Total:</span>
                                    <span>KSh ${(order.total_amount || 0).toLocaleString()}</span>
                                </div>
                            </div>
                        </div>
                        
                        <h3 style="margin: 2rem 0 1rem 0;">Customer Information</h3>
                        <div style="background: #f8fafc; padding: 1.5rem; border-radius: 8px;">
                            <p><strong>Name:</strong> ${order.customer_name || 'N/A'}</p>
                            <p><strong>Email:</strong> ${order.customer_email || 'N/A'}</p>
                            <p><strong>Phone:</strong> ${order.customer_phone || 'N/A'}</p>
                            <p><strong>Delivery Location:</strong> 
                                ${order.delivery_lat && order.delivery_lng ? 
                                    `<button class="btn btn-sm btn-secondary" onclick="showOrderLocation(${order.delivery_lat}, ${order.delivery_lng})">
                                        <i class="fas fa-map-marker-alt"></i> View on Map
                                    </button>` : 
                                    'N/A'}
                            </p>
                        </div>
                    </div>
                    
                    <div>
                        <h3 style="margin-bottom: 1rem;">Order Status</h3>
                        <div style="background: #f8fafc; padding: 1.5rem; border-radius: 8px;">
                            <div style="margin-bottom: 1rem;">
                                <div style="font-weight: 500; margin-bottom: 0.5rem;">Current Status</div>
                                <select class="form-control" onchange="updateOrderStatus('${order.order_id}', this.value)">
                                    <option value="pending" ${order.status === 'pending' ? 'selected' : ''}>Pending</option>
                                    <option value="paid" ${order.status === 'paid' ? 'selected' : ''}>Paid</option>
                                    <option value="processing" ${order.status === 'processing' ? 'selected' : ''}>Processing</option>
                                    <option value="delivered" ${order.status === 'delivered' ? 'selected' : ''}>Delivered</option>
                                    <option value="cancelled" ${order.status === 'cancelled' ? 'selected' : ''}>Cancelled</option>
                                </select>
                            </div>
                            
                            <div style="margin-bottom: 1rem;">
                                <div style="font-weight: 500; margin-bottom: 0.5rem;">Payment Status</div>
                                <span class="status-badge ${order.payment_status === 'completed' ? 'status-paid' : 'status-pending'}">
                                    ${order.payment_status || 'pending'}
                                </span>
                            </div>
                            
                            <div>
                                <div style="font-weight: 500; margin-bottom: 0.5rem;">Transaction ID</div>
                                <code style="background: white; padding: 0.5rem; border-radius: 4px; display: block; font-size: 0.9rem;">
                                    ${order.transaction_id || 'N/A'}
                                </code>
                            </div>
                        </div>
                        
                        ${order.status !== 'delivered' ? `
                        <div style="margin-top: 2rem;">
                            <button class="btn btn-success" style="width: 100%;" onclick="confirmReceipt('${order.order_id}')">
                                <i class="fas fa-check"></i> Confirm Receipt & Notify Customer
                            </button>
                        </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
        
        modal.style.display = 'flex';
    } catch (error) {
        console.error('Error loading order details:', error);
        showNotification('Failed to load order details', 'error');
    }
}

async function confirmReceipt(orderId) {
    if (!confirm('Confirm receipt of this order and notify customer?')) return;
    
    try {
        const response = await fetch(`${BACKEND_URL}/api/admin/orders/${orderId}/confirm`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${adminState.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                estimated_delivery: new Date(Date.now() + 3 * 60 * 60 * 1000).toISOString() // 3 hours from now
            })
        });
        
        if (response.ok) {
            showNotification('Order confirmed! Customer has been notified.', 'success');
            closeModal('orderDetailModal');
            loadSection('orders'); // Refresh orders list
        } else {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to confirm order');
        }
    } catch (error) {
        console.error('Error confirming order:', error);
        showNotification(error.message || 'Failed to confirm order', 'error');
    }
}

async function updateOrderStatus(orderId, status) {
    try {
        const response = await fetch(`${BACKEND_URL}/api/admin/orders/${orderId}/status`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${adminState.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status })
        });
        
        if (response.ok) {
            showNotification('Order status updated', 'success');
            // Update local state
            const order = adminState.orders.find(o => o.order_id === orderId);
            if (order) {
                order.status = status;
            }
        } else {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to update status');
        }
    } catch (error) {
        console.error('Error updating order status:', error);
        showNotification(error.message || 'Failed to update status', 'error');
    }
}

// Map Functions - FIXED
let adminMap = null;

// Make showOrderLocation globally available
window.showOrderLocation = function(lat, lng) {
    const modal = document.getElementById('mapModal');
    const mapElement = document.getElementById('adminMap');
    
    if (!mapElement) {
        showNotification('Map element not found', 'error');
        return;
    }
    
    modal.style.display = 'flex';
    
    // Initialize map if not already initialized
    if (!adminMap) {
        adminMap = new google.maps.Map(mapElement, {
            center: { lat: parseFloat(lat), lng: parseFloat(lng) },
            zoom: 15,
            mapTypeControl: true,
            streetViewControl: true
        });
    } else {
        adminMap.setCenter({ lat: parseFloat(lat), lng: parseFloat(lng) });
    }
    
    // Clear existing markers
    if (window.adminMarker) {
        window.adminMarker.setMap(null);
    }
    
    // Add marker
    window.adminMarker = new google.maps.Marker({
        position: { lat: parseFloat(lat), lng: parseFloat(lng) },
        map: adminMap,
        title: "Delivery Location"
    });
}

// Make closeModal globally available
window.closeModal = function(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
};

// Chart Functions
function renderDashboardCharts() {
    // Check if Google Charts is available
    if (typeof google === 'undefined') {
        console.warn('Google Charts not loaded');
        return;
    }
    
    // Load Google Charts
    google.charts.load('current', { packages: ['corechart'] });
    google.charts.setOnLoadCallback(drawCharts);
}

function drawCharts() {
    // Check if elements exist
    const revenueChartEl = document.getElementById('revenueChart');
    const topProductsChartEl = document.getElementById('topProductsChart');
    
    if (!revenueChartEl || !topProductsChartEl) {
        return;
    }
    
    // Revenue Chart
    const revenueData = google.visualization.arrayToDataTable([
        ['Day', 'Revenue'],
        ['Mon', 12000],
        ['Tue', 18500],
        ['Wed', 15500],
        ['Thu', 22000],
        ['Fri', 28000],
        ['Sat', 35000],
        ['Sun', 25000]
    ]);

    const revenueOptions = {
        title: '',
        curveType: 'function',
        legend: { position: 'none' },
        colors: ['#f97316'],
        backgroundColor: 'transparent',
        hAxis: { textStyle: { color: '#64748b' } },
        vAxis: { 
            textStyle: { color: '#64748b' },
            format: 'KSh #,###'
        }
    };

    const revenueChart = new google.visualization.LineChart(revenueChartEl);
    revenueChart.draw(revenueData, revenueOptions);

    // Top Products Chart
    const productData = google.visualization.arrayToDataTable([
        ['Product', 'Sales'],
        ['Broiler Chicken', 45],
        ['Kienyeji Chicken', 32],
        ['Turkey Breast', 18],
        ['Chicken Wings', 25],
        ['Eggs (Tray)', 40]
    ]);

    const productOptions = {
        title: '',
        pieHole: 0.4,
        colors: ['#f97316', '#fb923c', '#fdba74', '#fed7aa', '#ffedd5'],
        backgroundColor: 'transparent',
        legend: { textStyle: { color: '#64748b' } }
    };

    const productChart = new google.visualization.PieChart(topProductsChartEl);
    productChart.draw(productData, productOptions);
}

// Notifications
async function loadNotifications() {
    try {
        const response = await fetch(`${BACKEND_URL}/api/admin/notifications`, {
            headers: { 'Authorization': `Bearer ${adminState.token}` }
        });
        
        if (response.ok) {
            adminState.notifications = await response.json();
            updateNotificationCounts();
        }
    } catch (error) {
        console.error('Error loading notifications:', error);
    }
}

function updateNotificationCounts() {
    const pendingOrders = adminState.orders.filter(o => o.status === 'pending').length;
    
    const orderNotification = document.getElementById('orderNotification');
    const globalNotification = document.getElementById('globalNotification');
    
    if (orderNotification) {
        orderNotification.textContent = pendingOrders;
    }
    
    if (globalNotification) {
        globalNotification.textContent = adminState.notifications.length;
    }
}

function showNotification(message, type = 'info') {
    // Create and show notification
    const notification = document.createElement('div');
    notification.className = 'admin-notification';
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#f97316'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
    `;
    
    notification.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                document.body.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

// Make other functions globally available
window.loadSection = loadSection;
window.viewOrderDetails = viewOrderDetails;
window.confirmReceipt = confirmReceipt;
window.updateOrderStatus = updateOrderStatus;
window.exportOrders = exportOrders;
window.editProduct = function(id) {
    showNotification('Edit product feature coming soon', 'info');
};
window.deleteProduct = function(id) {
    if (confirm('Are you sure you want to delete this product?')) {
        showNotification('Product deleted (demo)', 'success');
    }
};

// Export functions
function exportOrders() {
    const data = adminState.orders.map(order => ({
        'Order ID': order.order_id,
        'Customer': order.customer_name,
        'Email': order.customer_email,
        'Phone': order.customer_phone,
        'Amount': `KSh ${order.total_amount}`,
        'Status': order.status,
        'Payment': order.payment_status,
        'Date': new Date(order.created_at).toLocaleString()
    }));
    
    // Convert to CSV
    const csv = convertToCSV(data);
    downloadCSV(csv, 'kuku-yetu-orders.csv');
}

function convertToCSV(data) {
    if (!data.length) return '';
    const headers = Object.keys(data[0]);
    const rows = data.map(row => headers.map(header => `"${row[header] || ''}"`).join(','));
    return [headers.join(','), ...rows].join('\n');
}

function downloadCSV(csv, filename) {
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Product Management
document.addEventListener('click', function(e) {
    // Handle image upload
    if (e.target.closest('#imageUploadArea')) {
        document.getElementById('imageInput').click();
    }
    
    // Handle status updates
    if (e.target.closest('.status-select')) {
        const select = e.target.closest('.status-select');
        const orderId = select.dataset.orderId;
        const status = select.value;
        updateOrderStatus(orderId, status);
    }
});

// Handle image upload
document.addEventListener('change', function(e) {
    if (e.target.id === 'imageInput') {
        const files = Array.from(e.target.files);
        const preview = document.getElementById('imagePreview');
        
        if (!preview) return;
        
        // Clear existing previews
        preview.innerHTML = '';
        
        files.forEach(file => {
            if (file.size > 5 * 1024 * 1024) {
                alert(`File ${file.name} is too large. Maximum size is 5MB.`);
                return;
            }
            
            const reader = new FileReader();
            reader.onload = function(e) {
                const imgContainer = document.createElement('div');
                imgContainer.style.position = 'relative';
                imgContainer.style.display = 'inline-block';
                imgContainer.style.margin = '5px';
                
                imgContainer.innerHTML = `
                    <img src="${e.target.result}" style="width: 100px; height: 100px; object-fit: cover; border-radius: 4px;">
                    <button class="remove-image" onclick="this.parentElement.remove()" 
                            style="position: absolute; top: 5px; right: 5px; background: #ef4444; color: white; border: none; border-radius: 50%; width: 20px; height: 20px; cursor: pointer; font-size: 12px;">
                        <i class="fas fa-times"></i>
                    </button>
                `;
                
                preview.appendChild(imgContainer);
            };
            reader.readAsDataURL(file);
        });
    }
});

// Handle product form submission
document.addEventListener('submit', async function(e) {
    if (e.target.id === 'productForm') {
        e.preventDefault();
        
        const formData = new FormData();
        formData.append('title', document.getElementById('productTitle').value);
        formData.append('description', document.getElementById('productDescription').value);
        formData.append('type', document.getElementById('productType').value);
        formData.append('price', document.getElementById('productPrice').value);
        formData.append('quantity', document.getElementById('productQuantity').value);
        formData.append('in_stock', document.getElementById('productAvailability').value);
        
        // Add images
        const imageInput = document.getElementById('imageInput');
        for (let i = 0; i < imageInput.files.length; i++) {
            formData.append('images', imageInput.files[i]);
        }
        
        try {
            const response = await fetch(`${BACKEND_URL}/api/admin/products`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${adminState.token}`
                },
                body: formData
            });
            
            if (response.ok) {
                showNotification('Product added successfully!', 'success');
                loadSection('products');
            } else {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Failed to add product');
            }
        } catch (error) {
            console.error('Error adding product:', error);
            showNotification(error.message || 'Failed to add product', 'error');
        }
    }
});

// Add CSS animations
const adminStyle = document.createElement('style');
adminStyle.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    /* Print styles for receipts */
    @media print {
        .sidebar, .header, .no-print {
            display: none !important;
        }
        
        .main-content {
            margin-left: 0 !important;
            padding: 0 !important;
        }
        
        .modal-content {
            box-shadow: none !important;
            border: 1px solid #ddd !important;
        }
    }
    
    .admin-notification {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: #f97316;
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    }
`;
document.head.appendChild(adminStyle);
