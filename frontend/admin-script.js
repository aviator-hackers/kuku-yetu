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
        const response = await fetch('https://kuku-yetu.onrender.com//api/admin/verify', {
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

// Login form submission
document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const email = document.getElementById('adminEmail').value;
    const password = document.getElementById('adminPassword').value;
    
    try {
        const response = await fetch('https://your-backend.onrender.com/api/admin/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Save token and user info
            adminState.token = data.token;
            adminState.user = data.user;
            
            localStorage.setItem('adminToken', data.token);
            localStorage.setItem('adminUser', JSON.stringify(data.user));
            
            // Switch to dashboard
            checkAdminAuth();
            showNotification('Login successful!', 'success');
        } else {
            alert('Invalid credentials');
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please try again.');
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
            fetch('https://your-backend.onrender.com/api/admin/orders', {
                headers: { 'Authorization': `Bearer ${adminState.token}` }
            }),
            fetch('https://your-backend.onrender.com/api/admin/products', {
                headers: { 'Authorization': `Bearer ${adminState.token}` }
            }),
            fetch('https://your-backend.onrender.com/api/admin/stats', {
                headers: { 'Authorization': `Bearer ${adminState.token}` }
            })
        ]);

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
    const customers = adminState.customers || [];
    
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

// Analytics Content
function loadAnalyticsContent() {
    return `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem;">
            <div class="chart-container">
                <h3 style="margin-bottom: 1rem;">Sales Trend (Last 30 Days)</h3>
                <div id="salesTrendChart" style="height: 300px;"></div>
            </div>
            
            <div class="chart-container">
                <h3 style="margin-bottom: 1rem;">Order Status Distribution</h3>
                <div id="orderStatusChart" style="height: 300px;"></div>
            </div>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
            <div class="chart-container">
                <h3 style="margin-bottom: 1rem;">Top Selling Products</h3>
                <div id="topSellingChart" style="height: 300px;"></div>
            </div>
            
            <div class="chart-container">
                <h3 style="margin-bottom: 1rem;">Customer Acquisition</h3>
                <div id="customerChart" style="height: 300px;"></div>
            </div>
        </div>
        
        <div class="table-container" style="margin-top: 2rem;">
            <div class="table-header">
                <h3>Sales Report</h3>
                <div style="display: flex; gap: 0.5rem;">
                    <select class="form-control" style="width: auto;">
                        <option>Last 7 days</option>
                        <option>Last 30 days</option>
                        <option>Last 90 days</option>
                        <option>This year</option>
                    </select>
                    <button class="btn btn-primary">
                        <i class="fas fa-download"></i> Download Report
                    </button>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Orders</th>
                        <th>Revenue</th>
                        <th>Avg. Order Value</th>
                        <th>Conversion Rate</th>
                        <th>New Customers</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Today</td>
                        <td>15</td>
                        <td>KSh 45,200</td>
                        <td>KSh 3,013</td>
                        <td>2.4%</td>
                        <td>5</td>
                    </tr>
                    <tr>
                        <td>Yesterday</td>
                        <td>23</td>
                        <td>KSh 62,500</td>
                        <td>KSh 2,717</td>
                        <td>3.1%</td>
                        <td>8</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;
}

// Settings Content
function loadSettingsContent() {
    return `
        <div class="upload-container">
            <h3 style="margin-bottom: 1.5rem;">Store Settings</h3>
            
            <form id="settingsForm">
                <div class="form-group">
                    <label class="form-label">Store Name</label>
                    <input type="text" class="form-control" value="Kuku Yetu">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Store Email</label>
                    <input type="email" class="form-control" value="contact@kukuyetu.co.ke">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Store Phone</label>
                    <input type="tel" class="form-control" value="+254 700 000 000">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Delivery Fee (KSh)</label>
                    <input type="number" class="form-control" value="200">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Store Address</label>
                    <textarea class="form-control" rows="3">Nairobi, Kenya</textarea>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Business Hours</label>
                    <input type="text" class="form-control" value="7:00 AM - 10:00 PM (Daily)">
                </div>
                
                <h4 style="margin: 2rem 0 1rem 0;">Payment Settings</h4>
                
                <div class="form-group">
                    <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                        <input type="checkbox" id="enableMpesa" checked>
                        <label for="enableMpesa">Enable M-Pesa Payments</label>
                    </div>
                    
                    <div style="display: flex; align-items: center; gap: 1rem;">
                        <input type="checkbox" id="enableCard" checked>
                        <label for="enableCard">Enable Card Payments</label>
                    </div>
                </div>
                
                <div style="margin-top: 2rem; display: flex; gap: 1rem;">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Settings
                    </button>
                    <button type="button" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Clear Cache
                    </button>
                </div>
            </form>
        </div>
    `;
}

// Order Functions
async function viewOrderDetails(orderId) {
    try {
        const response = await fetch(`https://your-backend.onrender.com/api/admin/orders/${orderId}`, {
            headers: { 'Authorization': `Bearer ${adminState.token}` }
        });
        
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
                            ${order.items.map(item => `
                                <div style="display: flex; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid #e2e8f0;">
                                    <div>
                                        <div style="font-weight: 500;">${item.title}</div>
                                        <div style="color: #64748b; font-size: 0.9rem;">Qty: ${item.quantity}</div>
                                    </div>
                                    <div style="font-weight: 500;">
                                        KSh ${(item.price * item.quantity).toLocaleString()}
                                    </div>
                                </div>
                            `).join('')}
                            
                            <div style="padding-top: 1rem;">
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                                    <span>Subtotal:</span>
                                    <span>KSh ${(order.total_amount - 200).toLocaleString()}</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                                    <span>Delivery:</span>
                                    <span>KSh 200.00</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; font-size: 1.2rem; font-weight: bold; border-top: 2px solid #e2e8f0; padding-top: 0.5rem;">
                                    <span>Total:</span>
                                    <span>KSh ${order.total_amount.toLocaleString()}</span>
                                </div>
                            </div>
                        </div>
                        
                        <h3 style="margin: 2rem 0 1rem 0;">Customer Information</h3>
                        <div style="background: #f8fafc; padding: 1.5rem; border-radius: 8px;">
                            <p><strong>Name:</strong> ${order.customer_name}</p>
                            <p><strong>Email:</strong> ${order.customer_email}</p>
                            <p><strong>Phone:</strong> ${order.customer_phone}</p>
                            <p><strong>Delivery Location:</strong> 
                                <button class="btn btn-sm btn-secondary" onclick="showOrderLocation(${order.delivery_lat}, ${order.delivery_lng})">
                                    <i class="fas fa-map-marker-alt"></i> View on Map
                                </button>
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
                                    ${order.payment_status}
                                </span>
                            </div>
                            
                            <div>
                                <div style="font-weight: 500; margin-bottom: 0.5rem;">Transaction ID</div>
                                <code style="background: white; padding: 0.5rem; border-radius: 4px; display: block; font-size: 0.9rem;">
                                    ${order.transaction_id || 'N/A'}
                                </code>
                            </div>
                        </div>
                        
                        <div style="margin-top: 2rem;">
                            <button class="btn btn-success" style="width: 100%;" onclick="confirmReceipt('${order.order_id}')">
                                <i class="fas fa-check"></i> Confirm Receipt & Notify Customer
                            </button>
                        </div>
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
        const response = await fetch(`https://your-backend.onrender.com/api/admin/orders/${orderId}/confirm`, {
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
            throw new Error('Failed to confirm order');
        }
    } catch (error) {
        console.error('Error confirming order:', error);
        showNotification('Failed to confirm order', 'error');
    }
}

async function updateOrderStatus(orderId, status) {
    try {
        const response = await fetch(`https://your-backend.onrender.com/api/admin/orders/${orderId}/status`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${adminState.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status })
        });
        
        if (response.ok) {
            showNotification('Order status updated', 'success');
        }
    } catch (error) {
        console.error('Error updating order status:', error);
        showNotification('Failed to update status', 'error');
    }
}

// Map Functions
let adminMap = null;

function initAdminMap() {
    // Initialize map for admin panel
}

function showOrderLocation(lat, lng) {
    const modal = document.getElementById('mapModal');
    
    if (!adminMap) {
        adminMap = new google.maps.Map(document.getElementById('adminMap'), {
            center: { lat, lng },
            zoom: 15,
            mapTypeControl: true,
            streetViewControl: true
        });
    } else {
        adminMap.setCenter({ lat, lng });
    }
    
    // Add marker
    new google.maps.Marker({
        position: { lat, lng },
        map: adminMap,
        title: "Delivery Location"
    });
    
    modal.style.display = 'flex';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

// Chart Functions
function renderDashboardCharts() {
    // Load Google Charts
    google.charts.load('current', { packages: ['corechart'] });
    google.charts.setOnLoadCallback(drawCharts);
}

function drawCharts() {
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

    const revenueChart = new google.visualization.LineChart(document.getElementById('revenueChart'));
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

    const productChart = new google.visualization.PieChart(document.getElementById('topProductsChart'));
    productChart.draw(productData, productOptions);
}

// Notifications
async function loadNotifications() {
    try {
        const response = await fetch('https://your-backend.onrender.com/api/admin/notifications', {
            headers: { 'Authorization': `Bearer ${adminState.token}` }
        });
        
        adminState.notifications = await response.json();
        updateNotificationCounts();
    } catch (error) {
        console.error('Error loading notifications:', error);
    }
}

function updateNotificationCounts() {
    const pendingOrders = adminState.orders.filter(o => o.status === 'pending').length;
    
    document.getElementById('orderNotification').textContent = pendingOrders;
    document.getElementById('globalNotification').textContent = adminState.notifications.length;
}

function showNotification(message, type = 'info') {
    // Create and show notification
    const notification = document.createElement('div');
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
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

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
    const headers = Object.keys(data[0]);
    const rows = data.map(row => headers.map(header => `"${row[header]}"`).join(','));
    return [headers.join(','), ...rows].join('\n');
}

function downloadCSV(csv, filename) {
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
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
                
                imgContainer.innerHTML = `
                    <img src="${e.target.result}" class="preview-image">
                    <button class="remove-image" onclick="removePreviewImage(this)">
                        <i class="fas fa-times"></i>
                    </button>
                `;
                
                preview.appendChild(imgContainer);
            };
            reader.readAsDataURL(file);
        });
    }
});

function removePreviewImage(button) {
    button.parentElement.remove();
}

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
            const response = await fetch('https://your-backend.onrender.com/api/admin/products', {
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
                throw new Error('Failed to add product');
            }
        } catch (error) {
            console.error('Error adding product:', error);
            showNotification('Failed to add product', 'error');
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
`;
document.head.appendChild(adminStyle);
