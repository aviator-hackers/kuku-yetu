// Main application state
const appState = {
    cart: JSON.parse(localStorage.getItem('kukuYetuCart')) || [],
    products: [],
    currentLocation: null,
    map: null,
    marker: null
};

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    loadProducts();
    updateCartCount();
    setupEventListeners();
});

function initializeApp() {
    // Initialize Google Maps
    if (typeof google !== 'undefined') {
        initMap();
    }
}

function loadProducts() {
    // In a real app, fetch from backend API
    const sampleProducts = [
        {
            id: 1,
            title: "Fresh Broiler Chicken",
            description: "Premium farm-fresh broiler chicken, perfect for roasting or grilling. Delivered within 3 hours of processing.",
            price: 850,
            type: "broiler",
            images: ["chicken1.jpg", "chicken2.jpg"],
            inStock: true,
            quantity: 50
        },
        {
            id: 2,
            title: "Kienyeji Chicken",
            description: "Free-range indigenous chicken, naturally fed for superior taste and nutrition.",
            price: 1500,
            type: "kienyeji",
            images: ["kienyeji1.jpg", "kienyeji2.jpg"],
            inStock: true,
            quantity: 25
        },
        {
            id: 3,
            title: "Turkey Breast",
            description: "Lean turkey breast, perfect for healthy meals and special occasions.",
            price: 1200,
            type: "turkey",
            images: ["turkey1.jpg"],
            inStock: true,
            quantity: 15
        }
    ];

    appState.products = sampleProducts;
    renderProducts(sampleProducts);
}

function renderProducts(products) {
    const grid = document.getElementById('productGrid');
    grid.innerHTML = '';

    products.forEach(product => {
        const card = document.createElement('div');
        card.className = 'product-card';
        card.innerHTML = `
            <img src="assets/images/${product.images[0]}" alt="${product.title}" class="product-image" onerror="this.src='https://via.placeholder.com/400x300?text=Chicken'">
            <div class="product-info">
                <h3 class="product-title">${product.title}</h3>
                <div class="product-price">KSh ${product.price.toLocaleString()}</div>
                <span class="in-stock">In Stock (${product.quantity})</span>
                <div style="margin-top: 1rem; display: flex; gap: 0.5rem;">
                    <button class="btn btn-primary add-to-cart" data-id="${product.id}">
                        <i class="fas fa-cart-plus"></i> Add to Cart
                    </button>
                    <button class="btn btn-secondary view-details" data-id="${product.id}">
                        <i class="fas fa-eye"></i> Details
                    </button>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });

    // Add event listeners to new buttons
    document.querySelectorAll('.add-to-cart').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const productId = parseInt(e.target.closest('button').dataset.id);
            addToCart(productId);
        });
    });

    document.querySelectorAll('.view-details').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const productId = parseInt(e.target.closest('button').dataset.id);
            showProductDetails(productId);
        });
    });
}

function addToCart(productId) {
    const product = appState.products.find(p => p.id === productId);
    if (!product) return;

    const existingItem = appState.cart.find(item => item.id === productId);
    
    if (existingItem) {
        if (existingItem.quantity < product.quantity) {
            existingItem.quantity++;
        } else {
            alert('Maximum available quantity reached');
            return;
        }
    } else {
        appState.cart.push({
            ...product,
            quantity: 1,
            selectedImage: product.images[0]
        });
    }

    saveCart();
    updateCartCount();
    showNotification('Added to cart!', 'success');
}

function removeFromCart(productId) {
    appState.cart = appState.cart.filter(item => item.id !== productId);
    saveCart();
    updateCartCount();
    renderCart();
}

function updateCartCount() {
    const count = appState.cart.reduce((total, item) => total + item.quantity, 0);
    document.querySelector('.cart-count').textContent = count;
}

function saveCart() {
    localStorage.setItem('kukuYetuCart', JSON.stringify(appState.cart));
}

function renderCart() {
    const container = document.getElementById('cartItems');
    const subtotalEl = document.getElementById('cartSubtotal');
    const deliveryEl = document.getElementById('cartDelivery');
    const totalEl = document.getElementById('cartTotal');

    if (appState.cart.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #64748b;">Your cart is empty</p>';
        subtotalEl.textContent = 'KSh 0.00';
        deliveryEl.textContent = 'KSh 0.00';
        totalEl.textContent = 'KSh 0.00';
        return;
    }

    let subtotal = 0;
    container.innerHTML = '';

    appState.cart.forEach(item => {
        const itemTotal = item.price * item.quantity;
        subtotal += itemTotal;

        const cartItem = document.createElement('div');
        cartItem.className = 'cart-item';
        cartItem.style.cssText = `
            display: flex;
            align-items: center;
            padding: 1rem 0;
            border-bottom: 1px solid #e2e8f0;
        `;
        cartItem.innerHTML = `
            <img src="assets/images/${item.images[0]}" alt="${item.title}" 
                 style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px; margin-right: 1rem;"
                 onerror="this.src='https://via.placeholder.com/80x80?text=Chicken'">
            <div style="flex: 1;">
                <h4 style="margin-bottom: 0.5rem;">${item.title}</h4>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <button class="icon-btn decrease-quantity" data-id="${item.id}">
                            <i class="fas fa-minus"></i>
                        </button>
                        <span style="font-weight: bold;">${item.quantity}</span>
                        <button class="icon-btn increase-quantity" data-id="${item.id}">
                            <i class="fas fa-plus"></i>
                        </button>
                    </div>
                    <div style="font-weight: bold; color: var(--primary-color);">
                        KSh ${itemTotal.toLocaleString()}
                    </div>
                </div>
            </div>
            <button class="icon-btn remove-item" data-id="${item.id}" style="margin-left: 1rem;">
                <i class="fas fa-trash" style="color: var(--danger-color);"></i>
            </button>
        `;
        container.appendChild(cartItem);
    });

    const delivery = subtotal > 0 ? 200 : 0;
    const total = subtotal + delivery;

    subtotalEl.textContent = `KSh ${subtotal.toLocaleString()}`;
    deliveryEl.textContent = `KSh ${delivery.toLocaleString()}`;
    totalEl.textContent = `KSh ${total.toLocaleString()}`;

    // Add event listeners to cart buttons
    document.querySelectorAll('.decrease-quantity').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const productId = parseInt(e.target.closest('button').dataset.id);
            updateCartQuantity(productId, -1);
        });
    });

    document.querySelectorAll('.increase-quantity').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const productId = parseInt(e.target.closest('button').dataset.id);
            updateCartQuantity(productId, 1);
        });
    });

    document.querySelectorAll('.remove-item').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const productId = parseInt(e.target.closest('button').dataset.id);
            removeFromCart(productId);
        });
    });
}

function updateCartQuantity(productId, change) {
    const item = appState.cart.find(item => item.id === productId);
    if (!item) return;

    const product = appState.products.find(p => p.id === productId);
    if (!product) return;

    const newQuantity = item.quantity + change;
    
    if (newQuantity < 1) {
        removeFromCart(productId);
        return;
    }

    if (newQuantity > product.quantity) {
        alert(`Only ${product.quantity} items available`);
        return;
    }

    item.quantity = newQuantity;
    saveCart();
    updateCartCount();
    renderCart();
}

function showProductDetails(productId) {
    const product = appState.products.find(p => p.id === productId);
    if (!product) return;

    const modal = document.getElementById('productModal');
    const content = modal.querySelector('.modal-content');
    
    content.innerHTML = `
        <div style="display: flex; flex-direction: column; max-height: 90vh;">
            <div style="position: relative;">
                <!-- Swiper Container -->
                <div class="swiper productSwiper" style="height: 300px;">
                    <div class="swiper-wrapper">
                        ${product.images.map(img => `
                            <div class="swiper-slide">
                                <img src="assets/images/${img}" alt="${product.title}" 
                                     style="width: 100%; height: 100%; object-fit: cover;"
                                     onerror="this.src='https://via.placeholder.com/800x600?text=Chicken'">
                            </div>
                        `).join('')}
                    </div>
                    <div class="swiper-pagination"></div>
                    <div class="swiper-button-next"></div>
                    <div class="swiper-button-prev"></div>
                </div>
                <button class="icon-btn" style="position: absolute; top: 1rem; right: 1rem; background: white; border-radius: 50%; width: 40px; height: 40px;" onclick="closeModal('productModal')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div style="padding: 2rem; overflow-y: auto;">
                <h2 style="margin-bottom: 1rem;">${product.title}</h2>
                <div style="font-size: 1.5rem; color: var(--primary-color); font-weight: bold; margin-bottom: 1rem;">
                    KSh ${product.price.toLocaleString()}
                </div>
                <div style="margin-bottom: 1.5rem;">
                    <span class="in-stock">${product.inStock ? 'In Stock' : 'Out of Stock'}</span>
                    <span style="margin-left: 1rem; color: #64748b;">Type: ${product.type}</span>
                </div>
                <p style="margin-bottom: 2rem; line-height: 1.8;">${product.description}</p>
                <div style="display: flex; gap: 1rem;">
                    <button class="btn btn-primary" onclick="addToCart(${product.id}); closeModal('productModal')">
                        <i class="fas fa-cart-plus"></i> Add to Cart
                    </button>
                    <button class="btn btn-success" onclick="buyNow(${product.id})">
                        <i class="fas fa-bolt"></i> Buy Now
                    </button>
                </div>
            </div>
        </div>
    `;

    // Initialize Swiper
    setTimeout(() => {
        new Swiper('.productSwiper', {
            pagination: {
                el: '.swiper-pagination',
                clickable: true,
            },
            navigation: {
                nextEl: '.swiper-button-next',
                prevEl: '.swiper-button-prev',
            },
        });
    }, 100);

    modal.style.display = 'flex';
    document.getElementById('modalOverlay').style.display = 'block';
}

function buyNow(productId) {
    const product = appState.products.find(p => p.id === productId);
    if (!product) return;

    // Clear cart and add only this product
    appState.cart = [{
        ...product,
        quantity: 1,
        selectedImage: product.images[0]
    }];
    saveCart();
    updateCartCount();
    closeModal('productModal');
    openCart();
}

function openCart() {
    renderCart();
    document.getElementById('cartSidebar').classList.add('active');
    document.getElementById('modalOverlay').style.display = 'block';
}

function closeCart() {
    document.getElementById('cartSidebar').classList.remove('active');
    document.getElementById('modalOverlay').style.display = 'none';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
    document.getElementById('modalOverlay').style.display = 'none';
}

function initMap() {
    // Default to Nairobi coordinates
    const defaultLocation = { lat: -1.286389, lng: 36.817223 };
    
    const map = new google.maps.Map(document.getElementById('map'), {
        center: defaultLocation,
        zoom: 12,
        mapTypeControl: true,
        streetViewControl: false,
        fullscreenControl: true,
    });

    const marker = new google.maps.Marker({
        position: defaultLocation,
        map: map,
        draggable: true,
        title: "Drag to your exact location"
    });

    appState.map = map;
    appState.marker = marker;
    appState.currentLocation = defaultLocation;

    // Add click listener to map
    map.addListener('click', (e) => {
        marker.setPosition(e.latLng);
        appState.currentLocation = {
            lat: e.latLng.lat(),
            lng: e.latLng.lng()
        };
    });

    // Add dragend listener to marker
    marker.addListener('dragend', (e) => {
        appState.currentLocation = {
            lat: e.latLng.lat(),
            lng: e.latLng.lng()
        };
    });
}

function useCurrentLocation() {
    if (!navigator.geolocation) {
        alert("Geolocation is not supported by your browser");
        return;
    }

    navigator.geolocation.getCurrentPosition(
        (position) => {
            const location = {
                lat: position.coords.latitude,
                lng: position.coords.longitude
            };

            appState.map.setCenter(location);
            appState.marker.setPosition(location);
            appState.currentLocation = location;

            showNotification('Location updated!', 'success');
        },
        (error) => {
            console.error("Error getting location:", error);
            alert("Unable to get your location. Please enable location services.");
        }
    );
}

function setupEventListeners() {
    // Cart toggle
    document.querySelectorAll('.cart-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            if (document.getElementById('cartSidebar').classList.contains('active')) {
                closeCart();
            } else {
                openCart();
            }
        });
    });

    // Checkout button
    document.getElementById('checkoutBtn').addEventListener('click', () => {
        if (appState.cart.length === 0) {
            alert('Your cart is empty');
            return;
        }
        closeCart();
        openCheckout();
    });

    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const type = e.target.dataset.type;
            filterProducts(type);
            
            // Update active filter
            document.querySelectorAll('.filter-btn').forEach(b => {
                b.classList.remove('btn-primary');
                b.classList.add('btn-secondary');
            });
            e.target.classList.remove('btn-secondary');
            e.target.classList.add('btn-primary');
        });
    });

    // Use current location
    document.getElementById('useCurrentLocation').addEventListener('click', useCurrentLocation);

    // Checkout form
    document.getElementById('checkoutForm').addEventListener('submit', (e) => {
        e.preventDefault();
        processCheckout();
    });

    // Cancel checkout
    document.getElementById('cancelCheckout').addEventListener('click', () => {
        closeModal('checkoutModal');
    });

    // Payment buttons
    document.getElementById('cancelPayment').addEventListener('click', () => {
        document.getElementById('paymentOverlay').style.display = 'none';
    });

    document.getElementById('processPayment').addEventListener('click', () => {
        handlePayment();
    });

    // Modal overlay
    document.getElementById('modalOverlay').addEventListener('click', () => {
        closeCart();
        closeModal('productModal');
        closeModal('checkoutModal');
    });
}

function filterProducts(type) {
    if (type === 'all') {
        renderProducts(appState.products);
    } else {
        const filtered = appState.products.filter(product => product.type === type);
        renderProducts(filtered);
    }
}

function openCheckout() {
    if (!appState.currentLocation) {
        initMap();
    }
    document.getElementById('checkoutModal').style.display = 'flex';
    document.getElementById('modalOverlay').style.display = 'block';
}

function processCheckout() {
    const form = document.getElementById('checkoutForm');
    const formData = new FormData(form);
    
    const orderData = {
        customer: {
            name: formData.get('name'),
            email: formData.get('email'),
            phone: formData.get('phone')
        },
        location: appState.currentLocation,
        items: appState.cart,
        total: calculateTotal(),
        timestamp: new Date().toISOString()
    };

    // Validate
    if (!orderData.customer.name || !orderData.customer.email || !orderData.customer.phone) {
        alert('Please fill in all required fields');
        return;
    }

    if (!orderData.location) {
        alert('Please select a delivery location');
        return;
    }

    // Close checkout modal and show payment
    closeModal('checkoutModal');
    showPayment(orderData);
}

function calculateTotal() {
    const subtotal = appState.cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    return subtotal + (subtotal > 0 ? 200 : 0);
}

function showPayment(orderData) {
    document.getElementById('paymentAmount').textContent = `KSh ${orderData.total.toLocaleString()}`;
    document.getElementById('paymentOverlay').style.display = 'flex';
    window.currentOrder = orderData; // Store for later use
}

async function handlePayment() {
    const orderData = window.currentOrder;
    
    try {
        // Show loading state
        const paymentBtn = document.getElementById('processPayment');
        const originalText = paymentBtn.innerHTML;
        paymentBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        paymentBtn.disabled = true;

        // Generate order ID
        const orderId = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();

        // Process payment via Lipiana
        const paymentResult = await handleLipianaPayment(orderData, orderId);

        if (paymentResult.success) {
            // Generate receipt
            generateReceipt(orderData, orderId, paymentResult.transactionId);
            
            // Clear cart
            appState.cart = [];
            saveCart();
            updateCartCount();
            
            // Hide payment overlay
            document.getElementById('paymentOverlay').style.display = 'none';
            
            // Show success message
            showNotification('Payment successful! Your order has been placed.', 'success');
            
            // In a real app, send order to backend
            await sendOrderToBackend(orderData, orderId, paymentResult.transactionId);
            
        } else {
            throw new Error(paymentResult.message || 'Payment failed');
        }

    } catch (error) {
        console.error('Payment error:', error);
        alert('Payment failed: ' + error.message);
        
        // Reset payment button
        const paymentBtn = document.getElementById('processPayment');
        paymentBtn.innerHTML = originalText;
        paymentBtn.disabled = false;
    }
}

async function handleLipianaPayment(orderData, orderId) {
    // This is where you integrate with Lipiana.dev API
    // For now, we'll simulate a successful payment
    
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({
                success: true,
                transactionId: 'TXN-' + Date.now(),
                message: 'Payment processed successfully'
            });
        }, 2000);
    });
}

function generateReceipt(orderData, orderId, transactionId) {
    const receipt = document.getElementById('receipt');
    
    const itemsHtml = orderData.items.map(item => `
        <tr>
            <td>${item.title}</td>
            <td>${item.quantity}</td>
            <td>KSh ${item.price.toLocaleString()}</td>
            <td>KSh ${(item.price * item.quantity).toLocaleString()}</td>
        </tr>
    `).join('');

    receipt.innerHTML = `
        <div class="no-print" style="margin-bottom: 2rem; text-align: right;">
            <button class="btn btn-primary" onclick="window.print()">
                <i class="fas fa-print"></i> Print Receipt
            </button>
            <button class="btn btn-secondary" onclick="closeReceipt()" style="margin-left: 1rem;">
                <i class="fas fa-times"></i> Close
            </button>
        </div>
        
        <div style="text-align: center; margin-bottom: 2rem;">
            <h2 style="color: var(--primary-color);">
                <i class="fas fa-drumstick-bite"></i> Kuku Yetu
            </h2>
            <p>Fresh Poultry Delivery</p>
        </div>
        
        <div style="margin-bottom: 2rem;">
            <h3>Order Receipt</h3>
            <p><strong>Order ID:</strong> ${orderId}</p>
            <p><strong>Transaction ID:</strong> ${transactionId}</p>
            <p><strong>Date:</strong> ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}</p>
        </div>
        
        <div style="margin-bottom: 2rem;">
            <h4>Customer Information</h4>
            <p><strong>Name:</strong> ${orderData.customer.name}</p>
            <p><strong>Email:</strong> ${orderData.customer.email}</p>
            <p><strong>Phone:</strong> ${orderData.customer.phone}</p>
        </div>
        
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 2rem;">
            <thead>
                <tr style="border-bottom: 2px solid #ddd;">
                    <th style="text-align: left; padding: 0.5rem;">Item</th>
                    <th style="text-align: center; padding: 0.5rem;">Qty</th>
                    <th style="text-align: right; padding: 0.5rem;">Price</th>
                    <th style="text-align: right; padding: 0.5rem;">Total</th>
                </tr>
            </thead>
            <tbody>
                ${itemsHtml}
            </tbody>
            <tfoot>
                <tr>
                    <td colspan="3" style="text-align: right; padding: 0.5rem;"><strong>Subtotal:</strong></td>
                    <td style="text-align: right; padding: 0.5rem;">KSh ${(orderData.total - 200).toLocaleString()}</td>
                </tr>
                <tr>
                    <td colspan="3" style="text-align: right; padding: 0.5rem;"><strong>Delivery:</strong></td>
                    <td style="text-align: right; padding: 0.5rem;">KSh 200.00</td>
                </tr>
                <tr style="border-top: 2px solid #ddd;">
                    <td colspan="3" style="text-align: right; padding: 0.5rem; font-size: 1.2rem;"><strong>Total:</strong></td>
                    <td style="text-align: right; padding: 0.5rem; font-size: 1.2rem; color: var(--primary-color);">
                        <strong>KSh ${orderData.total.toLocaleString()}</strong>
                    </td>
                </tr>
            </tfoot>
        </table>
        
        <div style="margin-top: 2rem; padding-top: 2rem; border-top: 2px dashed #ddd; text-align: center;">
            <p>Thank you for your order!</p>
            <p>Your order will be delivered within 3 hours.</p>
            <p style="color: #64748b; font-size: 0.9rem;">For inquiries: contact@kukuyetu.co.ke | +254 700 000 000</p>
        </div>
    `;

    receipt.style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function closeReceipt() {
    document.getElementById('receipt').style.display = 'none';
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? 'var(--success-color)' : 'var(--primary-color)'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    
    notification.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

async function sendOrderToBackend(orderData, orderId, transactionId) {
    // In a real app, this would send to your backend
    const order = {
        ...orderData,
        orderId,
        transactionId,
        status: 'paid',
        createdAt: new Date().toISOString()
    };

    try {
        const response = await fetch('https://your-backend.onrender.com/api/orders', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(order)
        });

        if (!response.ok) {
            throw new Error('Failed to save order');
        }

        return await response.json();
    } catch (error) {
        console.error('Error sending order to backend:', error);
        // You might want to implement retry logic or offline storage here
    }
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
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
`;
document.head.appendChild(style);