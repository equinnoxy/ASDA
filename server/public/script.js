document.addEventListener('DOMContentLoaded', function() {
    // Check authentication
    checkAuthentication();
    
    // Initialize navigation
    initNavigation();
    
    // Load initial data
    loadDashboardStats();
    
    // Set up refresh buttons
    document.getElementById('refresh-stats').addEventListener('click', loadDashboardStats);
    document.getElementById('refresh-clients').addEventListener('click', loadClients);
    document.getElementById('refresh-blocked-ips').addEventListener('click', loadBlockedIPs);
    document.getElementById('refresh-metrics').addEventListener('click', loadMetrics);
    
    // Set up IP blocking form
    document.getElementById('block-ip-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const ipInput = document.getElementById('ip-input');
        const ip = ipInput.value.trim();
        
        if (isValidIP(ip)) {
            blockIP(ip);
            ipInput.value = '';
        } else {
            showNotification('Error', 'Invalid IP address format', 'danger');
        }
    });
    
    // Set up logout button
    document.getElementById('logout-btn').addEventListener('click', function(e) {
        e.preventDefault();
        logout();
    });
    
    // Update last refresh time
    updateLastRefreshTime();
});

// Navigation functions
function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get section name from data attribute
            const sectionName = this.getAttribute('data-section');
            
            // Hide all sections
            document.querySelectorAll('.section').forEach(section => {
                section.classList.add('d-none');
            });
            
            // Show the selected section
            document.getElementById(`${sectionName}-section`).classList.remove('d-none');
            
            // Update active nav link
            navLinks.forEach(navLink => {
                navLink.classList.remove('active');
            });
            this.classList.add('active');
            
            // Load data for the section
            switch (sectionName) {
                case 'dashboard':
                    loadDashboardStats();
                    break;
                case 'clients':
                    loadClients();
                    break;
                case 'blocked-ips':
                    loadBlockedIPs();
                    break;
                case 'metrics':
                    loadMetrics();
                    break;
                case 'users':
                    loadUsers();
                    break;
            }
        });
    });
}

// API functions
async function fetchAPI(endpoint) {
    try {
        const response = await fetch(`/api/${endpoint}`);
        
        if (response.status === 401) {
            // Unauthorized - session expired or not logged in
            console.log('Session expired, redirecting to login');
            window.location.href = '/login';
            return null;
        }
        
        if (response.status === 403) {
            // Forbidden - don't have permission
            console.error(`Access denied to ${endpoint} - insufficient permissions`);
            
            // Try to get more detailed error info
            try {
                const errorData = await response.json();
                showNotification(
                    'Access Denied', 
                    `You do not have permission to access this resource: ${errorData.reason || 'Insufficient privileges'}`, 
                    'danger'
                );
                console.error('Access denied details:', errorData);
            } catch (e) {
                showNotification('Access Denied', 'You do not have permission to access this resource', 'danger');
            }
            
            return null;
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage;
            
            try {
                const errorJson = JSON.parse(errorText);
                errorMessage = errorJson.error || `API request failed: ${response.status}`;
                console.error('API Error Details:', errorJson);
            } catch (e) {
                errorMessage = `API request failed: ${response.status}`;
            }
            
            throw new Error(errorMessage);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`Error fetching ${endpoint}:`, error);
        showNotification('Error', `Failed to fetch data from server: ${error.message}`, 'danger');
        return null;
    }
}

async function postAPI(endpoint, data) {
    try {
        const response = await fetch(`/api/${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `API request failed: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`Error posting to ${endpoint}:`, error);
        showNotification('Error', `Failed to send data to server: ${error.message}`, 'danger');
        return null;
    }
}

// Data loading functions
async function loadDashboardStats() {
    const stats = await fetchAPI('stats');
    if (!stats) return;
    
    // Update stats cards
    document.getElementById('total-clients').textContent = stats.totalClients;
    document.getElementById('active-clients').textContent = stats.activeClients;
    document.getElementById('active-blocked-ips').textContent = stats.activeBlockedIPs;
    document.getElementById('total-block-events').textContent = stats.totalBlockEvents;
    
    // Update database status
    const dbStatus = document.getElementById('database-status');
    if (stats.totalClients !== undefined) {
        dbStatus.textContent = 'Connected';
        dbStatus.className = 'badge bg-success rounded-pill';
    } else {
        dbStatus.textContent = 'Not Connected';
        dbStatus.className = 'badge bg-danger rounded-pill';
    }
    
    // Update last refresh time
    updateLastRefreshTime();
}

async function loadClients() {
    const clients = await fetchAPI('clients');
    if (!clients) return;
    
    const tableBody = document.getElementById('clients-table-body');
    
    if (clients.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No clients connected</td></tr>';
        return;
    }
    
    tableBody.innerHTML = '';
    
    clients.forEach(client => {
        const tr = document.createElement('tr');
        
        // Format dates
        const lastSeen = new Date(client.last_seen).toLocaleString();
        const firstConnected = new Date(client.first_connected).toLocaleString();
        
        // Status indicator
        const statusClass = client.status === 'online' ? 'status-online' : 'status-offline';
        const statusText = client.status === 'online' ? 'Online' : 'Offline';
        
        tr.innerHTML = `
            <td>${client.id}</td>
            <td>${client.ip || 'Unknown'}</td>
            <td><span class="status-badge ${statusClass}"></span>${statusText}</td>
            <td>${lastSeen}</td>
            <td>${client.version || 'Unknown'}</td>
            <td>${firstConnected}</td>
        `;
        
        tableBody.appendChild(tr);
    });
    
    updateLastRefreshTime();
}

async function loadBlockedIPs() {
    const blockedIPs = await fetchAPI('blocked-ips');
    if (!blockedIPs) return;
    
    const tableBody = document.getElementById('blocked-ips-table-body');
    
    if (blockedIPs.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="7" class="text-center">No blocked IPs</td></tr>';
        return;
    }
    
    tableBody.innerHTML = '';
    
    blockedIPs.forEach(ip => {
        const tr = document.createElement('tr');
        
        // Format dates
        const firstBlocked = new Date(ip.first_blocked).toLocaleString();
        const lastBlocked = new Date(ip.last_blocked).toLocaleString();
        
        // Status badge
        const statusBadge = ip.status === 'active' 
            ? '<span class="badge bg-danger">Active</span>' 
            : '<span class="badge bg-secondary">Inactive</span>';
        
        // Action button
        const actionButton = ip.status === 'active'
            ? `<button class="btn btn-sm btn-outline-success unblock-ip-btn" data-ip="${ip.ip}">Unblock</button>`
            : `<button class="btn btn-sm btn-outline-danger block-ip-btn" data-ip="${ip.ip}">Block</button>`;
        
        tr.innerHTML = `
            <td>${ip.ip}</td>
            <td>${firstBlocked}</td>
            <td>${lastBlocked}</td>
            <td>${ip.source || 'Unknown'}</td>
            <td>${ip.block_count}</td>
            <td>${statusBadge}</td>
            <td>${actionButton}</td>
        `;
        
        tableBody.appendChild(tr);
    });
    
    // Add event listeners for action buttons
    document.querySelectorAll('.unblock-ip-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            unblockIP(this.getAttribute('data-ip'));
        });
    });
    
    document.querySelectorAll('.block-ip-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            blockIP(this.getAttribute('data-ip'));
        });
    });
    
    updateLastRefreshTime();
}

async function loadMetrics() {
    const metrics = await fetchAPI('metrics');
    if (!metrics) return;
    
    const tableBody = document.getElementById('metrics-table-body');
    
    if (metrics.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No metrics data available</td></tr>';
        return;
    }
    
    tableBody.innerHTML = '';
    
    metrics.forEach(metric => {
        const tr = document.createElement('tr');
        
        // Format values
        const lastReport = new Date(metric.latest_timestamp).toLocaleString();
        const uptime = formatUptime(metric.uptime_seconds);
        const memoryUsage = metric.avg_memory_usage_mb ? `${metric.avg_memory_usage_mb.toFixed(2)} MB` : 'N/A';
        
        tr.innerHTML = `
            <td>${metric.client_id}</td>
            <td>${metric.avg_blocks_per_minute ? metric.avg_blocks_per_minute.toFixed(2) : '0.00'}</td>
            <td>${metric.total_blocks || '0'}</td>
            <td>${uptime}</td>
            <td>${memoryUsage}</td>
            <td>${lastReport}</td>
        `;
        
        tableBody.appendChild(tr);
    });
    
    updateLastRefreshTime();
}

async function loadUsers() {
    const users = await fetchAPI('users');
    if (!users) return;
    
    const tableBody = document.getElementById('users-table-body');
    
    if (users.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5" class="text-center">No users found</td></tr>';
        return;
    }
    
    tableBody.innerHTML = '';
    
    users.forEach(user => {
        const tr = document.createElement('tr');
        
        // Format dates
        const createdAt = user.created_at ? new Date(user.created_at).toLocaleString() : 'N/A';
        const lastLogin = user.last_login ? new Date(user.last_login).toLocaleString() : 'Never';
        
        tr.innerHTML = `
            <td>${user.username}</td>
            <td>${user.email || 'N/A'}</td>
            <td><span class="badge ${user.role === 'admin' ? 'bg-danger' : 'bg-primary'}">${user.role}</span></td>
            <td>${createdAt}</td>
            <td>${lastLogin}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary edit-user-btn" data-user-id="${user.id}">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-outline-danger delete-user-btn" data-user-id="${user.id}">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        `;
        
        tableBody.appendChild(tr);
    });
    
    // Add event listeners for action buttons
    document.querySelectorAll('.edit-user-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const userId = this.getAttribute('data-user-id');
            const user = users.find(u => u.id == userId);
            showEditUserModal(user);
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const userId = this.getAttribute('data-user-id');
            const user = users.find(u => u.id == userId);
            showDeleteUserConfirmation(user);
        });
    });
    
    updateLastRefreshTime();
}

// Action functions
async function blockIP(ip) {
    const result = await postAPI('block-ip', { ip });
    if (result && result.success) {
        showNotification('Success', `IP ${ip} has been blocked`, 'success');
        
        // Refresh data
        loadDashboardStats();
        loadBlockedIPs();
    }
}

async function unblockIP(ip) {
    const result = await postAPI('unblock-ip', { ip });
    if (result && result.success) {
        showNotification('Success', `IP ${ip} has been unblocked`, 'success');
        
        // Refresh data
        loadDashboardStats();
        loadBlockedIPs();
    }
}

// Authentication functions
function checkAuthentication() {
    fetch('/api/check-auth')
        .then(response => {
            if (!response.ok) {
                throw new Error(`Authentication check failed: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (!data.authenticated) {
                console.log('Not authenticated, redirecting to login');
                window.location.href = '/login';
            } else {
                // Update user info in UI
                document.getElementById('user-display-name').textContent = data.username;
                
                // Show admin options if user is admin
                if (data.role === 'admin') {
                    document.getElementById('user-management-link').classList.remove('d-none');
                    console.log('Admin user detected, enabling user management');
                } else {
                    console.log('Regular user, hiding admin features');
                }
            }
        })
        .catch(error => {
            console.error('Authentication check error:', error);
            // Redirect to login on error
            window.location.href = '/login';
        });
}

function logout() {
    fetch('/api/logout', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.href = '/login';
        } else {
            showNotification('Error', 'Logout failed', 'danger');
        }
    })
    .catch(error => {
        console.error('Logout error:', error);
        showNotification('Error', 'Logout failed', 'danger');
    });
}

// User Management functions
function showAddUserModal() {
    const modal = new bootstrap.Modal(document.getElementById('user-modal'));
    
    // Reset form
    document.getElementById('user-form').reset();
    document.getElementById('user-modal-title').textContent = 'Add New User';
    document.getElementById('user-id').value = '';
    
    // Show password field
    document.getElementById('password-group').classList.remove('d-none');
    
    // Configure submit handler
    document.getElementById('user-form').onsubmit = function(e) {
        e.preventDefault();
        addUser();
        modal.hide();
    };
    
    modal.show();
}

function showEditUserModal(user) {
    const modal = new bootstrap.Modal(document.getElementById('user-modal'));
    
    // Populate form
    document.getElementById('user-modal-title').textContent = 'Edit User';
    document.getElementById('user-id').value = user.id;
    document.getElementById('username').value = user.username;
    document.getElementById('email').value = user.email || '';
    document.getElementById('role').value = user.role;
    
    // Hide password field (optional for edit)
    document.getElementById('password-group').classList.remove('d-none');
    document.getElementById('password').required = false;
    
    // Configure submit handler
    document.getElementById('user-form').onsubmit = function(e) {
        e.preventDefault();
        updateUser(user.id);
        modal.hide();
    };
    
    modal.show();
}

function showDeleteUserConfirmation(user) {
    if (confirm(`Are you sure you want to delete user ${user.username}?`)) {
        deleteUser(user.id);
    }
}

function addUser() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const email = document.getElementById('email').value;
    const role = document.getElementById('role').value;
    
    postAPI('users', { username, password, email, role })
        .then(result => {
            if (result && result.success) {
                showNotification('Success', `User ${username} created successfully`, 'success');
                loadUsers();
            }
        });
}

function updateUser(userId) {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const email = document.getElementById('email').value;
    const role = document.getElementById('role').value;
    
    // Only include password if provided
    const userData = { username, email, role };
    if (password) {
        userData.password = password;
    }
    
    fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
    })
    .then(response => response.json())
    .then(result => {
        if (result && result.success) {
            showNotification('Success', `User ${username} updated successfully`, 'success');
            loadUsers();
        } else {
            showNotification('Error', result.error || 'Failed to update user', 'danger');
        }
    })
    .catch(error => {
        console.error(`Error updating user ${userId}:`, error);
        showNotification('Error', 'Failed to update user', 'danger');
    });
}

function deleteUser(userId) {
    fetch(`/api/users/${userId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(result => {
        if (result && result.success) {
            showNotification('Success', result.message, 'success');
            loadUsers();
        } else {
            showNotification('Error', result.error || 'Failed to delete user', 'danger');
        }
    })
    .catch(error => {
        console.error(`Error deleting user ${userId}:`, error);
        showNotification('Error', 'Failed to delete user', 'danger');
    });
}

// Utility functions
function isValidIP(ip) {
    const ipRegex = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    return ipRegex.test(ip);
}

function formatUptime(seconds) {
    if (!seconds) return 'N/A';
    
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
        return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m ${Math.floor(seconds % 60)}s`;
    }
}

function updateLastRefreshTime() {
    const now = new Date();
    document.getElementById('last-refresh-time').textContent = now.toLocaleTimeString();
}

function showNotification(title, message, type = 'info') {
    const toast = document.getElementById('notification-toast');
    const toastTitle = document.getElementById('toast-title');
    const toastMessage = document.getElementById('toast-message');
    const toastTime = document.getElementById('toast-time');
    
    // Set content
    toastTitle.textContent = title;
    toastMessage.textContent = message;
    toastTime.textContent = 'just now';
    
    // Set color based on type
    toast.className = 'toast';
    if (type === 'success') {
        toast.classList.add('text-bg-success');
    } else if (type === 'danger') {
        toast.classList.add('text-bg-danger');
    } else if (type === 'warning') {
        toast.classList.add('text-bg-warning');
    } else {
        toast.classList.add('text-bg-info');
    }
    
    // Show the toast
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}
