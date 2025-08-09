<?php
// CORS configuration for the API
function setCorsHeaders() {
    // Get the origin from the request
    $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
    
    // List of allowed origins
    $allowedOrigins = [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:3001',
        'http://127.0.0.1:3001',
        'http://localhost',
        'http://127.0.0.1'
    ];
    
    // Check if the origin is allowed
    if (in_array($origin, $allowedOrigins)) {
        header('Access-Control-Allow-Origin: ' . $origin);
    } else {
        // For development, allow localhost origins
        if (strpos($origin, 'localhost') !== false || strpos($origin, '127.0.0.1') !== false) {
            header('Access-Control-Allow-Origin: ' . $origin);
        } else {
            // In production, you might want to be more restrictive
            header('Access-Control-Allow-Origin: http://localhost:3000');
        }
    }
    
    // Set other CORS headers
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token, Authorization');
    header('Access-Control-Max-Age: 86400'); // 24 hours
    
    // Handle preflight requests
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit(0);
    }
}

// Call the function to set CORS headers
setCorsHeaders();
?>
