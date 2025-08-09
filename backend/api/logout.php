<?php
require_once 'cors.php';
header('Content-Type: application/json');

require_once '../db-con.php';
require_once '../hash.php';
require_once 'csrf.php';

// Initialize response array
$response = array(
    'status' => false,
    'message' => '',
    'data' => null
);

try {
    // Initialize CSRF protection
    $csrf = new CSRFProtection();
    
    // Check if request method is POST
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Only POST method is allowed');
    }

    // Validate CSRF token
    $headers = getallheaders();
    $csrfToken = isset($headers['X-CSRF-Token']) ? $headers['X-CSRF-Token'] : '';
    
    if (!$csrf->validateToken($csrfToken)) {
        throw new Exception('Invalid CSRF token');
    }

    // Initialize encryption class
    $crypto = new SecureEncryption();

    // Clear user cookies
    if (isset($_COOKIE['user_id'])) {
        setcookie('user_id', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }
    
    if (isset($_COOKIE['user_email'])) {
        setcookie('user_email', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }

    // Clear session
    session_start();
    session_destroy();

    // Generate new CSRF token
    $newToken = $csrf->refreshToken();

    $response['status'] = true;
    $response['message'] = 'Logout successful';
    $response['data'] = [
        'csrf_token' => $newToken
    ];

} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>
