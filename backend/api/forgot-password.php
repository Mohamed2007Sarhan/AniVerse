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

    // Get POST data
    $data = json_decode(file_get_contents("php://input"));

    // Validate required fields
    if (!isset($data->email)) {
        throw new Exception('Email is required');
    }

    // Validate email format
    if (!filter_var($data->email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception('Invalid email format');
    }

    // Sanitize email
    $email = filter_var(trim($data->email), FILTER_SANITIZE_EMAIL);

    // Check if user exists
    global $pdo;
    $checkQuery = "SELECT id, name FROM users WHERE email = :email AND is_active = 1";
    $checkStmt = $pdo->prepare($checkQuery);
    $checkStmt->execute(['email' => $email]);

    if ($checkStmt->rowCount() === 0) {
        throw new Exception('Email not found or account is inactive');
    }

    $user = $checkStmt->fetch();

    // Generate reset token
    $resetToken = bin2hex(random_bytes(32));
    $expiresAt = date('Y-m-d H:i:s', time() + 3600); // 1 hour from now

    // Store reset token
    $insertQuery = "INSERT INTO password_resets (email, token, expires_at) VALUES (:email, :token, :expires_at)";
    $insertStmt = $pdo->prepare($insertQuery);
    $result = $insertStmt->execute([
        'email' => $email,
        'token' => $resetToken,
        'expires_at' => $expiresAt
    ]);

    if ($result) {
        // In a real application, you would send an email here
        // For now, we'll just return the token (in production, remove this)
        $response['status'] = true;
        $response['message'] = 'Password reset link sent to your email';
        $response['data'] = [
            'reset_token' => $resetToken, // Remove this in production
            'expires_at' => $expiresAt
        ];
    } else {
        throw new Exception('Failed to generate reset token');
    }

} catch (PDOException $e) {
    $response['message'] = 'Database error occurred';
    error_log('Forgot Password PDO Error: ' . $e->getMessage());
} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>
