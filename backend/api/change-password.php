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
    if (!isset($data->current_password) || !isset($data->new_password) || !isset($data->confirm_password)) {
        throw new Exception('Current password, new password, and confirm password are required');
    }

    // Validate password strength
    if (strlen($data->new_password) < 8) {
        throw new Exception('Password must be at least 8 characters long');
    }

    // Check for at least one lowercase letter
    if (!preg_match('/[a-z]/', $data->new_password)) {
        throw new Exception('Password must contain at least one lowercase letter');
    }

    // Check for at least one uppercase letter
    if (!preg_match('/[A-Z]/', $data->new_password)) {
        throw new Exception('Password must contain at least one uppercase letter');
    }

    // Check for at least one number
    if (!preg_match('/\d/', $data->new_password)) {
        throw new Exception('Password must contain at least one number');
    }

    // Check for at least one special character
    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?~`]/', $data->new_password)) {
        throw new Exception('Password must contain at least one special character');
    }

    // Check if passwords match
    if ($data->new_password !== $data->confirm_password) {
        throw new Exception('New passwords do not match');
    }

    // Check if new password is different from current
    if ($data->current_password === $data->new_password) {
        throw new Exception('New password must be different from current password');
    }

    // Get user from session/cookies
    $userId = null;
    if (isset($_COOKIE['user_id'])) {
        $crypto = new SecureEncryption();
        $decryptedId = $crypto->decrypt($_COOKIE['user_id']);
        if ($decryptedId !== false) {
            $userId = $decryptedId;
        }
    }

    if (!$userId) {
        throw new Exception('User not authenticated');
    }

    // Get current user data
    global $pdo;
    $userQuery = "SELECT id, email, password FROM users WHERE id = :id AND is_active = 1";
    $userStmt = $pdo->prepare($userQuery);
    $userStmt->execute(['id' => $userId]);

    if ($userStmt->rowCount() === 0) {
        throw new Exception('User not found or inactive');
    }

    $user = $userStmt->fetch();

    // Verify current password
    $crypto = new SecureEncryption();
    $decryptedPassword = $crypto->decrypt($user['password']);
    
    if ($decryptedPassword === false || $decryptedPassword !== $data->current_password) {
        throw new Exception('Current password is incorrect');
    }

    // Encrypt new password
    $encryptedPassword = $crypto->encrypt($data->new_password);
    if ($encryptedPassword === false) {
        throw new Exception('Error encrypting password');
    }

    // Update password
    $updateQuery = "UPDATE users SET password = :password, updated_at = NOW() WHERE id = :id";
    $updateStmt = $pdo->prepare($updateQuery);
    $result = $updateStmt->execute([
        'password' => $encryptedPassword,
        'id' => $userId
    ]);

    if ($result) {
        $response['status'] = true;
        $response['message'] = 'Password changed successfully';
    } else {
        throw new Exception('Failed to change password');
    }

} catch (PDOException $e) {
    $response['message'] = 'Database error occurred';
    error_log('Change Password PDO Error: ' . $e->getMessage());
} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>
