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
    if (!isset($data->token) || !isset($data->password) || !isset($data->confirm_password)) {
        throw new Exception('Token, password, and confirm password are required');
    }

    // Validate password strength
    if (strlen($data->password) < 8) {
        throw new Exception('Password must be at least 8 characters long');
    }

    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/', $data->password)) {
        throw new Exception('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character');
    }

    // Check if passwords match
    if ($data->password !== $data->confirm_password) {
        throw new Exception('Passwords do not match');
    }

    // Sanitize inputs
    $token = filter_var(trim($data->token), FILTER_SANITIZE_STRING);
    $password = $data->password;

    // Check if reset token exists and is valid
    global $pdo;
    $checkQuery = "SELECT email FROM password_resets WHERE token = :token AND expires_at > NOW() AND used = 0";
    $checkStmt = $pdo->prepare($checkQuery);
    $checkStmt->execute(['token' => $token]);

    if ($checkStmt->rowCount() === 0) {
        throw new Exception('Invalid or expired reset token');
    }

    $resetData = $checkStmt->fetch();
    $email = $resetData['email'];

    // Initialize encryption class
    $crypto = new SecureEncryption();

    // Encrypt new password
    $encryptedPassword = $crypto->encrypt($password);
    if ($encryptedPassword === false) {
        throw new Exception('Error encrypting password');
    }

    // Update user password
    $updateQuery = "UPDATE users SET password = :password, updated_at = NOW() WHERE email = :email";
    $updateStmt = $pdo->prepare($updateQuery);
    $result = $updateStmt->execute([
        'password' => $encryptedPassword,
        'email' => $email
    ]);

    if ($result) {
        // Mark reset token as used
        $markUsedQuery = "UPDATE password_resets SET used = 1 WHERE token = :token";
        $markUsedStmt = $pdo->prepare($markUsedQuery);
        $markUsedStmt->execute(['token' => $token]);

        $response['status'] = true;
        $response['message'] = 'Password reset successfully';
    } else {
        throw new Exception('Failed to reset password');
    }

} catch (PDOException $e) {
    $response['message'] = 'Database error occurred';
    error_log('Reset Password PDO Error: ' . $e->getMessage());
} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>
