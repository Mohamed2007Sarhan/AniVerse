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
    if (!isset($data->name) || !isset($data->email) || !isset($data->password)) {
        throw new Exception('Required fields: name, email, password');
    }

    // Validate email format
    if (!filter_var($data->email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception('Invalid email format');
    }

    // Validate password strength
    if (strlen($data->password) < 8) {
        throw new Exception('Password must be at least 8 characters long');
    }

    // Check for at least one lowercase letter
    if (!preg_match('/[a-z]/', $data->password)) {
        throw new Exception('Password must contain at least one lowercase letter');
    }

    // Check for at least one uppercase letter
    if (!preg_match('/[A-Z]/', $data->password)) {
        throw new Exception('Password must contain at least one uppercase letter');
    }

    // Check for at least one number
    if (!preg_match('/\d/', $data->password)) {
        throw new Exception('Password must contain at least one number');
    }

    // Check for at least one special character
    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?~`]/', $data->password)) {
        throw new Exception('Password must contain at least one special character');
    }

    // Sanitize inputs
    $name = filter_var(trim($data->name), FILTER_SANITIZE_STRING);
    $email = filter_var(trim($data->email), FILTER_SANITIZE_EMAIL);
    $phone = isset($data->phone) ? filter_var(trim($data->phone), FILTER_SANITIZE_STRING) : null;
    $password = $data->password;

    // Validate phone number if provided
    if ($phone && !preg_match('/^\+?[\d\s\-\(\)]{10,}$/', $phone)) {
        throw new Exception('Invalid phone number format');
    }

    // Check if email already exists
    global $pdo;
    $checkQuery = "SELECT id FROM users WHERE email = :email";
    $checkStmt = $pdo->prepare($checkQuery);
    $checkStmt->execute(['email' => $email]);

    if ($checkStmt->rowCount() > 0) {
        throw new Exception('Email already registered');
    }

    // Initialize encryption class
    $crypto = new SecureEncryption();

    // Encrypt password
    $encryptedPassword = $crypto->encrypt($password);
    if ($encryptedPassword === false) {
        throw new Exception('Error encrypting password');
    }

    // Generate unique nickname if not provided
    $nickname = strtolower(str_replace(' ', '', $name)) . '_' . substr(md5(uniqid()), 0, 6);

    // Insert new user
    $insertQuery = "INSERT INTO users (name, email, phone, password, nickname, created_at) 
                    VALUES (:name, :email, :phone, :password, :nickname, NOW())";
    
    $insertStmt = $pdo->prepare($insertQuery);
    $result = $insertStmt->execute([
        'name' => $name,
        'email' => $email,
        'phone' => $phone,
        'password' => $encryptedPassword,
        'nickname' => $nickname
    ]);

    if ($result) {
        $userId = $pdo->lastInsertId();
        
        // Create encrypted session cookies
        $encryptedId = $crypto->encrypt($userId);
        $encryptedEmail = $crypto->encrypt($email);
        
        if ($encryptedId === false || $encryptedEmail === false) {
            throw new Exception('Error creating secure session');
        }

        // Set secure cookies
        setcookie('user_id', $encryptedId, [
            'expires' => time() + 86400,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        setcookie('user_email', $encryptedEmail, [
            'expires' => time() + 86400,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);

        // Generate new CSRF token for the session
        $newToken = $csrf->refreshToken();

        $response['status'] = true;
        $response['message'] = 'Registration successful';
        $response['data'] = [
            'id' => $userId,
            'name' => $name,
            'email' => $email,
            'nickname' => $nickname,
            'phone' => $phone,
            'csrf_token' => $newToken
        ];
    } else {
        throw new Exception('Failed to create user account');
    }

} catch (PDOException $e) {
    $response['message'] = 'Database error occurred';
    error_log('Registration PDO Error: ' . $e->getMessage());
} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>
