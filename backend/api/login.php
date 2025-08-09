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

    // Validate input
    if (!isset($data->email) || !isset($data->password)) {
        throw new Exception('Email and password are required');
    }

    // Validate email format
    if (!filter_var($data->email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception('Invalid email format');
    }

    // Sanitize inputs
    $email = filter_var(trim($data->email), FILTER_SANITIZE_EMAIL);
    $password = $data->password;

    // Use the existing PDO connection from db-con.php
    global $pdo;

    // Prepare query with rate limiting check
    $query = "SELECT id, email, password, nickname, name, phone, login_attempts, last_login_attempt 
              FROM users WHERE email = :email";
    $stmt = $pdo->prepare($query);
    $stmt->execute(['email' => $email]);

    if ($stmt->rowCount() > 0) {
        $user = $stmt->fetch();
        
        // Check for rate limiting (max 5 attempts in 15 minutes)
        $lastAttempt = strtotime($user['last_login_attempt']);
        $timeDiff = time() - $lastAttempt;
        
        if ($user['login_attempts'] >= 5 && $timeDiff < 900) { // 15 minutes = 900 seconds
            $remainingTime = 900 - $timeDiff;
            throw new Exception("Too many login attempts. Please try again in " . ceil($remainingTime / 60) . " minutes");
        }

        // Reset login attempts if 15 minutes have passed
        if ($timeDiff >= 900) {
            $resetQuery = "UPDATE users SET login_attempts = 0 WHERE id = :id";
            $resetStmt = $pdo->prepare($resetQuery);
            $resetStmt->execute(['id' => $user['id']]);
            $user['login_attempts'] = 0;
        }
        
        // Initialize encryption class
        $crypto = new SecureEncryption();
        
        // Decrypt stored password and verify
        $decrypted_password = $crypto->decrypt($user['password']);
        
        if ($decrypted_password === false) {
            throw new Exception('Error decrypting password');
        }

        if ($password === $decrypted_password) {
            // Reset login attempts on successful login
            $resetQuery = "UPDATE users SET login_attempts = 0, last_login = NOW() WHERE id = :id";
            $resetStmt = $pdo->prepare($resetQuery);
            $resetStmt->execute(['id' => $user['id']]);

            // Create encrypted cookies
            $encrypted_id = $crypto->encrypt($user['id']);
            $encrypted_email = $crypto->encrypt($user['email']);
            
            if ($encrypted_id === false || $encrypted_email === false) {
                throw new Exception('Error creating secure session');
            }

            // Set secure cookies (valid for 24 hours)
            setcookie('user_id', $encrypted_id, [
                'expires' => time() + 86400,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
            
            setcookie('user_email', $encrypted_email, [
                'expires' => time() + 86400,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);

            // Generate new CSRF token for the session
            $newToken = $csrf->refreshToken();

            // Remove sensitive data from response
            unset($user['password']);
            unset($user['login_attempts']);
            unset($user['last_login_attempt']);
            
            $response['status'] = true;
            $response['message'] = 'Login successful';
            $response['data'] = [
                'id' => $user['id'],
                'email' => $user['email'],
                'nickname' => $user['nickname'],
                'name' => $user['name'],
                'phone' => $user['phone'],
                'csrf_token' => $newToken
            ];
        } else {
            // Increment login attempts
            $attempts = $user['login_attempts'] + 1;
            $updateQuery = "UPDATE users SET login_attempts = :attempts, last_login_attempt = NOW() WHERE id = :id";
            $updateStmt = $pdo->prepare($updateQuery);
            $updateStmt->execute(['attempts' => $attempts, 'id' => $user['id']]);
            
            throw new Exception('Invalid password');
        }
    } else {
        throw new Exception('User not found');
    }

} catch (PDOException $e) {
    $response['message'] = 'Database error occurred';
    error_log('Login PDO Error: ' . $e->getMessage());
} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>