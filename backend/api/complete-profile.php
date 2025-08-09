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

    // Get POST data
    $data = json_decode(file_get_contents("php://input"));

    // Validate required fields
    if (!isset($data->nickname) || !isset($data->policy_accepted)) {
        throw new Exception('Nickname and policy acceptance are required');
    }

    // Validate policy acceptance
    if (!$data->policy_accepted) {
        throw new Exception('You must accept the privacy policy to continue');
    }

    // Sanitize inputs
    $nickname = filter_var(trim($data->nickname), FILTER_SANITIZE_STRING);
    $avatar = isset($data->avatar) ? filter_var(trim($data->avatar), FILTER_SANITIZE_STRING) : null;
    $bodyAnalysis = isset($data->body_analysis) ? filter_var(trim($data->body_analysis), FILTER_SANITIZE_STRING) : null;
    $targets = isset($data->targets) ? filter_var(trim($data->targets), FILTER_SANITIZE_STRING) : null;
    $hobbies = isset($data->hobbies) ? filter_var(trim($data->hobbies), FILTER_SANITIZE_STRING) : null;
    $phone = isset($data->phone) ? filter_var(trim($data->phone), FILTER_SANITIZE_STRING) : null;

    // Validate nickname
    if (strlen($nickname) < 2 || strlen($nickname) > 50) {
        throw new Exception('Nickname must be between 2 and 50 characters');
    }

    // Check if nickname is already taken
    global $pdo;
    $checkQuery = "SELECT id FROM users WHERE nickname = :nickname AND id != :id";
    $checkStmt = $pdo->prepare($checkQuery);
    $checkStmt->execute(['nickname' => $nickname, 'id' => $userId]);

    if ($checkStmt->rowCount() > 0) {
        throw new Exception('Nickname is already taken');
    }

    // Get client IP address
    $ipAddress = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '';

    // Update user profile
    $updateQuery = "UPDATE users SET 
                    nickname = :nickname,
                    avatar = :avatar,
                    body_analysis = :body_analysis,
                    targets = :targets,
                    hobbies = :hobbies,
                    phone = :phone,
                    policy_accepted = :policy_accepted,
                    ip_address = :ip_address,
                    updated_at = NOW()
                    WHERE id = :id";
    
    $updateStmt = $pdo->prepare($updateQuery);
    $result = $updateStmt->execute([
        'nickname' => $nickname,
        'avatar' => $avatar,
        'body_analysis' => $bodyAnalysis,
        'targets' => $targets,
        'hobbies' => $hobbies,
        'phone' => $phone,
        'policy_accepted' => $data->policy_accepted ? 1 : 0,
        'ip_address' => $ipAddress,
        'id' => $userId
    ]);

    if ($result) {
        // Get updated user data
        $userQuery = "SELECT id, name, email, nickname, avatar, body_analysis, targets, hobbies, phone, policy_accepted, created_at, updated_at 
                      FROM users WHERE id = :id";
        $userStmt = $pdo->prepare($userQuery);
        $userStmt->execute(['id' => $userId]);
        $userData = $userStmt->fetch();

        $response['status'] = true;
        $response['message'] = 'Profile completed successfully';
        $response['data'] = $userData;
    } else {
        throw new Exception('Failed to update profile');
    }

} catch (PDOException $e) {
    $response['message'] = 'Database error occurred';
    error_log('Complete Profile PDO Error: ' . $e->getMessage());
} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>
