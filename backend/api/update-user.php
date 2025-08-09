<?php
/**
 * 🎯 Ultimate User Profile Update API
 * Updates user profile data with full validation and security
 */

header('Content-Type: application/json');
require_once '../cors.php';
require_once '../db-con.php';
require_once '../security.php';

// Only allow PUT requests
if ($_SERVER['REQUEST_METHOD'] !== 'PUT') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

try {
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        throw new Exception('Invalid JSON data');
    }
    
    // Validate required fields
    $requiredFields = ['id', 'name', 'nickname', 'phone'];
    foreach ($requiredFields as $field) {
        if (!isset($input[$field]) || empty(trim($input[$field]))) {
            throw new Exception("Field '$field' is required");
        }
    }
    
    // Sanitize and validate input
    $userId = filter_var($input['id'], FILTER_VALIDATE_INT);
    $name = sanitizeInput($input['name']);
    $nickname = sanitizeInput($input['nickname']);
    $phone = sanitizeInput($input['phone']);
    $targets = isset($input['targets']) ? sanitizeInput($input['targets']) : '';
    $hobbies = isset($input['hobbies']) ? sanitizeInput($input['hobbies']) : '';
    $avatar = isset($input['avatar']) ? sanitizeInput($input['avatar']) : '';
    
    if (!$userId) {
        throw new Exception('Invalid user ID');
    }
    
    // Validate name length
    if (strlen($name) < 2 || strlen($name) > 50) {
        throw new Exception('Name must be between 2 and 50 characters');
    }
    
    // Validate nickname length
    if (strlen($nickname) < 2 || strlen($nickname) > 30) {
        throw new Exception('Nickname must be between 2 and 30 characters');
    }
    
    // Validate phone format (basic validation)
    if (!preg_match('/^[\+]?[0-9\s\-\(\)]{10,15}$/', $phone)) {
        throw new Exception('Invalid phone number format');
    }
    
    // Check if user exists
    $checkStmt = $conn->prepare("SELECT id FROM users WHERE id = ?");
    $checkStmt->bind_param("i", $userId);
    $checkStmt->execute();
    $result = $checkStmt->get_result();
    
    if ($result->num_rows === 0) {
        throw new Exception('User not found');
    }
    
    // Update user profile
    $updateStmt = $conn->prepare("
        UPDATE users 
        SET name = ?, nickname = ?, phone = ?, targets = ?, hobbies = ?, avatar = ?, updated_at = NOW()
        WHERE id = ?
    ");
    
    $updateStmt->bind_param("ssssssi", $name, $nickname, $phone, $targets, $hobbies, $avatar, $userId);
    
    if (!$updateStmt->execute()) {
        throw new Exception('Failed to update user profile');
    }
    
    // Get updated user data
    $getUserStmt = $conn->prepare("
        SELECT id, name, nickname, email, phone, targets, hobbies, avatar, 
               created_at, updated_at, is_profile_complete
        FROM users 
        WHERE id = ?
    ");
    $getUserStmt->bind_param("i", $userId);
    $getUserStmt->execute();
    $userResult = $getUserStmt->get_result();
    $userData = $userResult->fetch_assoc();
    
    // Log the update for security
    error_log("User profile updated: ID $userId by " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    
    // Return success response
    echo json_encode([
        'success' => true,
        'message' => 'Profile updated successfully! ✨',
        'data' => $userData
    ]);
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
    
    // Log error for debugging
    error_log("User update error: " . $e->getMessage());
}

// Close database connection
if (isset($conn)) {
    $conn->close();
}
?>
