<?php
/**
 * 🎯 Get User Profile API
 * Fetches complete user profile data
 */

header('Content-Type: application/json');
require_once '../cors.php';
require_once '../db-con.php';
require_once '../security.php';

// Only allow GET requests
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

try {
    // Get user ID from query parameter
    $userId = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT);
    
    if (!$userId) {
        throw new Exception('Valid user ID is required');
    }
    
    // Get user data from database
    $stmt = $conn->prepare("
        SELECT id, name, nickname, email, phone, targets, hobbies, avatar, 
               created_at, updated_at, is_profile_complete
        FROM users 
        WHERE id = ?
    ");
    
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        throw new Exception('User not found');
    }
    
    $userData = $result->fetch_assoc();
    
    // Convert boolean fields
    $userData['is_profile_complete'] = (bool)$userData['is_profile_complete'];
    
    // Return success response
    echo json_encode([
        'success' => true,
        'message' => 'User data retrieved successfully',
        'data' => $userData
    ]);
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
    
    // Log error for debugging
    error_log("Get user error: " . $e->getMessage());
}

// Close database connection
if (isset($conn)) {
    $conn->close();
}
?>
