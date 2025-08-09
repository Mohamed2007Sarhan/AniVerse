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

    // Check if file was uploaded
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        throw new Exception('No file uploaded or upload error');
    }

    $file = $_FILES['file'];
    $fileType = $_POST['type'] ?? 'avatar'; // avatar or body

    // Validate file type
    $allowedTypes = ['avatar', 'body'];
    if (!in_array($fileType, $allowedTypes)) {
        throw new Exception('Invalid file type');
    }

    // Validate file size (max 10MB)
    $maxSize = 10 * 1024 * 1024; // 10MB
    if ($file['size'] > $maxSize) {
        throw new Exception('File size too large. Maximum size is 10MB');
    }

    // Validate file extension
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    
    if (!in_array($fileExtension, $allowedExtensions)) {
        throw new Exception('Invalid file type. Allowed types: ' . implode(', ', $allowedExtensions));
    }

    // Create upload directory if it doesn't exist
    $uploadDir = "../uploads/$fileType/";
    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    // Generate unique filename
    $uniqueId = uniqid();
    $filename = $userId . '_' . $fileType . '_' . $uniqueId . '.' . $fileExtension;
    $filepath = $uploadDir . $filename;

    // Move uploaded file
    if (!move_uploaded_file($file['tmp_name'], $filepath)) {
        throw new Exception('Failed to save file');
    }

    // Generate URL for the file
    $fileUrl = "/AnimeProject/backend/uploads/$fileType/" . $filename;

    // Update user profile with file URL
    global $pdo;
    $updateField = $fileType === 'avatar' ? 'avatar' : 'body_analysis';
    $updateQuery = "UPDATE users SET $updateField = :file_url, updated_at = NOW() WHERE id = :id";
    $updateStmt = $pdo->prepare($updateQuery);
    $result = $updateStmt->execute([
        'file_url' => $fileUrl,
        'id' => $userId
    ]);

    if ($result) {
        $response['status'] = true;
        $response['message'] = 'File uploaded successfully';
        $response['data'] = [
            'file_url' => $fileUrl,
            'filename' => $filename,
            'type' => $fileType
        ];
    } else {
        throw new Exception('Failed to update profile with file URL');
    }

} catch (PDOException $e) {
    $response['message'] = 'Database error occurred';
    error_log('File Upload PDO Error: ' . $e->getMessage());
} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>
