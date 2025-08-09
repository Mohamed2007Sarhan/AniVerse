<?php
/**
 * 🎨 Ultimate Avatar Upload API
 * Handles avatar image uploads with validation and optimization
 */

header('Content-Type: application/json');
require_once '../cors.php';
require_once '../db-con.php';
require_once '../security.php';

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

try {
    // Check if file was uploaded
    if (!isset($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
        throw new Exception('No file uploaded or upload error occurred');
    }
    
    // Get user ID
    $userId = filter_var($_POST['userId'] ?? null, FILTER_VALIDATE_INT);
    if (!$userId) {
        throw new Exception('Valid user ID is required');
    }
    
    $file = $_FILES['avatar'];
    
    // Validate file size (max 5MB)
    $maxSize = 5 * 1024 * 1024; // 5MB
    if ($file['size'] > $maxSize) {
        throw new Exception('File size too large. Maximum allowed size is 5MB');
    }
    
    // Validate file type
    $allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    $fileType = mime_content_type($file['tmp_name']);
    
    if (!in_array($fileType, $allowedTypes)) {
        throw new Exception('Invalid file type. Only JPG, PNG, GIF, and WebP images are allowed');
    }
    
    // Validate image dimensions (optional - prevent extremely large images)
    $imageInfo = getimagesize($file['tmp_name']);
    if (!$imageInfo) {
        throw new Exception('Invalid image file');
    }
    
    $maxWidth = 2000;
    $maxHeight = 2000;
    if ($imageInfo[0] > $maxWidth || $imageInfo[1] > $maxHeight) {
        throw new Exception("Image dimensions too large. Maximum allowed: {$maxWidth}x{$maxHeight}px");
    }
    
    // Check if user exists
    $checkStmt = $conn->prepare("SELECT id, avatar FROM users WHERE id = ?");
    $checkStmt->bind_param("i", $userId);
    $checkStmt->execute();
    $result = $checkStmt->get_result();
    
    if ($result->num_rows === 0) {
        throw new Exception('User not found');
    }
    
    $userData = $result->fetch_assoc();
    $oldAvatar = $userData['avatar'];
    
    // Create upload directory if it doesn't exist
    $uploadDir = "../uploads/avatars/{$userId}/";
    if (!file_exists($uploadDir)) {
        if (!mkdir($uploadDir, 0755, true)) {
            throw new Exception('Failed to create upload directory');
        }
    }
    
    // Generate unique filename
    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
    $filename = 'avatar_' . time() . '_' . uniqid() . '.' . $extension;
    $uploadPath = $uploadDir . $filename;
    $relativePath = "uploads/avatars/{$userId}/{$filename}";
    
    // Move uploaded file
    if (!move_uploaded_file($file['tmp_name'], $uploadPath)) {
        throw new Exception('Failed to save uploaded file');
    }
    
    // Optional: Resize image if needed (requires GD extension)
    if (extension_loaded('gd')) {
        try {
            resizeImage($uploadPath, $uploadPath, 400, 400);
        } catch (Exception $e) {
            // If resize fails, continue with original image
            error_log("Image resize failed: " . $e->getMessage());
        }
    }
    
    // Update user avatar in database
    $updateStmt = $conn->prepare("UPDATE users SET avatar = ?, updated_at = NOW() WHERE id = ?");
    $updateStmt->bind_param("si", $relativePath, $userId);
    
    if (!$updateStmt->execute()) {
        // If database update fails, remove uploaded file
        unlink($uploadPath);
        throw new Exception('Failed to update user avatar in database');
    }
    
    // Delete old avatar file if it exists and is different
    if ($oldAvatar && $oldAvatar !== $relativePath && file_exists("../{$oldAvatar}")) {
        unlink("../{$oldAvatar}");
    }
    
    // Log the upload for security
    error_log("Avatar uploaded: User ID $userId, File: $filename");
    
    // Return success response
    echo json_encode([
        'success' => true,
        'message' => 'Avatar uploaded successfully! ✨',
        'data' => [
            'avatar_path' => $relativePath,
            'filename' => $filename,
            'file_size' => $file['size'],
            'upload_time' => date('Y-m-d H:i:s')
        ]
    ]);
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
    
    // Log error for debugging
    error_log("Avatar upload error: " . $e->getMessage());
}

/**
 * Resize image to specified dimensions
 */
function resizeImage($source, $destination, $maxWidth, $maxHeight) {
    $imageInfo = getimagesize($source);
    $width = $imageInfo[0];
    $height = $imageInfo[1];
    $type = $imageInfo[2];
    
    // Calculate new dimensions maintaining aspect ratio
    $ratio = min($maxWidth / $width, $maxHeight / $height);
    $newWidth = (int)($width * $ratio);
    $newHeight = (int)($height * $ratio);
    
    // Create image resource based on type
    switch ($type) {
        case IMAGETYPE_JPEG:
            $sourceImage = imagecreatefromjpeg($source);
            break;
        case IMAGETYPE_PNG:
            $sourceImage = imagecreatefrompng($source);
            break;
        case IMAGETYPE_GIF:
            $sourceImage = imagecreatefromgif($source);
            break;
        case IMAGETYPE_WEBP:
            $sourceImage = imagecreatefromwebp($source);
            break;
        default:
            throw new Exception('Unsupported image type for resizing');
    }
    
    // Create new image
    $newImage = imagecreatetruecolor($newWidth, $newHeight);
    
    // Preserve transparency for PNG and GIF
    if ($type == IMAGETYPE_PNG || $type == IMAGETYPE_GIF) {
        imagealphablending($newImage, false);
        imagesavealpha($newImage, true);
        $transparent = imagecolorallocatealpha($newImage, 255, 255, 255, 127);
        imagefilledrectangle($newImage, 0, 0, $newWidth, $newHeight, $transparent);
    }
    
    // Resize image
    imagecopyresampled($newImage, $sourceImage, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
    
    // Save resized image
    switch ($type) {
        case IMAGETYPE_JPEG:
            imagejpeg($newImage, $destination, 90);
            break;
        case IMAGETYPE_PNG:
            imagepng($newImage, $destination);
            break;
        case IMAGETYPE_GIF:
            imagegif($newImage, $destination);
            break;
        case IMAGETYPE_WEBP:
            imagewebp($newImage, $destination, 90);
            break;
    }
    
    // Clean up memory
    imagedestroy($sourceImage);
    imagedestroy($newImage);
}

// Close database connection
if (isset($conn)) {
    $conn->close();
}
?>
