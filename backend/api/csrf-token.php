<?php
require_once 'cors.php';
header('Content-Type: application/json');

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
    
    // Check if request method is GET
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        throw new Exception('Only GET method is allowed');
    }

    // Get CSRF token
    $token = $csrf->getToken();
    
    if ($token) {
        $response['status'] = true;
        $response['message'] = 'CSRF token generated successfully';
        $response['data'] = [
            'csrf_token' => $token
        ];
    } else {
        throw new Exception('Failed to generate CSRF token');
    }

} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

// Send response
echo json_encode($response);
exit;
?>
