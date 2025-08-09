<?php
require_once 'cors.php';
header('Content-Type: application/json');

// Test response
$response = array(
    'status' => true,
    'message' => 'CORS test successful',
    'data' => array(
        'origin' => isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : 'No origin',
        'method' => $_SERVER['REQUEST_METHOD'],
        'headers' => getallheaders()
    )
);

echo json_encode($response);
exit;
?>
