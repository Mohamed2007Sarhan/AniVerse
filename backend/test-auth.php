<?php
// Test file for authentication system
require_once 'db-con.php';
require_once 'hash.php';
require_once 'api/csrf.php';

echo "<h1>AniVerse Authentication System Test</h1>";

// Test 1: Database Connection
echo "<h2>1. Database Connection Test</h2>";
try {
    global $pdo;
    if ($pdo) {
        echo "✅ Database connection successful<br>";
    } else {
        echo "❌ Database connection failed<br>";
    }
} catch (Exception $e) {
    echo "❌ Database connection error: " . $e->getMessage() . "<br>";
}

// Test 2: CSRF Token Generation
echo "<h2>2. CSRF Token Test</h2>";
try {
    $csrf = new CSRFProtection();
    $token = $csrf->getToken();
    if ($token && strlen($token) === 64) {
        echo "✅ CSRF token generated successfully: " . substr($token, 0, 16) . "...<br>";
    } else {
        echo "❌ CSRF token generation failed<br>";
    }
} catch (Exception $e) {
    echo "❌ CSRF token error: " . $e->getMessage() . "<br>";
}

// Test 3: Encryption Test
echo "<h2>3. Encryption Test</h2>";
try {
    $crypto = new SecureEncryption();
    $testData = "test_password_123";
    $encrypted = $crypto->encrypt($testData);
    $decrypted = $crypto->decrypt($encrypted);
    
    if ($encrypted && $decrypted === $testData) {
        echo "✅ Encryption/Decryption successful<br>";
    } else {
        echo "❌ Encryption/Decryption failed<br>";
    }
} catch (Exception $e) {
    echo "❌ Encryption error: " . $e->getMessage() . "<br>";
}

// Test 4: Database Schema Check
echo "<h2>4. Database Schema Check</h2>";
try {
    $tables = ['users', 'user_profiles', 'user_sessions', 'login_attempts'];
    foreach ($tables as $table) {
        $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
        if ($stmt->rowCount() > 0) {
            echo "✅ Table '$table' exists<br>";
        } else {
            echo "❌ Table '$table' missing<br>";
        }
    }
} catch (Exception $e) {
    echo "❌ Schema check error: " . $e->getMessage() . "<br>";
}

// Test 5: API Endpoints Check
echo "<h2>5. API Endpoints Check</h2>";
$endpoints = [
    'csrf-token.php',
    'login.php',
    'register.php',
    'logout.php'
];

foreach ($endpoints as $endpoint) {
    $filePath = "api/$endpoint";
    if (file_exists($filePath)) {
        echo "✅ Endpoint '$endpoint' exists<br>";
    } else {
        echo "❌ Endpoint '$endpoint' missing<br>";
    }
}

echo "<h2>Test Complete</h2>";
echo "<p>If all tests pass, your authentication system is ready to use!</p>";
echo "<p><a href='../frontend'>Go to Frontend</a></p>";
?>
