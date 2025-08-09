
<?php
try {
    $host = 'localhost';
    $dbname = 'aniverse';
    $username = 'root';
    $password = '';

    // Create PDO instance
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $username,
        $password,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );

    // Connection successful (no echo to avoid interfering with JSON responses)
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}
?>