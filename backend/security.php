<?php

class SecurityUtils {
    
    /**
     * Sanitize input data
     */
    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
    }
    
    /**
     * Validate email format
     */
    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    /**
     * Validate password strength
     */
    public static function validatePassword($password) {
        // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
        $pattern = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/';
        return preg_match($pattern, $password);
    }
    
    /**
     * Validate phone number
     */
    public static function validatePhone($phone) {
        // Allow international format with +, digits, spaces, dashes, parentheses
        $pattern = '/^\+?[\d\s\-\(\)]{10,}$/';
        return preg_match($pattern, $phone);
    }
    
    /**
     * Generate secure random token
     */
    public static function generateToken($length = 32) {
        return bin2hex(random_bytes($length));
    }
    
    /**
     * Hash password using bcrypt
     */
    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }
    
    /**
     * Verify password against hash
     */
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * Get client IP address
     */
    public static function getClientIP() {
        $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_CLIENT_IP', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Rate limiting check
     */
    public static function checkRateLimit($identifier, $maxAttempts = 5, $timeWindow = 900) {
        global $pdo;
        
        $ip = self::getClientIP();
        $currentTime = time();
        $cutoffTime = $currentTime - $timeWindow;
        
        // Clean old attempts
        $cleanQuery = "DELETE FROM login_attempts WHERE attempt_time < FROM_UNIXTIME(?)";
        $cleanStmt = $pdo->prepare($cleanQuery);
        $cleanStmt->execute([$cutoffTime]);
        
        // Count recent attempts
        $countQuery = "SELECT COUNT(*) as attempts FROM login_attempts 
                      WHERE (email = ? OR ip_address = ?) AND attempt_time > FROM_UNIXTIME(?)";
        $countStmt = $pdo->prepare($countQuery);
        $countStmt->execute([$identifier, $ip, $cutoffTime]);
        $result = $countStmt->fetch();
        
        return $result['attempts'] < $maxAttempts;
    }
    
    /**
     * Log login attempt
     */
    public static function logLoginAttempt($email, $success = false) {
        global $pdo;
        
        $ip = self::getClientIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        $logQuery = "INSERT INTO login_attempts (email, ip_address, user_agent, success) VALUES (?, ?, ?, ?)";
        $logStmt = $pdo->prepare($logQuery);
        $logStmt->execute([$email, $ip, $userAgent, $success]);
    }
    
    /**
     * Set secure cookie
     */
    public static function setSecureCookie($name, $value, $expires = 86400) {
        $options = [
            'expires' => time() + $expires,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ];
        
        setcookie($name, $value, $options);
    }
    
    /**
     * Clear secure cookie
     */
    public static function clearCookie($name) {
        setcookie($name, '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }
    
    /**
     * Validate CSRF token
     */
    public static function validateCSRFToken($token) {
        if (!isset($_SESSION['csrf_token'])) {
            return false;
        }
        
        return hash_equals($_SESSION['csrf_token'], $token);
    }
    
    /**
     * Generate CSRF token
     */
    public static function generateCSRFToken() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = self::generateToken();
        }
        
        return $_SESSION['csrf_token'];
    }
}
?>
