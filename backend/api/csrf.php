<?php
session_start();

class CSRFProtection {
    private $tokenName = 'csrf_token';
    private $tokenLength = 32;
    
    public function __construct() {
        if (!isset($_SESSION[$this->tokenName])) {
            $_SESSION[$this->tokenName] = $this->generateToken();
        }
    }
    
    private function generateToken() {
        return bin2hex(random_bytes($this->tokenLength));
    }
    
    public function getToken() {
        return $_SESSION[$this->tokenName];
    }
    
    public function validateToken($token) {
        if (!isset($_SESSION[$this->tokenName])) {
            return false;
        }
        
        return hash_equals($_SESSION[$this->tokenName], $token);
    }
    
    public function refreshToken() {
        $_SESSION[$this->tokenName] = $this->generateToken();
        return $_SESSION[$this->tokenName];
    }
    
    public function setCSRFHeaders() {
        header('X-CSRF-Token: ' . $this->getToken());
        header('Access-Control-Allow-Headers: X-CSRF-Token, Content-Type');
    }
}
?>
