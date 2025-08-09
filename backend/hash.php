<?php

class SecureEncryption {
    private $firstKey = 'Mohamed2007#4';
    private $secondKey = 'Anime#Shadow';
    private $firstIV;
    private $secondIV;
    private $cipher1 = 'AES-256-CBC';
    private $cipher2 = 'aes-256-gcm';

    public function __construct() {
        if (!extension_loaded('openssl')) {
            throw new Exception('OpenSSL extension is required');
        }
        
        // Generate unique IVs for each encryption step
        $this->firstIV = substr(hash('sha256', $this->firstKey), 0, 16);
        $this->secondIV = random_bytes(16);
    }

    public function encrypt($data) {
        if (empty($data)) {
            throw new Exception('Data to encrypt cannot be empty');
        }

        try {
            // First step encryption (AES-256-CBC)
            $firstStep = openssl_encrypt(
                $data,
                $this->cipher1,
                $this->firstKey,
                OPENSSL_RAW_DATA,
                $this->firstIV
            );

            if ($firstStep === false) {
                throw new Exception('First encryption step failed');
            }

            // Second step encryption (AES-256-GCM)
            $tag = '';
            $secondStep = openssl_encrypt(
                $firstStep,
                $this->cipher2,
                $this->secondKey,
                OPENSSL_RAW_DATA,
                $this->secondIV,
                $tag
            );

            if ($secondStep === false) {
                throw new Exception('Second encryption step failed');
            }

            // Combine IVs, tag and encrypted data
            $combined = base64_encode($this->secondIV . $tag . $secondStep);
            return $combined;

        } catch (Exception $e) {
            error_log('Encryption error: ' . $e->getMessage());
            return false;
        }
    }

    public function decrypt($encryptedData) {
        if (empty($encryptedData)) {
            throw new Exception('Encrypted data cannot be empty');
        }

        try {
            // Decode the combined string
            $decoded = base64_decode($encryptedData, true);
            
            if ($decoded === false) {
                throw new Exception('Invalid base64 encoding');
            }

            if (strlen($decoded) < 48) { // Minimum length check (16 + 16 + 16)
                throw new Exception('Invalid encrypted data length');
            }

            // Extract components
            $secondIV = substr($decoded, 0, 16);
            $tag = substr($decoded, 16, 16);
            $encrypted = substr($decoded, 32);

            // Second step decryption (AES-256-GCM)
            $firstStep = openssl_decrypt(
                $encrypted,
                $this->cipher2,
                $this->secondKey,
                OPENSSL_RAW_DATA,
                $secondIV,
                $tag
            );

            if ($firstStep === false) {
                throw new Exception('Second decryption step failed');
            }

            // First step decryption (AES-256-CBC)
            $decrypted = openssl_decrypt(
                $firstStep,
                $this->cipher1,
                $this->firstKey,
                OPENSSL_RAW_DATA,
                $this->firstIV
            );

            if ($decrypted === false) {
                throw new Exception('First decryption step failed');
            }

            return $decrypted;

        } catch (Exception $e) {
            error_log('Decryption error: ' . $e->getMessage());
            return false;
        }
    }
}

// Example usage function
function testEncryption() {
    try {
        $crypto = new SecureEncryption();
        
        // Test data
        $sensitiveData = "This is sensitive information";
        
        // Encrypt
        $encrypted = $crypto->encrypt($sensitiveData);
        if ($encrypted === false) {
            throw new Exception('Encryption failed');
        }
        echo "Encrypted: " . $encrypted . "\n";
        
        // Decrypt
        $decrypted = $crypto->decrypt($encrypted);
        if ($decrypted === false) {
            throw new Exception('Decryption failed');
        }
        echo "Decrypted: " . $decrypted . "\n";
        
        // Verify
        if ($decrypted === $sensitiveData) {
            echo "Encryption/Decryption successful!\n";
        } else {
            echo "Verification failed!\n";
        }

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
}

// To test the encryption/decryption, uncomment the following line:
// testEncryption();
?>