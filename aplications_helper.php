<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * RSA Helper untuk CodeIgniter 3
 * 
 * Helper ini menyediakan fungsi enkripsi dan dekripsi menggunakan algoritma RSA
 * Simpan file ini sebagai: application/helpers/rsa_helper.php
 */

// Konstanta untuk nilai p dan q (bilangan prima)
define('RSA_P', 61);  // Bilangan prima pertama
define('RSA_Q', 53);  // Bilangan prima kedua

// Kalkulasi nilai RSA
define('RSA_N', RSA_P * RSA_Q);                    // n = p * q = 3233
define('RSA_PHI', (RSA_P - 1) * (RSA_Q - 1));     // φ(n) = (p-1) * (q-1) = 3120
define('RSA_E', 17);                               // eksponen publik (relatif prima dengan φ(n))
define('RSA_D', 2753);                             // eksponen privat (inverse modular e)

/**
 * Fungsi untuk menghitung pangkat modular (a^b mod m)
 * Menggunakan metode square-and-multiply untuk efisiensi
 */
if (!function_exists('mod_pow')) {
    function mod_pow($base, $exp, $mod) {
        if ($mod == 1) return 0;
        
        $result = 1;
        $base = $base % $mod;
        
        while ($exp > 0) {
            if ($exp % 2 == 1) {
                $result = ($result * $base) % $mod;
            }
            $exp = $exp >> 1;
            $base = ($base * $base) % $mod;
        }
        
        return $result;
    }
}

/**
 * Fungsi untuk menghitung GCD (Greatest Common Divisor)
 */
if (!function_exists('gcd')) {
    function gcd($a, $b) {
        while ($b != 0) {
            $temp = $b;
            $b = $a % $b;
            $a = $temp;
        }
        return $a;
    }
}

/**
 * Fungsi untuk menghitung inverse modular
 */
if (!function_exists('mod_inverse')) {
    function mod_inverse($a, $m) {
        if (gcd($a, $m) != 1) {
            return false; // Inverse tidak ada
        }
        
        // Extended Euclidean Algorithm
        $m0 = $m;
        $x0 = 0;
        $x1 = 1;
        
        if ($m == 1) return 0;
        
        while ($a > 1) {
            $q = intval($a / $m);
            $t = $m;
            
            $m = $a % $m;
            $a = $t;
            $t = $x0;
            
            $x0 = $x1 - $q * $x0;
            $x1 = $t;
        }
        
        if ($x1 < 0) $x1 += $m0;
        
        return $x1;
    }
}

/**
 * Fungsi enkripsi RSA
 * 
 * @param int $message Pesan yang akan dienkripsi (harus berupa angka)
 * @return int Hasil enkripsi
 */
if (!function_exists('enkripsi_rsa')) {
    function enkripsi_rsa($message) {
        // Validasi input
        if (!is_numeric($message)) {
            return false;
        }
        
        $message = intval($message);
        
        // Pastikan pesan tidak lebih besar dari n
        if ($message >= RSA_N) {
            return false;
        }
        
        // Enkripsi: C = M^e mod n
        return mod_pow($message, RSA_E, RSA_N);
    }
}

/**
 * Fungsi dekripsi RSA
 * 
 * @param int $ciphertext Pesan terenkripsi yang akan didekripsi
 * @return int Hasil dekripsi
 */
if (!function_exists('dekripsi_rsa')) {
    function dekripsi_rsa($ciphertext) {
        // Validasi input
        if (!is_numeric($ciphertext)) {
            return false;
        }
        
        $ciphertext = intval($ciphertext);
        
        // Dekripsi: M = C^d mod n
        return mod_pow($ciphertext, RSA_D, RSA_N);
    }
}

/**
 * Fungsi untuk menampilkan informasi kunci RSA (untuk debugging)
 */
if (!function_exists('info_rsa')) {
    function info_rsa() {
        return array(
            'p' => RSA_P,
            'q' => RSA_Q,
            'n' => RSA_N,
            'phi_n' => RSA_PHI,
            'e' => RSA_E,
            'd' => RSA_D,
            'kunci_publik' => '(' . RSA_N . ', ' . RSA_E . ')',
            'kunci_privat' => '(' . RSA_N . ', ' . RSA_D . ')'
        );
    }
}

/**
 * Fungsi enkripsi string (mengkonversi setiap karakter ke ASCII lalu enkripsi)
 * 
 * @param string $text Teks yang akan dienkripsi
 * @return string Hasil enkripsi dalam format JSON
 */
if (!function_exists('enkripsi_rsa_string')) {
    function enkripsi_rsa_string($text) {
        $encrypted = array();
        
        for ($i = 0; $i < strlen($text); $i++) {
            $ascii = ord($text[$i]);
            $encrypted[] = enkripsi_rsa($ascii);
        }
        
        return json_encode($encrypted);
    }
}

/**
 * Fungsi dekripsi string
 * 
 * @param string $encrypted_json Hasil enkripsi dalam format JSON
 * @return string Teks asli
 */
if (!function_exists('dekripsi_rsa_string')) {
    function dekripsi_rsa_string($encrypted_json) {
        $encrypted = json_decode($encrypted_json, true);
        $decrypted = '';
        
        if (is_array($encrypted)) {
            foreach ($encrypted as $encrypted_char) {
                $ascii = dekripsi_rsa($encrypted_char);
                $decrypted .= chr($ascii);
            }
        }
        
        return $decrypted;
    }
}

/**
 * Fungsi untuk validasi apakah nilai e dan d benar
 */
if (!function_exists('validasi_rsa')) {
    function validasi_rsa() {
        $test_message = 100;
        $encrypted = enkripsi_rsa($test_message);
        $decrypted = dekripsi_rsa($encrypted);
        
        return array(
            'test_message' => $test_message,
            'encrypted' => $encrypted,
            'decrypted' => $decrypted,
            'valid' => ($test_message == $decrypted)
        );
    }
}

/* End of file rsa_helper.php */
/* Location: ./application/helpers/rsa_helper.php */
