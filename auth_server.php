<?php

// Load Private Key
$private_key = file_get_contents("privatekey.pem");
file_put_contents('php://stderr', "Private Key: " . $private_key . "\n");

$rawData = file_get_contents
file_put_contents('php://stderr', "Raw Input: " . $rawData . "\n");
$data = json_decode($rawData, true);
file_put_contents('php://stderr', "Json Decoded: " . $data . "\n");
$base_encrypted_creds = $data['credentials'];
file_put_contents('php://stderr', "Base Encrypted Creds: " . $base_encrypted_creds . "\n");
$encrypted_credentials = base64_decode($base_encrypted_creds);
file_put_contents('php://stderr', "Encrypted Creds: " . $encrypted_credentials . "\n");

// $encrypted_credentials = $_POST['credentials'];
openssl_private_decrypt($encrypted_credentials, $decrypted_credentials, $private_key);
file_put_contents('php://stderr', "Decrypted Creds: " . $decrypted_credentials . "\n");

// Extract username and password from decrypted credentials
$credentials = json_decode($decrypted_credentials, true);
$username = $credentials['username'];
$password = $credentials['password'];
file_put_contents('php://stderr', "Username: " . $username . "\n");
file_put_contents('php://stderr', "Password: " . $password . "\n");

// Send Crendentials to Provider
$contents = stream_context_create([
    "ssl" => [
        "verify_peer" => false,
        "verify_peer_name" => true,
        "cafile" => "/etc/ssl/certs/wildcard.local.crt",
    ],
]);
$provider_response = file_get_contents("https://oauth.local/auth.php?username=$username$password=$password", false, $contents);

// Extract Access Token From Provider Response
$provider_token = json_decode($provider_response, true)['access_token'];
file_put_contents('php://stderr', "Provider Token: " . $provider_token . "\n");

// Load Shared Secret Key
$secret_shared = file_get_contents("secretshared.pem");

if ($provider_token) {
    $ivF = openssl_random_pseudo_bytes(16);
    $token = openssl_encrypt($provider_token, 'aes-256-cbc', hash("sha256", $secret_shared, true), 0, $ivF);
    file_put_contents('php://stderr', "Token: " . $token . "\n");
    $token = base64_encode($ivF . $token);
    $auth = "success";
} else {
    $token = "";
    $auth = "fail"
}

// Send auth response to client.local
$response = [
    "auth" => $auth,
    "token" => $token,
];
$response = json_encode($response);
file_put_contents('php://stderr', "NonHashed Response: " . $response . "\n");

// Encrypt response using client's password
$iv = openssl_random_pseudo_bytes(16);
file_put_contents('php://stderr', "IV: " . $iv . "\n");
$encrypt_response = openssl_encrypt($response, 'aes-256-cbc', hash("sha256", $password, true), 0, $iv);
file_put_contents('php://stderr', "Encrypted Response: " . $encrypt_response . "\n");
$en_ren_iv = base64_encode($iv . $encrypt_response);

echo $en_ren_iv;
?>  
