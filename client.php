<?php

// Get the username and password fromt the request
$username = $_POST['username'];
$password = $_POST['password'];

// Encrypt the username and password with the public key
$public_key = openssl_pkey_get_public(file_get_contents('public.pem'));
$jData = [
    'username' => $username,
    'password' => $password
];
$jData = json_encode($jData);
openssl_public_encrypt($jData, $encrypted, $public_key);
file_put_contents('php://stderr', "Base Encoded Encrypted input: $base64_encoded_data\n");

$json_data = json_encode(['credentials' => $base64_encoded_data]);

$ch = curl_init('192.168.195.58/auth.php')
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
$response = curl_exec($ch);
file_put_contents('php://stderr', "Response: $response\n");

$decbase_jresponse = base64_decode($response);
file_put_contents('php://stderr', "Base Encoded Decrypted Response: $decbase_jresponse\n");

$iv_length = openssl_cipher_iv_length('aes-256-cbc');
$iv = substr($decbase_jresponse, 0, $iv_length);
file_put_contents('php://stderr', "IV: $iv\n");

$encrypted_response = substr($decbase_jresponse, $iv_length);
$password_hash = hash('sha256', $password, true);
file_put_contents('php://stderr', "Encrypted response: $encrypted_response\n");

$unencrypted_response = openssl_decrypt($encrypted_response, 'aes-256-cbc', $password_hash, 0, $iv);
file_put_contents('php://stderr', "Unencrypted response: $unencrypted_response\n");

$json_dec_token = json_decode($unencrypted_response, true);
file_put_contents('php://stderr', "Encrypted Token: $json_dec_token\n");
$encrypted_token = $json_dec_token['token'];
file_put_contents('php://stderr', "Encrypted Token: $encrypted_token\n");
$auth_response = $json_dec_token['auth'];
file_put_contents('php://stderr', "Auth Response: $auth_response\n");

// if the authentication is successful
// $auth_response = $decoded_response['auht'];
if ($auth_response == 'true') {
    // Redirect to application local with the token
    file_put_contents('php://stderr', "Using token\n");
    header('Location: https://192.168.203.162:443?token=$encrypted_token');
} else {
    // Redirect to the login page
    header('Location: index.html');
}

curl_close($ch);
?>