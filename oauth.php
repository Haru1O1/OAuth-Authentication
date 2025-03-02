<?php

if (isset($_GET['username']) && isset($_GET['password'])) {
    $username = $_GET['username'];
    $password = $_GET['password'];

    $tokenUrl = 'http://localhost/token.php';
    $postData = [
        'grant_type' => 'client_credentials',
        'client_id' => $username,
        'client_secret' => $password
    ];
    file_put_contents('php://stderr', "Password is $password\n");

    $ch = curl_init($tokenUrl);

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));

    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/x-www-form-urlencoded'
    ]);

    $response = curl_exec($ch);
    file_put_contents('php://stderr', "Response is $response\n");
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);

    curl_close($ch);

    if ($httpCode == 200) {
        header('Content-Type: application/json');
        echo $response;
    } else {
        echo "Unable to rerieve token. HTTP Code: $httpCode";
        echo " cURL Error: $error";
        echo " Response: $response";
    }
} else {
    echo "Missing credentials";
}
?>