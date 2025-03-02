# OAuth
1. The user enters credentials into the client application.
2. The client application sends credentials to the authentication server.
3. The authentication server uses the credentials to make an HTTP request to the appropriate PHP
script on the OAUTH provider.
4. If the credentials are not valid, the OAUTH provider will not return an OAUTH token to the
authentication server and the authentication server should return the following JSON to the
client, indicating an unsuccessful login: {“auth”:”fail”, “token”:””}.
5. If the credentials are valid, the OAUTH provider will return an OAUTH token in a JSON response
to the authentication server.
6. The authentication server should encrypt the JSON response containing the valid OAUTH token
with a secret key known to the authentication server and the application server.
7. The authentication server should then construct the following 'JSON response: {“auth”:
“success”, “token”: “<encrypted JSON RESPONSE>”}'
8. The authentication server will encrypt this JSON response using the SHA256 hash of the user’s
password and return it to the client.
9. The client will decrypt the response sent to it from the authentication server and send the
encrypted JSON containing the OAUTH token to the application server.
10. The application server will decrypt the encrypted JSON response containing the token using its
secret key, indicating that the token came from the authentication server.