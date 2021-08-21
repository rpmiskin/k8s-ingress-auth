# Adding authentication to a k8s Ingress

This project is an investigation into adding authentication to a k8s ingress.
Steps to include:

1. Using an ingress to allow access to a service (and pod) from outside k8s
2. Adding basic auth to the ingress
3. Setting up OIDC auth

# Initial deployment

To start with we need to have a container to deploy, I've previously created and
echo server and build it as `local/simple-server` so we can start with that.
This Docker image will form the basis of our Pod.
The we need a Service to link to the Pod.
And finally an Ingress to allow external access to the Service (and in turn the pod).

This are all defined in the file `initial_deployment.yml`. NB: This assumes that an nginx
ingress controller has already been deployed to the cluster.

```
% kubectl apply -f initial_deployment.yml
% curl -XGET http://localhost/example-service/a/b
```

Should return:

```
{"method":"GET","url":"/example-service/a/b","headers":{"host":"localhost","x-request-id":"8fe277902702fd001c4a2d76afb2fb9b","x-real-ip":"192.168.65.6","x-forwarded-for":"192.168.65.6","x-forwarded-host":"localhost","x-forwarded-port":"80","x-forwarded-proto":"http","x-scheme":"http","user-agent":"curl/7.64.1","accept":"*/*"},"query":{},"body":{}}
```

# Adding basic auth

This follows the instructions [here](https://kubernetes.github.io/ingress-nginx/examples/auth/basic/) to add basic auth. The steps required are:

1. Create a htpasswd file
2. Create a secret from the passwd file
3. Mount the secret in the ingress and configure annotations to enable auth.

First create the password file:

```
% htpasswd -c auth foo
New password: <bar>
New password:
Re-type new password:
Adding password for user foo
```

```
% kubectl create secret generic basic-auth --from-file=auth
secret "basic-auth" created

% kubectl get secret basic-auth -o yaml
apiVersion: v1
data:
  auth: Zm9vOiRhcHIxJE9GRzNYeWJwJGNrTDBGSERBa29YWUlsSDkuY3lzVDAK
kind: Secret
metadata:
  name: basic-auth
  namespace: default
type: Opaque
```

We can now make use of this secret on a ingress with the following annotations:

```
    # type of authentication
    nginx.ingress.kubernetes.io/auth-type: basic
    # name of the secret that contains the user/password definitions
    nginx.ingress.kubernetes.io/auth-secret: basic-auth
    # message to display with an appropriate context why the authentication
    # is required. This is returned in the 'WWW-Authenticate' response
    # header.
    nginx.ingress.kubernetes.io/auth-realm: 'Authentication Required - foo'
```

The file `basic-auth.yml` deploys an additional ingress, this time taking all
requests to `/auth-service` and routing them to the original service _but_
ensuring that basic authentication is used.

You can apply this as follows:

```
% kubectl apply -f basic-auth.yml
```

Now listing the ingresses will show:

```
% kubectl get ingress

NAME                 CLASS    HOSTS       ADDRESS     PORTS   AGE
ingress-basic-auth   <none>   localhost   localhost   80      12m
ingress-no-auth      <none>   localhost   localhost   80      8m9s
```

This means the original ingress is still available, but there is an additional ingress which will enforce basic auth. (Obviously if you need people to login then you shouldn't leave the original ingress present!). You can test this as follows:

```
% curl -XGET http://localhost/example-service/234
{"method":"GET","url":"/234","headers":{"host":"localhost","x-request-id":"04952e1b360d001371f6ef14faa3817a","x-real-ip":"192.168.65.6","x-forwarded-for":"192.168.65.6","x-forwarded-host":"localhost","x-forwarded-port":"80","x-forwarded-proto":"http","x-scheme":"http","user-agent":"curl/7.64.1","accept":"*/*"},"query":{},"body":{}}

% curl -XGET http://localhost/auth-service/234
<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

To make a successful call to `auth-service` you must provide the username and
password that we created previously e.g.

```
% curl -ufoo:bar -XGET http://localhost/auth-service/234
{"method":"GET","url":"/234","headers":{"host":"localhost","x-request-id":"ab3b1f43bd1eb31d95c8c614208067ac","x-real-ip":"192.168.65.6","x-forwarded-for":"192.168.65.6","x-forwarded-host":"localhost","x-forwarded-port":"80","x-forwarded-proto":"http","x-scheme":"http","user-agent":"curl/7.64.1","accept":"*/*"},"query":{},"body":{}}
```

## But who is logged in?

A slight limitation with this approach is that at this point while we know
the user has been authenticated, we do not know who they are. The easiest
option here is to add some nginx config to pass the details of the
`$remote_user` in a custom header.

```
    # nginx snippet to pass through the logged in user in a header.
    nginx.ingress.kubernetes.io/configuration-snippet: proxy_set_header x-remote-user $remote_user;
```

This can be applied and tested by running:

```
% kubectl apply -f basic-auth-with-user-details.yml
% curl -ufoo:bar -XGET http://localhost/auth-service/234
{"method":"GET","url":"/234","headers":{"host":"localhost","x-request-id":"599aafc26760561dd76cfde02797713b","x-real-ip":"192.168.65.6","x-forwarded-for":"192.168.65.6","x-forwarded-host":"localhost","x-forwarded-port":"80","x-forwarded-proto":"http","x-scheme":"http","x-remote-user":"foo","user-agent":"curl/7.64.1","accept":"*/*"},"query":{},"body":{}}
```

It's a little hard to see, but there is now an `x-remote-user` header being
set which contains the user who logged in.

# A diversion into HTTPS

A very significant issue with using HTTP Basic Auth is that the username and
password are being sent over the internet as base64 encoded plaintext. This
means that someone could sniff your network traffic, extract the user/password
and login as you. To fix this, we need to enable SSL for our ingress. For this
example I am only going to use self-signed certificates, but the same process
should apply for certifcates signed by a trusted CA.

## Generate a certificate and deploy to our cluster

Use `openssl` to generate a self signed certificate for `localhost`.

```
% openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.file -out cert.file -subj "/CN=localhost/O=localhost"
```

Now upload the certifcate as a Secret

```
% kubectl create secret tls localhost.cert --key key.file --cert cert.file
secret/localhost.cert created
% kubectl get secret localhost.cert
NAME             TYPE                DATA   AGE
localhost.cert   kubernetes.io/tls   2      29s
```

## Update our ingress to use the certificate

You can apply the change as follows:

```
% kubectl apply -f basic-auth-ssl.yml
ingress.networking.k8s.io/ingress-basic-auth configured
% curl -ufoo:bar -XGET http://localhost/auth-service/234
<html>
<head><title>308 Permanent Redirect</title></head>
<body>
<center><h1>308 Permanent Redirect</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

As you can see, attempting to use http for this ingress now gives a `308 Permanent Redirect`. If you run curl with `-v` you can see the the response header that says
where to go `Location: https://localhost/auth-service/234`. When using a web browser
the redirect would be automatically followed, you can do the same by using the `-L`
option with `curl`, or just use the https protocol. You will additionally need to
provide `-k` to avoid errors due to the selfsigned certificate.

The following shows the verbose output, following the redirect and accepting the
self signed certificate.

```
% curl -Lvk -ufoo:bar http://localhost/auth-service/234
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 80 (#0)
* Server auth using Basic with user 'foo'
> GET /auth-service/234 HTTP/1.1
> Host: localhost
> Authorization: Basic Zm9vOmJhcg==
> User-Agent: curl/7.64.1
> Accept: */*
>
< HTTP/1.1 308 Permanent Redirect
< Date: Sat, 21 Aug 2021 14:55:44 GMT
< Content-Type: text/html
< Content-Length: 164
< Connection: keep-alive
< Location: https://localhost/auth-service/234
<
* Ignoring the response-body
* Connection #0 to host localhost left intact
* Issue another request to this URL: 'https://localhost/auth-service/234'
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 443 (#1)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/cert.pem
  CApath: none
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256
* ALPN, server accepted to use h2
* Server certificate:
*  subject: CN=localhost; O=localhost
*  start date: Aug 21 14:37:41 2021 GMT
*  expire date: Aug 21 14:37:41 2022 GMT
*  issuer: CN=localhost; O=localhost
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
* Using HTTP2, server supports multi-use
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Server auth using Basic with user 'foo'
* Using Stream ID: 1 (easy handle 0x7f956b80f800)
> GET /auth-service/234 HTTP/2
> Host: localhost
> Authorization: Basic Zm9vOmJhcg==
> User-Agent: curl/7.64.1
> Accept: */*
>
* Connection state changed (MAX_CONCURRENT_STREAMS == 128)!
< HTTP/2 200
< date: Sat, 21 Aug 2021 14:55:44 GMT
< content-type: application/json; charset=utf-8
< content-length: 358
< x-echo: true
< etag: W/"166-kmufwfztF4R8pAvdVBCfpDp7Js8"
< strict-transport-security: max-age=15724800; includeSubDomains
<
* Connection #1 to host localhost left intact
{"method":"GET","url":"/234","headers":{"host":"localhost","x-request-id":"bc8f64025be129e4ab2f53bfe7322ddd","x-real-ip":"192.168.65.6","x-forwarded-for":"192.168.65.6","x-forwarded-host":"localhost","x-forwarded-port":"443","x-forwarded-proto":"https","x-scheme":"https","x-remote-user":"foo","user-agent":"curl/7.64.1","accept":"*/*"},"query":{},"body":{}}* Closing connection 0
* Closing connection 1
```

**NOTE** An interesting side effect of the way that nginx configures the location is that despite
only one ingress having been updated HTTPS is enforced for both `ingress-basic-auth` and
`ingress-no-auth`.
