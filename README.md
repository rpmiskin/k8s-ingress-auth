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
kubectl apply -f initial_deployment.yml
curl -XGET http://localhost/example-service/a/b
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
$ htpasswd -c auth foo
New password: <bar>
New password:
Re-type new password:
Adding password for user foo
```

```
$ kubectl create secret generic basic-auth --from-file=auth
secret "basic-auth" created

$ kubectl get secret basic-auth -o yaml
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
kubectl apply -f basic-auth.yml
```

Now listing the ingresses will show:

```
kubectl get ingress

NAME                 CLASS    HOSTS       ADDRESS     PORTS   AGE
ingress-basic-auth   <none>   localhost   localhost   80      12m
ingress-no-auth      <none>   localhost   localhost   80      8m9s
```

This means the original ingress is still available, but there is an additional ingress which will enforce basic auth. You can test this as follows:

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
