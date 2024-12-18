# AWS RolesAnywhere's CreateSession client

This project provides the Java client for AWS RolesAnywhere's [CreateSession](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html) service, using X.509 certificate for request signing (as described [here](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html)). 

The code is based on similar [python implementation](https://github.com/awslabs/iam-roles-anywhere-session).

Requirements:
- JDK 21 with Gradle
- Valid CA private key and certificate compliant with trust anchor (see test resources)
- AWS configuration properties:
  - region
  - profile ARN
  - assumed role ARN
  - trust anchor ARN

Example execution:
```java
// load PEM data for cetificate and private key
var certificate = Files.readAllBytes(Paths.get("src", "test", "resources", "rsa", "certificate.pem"));
var privateKey = Files.readAllBytes(Paths.get("src", "test", "resources", "rsa", "ca.key"));
// initialize client
var client = new CreateSessionClient(new ObjectMapper());
// create and execute command
var command = new CreateSessionCommand("eu-central-1",
        certificate,
        privateKey,
        "arn:aws:rolesanywhere:eu-central-1:012345678901:profile/11472cf9-8719-44a2-89ce-96003d8040ad",
        "arn:aws:iam::012345678901:role/example-role",
        "arn:aws:rolesanywhere:eu-central-1:012345678901:trust-anchor/e4473a77-6a14-42cc-ab7b-87ba65dc571b");
var result = client.execute(command);
log.debug("Acquired temporary credentials: " + result.accessKeyId() + ", " + result.secretAccessKey());
```