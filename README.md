# jwt4j
Java JWT Authentication

This library includes everything you need to both create and verify JWTs in Java!

It assumes that you have already figured out how to get a X509 Signing Certificate and it's Private Key loaded into your application.

### How to use

#### Creating a JwtVerifier

You can use JwtVerifiers to verify that a JWT has a certain signing pattern, as well as whether it is valid or not. A Jwt's validity could be based on things like if it is being used before it's issue date, or if it is being used after it's expiration date.

```java
// Create a JWT Verfier with a Signing Pattern. This pattern will be run against all
String signingPattern = "^.*\\bCN=test-cert\\.swiftengineer\\.com\\b(?:,.*|\\s*)$";
JwtVerifier jwtVerifier = new JwtVerifier(signingPattern);
```

#### Creating a JwtIssuer

You can use JwtIssuers to sign and issue JWTs.

```java
// Create a JWT Issuer
JwtIssuer jwtIssuer = new JwtIssuer(privateKey, signingCertificate);
```

#### Creating a JWT

```java
// create a jwt issuer
JwtIssuer jwtIssuer = new JwtIssuer(privateKey, signingCertificate);

// create a valid set of JWT claims that expires 30 minutes from now
JwtClaims claims = JwtClaims.JwtClaimsBuilder.newInstance()
        .addIssuedAt(Date.from(Instant.now()) // issued now
        .addExpirationTime(Date.from(Instant.now().plusSeconds(30L * 60))) // expires 30 minutes from now
        .build();

// issue the Jwt with some claims
String serializedJwt = jwtIssuer.issueToken(claims);

// attach the serializedJwt to an authentication header or pass it from Service to Service.
```
