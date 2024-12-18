package net.mnowicki.aws.iam.createsession.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.mnowicki.aws.iam.createsession.CreateSessionCommand;
import net.mnowicki.aws.iam.createsession.CreateSessionCommandResult;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class CreateSessionClient {
    static final DateTimeFormatter REQUEST_DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd'T'hhmmss'Z'");
    static final DateTimeFormatter REQUEST_DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd");

    private static final Log log = LogFactory.getLog(CreateSessionClient.class);

    private static final int MAX_TTL_IN_SECONDS = 3600; //max TTL for temporary credentials
    private static final String DEFAULT_LINE_SEPARATOR = "\n";

    private final ObjectMapper objectMapper;

    public CreateSessionClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public CreateSessionCommandResult execute(CreateSessionCommand command) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost request = buildCreateSessionRequest(command);
            log.info(String.format("CreateSession request: %s\n%s\n%s", request, Arrays.toString(request.getAllHeaders()), EntityUtils.toString(request.getEntity())));
            HttpResponse response = httpClient.execute(request);
            int responseCode = response.getStatusLine().getStatusCode();
            if (responseCode > 299) {
                String responseBody = new BufferedReader(new InputStreamReader(response.getEntity().getContent())).lines().collect(Collectors.joining(DEFAULT_LINE_SEPARATOR));
                throw new RuntimeException(String.format("%d\n%s", responseCode, responseBody));
            }
            log.info("CreateSession request successful!");
            CreateSessionResponseDto responseDto = objectMapper.readValue(response.getEntity().getContent(), CreateSessionResponseDto.class);
            CreateSessionResponseDto.Credentials credentials = responseDto.getCredentialSet().stream()
                    .findFirst()
                    .map(CreateSessionResponseDto.CredentialSetEntry::getCredentials)
                    .orElseThrow(() -> new RuntimeException("Credentials not found in response"));
            return new CreateSessionCommandResult(credentials.getAccessKeyId(), credentials.getExpiration(), credentials.getSecretAccessKey(), credentials.getSessionToken());
        } catch (Exception e) {
            throw new RuntimeException(String.format("CreateSession failed, reason: %s", e.getMessage()), e);
        }
    }

    private HttpPost buildCreateSessionRequest(CreateSessionCommand command) throws Exception {
        // prepare data
        X509Certificate certificate = loadCertificate(command.certificateData());
        PrivateKey privateKey = loadPrivateKey(command.privateKeyData());
        String algorithm = getAlgorithm(privateKey, certificate);
        String region = command.region();
        String host = String.format("rolesanywhere.%s.amazonaws.com", region);
        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("UTC"));
        String requestDateTime = REQUEST_DATE_TIME_FORMATTER.format(now);
        String requestDate = REQUEST_DATE_FORMATTER.format(now);

        // build request payload
        byte[] payload = objectMapper.writeValueAsBytes(new CreateSessionRequestDto(MAX_TTL_IN_SECONDS, command.profileArn(), command.roleArn(), command.trustAnchorArn()));
        // prepare request headers
        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.HOST, host);
        headers.put(HttpHeaders.CONTENT_TYPE, "application/x-amz-json-1.0");
        headers.put("X-Amz-Date", requestDateTime);
        headers.put("X-Amz-X509", Base64.getEncoder().encodeToString(certificate.getEncoded()));

        // sign request (https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html)
        Map<String, String> canonicalHeaders = getCanonicalHeaders(headers);
        String signedHeaders = getSignedHeaders(canonicalHeaders);
        String canonicalRequest = createCanonicalRequest(canonicalHeaders, signedHeaders, payload);
        log.info(String.format("Canonical request:\n%s", canonicalRequest));
        String credentialScope = createCredentialScope(requestDate, region);
        String stringToSign = createStringToSign(algorithm, requestDateTime, canonicalRequest, credentialScope);
        String signature = calculateSignature(certificate, privateKey, stringToSign);
        String credentialString = createCredentialString(certificate, credentialScope);
        String authorization = createAuthorizationHeader(algorithm, credentialString, signedHeaders, signature);

        // build request
        HttpPost post = new HttpPost(String.format("https://%s/sessions", host));
        post.addHeader("Authorization", authorization);
        headers.forEach(post::setHeader);
        post.setEntity(new ByteArrayEntity(payload));

        return post;
    }

    String getAlgorithm(PrivateKey privateKey, X509Certificate certificate) {
        return "AWS4-X509-" + privateKey.getAlgorithm() + "-" + certificate.getSigAlgName().substring(0, 6).toUpperCase();
    }

    String createCredentialString(X509Certificate certificate, String credentialScope) {
        return String.join("/", certificate.getSerialNumber().toString(), credentialScope);
    }

    // Task 1: Create a canonical request
    // https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html#authentication-task1
    String createCanonicalRequest(Map<String, String> canonicalHeaders, String signedHeaders, byte[] payload) throws Exception {
        String httpMethod = "POST";
        String canonicalUri = "/sessions";
        String canonicalStringQuery = "";
        String canonicalHeadersFormatted = canonicalHeaders.entrySet().stream()
                .map(entry -> String.format("%s:%s", entry.getKey(), entry.getValue())).collect(Collectors.joining(DEFAULT_LINE_SEPARATOR));
        String payloadHash = getHash(payload);
        return String.join(DEFAULT_LINE_SEPARATOR, httpMethod, canonicalUri, canonicalStringQuery, canonicalHeadersFormatted, "", signedHeaders, payloadHash);
    }

    Map<String, String> getCanonicalHeaders(Map<String, String> headers) {
        return headers.entrySet().stream()
                .map(e -> new AbstractMap.SimpleEntry<>(e.getKey().toLowerCase(), e.getValue().trim()))
                .sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (v1, v2) -> {
                    throw new RuntimeException(String.format("Duplicate key for values '%s' and '%s'", v1, v2));
                }, TreeMap::new));
    }

    String getSignedHeaders(Map<String, String> canonicalHeaders) {
        return String.join(";", canonicalHeaders.keySet());
    }

    // Task 2: Create a string to sign
    // https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html#authentication-task2
    String createStringToSign(String algorithm, String requestDateTime, String canonicalRequest, String credentialScope) throws Exception {
        String hashedCanonicalRequest = getHash(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        return String.join(DEFAULT_LINE_SEPARATOR, algorithm, requestDateTime, credentialScope, hashedCanonicalRequest);
    }

    // Task 3: Calculate the signature
    // https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html#authentication-task3
    String calculateSignature(X509Certificate certificate, PrivateKey privateKey, String stringToSign) throws Exception {
        byte[] data = stringToSign.getBytes(StandardCharsets.UTF_8);
        // sign string
        Signature sig = Signature.getInstance("SHA256withRSA"); //SHA-256 digest required
        sig.initSign(privateKey);
        sig.update(data);
        byte[] signature = sig.sign();
        // verify signature
        sig.initVerify(certificate);
        sig.update(data);
        sig.verify(signature);
        return toHex(signature);
    }

    // Task 4: Add the signature to the HTTP request
    // https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html#authentication-task4
    String createAuthorizationHeader(String algorithm, String credentialString, String signedHeaders, String signature) {
        return String.format("%s Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, credentialString, signedHeaders, signature);
    }

    String createCredentialScope(String requestDate, String region) {
        return String.format("%s/%s/rolesanywhere/aws4_request", requestDate, region);
    }

    private String getHash(byte[] data) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        return toHex(hash).toLowerCase();
    }

    private String toHex(byte[] data) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : data) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    X509Certificate loadCertificate(byte[] certificate) {
        try (InputStream is = new ByteArrayInputStream(certificate)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    PrivateKey loadPrivateKey(byte[] privateKey) {
        try (InputStream is = new ByteArrayInputStream(privateKey)) {
            String privateKeyValue = new BufferedReader(new InputStreamReader(is))
                    .lines()
                    .collect(Collectors.joining(DEFAULT_LINE_SEPARATOR))
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decodedKey = Base64.getDecoder().decode(privateKeyValue);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
