package net.mnowicki.aws.iam.createsession.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CreateSessionClientTest {
    private static final byte[] CERTIFICATE = readPem(Paths.get("src", "test", "resources", "rsa", "certificate.pem"));
    private static final byte[] PRIVATE_KEY = readPem(Paths.get("src", "test", "resources", "rsa", "ca.key"));
    private static final String REGION = "eu-central-1";
    private static final String ALGORITHM = "AWS4-X509-RSA-SHA384";
    private static final String REQUEST_DATE_TIME = "20240101T000000Z";
    private static final String REQUEST_DATE = "20240101";
    // expected values
    private static final String EXPECTED_CREDENTIAL_SCOPE = "20240101/eu-central-1/rolesanywhere/aws4_request";
    private static final String EXPECTED_CREDENTIAL_STRING = "1/20240101/eu-central-1/rolesanywhere/aws4_request";
    private static final String EXPECTED_SIGNED_HEADERS = "content-type;host;x-amz-date;x-amz-x509";
    private static final String EXPECTED_CANONICAL_REQUEST = "POST\n" +
            "/sessions\n" +
            "\n" +
            "content-type:application/x-amz-json-1.0\n" +
            "host:rolesanywhere.eu-central-1.amazonaws.com\n" +
            "x-amz-date:20240101T000000Z\n" +
            "x-amz-x509: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\n" +
            "\n" +
            "content-type;host;x-amz-date;x-amz-x509\n" +
            "cd319638dcbed9e7e78f1c9179c00ada7144ac563281de790cbb861f8378bea3";
    private static final String EXPECTED_STRING_TO_SIGN = "AWS4-X509-RSA-SHA384\n" +
            "20240101T000000Z\n" +
            "20240101/eu-central-1/rolesanywhere/aws4_request\n" +
            "a3322ce0593831dd52319dfa994749ec85dfbe5e1ca16d7ac8a8bf32ea17211e";
    private static final String EXPECTED_SIGNATURE = "392a1c72ab2287c8378180c1da002721deff0caa4006bb0565d8643a40106083e4836af9a02bc6a407de3fadc4d6eb90920a32878b11ae177336e8df24eb6bb360f5a499d343d390c3a14f3dfc623fdad666d0d2ec40d68a3a9a7dcab2682b199c3d166facb26c3bcf86bfa27f949f71627a1d33bcd8ef8abf12f54ce49c3c8ea1277327f4e47be96ff37e58d9c86d191b77c4d8cfc01164609d85c197f232a0015d00f7ff5d887737f9c2b4a303066ef2e340929b9a6e2bec1273427ba63800c8b8b464173c4ee3cf6b351ecf8c894ed95aaaf9a5f9104d8c18e0704f2652aff88b99aac507eb95f570e789b27942e62dd7189135a78028ea2f8ba9b5c9be75";
    private static final String EXPECTED_AUTHORIZATION = "AWS4-X509-RSA-SHA384 Credential=1/20240101/eu-central-1/rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, Signature=392a1c72ab2287c8378180c1da002721deff0caa4006bb0565d8643a40106083e4836af9a02bc6a407de3fadc4d6eb90920a32878b11ae177336e8df24eb6bb360f5a499d343d390c3a14f3dfc623fdad666d0d2ec40d68a3a9a7dcab2682b199c3d166facb26c3bcf86bfa27f949f71627a1d33bcd8ef8abf12f54ce49c3c8ea1277327f4e47be96ff37e58d9c86d191b77c4d8cfc01164609d85c197f232a0015d00f7ff5d887737f9c2b4a303066ef2e340929b9a6e2bec1273427ba63800c8b8b464173c4ee3cf6b351ecf8c894ed95aaaf9a5f9104d8c18e0704f2652aff88b99aac507eb95f570e789b27942e62dd7189135a78028ea2f8ba9b5c9be75";

    private final CreateSessionClient subject = new CreateSessionClient(new ObjectMapper());

    @Test
    public void shouldCreateCanonicalHeaders() {
        // given
        Map<String, String> headers = initHeaders();
        // when
        Map<String, String> result = subject.getCanonicalHeaders(headers);
        // then
        assertEquals(4, result.size());
        assertEquals("application/x-amz-json-1.0", result.get("content-type"));
        assertEquals("rolesanywhere.eu-central-1.amazonaws.com", result.get("host"));
        assertEquals("20240101T000000Z", result.get("x-amz-date"));
        assertEquals("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", result.get("x-amz-x509"));
    }

    @Test
    public void shouldCreateSignedHeaders() {
        // given
        Map<String, String> canonicalHeaders = subject.getCanonicalHeaders(initHeaders());
        // when
        String result = subject.getSignedHeaders(canonicalHeaders);
        // then
        assertEquals(EXPECTED_SIGNED_HEADERS, result);
    }

    @Test
    public void shouldCreateCanonicalRequest() throws Exception {
        // given
        Map<String, String> headers = initHeaders();
        Map<String, String> canonicalHeaders = subject.getCanonicalHeaders(headers);
        String signedHeaders = subject.getSignedHeaders(canonicalHeaders);
        byte[] payload = initPayload();
        // when
        String result = subject.createCanonicalRequest(canonicalHeaders, signedHeaders, payload);
        // then
        assertEquals(EXPECTED_CANONICAL_REQUEST, result);
    }

    @Test
    public void shouldCreateCredentialScope() {
        // when
        String result = subject.createCredentialScope(REQUEST_DATE, REGION);
        // then
        assertEquals(EXPECTED_CREDENTIAL_SCOPE, result);
    }

    @Test
    public void shouldCreateCredentialString() {;
        // when
        X509Certificate certificate = subject.loadCertificate(CERTIFICATE);
        String result = subject.createCredentialString(certificate, EXPECTED_CREDENTIAL_SCOPE);
        // then
        assertEquals(EXPECTED_CREDENTIAL_STRING, result);
    }

    @Test
    public void shouldCreateStringToSign() throws Exception {
        // when
        String result = subject.createStringToSign(ALGORITHM, REQUEST_DATE_TIME, EXPECTED_CANONICAL_REQUEST, EXPECTED_CREDENTIAL_SCOPE);
        // then
        assertEquals(EXPECTED_STRING_TO_SIGN, result);
    }

    @Test
    public void shouldCalculateSignature() throws Exception {
        // given
        X509Certificate certificate = subject.loadCertificate(CERTIFICATE);
        PrivateKey privateKey = subject.loadPrivateKey(PRIVATE_KEY);
        // when
        String result = subject.calculateSignature(certificate, privateKey, EXPECTED_STRING_TO_SIGN);
        // then
        assertEquals(EXPECTED_SIGNATURE, result);
    }

    @Test
    public void shouldCreateAuthorizationHeader() {
        // when
        String result = subject.createAuthorizationHeader(ALGORITHM, EXPECTED_CREDENTIAL_STRING, EXPECTED_SIGNED_HEADERS, EXPECTED_SIGNATURE);
        // then
        assertEquals(EXPECTED_AUTHORIZATION, result);
    }

    private static Map<String, String> initHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.HOST, "rolesanywhere.eu-central-1.amazonaws.com");
        headers.put(HttpHeaders.CONTENT_TYPE, "application/x-amz-json-1.0");
        headers.put("X-Amz-Date", REQUEST_DATE_TIME);
        headers.put("X-Amz-X509", "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");
        return headers;
    }

    private static byte[] initPayload() {
        return "{\"durationSeconds\": 3600, \"profileArn\": \"arn:aws:rolesanywhere:eu-central-1:012345678901:profile/11472cf9-8719-44a2-89ce-96003d8040ad\", \"roleArn\": \"arn:aws:iam::012345678901:role/example-role\", \"trustAnchorArn\": \"arn:aws:rolesanywhere:eu-central-1:012345678901:trust-anchor\"}".getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] readPem(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}