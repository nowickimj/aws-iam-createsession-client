package net.mnowicki.aws.iam.createsession;

public record CreateSessionCommandResult(String accessKeyId, String expiration, String secretAccessKey,
                                         String sessionToken) {
}
