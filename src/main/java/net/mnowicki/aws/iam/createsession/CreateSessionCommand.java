package net.mnowicki.aws.iam.createsession;

public record CreateSessionCommand(String region,
                                   byte[] certificateData,
                                   byte[] privateKeyData,
                                   String profileArn,
                                   String roleArn,
                                   String trustAnchorArn) {
}
