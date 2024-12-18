package net.mnowicki.aws.iam.createsession.client;

record CreateSessionRequestDto(int durationSeconds, String profileArn, String roleArn, String trustAnchorArn) {
}
