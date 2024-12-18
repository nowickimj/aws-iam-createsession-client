package net.mnowicki.aws.iam.createsession.client;

import java.util.Set;

class CreateSessionResponseDto {
    private String subjectArn;
    private Set<CredentialSetEntry> credentialSet;

    CreateSessionResponseDto() {
    }

    public String getSubjectArn() {
        return subjectArn;
    }

    public Set<CredentialSetEntry> getCredentialSet() {
        return credentialSet;
    }

    static class CredentialSetEntry {
        private AssumedRoleUser assumedRoleUser;
        private Credentials credentials;
        private long packedPolicySize;
        private String roleArn;
        private String sourceIdentity;

        public CredentialSetEntry() {
        }

        public AssumedRoleUser getAssumedRoleUser() {
            return assumedRoleUser;
        }

        public Credentials getCredentials() {
            return credentials;
        }

        public long getPackedPolicySize() {
            return packedPolicySize;
        }

        public String getRoleArn() {
            return roleArn;
        }

        public String getSourceIdentity() {
            return sourceIdentity;
        }
    }

    static class AssumedRoleUser {
        private String arn;
        private String assumedRoleId;

        public AssumedRoleUser() {

        }

        public String getArn() {
            return arn;
        }

        public String getAssumedRoleId() {
            return assumedRoleId;
        }
    }

    static class Credentials {
        private String accessKeyId;
        private String secretAccessKey;
        private String sessionToken;
        private String expiration;

        public Credentials() {

        }

        public String getAccessKeyId() {
            return accessKeyId;
        }

        public String getSecretAccessKey() {
            return secretAccessKey;
        }

        public String getSessionToken() {
            return sessionToken;
        }

        public String getExpiration() {
            return expiration;
        }
    }
}

