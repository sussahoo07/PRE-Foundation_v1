# Requirements Document

## Introduction

This document defines the requirements for establishing the Protected Recovery Environment (PRE) on AWS as part of a Cyber Recovery Solution. The PRE is a trusted, isolated staging environment built on the existing DR VPC in eu-central-1, used to receive workloads promoted from the Isolated Recovery Environment (IRE), harden them, validate them, and prepare them for business restoration. The PRE must operate independently of a potentially compromised production environment while maintaining controlled, audited connectivity to essential foundational services including identity, secrets management, PKI, DevOps tooling, security monitoring, and network services.

## Glossary

- **PRE**: Protected Recovery Environment — the isolated AWS-based staging environment in eu-central-1 built on the DR VPC, used for workload recovery, hardening, and validation.
- **IRE**: Isolated Recovery Environment — the AWS recovery account from which hardened workloads are promoted into the PRE.
- **DR_VPC**: The existing disaster recovery VPC in eu-central-1 repurposed as the PRE network boundary.
- **DR_Administrator**: A privileged identity dedicated exclusively to PRE/DR operations, separate from production administrator identities.
- **PRE_KMS**: Independent AWS KMS keys provisioned for the PRE, administered separately from production key material.
- **Break_Glass_Procedure**: An emergency access process that grants elevated PRE access outside normal approval workflows, subject to audit and mandatory review.
- **TGW**: AWS Transit Gateway — the managed routing hub used to control network paths between the PRE, on-premises, Azure, and other environments.
- **Foundational_Services**: The set of shared infrastructure services that the PRE depends on during recovery, including Active Directory, DNS, PKI, secrets management, security monitoring, and DevOps tooling.
- **SCM**: Source Control Management system (e.g., GitHub Enterprise, Bitbucket).
- **PKI**: Public Key Infrastructure, including certificate authority services (DigiCert).
- **IAM**: AWS Identity and Access Management.
- **SCP**: AWS Service Control Policy — organisation-level guardrails applied to restrict actions within the PRE account/OU.
- **WLAN_ISE**: Cisco Identity Services Engine used for network access control.
- **SD_WAN**: Software-defined wide area network overlay (Palo Alto SD-WAN).
- **Allow_List**: An explicit, maintained list of approved IP ranges, protocols, and ports permitted through PRE network controls.
- **Recovery_Runbook**: Documented, version-controlled step-by-step procedure governing each stage of a recovery exercise or actual cyber incident response.
- **Cleansing_Stage**: The recovery phase in which recovered workloads are scanned, remediated, and hardened before validation.
- **Validation_Stage**: The recovery phase in which cleansed workloads are tested for functional correctness and security compliance.
- **Business_Restoration_Stage**: The recovery phase in which validated workloads are promoted back to production or made available to business users.
- **Connectivity_Gate**: A formally approved, time-bounded network connectivity change that enables or disables a specific communication path between the PRE and an external environment.

---

## Requirements

### Requirement 1: PRE Identity and Access Separation

**User Story:** As a DR Administrator, I want dedicated DR identities and protected IAM roles that are entirely separate from production, so that a compromise of production credentials cannot grant access to the PRE.

#### Acceptance Criteria

1. THE PRE SHALL maintain a dedicated set of DR_Administrator identities that are provisioned, managed, and stored in an identity store with no shared credentials, shared MFA devices, or shared access keys with any production administrator account.
2. THE PRE SHALL enforce IAM roles and policies that grant access exclusively to PRE resources, with no cross-account trust relationships to the production AWS account unless explicitly approved via a Connectivity_Gate.
3. WHEN a production IAM principal attempts to assume a PRE IAM role, THE PRE SHALL deny the request and generate a CloudTrail log entry with the principal ARN, timestamp, and denial reason.
4. THE PRE SHALL apply SCPs at the AWS organisational unit level to prevent PRE IAM roles from being modified by any identity outside the designated DR_Administrator group.
5. WHEN a DR_Administrator account is created or modified, THE PRE SHALL require approval from a minimum of two authorised DR_Administrators and record the approval event in an audit log that is configured as write-once with a minimum retention period of 365 days.
6. WHEN a DR_Administrator attempts console or API access to the PRE without a valid MFA token, THE PRE SHALL deny the request and return an error indicating MFA is required.
7. IF a DR_Administrator credential is reported as compromised by a DR_Administrator or an automated security alert, THEN THE PRE SHALL provide a documented procedure to revoke that credential, rotate all associated access keys, and notify the security team within 30 minutes of the report.

---

### Requirement 2: Independent PRE KMS Key Management

**User Story:** As a DR Administrator, I want independent KMS keys for the PRE with separate key administrators, so that encrypted recovery data cannot be decrypted using production key material or by production key administrators.

#### Acceptance Criteria

1. THE PRE SHALL provision one dedicated PRE_KMS key per service category (EBS volumes, S3 buckets, RDS instances, and Secrets Manager secrets) in the eu-central-1 region, such that each service category's data at rest is encrypted exclusively with its designated PRE_KMS key.
2. THE PRE_KMS keys SHALL be administered exclusively by DR_Administrator identities; production key administrators SHALL have no key administration permissions on PRE_KMS keys.
3. WHEN a PRE_KMS key reaches its 12-month anniversary from creation or last manual rotation, THE PRE SHALL automatically rotate the key material and retain all previous key versions for decryption of existing ciphertext; the new key version SHALL become the active encrypting key within 24 hours of the anniversary date.
4. IF a PRE_KMS key deletion is requested and fewer than two DR_Administrators have approved the deletion, THEN THE PRE SHALL reject the deletion request, preserve the key in its current state, and emit an alert indicating the approval quorum was not met.
5. IF a PRE_KMS key deletion receives approval from two or more DR_Administrators, THEN THE PRE SHALL enforce a minimum 30-day waiting period before the deletion is executed.
6. THE PRE SHALL log all PRE_KMS key usage events, including encrypt, decrypt, and GenerateDataKey calls, to a dedicated CloudTrail trail in eu-central-1 that grants read access exclusively to DR_Administrator identities and denies write, modify, and delete access to all principals including DR_Administrators.
7. THE PRE SHALL ensure that PRE_KMS key policies explicitly deny key usage and administration to any AWS principal whose identity originates outside the PRE organisational unit, except AWS service principals operating on behalf of PRE-provisioned resources within eu-central-1.

---

### Requirement 3: PRE Network Architecture and Isolation

**User Story:** As a network architect, I want a protected DR network configuration based on the DR VPC that enforces default isolation from production while enabling controlled connectivity to required environments, so that the PRE cannot be laterally compromised from a production network incident.

#### Acceptance Criteria

1. THE PRE SHALL use the existing DR_VPC in eu-central-1 as its primary network boundary, with subnet segmentation that assigns each of the management, workload, and connectivity tiers to non-overlapping CIDR ranges and distinct route tables with no cross-tier implicit routing.
2. THE PRE SHALL be isolated from the production VPC in eu-west-1 by default, with no active peering or routing paths to production unless a Connectivity_Gate is explicitly open.
3. WHEN a Connectivity_Gate is requested between the PRE and any external environment (production, on-premises, Azure), THE PRE SHALL require documented approval from a DR_Administrator and a named security reviewer, with the approval record stored in the change management system, before any routing change is applied; the routing change SHALL NOT be applied more than 24 hours after approval is granted without re-approval.
4. THE PRE SHALL implement AWS Security Groups and Network ACLs with a default-deny-all posture, permitting only traffic that matches an entry in the Allow_List of approved source/destination IP ranges, protocols, and ports for each Foundational_Services connectivity path.
5. THE PRE SHALL route all Foundational_Services traffic through the TGW, with route tables that are stored in version control and include a timestamp, author, and change description for every modification.
6. WHILE the PRE is in the Cleansing_Stage or Validation_Stage, THE PRE SHALL block all direct internet egress from workload subnets; internet access, where required, SHALL be proxied and inspected such that all outbound requests are logged with source IP, destination, protocol, and timestamp.
7. THE PRE SHALL deploy firewall controls at the TGW attachment boundary that perform deep-packet inspection on all inter-environment traffic entering or leaving the PRE; an equivalent control must enforce stateful layer-7 inspection, protocol anomaly detection, and per-session logging at minimum.
8. IF a network path that is not in the Allow_List is detected as active, THEN THE PRE SHALL generate a high-severity alert within 5 minutes and automatically disable the unauthorized path without requiring manual intervention, returning the network state to Allow_List compliance.

---

### Requirement 4: Foundational Services Connectivity — Identity and Secrets

**User Story:** As a DR Administrator, I want the PRE to maintain secure, independently verifiable connectivity to identity and secrets management services, so that recovered workloads can authenticate and retrieve secrets without depending on potentially compromised production pathways.

#### Acceptance Criteria

1. THE PRE SHALL establish connectivity to HashiCorp Vault via a dedicated, TGW-routed network path, with mutual TLS authentication using certificates issued by DigiCert.
2. THE PRE SHALL establish connectivity to CyberArk Privileged Access Management via TCP port 443 over the TGW, restricted to PRE workload subnets and explicitly allow-listed by subnet CIDR in the TGW route policy.
3. THE PRE SHALL establish connectivity to Microsoft Active Directory (on-premises or Azure-hosted) via an Authentication Bridge, using a dedicated LDAPS connection on TCP port 636 over the TGW with the AD domain controller IP range explicitly defined in the Allow_List.
4. WHEN the Authentication Bridge is unavailable, THE PRE SHALL fail closed by denying workload authentication requests and generating an alert to the DR_Administrator within 2 minutes.
5. THE PRE SHALL integrate with DigiCert for certificate issuance and renewal for all PRE-internal TLS endpoints, using an ACME or REST API connection allow-listed at the TGW; IF DigiCert is unreachable at the time of a scheduled renewal, THEN THE PRE SHALL generate an alert to the DR_Administrator and retain the existing certificate until connectivity is restored or the certificate expiry threshold of 7 days is reached.
6. THE PRE SHALL maintain a local secrets cache within HashiCorp Vault deployed inside the PRE network boundary, populated with secrets no older than 24 hours at the time of any cache refresh, to ensure secret availability for a minimum of 72 hours if external Vault connectivity is severed.
7. WHILE connectivity to external identity services is unavailable, THE PRE SHALL continue to allow DR_Administrator break-glass access using locally stored, encrypted credentials that have been rotated within the preceding 90 days.
8. WHEN a connectivity verification check is performed, THE PRE SHALL confirm active reachability to each of HashiCorp Vault, CyberArk, and the Authentication Bridge by completing a successful health-check query to each service and reporting the result — reachable or unreachable — to the DR_Administrator within 60 seconds.

---

### Requirement 5: Foundational Services Connectivity — DevOps and SCM

**User Story:** As a DevOps engineer, I want the PRE to connect to source control and pipeline tooling so that infrastructure-as-code changes, recovery runbooks, and deployment pipelines required during recovery can be executed from within the PRE.

#### Acceptance Criteria

1. THE PRE SHALL establish outbound HTTPS connectivity to GitHub Enterprise over the TGW or a proxied egress path, restricted to the allow-listed IP ranges of the GitHub Enterprise server.
2. THE PRE SHALL establish outbound connectivity to Terraform Cloud over HTTPS (port 443), proxied through the PRE inspection layer, to allow infrastructure provisioning during recovery.
3. WHERE Azure DevOps is included in the PRE deployment scope, THE PRE SHALL establish outbound HTTPS connectivity (port 443) to Azure DevOps with source IP restricted to PRE management subnet CIDR ranges.
4. WHERE Bamboo is included in the PRE deployment scope, THE PRE SHALL establish outbound HTTPS connectivity (port 443) to Bamboo with source IP restricted to PRE management subnet CIDR ranges.
5. THE PRE SHALL establish connectivity to Bitbucket over HTTPS, using a service account credential stored in the PRE instance of HashiCorp Vault.
6. THE PRE SHALL establish connectivity to Sonatype Nexus over HTTPS for artifact retrieval, with package integrity verified against checksums stored in the PRE HashiCorp Vault.
7. IF a retrieved artifact's checksum does not match the value stored in the PRE HashiCorp Vault, THEN THE PRE SHALL reject the artifact, halt the retrieval operation, and present an error indicating a checksum mismatch to the operator before any artifact content is consumed.
8. WHEN a DevOps tool connection is initiated during a recovery exercise, THE PRE SHALL verify the remote server TLS certificate against the DigiCert-issued trust chain before allowing data transfer.
9. IF TLS certificate verification fails for a DevOps tool connection, THEN THE PRE SHALL terminate the connection attempt and present an error indicating the certificate validation failure, without transferring any data.
10. IF an SCM or pipeline tool is unreachable from the PRE, THEN THE PRE SHALL provide an offline fallback procedure that allows recovery runbooks and Terraform configurations to be executed from a locally cached repository within the PRE, where the cached content is no more than 24 hours old at the time of the last successful synchronisation.

---

### Requirement 6: Foundational Services Connectivity — Security and Monitoring

**User Story:** As a security engineer, I want the PRE to connect to security monitoring and telemetry services so that all workloads within the PRE are observable, threat-detected, and generating alerts during recovery operations.

#### Acceptance Criteria

1. WHEN a compute instance is provisioned within the PRE, THE PRE SHALL deploy a CrowdStrike Falcon sensor on that instance, with sensor telemetry routed outbound to the CrowdStrike cloud over HTTPS via the PRE inspection layer, and the sensor SHALL register a successful check-in heartbeat to the Falcon console within 15 minutes of provisioning.
2. THE PRE SHALL establish connectivity to Cortex Xpanse for external attack surface monitoring, with API calls restricted to the PRE management subnet.
3. THE PRE SHALL deploy ThousandEyes agents within the PRE network to monitor connectivity health to all Foundational_Services endpoints, probing each endpoint at intervals no greater than 5 minutes; IF a monitored endpoint is unreachable for two consecutive probes, THEN THE PRE SHALL deliver an alert to the DR_Administrator notification channel within 5 minutes of the second failed probe.
4. THE PRE SHALL instrument all PRE services with OpenTelemetry collectors, exporting traces and metrics to an isolated observability backend within the PRE boundary or to a designated DR monitoring account.
5. WHEN a CrowdStrike detection event of severity High or Critical is generated within the PRE, THE PRE SHALL quarantine the affected instance within 10 minutes of the detection event timestamp.
6. WHEN a CrowdStrike detection event of severity High or Critical is generated within the PRE, THE PRE SHALL deliver a page notification to the DR_Administrator on-call within 5 minutes of the detection event timestamp.
7. IF a WLAN_ISE instance is unreachable from the PRE management access path, THEN THE PRE SHALL deny all management access on that path until ISE connectivity is restored, with no fail-open exception permitted.
8. THE PRE SHALL establish connectivity to WLAN_ISE for network access control enforcement on PRE management access paths, with ISE policy enforcing device compliance — defined as the requesting device holding a valid, unexpired certificate issued by the PRE trust authority and passing a posture check with zero critical policy violations — before granting access.
9. WHILE a recovery or validation exercise is active, THE PRE SHALL retain all security event logs for a minimum of 90 days in an isolated log store within the PRE boundary, where the log store SHALL reject any delete or overwrite operation against stored log entries for the duration of the retention period.

---

### Requirement 7: Foundational Services Connectivity — Collaboration

**User Story:** As a DR Administrator, I want the PRE to connect to Atlassian Jira and Confluence so that incident tracking, recovery runbook documentation, and stakeholder communication can continue from within the PRE.

#### Acceptance Criteria

1. THE PRE SHALL establish outbound HTTPS connectivity to Atlassian Jira Cloud or on-premises Jira from the PRE management subnet, with the destination URL and associated IP ranges explicitly enumerated on the Allow_List prior to activation.
2. THE PRE SHALL establish outbound HTTPS connectivity to Atlassian Confluence from the PRE management subnet using a service account credential retrieved from the PRE HashiCorp Vault; IF the credential cannot be retrieved from Vault, THEN THE PRE SHALL block the connection attempt and generate an error indicating a Vault retrieval failure.
3. WHEN a Connectivity_Gate to Atlassian services is closed, THE PRE SHALL serve access to a locally cached copy of all runbooks designated as Recovery_Runbooks, where the cached copy was last refreshed no more than 24 hours before the gate closure, and the cache SHALL contain no fewer than the complete set of Recovery_Runbooks defined in the PRE runbook registry.
4. THE PRE SHALL ensure that no Jira or Confluence connection path routes through the production environment network.
5. WHEN a Jira or Confluence connection is established from the PRE management subnet, THE PRE SHALL route that connection directly through the Transit Gateway without traversing any production environment network segment.

---

### Requirement 8: DNS Services for the PRE

**User Story:** As a network engineer, I want the PRE to resolve DNS independently of the production DNS infrastructure so that DNS-based attacks or production DNS failures do not affect name resolution within the PRE.

#### Acceptance Criteria

1. THE PRE SHALL deploy dedicated DNS resolvers within the DR_VPC using AWS Route 53 Resolver, configured to forward queries for domains listed in the DNS_Forward_Domain_List exclusively to allow-listed on-premises or Azure-hosted DNS servers via the TGW.
2. THE PRE SHALL maintain a local Route 53 private hosted zone registering all PRE-internal service endpoints, such that every endpoint reachable within the PRE resolves without querying any DNS server outside the DR_VPC.
3. WHEN the upstream DNS forwarder is unreachable, THE PRE SHALL continue resolving PRE-internal hostnames from the local private hosted zone with 100% query success and a response time not exceeding 2 seconds per query.
4. IF a DNS query resolves to an IP address outside the defined Allow_List for that domain, THEN THE PRE SHALL block the connection and generate a DNS anomaly alert to the DR_Administrator within 5 minutes of the anomalous resolution.
5. THE PRE SHALL log all DNS queries originating from workload subnets to the isolated PRE log store for a minimum of 90 days, with each log record capturing at minimum the source IP address, queried FQDN, returned IP address, timestamp, and resolution outcome.

---

### Requirement 9: PKI and Certificate Services

**User Story:** As a security engineer, I want the PRE to issue and manage TLS certificates independently so that certificate infrastructure compromised in production cannot affect the trust chain within the PRE.

#### Acceptance Criteria

1. THE PRE SHALL establish a dedicated certificate issuance path via DigiCert, using an API key and account credential stored exclusively in the PRE HashiCorp Vault instance.
2. THE PRE SHALL deploy an internal subordinate Certificate Authority within the PRE boundary to issue certificates for PRE-internal service endpoints, where each certificate has a validity period of no less than 1 day and no more than 90 days.
3. WHEN a PRE certificate is within 14 days of expiry, THE PRE SHALL automatically initiate a renewal request via the DigiCert API, retrying up to 3 times at 30-minute intervals if the initial request does not receive a success response within 60 seconds.
4. IF all renewal attempts for a PRE certificate fail, THEN THE PRE SHALL send an alert to the DR_Administrator via the PRE monitoring and notification system within 15 minutes of the final failed attempt, including the certificate subject and expiry date.
5. THE PRE SHALL maintain a Certificate Revocation List (CRL) or OCSP responder within the PRE boundary, refreshed at intervals not exceeding 1 hour, so that certificate validity can be verified without reaching production PKI infrastructure.
6. IF a certificate used within the PRE is found to have been issued by the production PKI trust chain without explicit DR_Administrator approval, THEN THE PRE SHALL flag the certificate as untrusted and block its use within 5 minutes of detection, until a DR_Administrator records an approval exception in the PRE audit log.

---

### Requirement 10: Connectivity Lifecycle Control

**User Story:** As a DR Administrator, I want formally controlled, time-bounded connectivity gates that can be opened, monitored, and closed for each stage of recovery, so that the PRE's isolation is enforced by process and automation rather than manual discipline alone.

#### Acceptance Criteria

1. THE PRE SHALL implement a Connectivity_Gate mechanism that requires a documented change request, named approver, and a defined expiry time between 1 hour and 72 hours before any inter-environment routing path is activated.
2. WHEN a Connectivity_Gate expiry time is reached, THE PRE SHALL automatically revoke the associated routing change and notify the DR_Administrator within 5 minutes of revocation.
3. THE PRE SHALL maintain a Connectivity_Gate log recording the requester, approver, activation timestamp, expiry timestamp, and revocation timestamp for every gate event, stored in the PRE log store in a write-once, non-deletable format that rejects any modification or deletion attempt.
4. WHILE the PRE is in the Cleansing_Stage, THE PRE SHALL permit connectivity only to Foundational_Services endpoints defined in the Allow_List; connectivity to production systems SHALL require a separately submitted and independently approved Connectivity_Gate.
5. WHILE the PRE is in the Validation_Stage, THE PRE SHALL permit connectivity to the endpoints defined in the Validation_Stage_Allow_List in addition to the Cleansing_Stage Allow_List; connectivity to production systems SHALL remain gated by an approved Connectivity_Gate.
6. WHEN the Business_Restoration_Stage is initiated, THE PRE SHALL require two independent approval submissions from two distinct DR_Administrators before any connectivity path to the production environment is activated.
7. WHEN a DR_Administrator requests a connectivity audit report, THE PRE SHALL generate and return the report within 60 seconds, listing all currently active Connectivity_Gates, their approvers, and their expiry times.

---

### Requirement 11: Break-Glass Emergency Access

**User Story:** As a DR Administrator, I want a documented and tested break-glass procedure that allows emergency access to the PRE without dependency on external identity services, so that recovery operations can continue even when normal authentication paths are unavailable.

#### Acceptance Criteria

1. THE PRE SHALL maintain break-glass credentials for a minimum of two DR_Administrator accounts, stored in an offline or hardware-isolated secure medium independent of HashiCorp Vault and CyberArk, with access restricted to no more than two named custodians.
2. WHEN break-glass credentials are accessed, THE PRE SHALL generate an immutable audit log entry within 1 minute, containing the accessor's full name, account identifier, timestamp, and a free-text justification field of no more than 500 characters.
3. WHEN a break-glass access session is initiated, THE PRE SHALL require a second DR_Administrator to formally acknowledge and close the session by recording a written sign-off (name, timestamp, and outcome summary) within 4 hours of initiation.
4. IF a break-glass access session has not been formally closed within 4 hours of initiation, THEN THE PRE SHALL generate a P1 security alert to the security operations team via the same alerting channel used for P1 incidents, within 5 minutes of the deadline being exceeded.
5. THE PRE SHALL test break-glass procedures at a minimum frequency of once per quarter; a test is considered passing only when credentials are successfully retrieved, a session is opened and closed within the documented procedure steps, and the audit log entry is verified as present and complete within the 1-minute window.
6. IF break-glass credentials are used outside a declared cyber incident or scheduled test, THEN THE PRE SHALL generate a P1 security alert to the security operations team via the same alerting channel used for P1 incidents, within 5 minutes of the access event.

---

### Requirement 12: Independence from Production Shared Services

**User Story:** As a DR Administrator, I want the PRE to operate without dependency on production shared services during a cyber incident, so that a compromised or unavailable production environment does not prevent recovery operations.

#### Acceptance Criteria

1. THE PRE SHALL deploy standalone instances of all critical Foundational_Services within or directly accessible from the PRE boundary, ensuring no single Foundational_Service path routes exclusively through the production environment.
2. THE PRE SHALL document, for each Foundational_Service, the production-independent path and the maximum tolerated outage duration before recovery operations are impacted, as part of the Recovery_Runbook.
3. WHEN the production environment is declared compromised or unavailable, THE PRE SHALL be operable — defined as all Foundational_Services listed in the Recovery_Runbook being reachable via non-production paths and all documented recovery workflows being executable without traversing the production environment — within 15 minutes of the declaration.
4. THE PRE SHALL maintain a configuration snapshot of all PRE network routes, IAM policies, KMS keys, and DNS records, stored in the PRE SCM repository and verified by an automated consistency check confirming the snapshot reflects the live PRE configuration, refreshed and re-verified at a minimum of once per week.
5. THE PRE SHALL conduct a full independence test at a minimum of once per quarter, simulating complete production network isolation; the test passes only if every Foundational_Service listed in the Recovery_Runbook responds successfully within 30 seconds via a non-production path and no recovery traffic is routed through the production environment.
6. IF a dependency on a production-only service is identified during a quarterly independence test, THEN THE PRE SHALL raise a remediation task in Jira within 24 hours, assign it to the DR_Administrator team, and resolve it within 90 calendar days of the identification date.

---

### Requirement 13: Audit, Logging, and Compliance

**User Story:** As a compliance officer, I want all PRE actions, connectivity changes, and access events to be logged in an immutable, isolated audit store so that recovery operations can be demonstrated to be controlled and auditable during and after a cyber incident.

#### Acceptance Criteria

1. THE PRE SHALL enable AWS CloudTrail across all PRE AWS accounts and regions, with trail logs delivered to an isolated S3 bucket protected by PRE_KMS encryption and an S3 Object Lock retention policy of a minimum of 1 year.
2. THE PRE SHALL forward all CloudTrail, VPC Flow Log, DNS query log, and application security event log streams to the isolated PRE log store with a maximum end-to-end delivery delay of 5 minutes.
3. WHEN a log delivery failure is detected, THE PRE SHALL generate an alert to the DR_Administrator within 10 minutes and attempt automatic recovery of the log pipeline for up to 30 minutes; IF the pipeline has not recovered within 30 minutes of the initial failure, THEN THE PRE SHALL generate an escalation alert to the DR_Administrator indicating that manual intervention is required.
4. THE PRE SHALL enforce S3 bucket policies on the isolated log store that deny deletion or modification of log objects by any identity, including DR_Administrators, except through an approved immutable-log exception process.
5. THE PRE SHALL provide a log search and query capability accessible to DR_Administrators that allows retrieval of events by principal, resource, time range, and event type within 30 seconds for queries spanning the most recent 30 days.
6. WHEN the weekly reporting period ends, THE PRE SHALL generate a compliance summary report covering IAM policy changes, Connectivity_Gate events, KMS key usage anomalies (defined as encrypt or decrypt call volume exceeding twice the 30-day rolling average for a key, or usage by an identity not in the approved key user list), and security alerts, and SHALL deliver the report to the designated distribution list within 24 hours of the period end.
