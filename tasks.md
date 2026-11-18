# Implementation Plan: AWS Protected Recovery Environment (PRE) — Cyber Recovery Solution

## Overview

This plan converts the PRE design into discrete, incremental coding tasks. The order follows a strict dependency chain: AWS organisation guardrails and encryption foundations are laid first, then network architecture, then identity and secrets services, then foundational service connectivity, then automation workflows, then observability and security tooling, then the isolated log store, and finally property-based and integration tests. Each task references the specific requirements and design components it satisfies.

Property-based tests (Python / Hypothesis for backend logic; TypeScript / fast-check for Lambda components) are placed as optional sub-tasks immediately after the implementation they validate, so errors surface early rather than accumulating until a final test pass.

---

## Tasks

- [ ] 1. Terraform project structure and shared modules
  - Create the top-level Terraform directory layout: `infra/modules/`, `infra/environments/pre/`, `infra/environments/pre/backend.tf`, `infra/environments/pre/providers.tf`
  - Define provider version constraints for `hashicorp/aws` (≥ 5.0), `hashicorp/random`, and `hashicorp/time`
  - Add a `terraform.tfvars` template documenting every required variable with type, description, and example
  - Create a shared `locals.tf` that derives all CIDR ranges, region, and OU path from input variables so downstream modules consume a single source of truth; note that `account_id` is **shared** between Prod (eu-west-1) and PRE/DR (eu-central-1) — both VPCs reside in the same AWS account; add `prod_vpc_id` and `dr_vpc_id` as required input variables, used in IAM role trust policies (`aws:SourceVpc` conditions) and KMS key policy deny statements
  - _Requirements: 3.1, 12.4_

- [ ] 2. AWS Organisation OU and Service Control Policies
  - [ ] 2.1 Create the PRE Organisational Unit and attach it under the existing organisation root
    - Write a Terraform `aws_organizations_organizational_unit` resource for the PRE OU
    - Write a Terraform `aws_organizations_account` data source referencing the **shared account** (which hosts both the Prod VPC in eu-west-1 and the PRE/DR VPC in eu-central-1) and move it into the OU via `aws_organizations_account` with the `parent_id` set to the new OU; this OU is for the shared account, not a PRE-only account
    - _Requirements: 1.4, 2.7_

  - [ ] 2.2 Implement the three SCP deny policies and attach them to the PRE OU
    - SCP 1 (Log Store Deletion Protection): Deny `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:PutBucketPolicy`, `s3:DeleteBucket` on the Isolated Log Store bucket ARN — applies to all principals including DR_Administrators
    - SCP 2 (Region Restriction): Deny service actions where `aws:RequestedRegion` is not in `[eu-central-1, eu-west-1]` for key services (IAM, KMS, S3, EC2, Lambda, CloudTrail, Secrets Manager); both regions must be allowed since the shared account spans Prod (eu-west-1) and PRE/DR (eu-central-1)
    - SCP 3 (KMS Key Deletion Guard): Deny `kms:DisableKey` and `kms:ScheduleKeyDeletion` on `alias/pre-dr-*` keys unless the caller IAM principal ARN matches the named `PRE-DR-Admin` role ARN pattern
    - Write an `aws_organizations_policy` and `aws_organizations_policy_attachment` resource per SCP
    - **Note:** SCPs cannot isolate within-account VPC resources; IAM Permission Boundaries, resource tag conditions (`Environment=PRE`), and `aws:SourceVpc` conditions serve as the compensating controls for intra-account isolation
    - _Requirements: 1.4, 2.4, 2.7, 13.4_

  - [ ]* 2.3 Write property test for SCP deny logic
    - **Property 1: Production VPC Principal Role Assumption Denied**
    - Generate IAM principal ARNs where the simulated request context sets `aws:SourceVpc` to the **Prod VPC ID** (eu-west-1) using Hypothesis; call a mock IAM policy evaluation engine applying the `PRE-DR-*` role trust policy (which requires `aws:SourceVpc` to equal `var.dr_vpc_id`); assert every such request produces a DENY decision and a CloudTrail-equivalent log entry containing the principal ARN, timestamp, and denial reason
    - Also assert the inverse: when `aws:SourceVpc` equals `var.dr_vpc_id` (the DR VPC), the role assumption is ALLOWED
    - Tag: `Feature: aws-pre-cyber-recovery, Property 1: production VPC principal role assumption denied`
    - **Validates: Requirements 1.3**

- [ ] 3. PRE_KMS independent encryption keys
  - [ ] 3.1 Provision the four PRE_KMS CMKs in eu-central-1
    - Write an `aws_kms_key` resource for each of `alias/pre-dr-ebs`, `alias/pre-dr-s3`, `alias/pre-dr-rds`, `alias/pre-dr-secrets`
    - Set `enable_key_rotation = true` and `deletion_window_in_days = 30` on every key
    - Set `multi_region = false`; KMS keys are provisioned only in eu-central-1, enforced by an explicit `provider` block in Terraform (not by SCP, since the region-restriction SCP allows both eu-central-1 and eu-west-1)
    - Write `aws_kms_alias` resources for each key
    - _Requirements: 2.1, 2.3, 2.5_

  - [ ] 3.2 Write KMS key policies that restrict administration to DR_Administrator and exclude all production principals
    - Key policy ADMIN ALLOW: allow `kms:Create*`, `kms:Delete*`, `kms:Put*`, `kms:ScheduleKeyDeletion`, `kms:EnableKeyRotation` exclusively to named `PRE-DR-AdministratorAccess` role ARN and `PRE-DR-BreakGlassAccess` role ARN
    - Key policy USAGE ALLOW: allow usage actions (`kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:ReEncrypt*`) to named PRE service role ARNs supplied via variable (e.g., `PRE-DR-VaultRole`, `PRE-DR-EC2Role`, `PRE-DR-LambdaRole`)
    - Key policy DENY 1 — Principal tag deny: `Deny` all KMS actions to any principal where `aws:PrincipalTag/Environment != PRE`; this blocks production IAM roles (tagged `Environment=Production`) from using PRE KMS keys even if they obtain the key ARN directly
    - Key policy DENY 2 — SourceVpc deny: `Deny` encryption/decryption usage actions (`kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:ReEncrypt*`) to any call where `aws:SourceVpc` is present and NOT equal to `var.dr_vpc_id`; this blocks production EC2 instances from using PRE KMS keys even if they obtained PRE role credentials
    - Key policy SERVICE ALLOW: allow AWS service principals (`delivery.logs.amazonaws.com`, `cloudtrail.amazonaws.com`, `s3.amazonaws.com`, `secretsmanager.amazonaws.com`) only for their specific, scoped usage actions; scope each service principal to `aws:SourceAccount` equals the shared account ID
    - _Requirements: 2.2, 2.6, 2.7_

  - [ ]* 3.3 Write property test for KMS key policy exclusion of production administrators
    - **Property 3: PRE_KMS Key Policy Excludes Production Administrators**
    - Generate Hypothesis-driven KMS policy documents with varying principal sets; assert no production admin ARN appears in any administrative statement (`kms:Create*`, `kms:Delete*`, `kms:Put*`, `kms:ScheduleKeyDeletion`)
    - Tag: `Feature: aws-pre-cyber-recovery, Property 3: PRE_KMS key policy excludes production admins`
    - **Validates: Requirements 2.2**

  - [ ] 3.4 Implement the KMS deletion approval gate Lambda and Step Functions workflow
    - Write a Python Lambda `kms_deletion_guard` that reads an approval list from DynamoDB and rejects deletion requests with fewer than two distinct DR_Administrator ARNs; emits an SNS alert when quorum is not met
    - Write a Step Functions state machine `KMSDeletionApprovalWorkflow` that orchestrates the two-approval collection, enforces the 30-day waiting period, and calls the Lambda before forwarding to `kms:ScheduleKeyDeletion`
    - Write an EventBridge rule that invokes the state machine when a `kms:ScheduleKeyDeletion` API call is logged in CloudTrail
    - _Requirements: 2.4, 2.5_

  - [ ]* 3.5 Write property test for KMS deletion approval gate
    - **Property 4: KMS Key Deletion Approval Gate**
    - Generate deletion requests with 0, 1, or 2-same-identity approvals using Hypothesis; assert all are rejected and an alert is emitted; with exactly 2 distinct identities, assert the deletion is forwarded
    - Tag: `Feature: aws-pre-cyber-recovery, Property 4: KMS deletion approval gate`
    - **Validates: Requirements 2.4**

- [ ] 4. DR VPC network foundation
  - [ ] 4.1 Define DR VPC subnet segmentation and route tables
    - Import or reference the existing DR_VPC; create (or verify) `pre-mgmt-1a`, `pre-mgmt-1b`, `pre-workload-1a`, `pre-workload-1b`, `pre-conn-1a`, `pre-conn-1b` subnets in non-overlapping CIDR ranges within the DR_VPC
    - Create three distinct route tables — `rt-management`, `rt-workload`, `rt-connectivity` — with explicit subnet associations; add no cross-tier implicit routes
    - _Requirements: 3.1_

  - [ ] 4.2 Implement Security Groups with default-deny-all posture and Allow_List rules
    - Write an `aws_security_group` per tier (management, workload, connectivity) with no default ingress rules and no default egress rules
    - Write an `aws_security_group_rule` resource per Allow_List entry, sourced from an `aws_ssm_parameter` document that version-controls the Allow_List (source CIDR, destination CIDR, protocol, port)
    - _Requirements: 3.4, 3.5_

  - [ ] 4.3 Implement Network ACLs with default-deny-all posture
    - Write `aws_network_acl` resources per subnet tier with rule 32767 set to DENY ALL for both inbound and outbound
    - Write `aws_network_acl_rule` resources for each approved Foundational_Services path, mirroring the Security Group Allow_List
    - _Requirements: 3.4_

- [ ] 5. Transit Gateway route tables and isolation
  - [ ] 5.1 Create the PRE-RT and Prod-RT TGW route tables
    - Write `aws_ec2_transit_gateway_route_table` resources for `PRE-RT` and `Prod-RT`
    - Associate the PRE TGW attachment with `PRE-RT` and the production VPC attachment with `Prod-RT`
    - Add a blackhole route for the production VPC CIDR in `PRE-RT`
    - Add no routes to the PRE VPC CIDR in `Prod-RT`
    - _Requirements: 3.2, 3.5_

  - [ ] 5.2 Seed the PRE-RT Allow_List routes for Foundational_Services paths
    - For each Foundational_Services CIDR (AD, Vault, CyberArk, DigiCert, GHE, TFC, Jira/Confluence, CrowdStrike, ThousandEyes, Cortex Xpanse), write a `aws_ec2_transit_gateway_route` resource pointing to the on-premises or Azure attachment
    - Store all CIDR values in `aws_ssm_parameter` with `Tier` = `Advanced` and type `StringList` for version history
    - _Requirements: 3.5, 4.1–4.3, 5.1–5.5, 6.2–6.3, 7.1–7.2_

- [ ] 6. IAM Identity Center and DR_Administrator permission sets
  - [ ] 6.1 Configure IAM Identity Center instance and DR_Administrator group
    - Reference the existing IAM Identity Center instance via data source; create `aws_identitystore_group` for `DR_Administrators`
    - Write `aws_ssoadmin_permission_set` for `PRE-DR-AdministratorAccess` with a session duration of 8 hours and an inline policy granting least-privilege access to PRE resources only (no access to production-tagged resources); include an explicit `Deny` statement scoped to `ec2:*` actions on resources tagged `Environment=Production` and all KMS, EC2, RDS, S3 resources in eu-west-1 not tagged `Environment=PRE`
    - Write `aws_ssoadmin_permission_set` for `PRE-DR-BreakGlassAccess` with a session duration of 4 hours; apply the same explicit `Deny` for production-tagged resources
    - _Requirements: 1.1, 1.2_

  - [ ] 6.2 Attach MFA enforcement condition to both permission sets
    - Add an inline policy condition `"aws:MultiFactorAuthPresent": "true"` to both permission sets; any API call without an MFA context key returns `AccessDenied`
    - _Requirements: 1.6_

  - [ ]* 6.3 Write property test for DR_Administrator MFA enforcement
    - **Property 2: DR_Administrator MFA Enforcement**
    - Generate DR_Administrator identity profiles without an MFA context key using Hypothesis; call a mock policy evaluation engine; assert every request is denied with an `AccessDenied: MFA required` response
    - Tag: `Feature: aws-pre-cyber-recovery, Property 2: DR_Administrator MFA enforcement`
    - **Validates: Requirements 1.6**

  - [ ] 6.4 Implement DR_Administrator identity provisioning workflow with dual-approval
    - Write a Python Lambda `dr_admin_provisioning` that creates IAM Identity Center users only after two distinct DR_Administrator approvals are recorded in DynamoDB
    - Write an audit log writer function that persists each approval event as an immutable entry in the Isolated Log Store (S3 Object Lock bucket)
    - _Requirements: 1.5_

  - [ ] 6.5 Implement PRE-DR-PermissionBoundary and enforce Environment=PRE resource tagging
    - Write an `aws_iam_policy` document `PRE-DR-PermissionBoundary` that:
      - Allows only actions on resources tagged `Environment=PRE` or on `PRE-DR-*`-prefixed resource ARNs
      - Explicitly denies `ec2:*`, `rds:*`, `s3:*`, `kms:*` on any resource in `eu-west-1` (Prod region)
      - Explicitly denies `iam:CreateRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy` without an `Environment=PRE` tag condition present
    - Attach this permission boundary to every `PRE-DR-*` IAM role using the `aws_iam_role` `permissions_boundary` argument
    - Write an `aws_iam_role` trust policy template that includes the `aws:SourceVpc` condition requiring `var.dr_vpc_id` for all `PRE-DR-*` roles: `Condition: { StringEquals: { "aws:SourceVpc": "${var.dr_vpc_id}" } }`
    - Write an AWS Config rule `pre-resource-tag-compliance` that flags any resource in eu-central-1 missing the `Environment=PRE` tag; configure auto-remediation via Systems Manager Automation to add the tag
    - Write a tag policy (AWS Organizations Tag Policy) enforcing the `Environment` tag with allowed values `["PRE", "Production"]` on all resources in both regions
    - _Requirements: 1.1, 1.2, 1.4, 2.2, 2.7_

- [ ] 7. Checkpoint — Verify foundational controls
  - Ensure all Terraform modules from tasks 1–6 plan and apply without error; run the following smoke tests before continuing:
    - IAM permission boundaries (`PRE-DR-PermissionBoundary`) are attached to all `PRE-DR-*` roles
    - All `PRE-DR-*` role trust policies contain `Condition: { StringEquals: { "aws:SourceVpc": DR_VPC_ID } }`
    - All PRE resources in eu-central-1 are tagged `Environment=PRE` (verified via AWS Config rule status)
    - KMS key policies for all `alias/pre-dr-*` keys contain explicit deny for `aws:PrincipalTag/Environment != PRE`
    - Region-restriction SCP is attached to OU (allowing eu-central-1 and eu-west-1 only)
    - Log-store protection SCP is attached to OU
    - MFA enforcement condition (`aws:MultiFactorAuthPresent: true`) is present in `PRE-DR-AdministratorAccess` permission set
    - KMS rotation is enabled on all 4 `alias/pre-dr-*` keys
  - Ask the user if any questions arise before continuing.

- [ ] 8. Isolated Log Store (S3 Object Lock)
  - [ ] 8.1 Provision the Isolated Log Store S3 bucket with Object Lock and PRE_KMS encryption
    - Write `aws_s3_bucket` with `object_lock_enabled = true`
    - Write `aws_s3_bucket_object_lock_configuration` with mode `COMPLIANCE` and `days = 365`
    - Write `aws_s3_bucket_server_side_encryption_configuration` using `alias/pre-dr-s3`
    - Write an `aws_s3_bucket_policy` that explicitly denies `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:PutBucketPolicy`, `s3:DeleteBucket` for all principals including DR_Administrators
    - _Requirements: 13.1, 13.4_

  - [ ] 8.2 Enable CloudTrail with delivery to the Isolated Log Store
    - Write `aws_cloudtrail` with `is_multi_region_trail = true`, `include_global_service_events = true`, `s3_bucket_name` pointing to the Isolated Log Store, and `kms_key_id` set to `alias/pre-dr-s3`
    - Add S3 data event selectors for the log store bucket itself (access to the log store is logged to a separate monitoring trail)
    - Write an EventBridge rule that fires on CloudTrail trail-interrupted events and invokes a Lambda to auto-remediate
    - _Requirements: 13.1, 13.2_

  - [ ] 8.3 Set up VPC Flow Logs and DNS query log delivery to the Isolated Log Store
    - Write `aws_flow_log` for the DR_VPC targeting the Isolated Log Store via Kinesis Firehose
    - Write `aws_route53_resolver_query_log_config` targeting the Kinesis Firehose delivery stream
    - _Requirements: 8.5, 13.2_

  - [ ] 8.4 Implement the log delivery pipeline health monitor and auto-recovery Lambda
    - Write a Python Lambda `log_pipeline_monitor` that listens to Kinesis Firehose delivery failure events via EventBridge; raises an SNS alert within 10 minutes; retries recovery for up to 30 minutes; emits an escalation alert if recovery is not confirmed within 30 minutes
    - _Requirements: 13.3_

  - [ ]* 8.5 Write property test for log delivery failure alerting
    - **Property 12: Log Delivery Failure Triggers Alert and Recovery**
    - Inject synthetic log pipeline failure events using Hypothesis; assert alert is generated within the 10-minute window; assert escalation is generated when simulated clock advances past 30 minutes without recovery
    - Tag: `Feature: aws-pre-cyber-recovery, Property 12: log delivery failure alert and recovery`
    - **Validates: Requirements 13.3**

  - [ ] 8.6 Implement the Athena log query layer
    - Write an `aws_glue_catalog_database` and `aws_glue_catalog_table` mapping CloudTrail log schema
    - Write an `aws_athena_workgroup` with output location in a separate query-results S3 bucket (also encrypted with `alias/pre-dr-s3`) and enforce query timeout of 30 seconds
    - Write a Lambda-backed API (accessible from management subnet only) that accepts principal, resource, time range, and event type parameters, executes a parameterised Athena query, and returns results
    - _Requirements: 13.5_

- [ ] 9. Route 53 DNS independence
  - [ ] 9.1 Create the Route 53 private hosted zone and Resolver configuration
    - Write `aws_route53_zone` (private, associated with DR_VPC) for the PRE internal domain
    - Write `aws_route53_resolver_endpoint` (inbound and outbound) in the management subnet
    - Write `aws_route53_resolver_rule` for each domain in the DNS_Forward_Domain_List, forwarding to allow-listed on-premises DNS server IPs via the TGW
    - Write `aws_route53_record` entries for every PRE-internal service endpoint
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ] 9.2 Implement DNS anomaly detection Lambda
    - Write a Python Lambda `dns_anomaly_detector` that processes Route 53 Resolver query logs from the Isolated Log Store; for any query resolving to an IP outside the Allow_List for that domain, blocks the connection (via Security Group rule update) and raises an SNS alert within 5 minutes
    - _Requirements: 8.4_

- [ ] 10. PRE_KMS–encrypted secrets and local HashiCorp Vault cache
  - [ ] 10.1 Deploy the HashiCorp Vault local cache in the Workload Subnet
    - Write Terraform resources to provision a Vault instance (EC2 or ECS Fargate) in `pre-workload-1a`/`1b`; configure auto-unseal using `alias/pre-dr-secrets`
    - Write a Vault configuration file (HCL) enabling the KV secrets engine, transit engine, and PKI secrets engine
    - Write an IAM instance profile granting the Vault instance access to `kms:Decrypt` and `kms:GenerateDataKey` on `alias/pre-dr-secrets` only
    - _Requirements: 4.1, 4.6_

  - [ ] 10.2 Implement the 24-hour Vault cache refresh and 72-hour availability Lambda
    - Write a Python Lambda `vault_cache_refresher` that syncs secrets from the external HashiCorp Vault (via mTLS over TGW on port 8200) into the local Vault instance every 24 hours
    - If the external Vault is unreachable, the Lambda logs a warning and leaves the local cache unchanged; it emits an SNS alert if the cache age exceeds 24 hours
    - _Requirements: 4.6_

- [ ] 11. Subordinate CA and certificate lifecycle management
  - [ ] 11.1 Deploy the Subordinate Certificate Authority in the Management Subnet
    - Write `aws_acmpca_certificate_authority` resources for the Subordinate CA chained to DigiCert; set `validity` to no more than 90 days per certificate
    - Alternatively, configure the Vault PKI secrets engine as the Subordinate CA if AWS Private CA is not in scope; write Vault policy HCL granting `pki/sign` only to PRE service roles
    - Write a CRL distribution point and OCSP responder configuration within the PRE boundary, refreshed on an hourly schedule via EventBridge + Lambda
    - _Requirements: 9.1, 9.2, 9.5_

  - [ ] 11.2 Implement certificate renewal automation Lambda
    - Write a Python Lambda `cert_renewal_manager` triggered daily by EventBridge; queries all Certificate Records from DynamoDB; for any certificate within 14 days of expiry, calls the DigiCert API (ACME or REST), retrying up to 3 times at 30-minute intervals if no success response arrives within 60 seconds
    - On final retry failure, emits an SNS alert within 15 minutes including subject CN and expiry date
    - Write a DynamoDB table `pre_certificate_registry` with schema matching the Certificate Record data model from the design
    - _Requirements: 9.3, 9.4_

  - [ ]* 11.3 Write property test for certificate renewal automation
    - **Property 10: Certificate Renewal Automation**
    - Generate Certificate Record inputs with `validity_days` from 1 to 14 using Hypothesis; assert the renewal Lambda initiates a DigiCert API call for each; assert retry schedule is exactly 3 attempts at 30-minute intervals when mock API returns failure
    - Tag: `Feature: aws-pre-cyber-recovery, Property 10: certificate renewal automation`
    - **Validates: Requirements 9.3**

  - [ ] 11.4 Implement production PKI trust chain detection and block Lambda
    - Write a Python Lambda `cert_trust_chain_auditor` triggered on certificate installation events (via EventBridge custom events); checks the issuer chain of the installed certificate; if the chain leads to the production PKI root, flags it in the `pre_certificate_registry` and blocks use within 5 minutes via Security Group rule update and SNS alert
    - _Requirements: 9.6_

- [ ] 12. Foundational Services connectivity — Identity and Secrets paths
  - [ ] 12.1 Wire HashiCorp Vault external connectivity (mTLS, port 8200)
    - Write Security Group rules and NACL entries allowing TCP 8200 from the Workload Subnet to the Vault server CIDR via the TGW; source the CIDR from SSM Parameter Store Allow_List
    - Write Vault agent configuration in the local cache instance enabling auto-auth via AWS IAM method and mTLS client cert (DigiCert-issued)
    - _Requirements: 4.1_

  - [ ] 12.2 Wire CyberArk PAM connectivity (HTTPS, port 443)
    - Write Security Group rules and NACL entries allowing TCP 443 from the Workload Subnet CIDR to the CyberArk server CIDR via the TGW
    - _Requirements: 4.2_

  - [ ] 12.3 Deploy Authentication Bridge and wire Microsoft AD connectivity (LDAPS, port 636)
    - Write Terraform resources to provision the Authentication Bridge (lightweight AD proxy) in the Management Subnet; configure it to connect to on-premises AD over LDAPS on port 636 via the TGW
    - Write Security Group rules allowing TCP 636 from the Management Subnet to the AD domain controller CIDR range
    - Write a health-check Lambda `auth_bridge_monitor` that probes the Authentication Bridge every 5 minutes; if unreachable, invokes fail-closed by updating the Security Group to block workload authentication and emits an SNS alert within 2 minutes
    - _Requirements: 4.3, 4.4_

  - [ ] 12.4 Wire DigiCert PKI connectivity (HTTPS, port 443)
    - Write Security Group rules and NACL entries allowing TCP 443 from the Management Subnet to DigiCert IP ranges
    - Store the DigiCert API key in the PRE Vault under `secret/pre/pki/digicert`
    - _Requirements: 4.5, 9.1_

- [ ] 13. Foundational Services connectivity — DevOps and SCM paths
  - [ ] 13.1 Wire GitHub Enterprise, Bitbucket, and Terraform Cloud connectivity
    - Write Security Group rules and NACL entries for TCP 443 from the Management Subnet to allow-listed IP ranges for GitHub Enterprise, Bitbucket, and Terraform Cloud
    - Write Vault secret paths for GitHub OAuth token, Bitbucket service account credential, and TFC API token
    - _Requirements: 5.1, 5.2, 5.5_

  - [ ] 13.2 Wire Azure DevOps and Bamboo connectivity (management subnet only)
    - Write Security Group rules restricting TCP 443 source to the Management Subnet CIDR for Azure DevOps and Bamboo endpoints
    - Write Vault secret paths for Azure DevOps PAT and Bamboo service account credential
    - _Requirements: 5.3, 5.4_

  - [ ] 13.3 Implement Nexus artifact cache with checksum validation
    - Write Terraform resources to provision a Sonatype Nexus mirror instance in the Workload Subnet; configure proxy repositories for required artifact groups
    - Write a Python Lambda `artifact_checksum_validator` that intercepts artifact retrieval requests, computes the SHA-256 checksum of the artifact, compares it against the value stored in the PRE Vault, and rejects the artifact with a checksum mismatch error before any content is consumed if they differ
    - _Requirements: 5.6, 5.7_

  - [ ]* 13.4 Write property test for artifact checksum rejection
    - **Property 8: Artifact Checksum Mismatch Rejection**
    - Generate artifact payloads with deliberately mismatched checksums using Hypothesis; assert the validator Lambda rejects every mismatched artifact before returning any content; assert that a matching checksum permits retrieval
    - Tag: `Feature: aws-pre-cyber-recovery, Property 8: artifact checksum mismatch rejection`
    - **Validates: Requirements 5.7**

  - [ ] 13.5 Implement DevOps tool TLS certificate verification and SCM offline fallback
    - Write a Python wrapper module `devops_tls_verifier` used by all DevOps Lambda functions; verifies the remote server TLS certificate against the DigiCert-issued trust chain before allowing data transfer; terminates the connection and returns a certificate validation failure error if verification fails
    - Write a local Git mirror provisioning script (Bash, executed via CodeBuild) that syncs GitHub Enterprise and Bitbucket repositories into an S3-backed mirror bucket every 24 hours; if the upstream is unreachable, the Lambda serving SCM requests falls back to the S3 mirror
    - _Requirements: 5.8, 5.9, 5.10_

- [ ] 14. Foundational Services connectivity — Security and Monitoring paths
  - [ ] 14.1 Wire Cortex Xpanse and ThousandEyes connectivity (management subnet only)
    - Write Security Group rules and NACL entries allowing TCP 443 from the Management Subnet to Cortex Xpanse and ThousandEyes API endpoints; store API keys in Vault
    - _Requirements: 6.2_

  - [ ] 14.2 Deploy ThousandEyes agents and implement Foundational_Services reachability monitoring
    - Write Terraform resources to provision ThousandEyes Enterprise Agents in the Management Subnet (EC2 instances with the agent package installed via EC2 user-data)
    - Write a Lambda `thousandeyes_alert_forwarder` subscribed to ThousandEyes webhook events; if any monitored endpoint is unreachable for two consecutive probes (detected via consecutive failure count in DynamoDB), forwards an alert to the DR_Administrator SNS topic within 5 minutes of the second failed probe
    - _Requirements: 6.3_

  - [ ] 14.3 Deploy OpenTelemetry collectors in Management and Workload Subnets
    - Write Terraform resources to provision OTEL collector instances in both the Management and Workload Subnets; configure exporters pointing to the isolated observability backend within the PRE boundary
    - Write OTEL pipeline configuration (`otel-collector-config.yaml`) with receivers for OTLP gRPC/HTTP and processors for batch, memory limiter, and resource attribution
    - _Requirements: 6.4_

  - [ ] 14.4 Implement CrowdStrike Falcon sensor auto-deployment and heartbeat monitor
    - Write an EC2 Auto Scaling lifecycle hook Lambda `crowdstrike_sensor_installer` that installs the Falcon sensor on every new PRE instance via Systems Manager Run Command; records the installation timestamp in DynamoDB
    - Write a Lambda `crowdstrike_heartbeat_monitor` that checks DynamoDB for any instance whose sensor has not registered a successful check-in heartbeat within 15 minutes of provisioning; emits an SNS alert for each such instance
    - _Requirements: 6.1_

  - [ ] 14.5 Implement CrowdStrike High/Critical detection quarantine automation
    - Write a Lambda `crowdstrike_quarantine_dispatcher` subscribed to CrowdStrike Falcon event webhook (via API Gateway, management subnet only); for any detection event with severity High or Critical, calls the EC2 `isolate-instance` Systems Manager document within 10 minutes; delivers a PagerDuty/SNS page to the DR_Administrator on-call within 5 minutes of the detection timestamp
    - _Requirements: 6.5, 6.6_

  - [ ]* 14.6 Write property test for CrowdStrike quarantine trigger
    - **Property 9: CrowdStrike High/Critical Detection Triggers Quarantine**
    - Generate synthetic CrowdStrike detection event payloads with High and Critical severities using Hypothesis (Python); assert the quarantine dispatcher issues a quarantine command within the 10-minute window and that the on-call notification is dispatched within the 5-minute window; assert that Low/Medium events do not trigger quarantine
    - Tag: `Feature: aws-pre-cyber-recovery, Property 9: CrowdStrike High/Critical quarantine`
    - **Validates: Requirements 6.5, 6.6**

  - [ ] 14.7 Wire WLAN_ISE connectivity and implement fail-closed management access control
    - Write Security Group rules for the Management Subnet allowing only traffic from devices that pass ISE posture checks (enforced via 802.1X / RADIUS challenge-response at the network boundary)
    - Write a Lambda `ise_connectivity_monitor` that probes ISE every 2 minutes from the Management Subnet; if ISE is unreachable, updates the Management Subnet Security Group to deny all inbound management traffic (fail-closed), and emits an SNS alert
    - _Requirements: 6.7, 6.8_

- [ ] 15. Foundational Services connectivity — Collaboration paths
  - [ ] 15.1 Wire Jira and Confluence connectivity and implement Vault credential retrieval
    - Write Security Group rules and NACL entries allowing TCP 443 from the Management Subnet to allow-listed Jira and Confluence IP ranges via the TGW
    - Write a Python module `atlassian_connector` used by collaboration Lambdas; retrieves credentials from the PRE Vault via `vault.read("secret/pre/atlassian/...")` before each connection; if Vault retrieval fails, blocks the connection and returns a Vault retrieval failure error
    - _Requirements: 7.1, 7.2, 7.4, 7.5_

  - [ ] 15.2 Implement the Recovery Runbook cache (S3 versioned + 24-hour Confluence sync)
    - Write `aws_s3_bucket` with `versioning { enabled = true }` for the runbook cache; encrypt with `alias/pre-dr-s3`; apply Object Lock for runbook retention
    - Write a Lambda `runbook_cache_refresher` that syncs all Recovery_Runbooks from Confluence to the S3 bucket every 24 hours; if Confluence is unreachable, the Lambda leaves the existing cache in place and emits a staleness alert if cache age > 24 hours
    - _Requirements: 7.3, 12.1, 12.2_

- [ ] 16. Connectivity_Gate mechanism
  - [ ] 16.1 Implement the Connectivity_Gate DynamoDB table and data model
    - Write `aws_dynamodb_table` `connectivity_gates` with partition key `gate_id` (UUID), all fields from the Connectivity_Gate Record data model, and streams enabled
    - Write an `aws_dynamodb_resource_policy` denying `dynamodb:DeleteItem` and `dynamodb:UpdateItem` on completed gate records (status EXPIRED or REVOKED) to enforce write-once semantics
    - _Requirements: 10.1, 10.3_

  - [ ] 16.2 Implement the Connectivity_Gate Step Functions state machine and Lambda handlers
    - Write a Step Functions state machine `ConnectivityGateWorkflow` with states: `ValidateChangeRequest`, `AwaitFirstApproval`, `AwaitSecondApproval` (Business_Restoration only), `ActivateRoute`, `ScheduleExpiry`, `ExpireAndRevoke`, `NotifyRevocation`
    - Write individual Python Lambda functions for each state: `gate_validate_change_request`, `gate_activate_route`, `gate_expire_route`, `gate_notify_revocation`
    - `gate_activate_route` calls `ec2:CreateTransitGatewayRoute` to write the time-bounded route entry in `PRE-RT`; `gate_expire_route` calls `ec2:DeleteTransitGatewayRoute` and updates the DynamoDB record
    - Expose the state machine invocation endpoint via API Gateway, restricted to the Management Subnet CIDR
    - _Requirements: 10.1, 10.2, 10.3_

  - [ ]* 16.3 Write property test for Connectivity_Gate routing requires prior approval
    - **Property 5: Connectivity_Gate Routing Requires Prior Approval**
    - Using fast-check (TypeScript), generate inter-environment routing change requests with and without an active gate record; assert all requests without an active gate are rejected; assert that an active gate with named approver, named security reviewer, and an expiry ≤ 24 hours from now is required for approval
    - Tag: `Feature: aws-pre-cyber-recovery, Property 5: Connectivity_Gate routing requires approval`
    - **Validates: Requirements 3.3, 10.1**

  - [ ] 16.4 Implement Connectivity_Gate expiry timer and auto-revocation
    - Write an EventBridge scheduled rule that invokes `gate_expire_route` Lambda at the exact expiry timestamp (stored in the gate record) for each active gate
    - `gate_notify_revocation` Lambda publishes to the DR_Administrator SNS topic within 5 minutes of revocation; write a CloudWatch alarm on the notification delivery latency to enforce the 5-minute SLA
    - _Requirements: 10.2_

  - [ ]* 16.5 Write property test for Connectivity_Gate expiry auto-revocation
    - **Property 6: Connectivity_Gate Expiry Triggers Automatic Revocation**
    - Using Hypothesis, generate gate records with random valid expiry durations between 1 and 72 hours; simulate wall-clock advancement past the expiry timestamp; assert the route is revoked and the notification is published within 5 minutes
    - Tag: `Feature: aws-pre-cyber-recovery, Property 6: Connectivity_Gate expiry triggers revocation`
    - **Validates: Requirements 10.2**

  - [ ] 16.6 Implement Business Restoration Stage dual-approval gate enforcement
    - In the `ConnectivityGateWorkflow` state machine, add a conditional branch on `recovery_stage == BUSINESS_RESTORATION` that routes to `AwaitSecondApproval`; the second approval must come from a distinct DR_Administrator account identifier (checked by Lambda `gate_validate_distinct_approvers`)
    - Reject any initiation request with zero, one, or two same-identity approvals and return a structured error response
    - _Requirements: 10.6_

  - [ ]* 16.7 Write property test for Business Restoration dual distinct approval
    - **Property 11: Business Restoration Stage Requires Two Distinct Approvals**
    - Using Hypothesis, generate stage initiation requests with 0, 1, and 2-same-identity approvals; assert all are rejected; with exactly 2 distinct DR_Administrator identities, assert the stage is activated
    - Tag: `Feature: aws-pre-cyber-recovery, Property 11: Business_Restoration dual distinct approval`
    - **Validates: Requirements 10.6**

  - [ ] 16.8 Implement the Connectivity_Gate audit report endpoint
    - Write a Python Lambda `gate_audit_reporter` accessible via API Gateway (management subnet only); executes an Athena query against the Isolated Log Store for all gate records; returns all currently ACTIVE gates with approver and expiry fields within 60 seconds
    - _Requirements: 10.7_

- [ ] 17. Checkpoint — Verify network controls and Connectivity_Gate
  - Ensure TGW route tables reflect correct isolation state (no PRE→Production routes in `PRE-RT` without an active gate); run TGW route table isolation integration test; ensure Connectivity_Gate Step Functions state machine reaches `ActivateRoute` state only after valid approval. Ask the user if any questions arise before continuing.

- [ ] 18. Unauthorized network path detection and auto-disable
  - [ ] 18.1 Implement the Allow_List compliance monitor Lambda
    - Write a Python Lambda `network_compliance_monitor` triggered every 5 minutes by EventBridge; reads the current TGW route table entries via `ec2:DescribeTransitGatewayRouteTables`; compares against the SSM-stored Allow_List; for any route not in the Allow_List, calls `ec2:DeleteTransitGatewayRoute` to disable the path and publishes a high-severity alert to the DR_Administrator SNS topic
    - _Requirements: 3.8_

  - [ ]* 18.2 Write property test for unauthorized path auto-disable
    - **Property 7: Unauthorized Network Path Detection and Auto-Disable**
    - Using Hypothesis, generate random sets of TGW route table entries where some routes are not in the Allow_List; assert the compliance monitor identifies every unauthorized path and disables it within the 5-minute window; assert that Allow_List-compliant routes are preserved
    - Tag: `Feature: aws-pre-cyber-recovery, Property 7: unauthorized path auto-disable`
    - **Validates: Requirements 3.8**

- [ ] 19. Break-glass procedure implementation
  - [ ] 19.1 Provision break-glass credentials storage and access control
    - Write AWS Secrets Manager secrets (encrypted with `alias/pre-dr-secrets`) for two break-glass DR_Administrator credential sets; restrict access to named custodian ARNs only via resource policy
    - Write an S3 bucket (encrypted, versioned) as the offline credential medium; write bucket policy denying all access except from named custodian roles and the audit Lambda
    - _Requirements: 11.1_

  - [ ] 19.2 Implement break-glass access audit Lambda
    - Write a Python Lambda `break_glass_audit_writer` triggered by S3 object access events on the break-glass credential bucket (via S3 Event Notifications); within 1 minute of the access event, writes an immutable audit log entry (accessor name, account ID, timestamp, justification) to the Isolated Log Store; publishes an SNS alert if the access occurs outside a declared incident or scheduled test
    - _Requirements: 11.2, 11.6_

  - [ ] 19.3 Implement break-glass session sign-off workflow
    - Write a Step Functions state machine `BreakGlassSessionWorkflow` with states: `RecordInitiation`, `AwaitSignOff`, `SessionClosed`, `P1AlertDeadlineExceeded`
    - If the second DR_Administrator has not recorded sign-off within 4 hours of initiation, the state machine transitions to `P1AlertDeadlineExceeded` and publishes a P1 alert to the security operations SNS topic within 5 minutes of the deadline
    - _Requirements: 11.3, 11.4_

- [ ] 20. Weekly compliance report and anomaly detection
  - [ ] 20.1 Implement the weekly compliance summary Lambda
    - Write a Python Lambda `compliance_report_generator` triggered every Sunday by EventBridge; executes Athena queries for IAM policy changes, Connectivity_Gate events, KMS key usage anomalies (call volume > 2× 30-day rolling average or usage by non-approved identity), and security alerts in the reporting period
    - Formats the report as an HTML or Markdown document and delivers it to the designated SNS distribution list within 24 hours of period end
    - _Requirements: 13.6_

- [ ] 21. PRE configuration snapshot and consistency checks
  - [ ] 21.1 Implement automated configuration snapshot export
    - Write a Lambda `config_snapshot_exporter` triggered weekly by EventBridge; calls AWS Config, IAM, KMS, EC2 (TGW routes), and Route 53 APIs to export a JSON snapshot of all PRE network routes, IAM policies, KMS key policies, and DNS records; commits the snapshot to the PRE SCM repository via GitHub/Bitbucket API
    - _Requirements: 12.4_

  - [ ] 21.2 Implement configuration consistency check Lambda
    - Write a Lambda `config_consistency_checker` that diffs the latest SCM-committed snapshot against the live AWS API state; raises an SNS alert if any discrepancy is found; records the check result in DynamoDB with a timestamp
    - _Requirements: 12.4_

- [ ] 22. Quarterly independence test automation
  - [ ] 22.1 Implement the quarterly independence test runner
    - Write a Python Lambda `quarterly_independence_tester` that simulates production isolation by inserting a blackhole route for all production CIDR ranges at the TGW; runs health-check probes against each Foundational_Service in the Recovery_Runbook within 30 seconds; asserts no recovery traffic traverses the production VPC CIDR; records the test result in DynamoDB and removes the blackhole route after the test completes
    - If any Foundational_Service probe fails or production traffic is detected, creates a Jira issue via the Atlassian API within 24 hours
    - _Requirements: 12.5, 12.6_

- [ ] 23. Checkpoint — End-to-end integration and smoke tests
  - Run all Terraform smoke tests and verify the following before proceeding to property tests:
    - IAM permission boundaries (`PRE-DR-PermissionBoundary`) attached to all `PRE-DR-*` roles
    - All `PRE-DR-*` role trust policies contain `aws:SourceVpc` condition equal to DR_VPC_ID
    - All PRE resources tagged `Environment=PRE`
    - KMS key policies for all `alias/pre-dr-*` keys contain explicit deny for `aws:PrincipalTag/Environment != PRE` and `aws:SourceVpc != DR_VPC_ID`
    - Region-restriction SCP attached to OU (eu-central-1 and eu-west-1 only)
    - Log-store protection SCP attached to OU
    - MFA enforcement condition present in `PRE-DR-AdministratorAccess` permission set
    - KMS rotation enabled on all 4 PRE_KMS keys
    - CloudTrail enabled, delivering to Object Lock-protected S3 bucket
    - S3 Object Lock in Compliance mode on Isolated Log Store with 365-day retention
    - Route 53 private hosted zone contains entries for all PRE-internal service FQDNs
    - Palo Alto firewall active at TGW boundary with stateful layer-7 inspection
    - CrowdStrike sensor registers heartbeat within 15 minutes on a newly provisioned test instance
    - Break-glass credentials exist for minimum 2 DR_Administrator accounts in offline secure medium
  - Ask the user if any questions arise before proceeding to property tests.

- [ ] 24. Property-based test suite — Python (Hypothesis)
  - [ ]* 24.1 Write property test for Production VPC Principal Role Assumption Denied (Property 1)
    - Implements the full Hypothesis test suite for Property 1 as described in task 2.3; uses `aws:SourceVpc` context (Prod VPC ID vs DR_VPC_ID) — not cross-account ARN checks — to assert DENY when source is the Prod VPC and ALLOW when source is the DR VPC
    - Tag: `Feature: aws-pre-cyber-recovery, Property 1: production VPC principal role assumption denied`
    - **Validates: Requirements 1.3**

  - [ ]* 24.2 Write property test for DR_Administrator MFA Enforcement (Property 2)
    - Implements the full Hypothesis test suite for Property 2 as described in task 6.3
    - Tag: `Feature: aws-pre-cyber-recovery, Property 2: DR_Administrator MFA enforcement`
    - **Validates: Requirements 1.6**

  - [ ]* 24.3 Write property test for PRE_KMS Key Policy Exclusion (Property 3)
    - Implements the full Hypothesis test suite for Property 3 as described in task 3.3
    - Tag: `Feature: aws-pre-cyber-recovery, Property 3: PRE_KMS key policy excludes production admins`
    - **Validates: Requirements 2.2**

  - [ ]* 24.4 Write property test for KMS Deletion Approval Gate (Property 4)
    - Implements the full Hypothesis test suite for Property 4 as described in task 3.5
    - Tag: `Feature: aws-pre-cyber-recovery, Property 4: KMS deletion approval gate`
    - **Validates: Requirements 2.4**

  - [ ]* 24.5 Write property test for Connectivity_Gate Expiry (Property 6)
    - Implements the full Hypothesis test suite for Property 6 as described in task 16.5
    - Tag: `Feature: aws-pre-cyber-recovery, Property 6: Connectivity_Gate expiry triggers revocation`
    - **Validates: Requirements 10.2**

  - [ ]* 24.6 Write property test for Unauthorized Path Auto-Disable (Property 7)
    - Implements the full Hypothesis test suite for Property 7 as described in task 18.2
    - Tag: `Feature: aws-pre-cyber-recovery, Property 7: unauthorized path auto-disable`
    - **Validates: Requirements 3.8**

  - [ ]* 24.7 Write property test for Artifact Checksum Rejection (Property 8)
    - Implements the full Hypothesis test suite for Property 8 as described in task 13.4
    - Tag: `Feature: aws-pre-cyber-recovery, Property 8: artifact checksum mismatch rejection`
    - **Validates: Requirements 5.7**

  - [ ]* 24.8 Write property test for CrowdStrike Quarantine Trigger (Property 9)
    - Implements the full Hypothesis test suite for Property 9 as described in task 14.6
    - Tag: `Feature: aws-pre-cyber-recovery, Property 9: CrowdStrike High/Critical quarantine`
    - **Validates: Requirements 6.5, 6.6**

  - [ ]* 24.9 Write property test for Certificate Renewal Automation (Property 10)
    - Implements the full Hypothesis test suite for Property 10 as described in task 11.3
    - Tag: `Feature: aws-pre-cyber-recovery, Property 10: certificate renewal automation`
    - **Validates: Requirements 9.3**

  - [ ]* 24.10 Write property test for Business Restoration Dual Approval (Property 11)
    - Implements the full Hypothesis test suite for Property 11 as described in task 16.7
    - Tag: `Feature: aws-pre-cyber-recovery, Property 11: Business_Restoration dual distinct approval`
    - **Validates: Requirements 10.6**

  - [ ]* 24.11 Write property test for Log Delivery Failure Alerting (Property 12)
    - Implements the full Hypothesis test suite for Property 12 as described in task 8.5
    - Tag: `Feature: aws-pre-cyber-recovery, Property 12: log delivery failure alert and recovery`
    - **Validates: Requirements 13.3**

- [ ] 25. Property-based test suite — TypeScript (fast-check)
  - [ ]* 25.1 Write fast-check property test for Connectivity_Gate Routing Requires Prior Approval (Property 5)
    - Implements the full fast-check test suite for Property 5 as described in task 16.3
    - Tag: `Feature: aws-pre-cyber-recovery, Property 5: Connectivity_Gate routing requires approval`
    - **Validates: Requirements 3.3, 10.1**

  - [ ]* 25.2 Write fast-check property test for Business Restoration Stage Dual Approval (Property 11 — TypeScript Lambda variant)
    - Write fast-check tests for the TypeScript Lambda implementation of `gate_validate_distinct_approvers`; generate approval request objects with 0, 1, 2-same, and 2-distinct approvers; assert correct allow/reject decisions
    - Tag: `Feature: aws-pre-cyber-recovery, Property 11: Business_Restoration dual distinct approval`
    - **Validates: Requirements 10.6**

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP delivery; all core security controls (SCP, KMS, network isolation, Connectivity_Gate) are non-optional
- Property tests use Python / Hypothesis for backend Lambda logic and TypeScript / fast-check for TypeScript Lambda components, as specified in the design document Testing Strategy section
- Each task references specific requirements for end-to-end traceability from acceptance criteria through to code
- Checkpoints (tasks 7, 17, 23) validate incremental correctness before continuing to the next phase
- The quarterly independence test automation (task 22) must be scheduled via EventBridge, not run continuously

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["2.1", "3.1", "4.1"] },
    { "id": 1, "tasks": ["2.2", "3.2", "4.2", "4.3", "5.1"] },
    { "id": 2, "tasks": ["2.3", "3.3", "5.2", "6.1", "8.1"] },
    { "id": 3, "tasks": ["3.4", "6.2", "8.2", "9.1"] },
    { "id": 4, "tasks": ["3.5", "6.3", "6.4", "6.5", "8.3", "9.2", "10.1", "11.1"] },
    { "id": 5, "tasks": ["8.4", "10.2", "11.2", "12.1", "12.2", "12.3", "12.4", "13.1", "13.2", "14.1", "15.1"] },
    { "id": 6, "tasks": ["8.5", "8.6", "11.3", "11.4", "13.3", "13.5", "14.2", "14.3", "14.4", "15.2", "16.1"] },
    { "id": 7, "tasks": ["13.4", "14.5", "14.7", "16.2", "19.1"] },
    { "id": 8, "tasks": ["14.6", "16.3", "16.4", "16.6", "18.1", "19.2", "19.3"] },
    { "id": 9, "tasks": ["16.5", "16.7", "16.8", "18.2", "20.1", "21.1"] },
    { "id": 10, "tasks": ["21.2", "22.1"] },
    { "id": 11, "tasks": ["24.1", "24.2", "24.3", "24.4", "24.5", "24.6", "24.7", "24.8", "24.9", "24.10", "24.11", "25.1", "25.2"] }
  ]
}
```
