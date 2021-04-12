# AWS Privilege Escalation - II

### EBS direct APIs and Snapshot

**Description:** 

- Attacker enumerates all of the Elastic Block Store volumes, snapshots, and snapshot permissions in the account
- Downloading if any EBS snapshot available
- Explore th snapshot using Vagrant and Virtualbox
- Steal credentials from it

**How to Exploit??**

    dsnap get <instance-id> # Pacu feature 
    
The temporary snapshot is downloaded to i-0d706e33814c1ef9a.img

    $ IMAGE="i-0d706e33814c1ef9a.img" vagrant up
    $ IMAGE="i-0d706e33814c1ef9a.img" vagrant ssh

**Potential Impact:**

Using the EBS Direct APIs can be a simple and effective way to exfiltrate data and discover secrets in an AWS network without alerting anyone.
Can be alerted by monitoring `ec2:ModifySnapshotAttribute` attribute

---

### S3 Ransomware

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### IAM Security flaws

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Cloudtrail CSV Injection

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Enumerate AWS users using AssumeRole

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Bypass Cloudtrail logging

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### IAM user enumeration using Account ID

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Compromising AWS IAM credentials

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Unauthenticated AWS Role Enumeration

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### IAM privilege escalation using CodeStar API

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Phishing AWS users with MFA enabled

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Bypass IP based block using AWS API gateway

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Phished AWS persistent cookies

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Capital One breach

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Exploiting AWS ECS and ECR

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### Abuse VPC traffic mirroring

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

### ECS task definition to stealing credentials

**Description:** 

- 

**How to Exploit??**



**Potential Impact:**



---

Reference -> [Rhinosecurity](https://rhinosecuritylabs.com/blog/)
