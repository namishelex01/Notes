# Privilege Escalation Methods and Mitigations

### Creating a new policy version

**Description:** Attacker with the `iam:CreatePolicyVersion` permission can create a new version of an IAM policy that they have access to. This allows them to define their own custom permissions. When creating a new policy version, it needs to be set as the default version to take effect, which you would think would require the `iam:SetDefaultPolicyVersion` permission, but when creating a new policy version, it is possible to include a flag (–set-as-default) that will automatically create it as the new default version. That flag does not require the `iam:SetDefaultPolicyVersion` permission to use.

### Setting the default policy version to an existing version

**Description:** An attacker with the `iam:SetDefaultPolicyVersion` permission may be able to escalate privileges through existing policy versions that are not currently in use. If a policy that they have access to has versions that are not the default, they would be able to change the default version to any other existing version.

### Creating an EC2 instance with an existing instance profile

**Description:** An attacker with the `iam:PassRole` and `ec2:RunInstances` permissions can create a new EC2 instance that they will have operating system access to and pass an existing EC2 instance profile/service role to it. They can then login to the instance and request the associated AWS keys from the EC2 instance meta data, which gives them access to all the permissions that the associated instance profile/service role has.

### Creating a new user access key

**Description:** An attacker with the `iam:CreateAccessKey` permission on other users can create an access key ID and secret access key belonging to another user in the AWS environment, if they don’t already have two sets associated with them (which best practice says they shouldn’t).

### Creating a new login profile

**Description:** An attacker with the `iam:CreateLoginProfile` permission on other users can create a password to use to login to the AWS console on any user that does not already have a login profile setup.

### Updating an existing login profile

**Description:** An attacker with the `iam:UpdateLoginProfile` permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.

### Attaching a policy to a user

**Description:** An attacker with the `iam:AttachUserPolicy` permission can escalate privileges by attaching a policy to a user that they have access to, adding the permissions of that policy to the attacker.

### Attaching a policy to a group

**Description:** An attacker with the `iam:AttachGroupPolicy` permission can escalate privileges by attaching a policy to a group that they are a part of, adding the permissions of that policy to the attacker.

### Attaching a policy to a role

**Description:** An attacker with the `iam:AttachRolePolicy` permission can escalate privileges by attaching a policy to a role that they have access to, adding the permissions of that policy to the attacker.

### Creating/updating an inline policy for a user

**Description:** An attacker with the `iam:PutUserPolicy` permission can escalate privileges by creating or updating an inline policy for a user that they have access to, adding the permissions of that policy to the attacker.

### Creating/updating an inline policy for a group

**Description:** An attacker with the `iam:PutGroupPolicy` permission can escalate privileges by creating or updating an inline policy for a group that they are a part of, adding the permissions of that policy to the attacker.

### Creating/updating an inline policy for a role

**Description:** An attacker with the `iam:PutRolePolicy` permission can escalate privileges by creating or updating an inline policy for a role that they have access to, adding the permissions of that policy to the attacker.

### Adding a user to a group

**Description:** An attacker with the `iam:AddUserToGroup` permission can use it to add themselves to an existing IAM Group in the AWS account.

### Updating the AssumeRolePolicyDocument of a role

**Description:** An attacker with the `iam:UpdateAssumeRolePolicy` and `sts:AssumeRole` permissions would be able to change the assume role policy document of any existing role to allow them to assume that role.

### Passing a role to a new Lambda function, then invoking it

**Description:** A user with the `iam:PassRole`, `lambda:CreateFunction`, and `lambda:InvokeFunction` permissions can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. The code could then be run by invoking the function through the AWS API.

### Passing a role to a new Lambda function, then triggering it with DynamoDB

**Description:** A user with the `iam:PassRole`, `lambda:CreateFunction`, and `lambda:CreateEventSourceMapping` (and possibly `dynamodb:PutItem` and `dynamodb:CreateTable`) permissions, but without the `lambda:InvokeFunction` permission, can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. They then would need to either create a DynamoDB table or use an existing one, to create an event source mapping for the Lambda function pointing to that DynamoDB table. Then they would need to either put an item into the table or wait for another method to do so that the Lambda function will be invoked.

### Updating the code of an existing Lambda function

**Description:** An attacker with the `lambda:UpdateFunctionCode` permission could update the code in an existing Lambda function with an IAM role attached so that it would import the relevant AWS library in that programming language and use it to perform actions on behalf of that role. They would then need to wait for it to be invoked if they were not able to do so directly, but if it already exists, there is likely some way that it will be invoked.


### Passing a role to a Glue Development Endpoint

**Description:** An attacker with the `iam:PassRole` and `glue:CreateDevEndpoint` permissions could create a new AWS Glue development endpoint and pass an existing service role to it. They then could SSH into the instance and use the AWS CLI to have access of the permissions the role has access to.

### Updating an existing Glue Dev Endpoint

**Description:** An attacker with the `glue:UpdateDevEndpoint` permission would be able to update the associated SSH public key of an existing Glue development endpoint, to then SSH into it and have access to the permissions the attached role has access to.

### Passing a role to CloudFormation

**Description:** An attacker with the `iam:PassRole` and `cloudformation:CreateStack` permissions would be able to escalate privileges by creating a CloudFormation template that will perform actions and create resources using the permissions of the role that was passed when creating a CloudFormation stack.

### Passing a role to Data Pipeline

**Description:** An attacker with the `iam:PassRole`, `datapipeline:CreatePipeline`, and `datapipeline:PutPipelineDefinition` permissions would be able to escalate privileges by creating a pipeline and updating it to run an arbitrary AWS CLI command or create other resources, either once or on an interval with the permissions of the role that was passed in.
