## aws-pipeline-data-protection

This project provides examples and sample code to DevOps pipeline for a three-tier WordPress web application deployed using Amazon Elastic Kubernetes Service (Amazon EKS).

## Prerequisites
Before you start you should have the following prerequisites:
* install aws-cli - https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
* install eksctl - https://docs.aws.amazon.com/eks/latest/userguide/eksctl.html
* install kubectl - https://kubernetes.io/docs/tasks/tools
* install helm - https://helm.sh/docs/intro/install/
* Update the resource input parameters in all the config files with the original values as per your environment by replacing the dummy values
    * Example: Account Id, VPC Id, Security Group Id, OIDC Id, ACM Cert Id and RDS DB Host Endpoint

## Environment Setup

Clone this repo:

```
git clone https://github.com/aws-samples/aws-pipeline-dataprotection.git

```

## Step by Step Implementation Guide
### Run bash scripts
* bash eks-cluster-setup.sh
* bash eks-cluster-addons-setup.sh

### DNS domain name
*  create a new DNS domain name if not already exists
    * update this parameter 'DNSDomainName' in this file 'basic-infra-cft.yaml'
    * update this parameter 'AlternateDomainNames' in this file 'basic-infra-cf-cft.yaml'
    * update 'WP_HOME & WP_SITEURL' parameters in this file 'wp-config-docker.php'

### Run prerequisites cloudformation template
* go to cloudformation console section after login to your account
* cloudformation stack role 'CFTStackCreationRole' is created in the previous step, use it for new cloudformation stack creation with the below templates    
* basic-infra-cft.yaml        
    * update the below parameters in this file by fetching the corresponding values from previously created cluster
        * EKSVpcId, EKSSubnetIds, EKSAvailabilityZone, EKSSecurityGroup
    * create a basic infra stack using this template to create new codecommit, rds mysql instance and acm certificate
    * check in all the source code into newly created codecommit
* cicd-codepipeline.yaml
    * update the below parameters in this file by fetching the corresponding values from previously created codecommit and EKS cluster
        * RepositoryName, BranchName, EksClusterName, EksClusterRegion, EKSServiceRole
    * create a application cicd pipeline stack using this template to create codepipeline with source, build and deploy stages

### Update rds secret and acm certificate arn
* update the ecr repository in the 'wordpress-deployment.yaml' containers section
* update the rds db host in the 'wordpress-deployment.yaml' env section
* update the rds mysql secret name in the 'wordpress-deployment-spc.yaml' spec section to pull the rds credentials from secretsmanager and set it in application pod
* update the acm certificate arn in the 'wordpress-ingress.yaml' annotation section to configure alb appropriately
* update alb security groups in the 'wordpress-ingress.yaml' annotation section to configure alb appropriately
    * please fetch these security group names "alb_managed" & "alb_shared" and update it

### Deploy the wordpress application using cicd pipeline

### Run cloudfront cloudformation template
* basic-infra-cf-cft.yaml
    * update the below parameters in this template to configure origin appropriately
        * ALBDNSName, AlternateDomainNames, ACMCertificateIdentifier, TrustedIPAddresses
    * this template has to be run/update whenever alb url changes, so that cloudfront configuration will get updated accordingly

### Delete all the resources once the sample application exercise is done

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.


