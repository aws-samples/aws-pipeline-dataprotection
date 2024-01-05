#! /bin/bash

# start datetime
echo "start datetime: $(date)";

# env variables
ACCOUNT='000000000000'
REGION='us-east-1'
EKS_CLUSTER_NAME='dev-security-cluster-model'
EKS_VPC_ID='vpc-0x00000x0000'
EKS_PRIMARY_SG='sg-0x00000x0000'
EKS_SERVICE_ROLE_PIPELINE='EKSServiceRole'
CLOUDFRONT_PREFIX_LIST_ID='pl-0x0000'
CLOUDFORMATION_ROLE='CFTStackCreationRole'
CLOUDFORMATION_POLICY='CFTStackCreationPolicy'
CLOUDFORMATION_CF_POLICY='CFTStackCreationCFPolicy'
OIDCID='0x00000x00000x00000x00000x0000'

# set cluster context
aws eks update-kubeconfig --name "$EKS_CLUSTER_NAME" --region "$REGION"

# aws lbc iam policy
curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.4.7/docs/install/iam_policy.json
aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam_policy.json

# aws lbc iam service account
eksctl create iamserviceaccount \
  --cluster="$EKS_CLUSTER_NAME" \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn=arn:aws:iam::"$ACCOUNT":policy/AWSLoadBalancerControllerIAMPolicy \
  --approve

# helm repo add for lbc
helm repo add eks https://aws.github.io/eks-charts
helm repo update

# create aws lbc
kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller/crds?ref=master"
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName="$EKS_CLUSTER_NAME" \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller \
  --set region="$REGION" \
  --set vpcId="$EKS_VPC_ID"
kubectl get deployment -n kube-system aws-load-balancer-controller

# helm repo add for csi driver
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm repo update

# create csi driver
helm install -n kube-system csi-secrets-store \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true \
  secrets-store-csi-driver/secrets-store-csi-driver
kubectl get daemonsets -n kube-system -l app.kubernetes.io/instance=csi-secrets-store

# create aws secret provider
kubectl apply -f https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml
kubectl get daemonsets -n kube-system -l app=csi-secrets-store-provider-aws

# create eks service role
TRUST="{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::"$ACCOUNT":root\" }, \"Action\": \"sts:AssumeRole\" } ] }"
aws iam create-role --role-name "$EKS_SERVICE_ROLE_PIPELINE" --assume-role-policy-document "$TRUST" --output text --query 'Role.Arn'
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy --role-name "$EKS_SERVICE_ROLE_PIPELINE"
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy  --role-name "$EKS_SERVICE_ROLE_PIPELINE"
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly  --role-name "$EKS_SERVICE_ROLE_PIPELINE"
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy  --role-name "$EKS_SERVICE_ROLE_PIPELINE"
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEKSServicePolicy  --role-name "$EKS_SERVICE_ROLE_PIPELINE"

# adding eks service role into authz configmap
ROLE="    - rolearn: arn:aws:iam::"$ACCOUNT":role/"$EKS_SERVICE_ROLE_PIPELINE"\n      username: "$EKS_SERVICE_ROLE_PIPELINE"\n      groups:\n        - system:masters"
kubectl get -n kube-system configmap/aws-auth -o yaml | awk "/mapRoles: \|/{print;print \"$ROLE\";next}1" > /tmp/aws-auth-patch.yml
kubectl patch configmap/aws-auth -n kube-system --patch "$(cat /tmp/aws-auth-patch.yml)"

# alb managed sg
ALB_MANAGED_SG_TEMP=$(aws ec2 create-security-group --group-name 'alb-managed' --description "alb managed sg" --vpc-id "$EKS_VPC_ID" --region "$REGION" --output json --query GroupId )
ALB_MANAGED_SG=$(sed -e 's/^"//' -e 's/"$//' <<<"$ALB_MANAGED_SG_TEMP")
aws ec2 authorize-security-group-ingress \
  --group-id $ALB_MANAGED_SG \
  --ip-permissions FromPort=443,ToPort=443,IpProtocol=tcp,PrefixListIds="[{PrefixListId=$CLOUDFRONT_PREFIX_LIST_ID}]"
echo $ALB_MANAGED_SG

# alb shared sg
ALB_SHARED_SG_TEMP=$(aws ec2 create-security-group --group-name 'alb-shared' --description "alb shared sg" --vpc-id "$EKS_VPC_ID" --region "$REGION" --output json --query GroupId )
ALB_SHARED_SG=$(sed -e 's/^"//' -e 's/"$//' <<<"$ALB_SHARED_SG_TEMP")
echo $ALB_SHARED_SG

# add alb-shared security group to eks primary security group to allow incoming traffic
aws ec2 authorize-security-group-ingress \
  --group-id "$EKS_PRIMARY_SG" \
  --protocol tcp \
  --port '0 - 65535' \
  --source-group "$ALB_SHARED_SG"

# ebs csi iam policy
curl -o ebs-csi-iam-policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-ebs-csi-driver/v0.9.0/docs/example-iam-policy.json
aws iam create-policy --policy-name AmazonEKS_EBS_CSI_Driver_Policy --policy-document file://ebs-csi-iam-policy.json
aws eks describe-cluster --name "$EKS_CLUSTER_NAME" --query "cluster.identity.oidc.issuer" --output text

# ebs csi iam trust policy
cat <<EOF > trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::$ACCOUNT:oidc-provider/oidc.eks.$REGION.amazonaws.com/id/$OIDCID"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.$REGION.amazonaws.com/id/$OIDCID:sub": "system:serviceaccount:kube-system:ebs-csi-controller-sa"
        }
      }
    }
  ]
}
EOF

# ebs csi iam role
aws iam create-role \
    --role-name AmazonEKS_EBS_CSI_DriverRole \
    --assume-role-policy-document file://"trust-policy.json"

aws iam attach-role-policy \
    --policy-arn arn:aws:iam::"$ACCOUNT":policy/AmazonEKS_EBS_CSI_Driver_Policy \
    --role-name AmazonEKS_EBS_CSI_DriverRole

# deploy ebs csi driver along with service account
kubectl apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=master"

# annotate service account with ebs csi iam role
kubectl annotate serviceaccount ebs-csi-controller-sa \
  -n kube-system \
  eks.amazonaws.com/role-arn=arn:aws:iam::"$ACCOUNT":role/AmazonEKS_EBS_CSI_DriverRole

# delete old csi pods, so new pods are created with proper iam permissions
kubectl delete pods \
  -n kube-system \
  -l=app=ebs-csi-controller

# create cloudformation stack role
TRUST="{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"Service\": \"cloudformation.amazonaws.com\" }, \"Action\": \"sts:AssumeRole\" } ] }"
aws iam create-role --role-name "$CLOUDFORMATION_ROLE" --assume-role-policy-document "$TRUST" --output text --query 'Role.Arn'
POLICY_ARN=$(aws --region "$REGION" --query Policy.Arn --output text iam create-policy --policy-name "$CLOUDFORMATION_POLICY" --policy-document '{
    "Version": "2012-10-17",
    "Statement": [ {
        "Effect": "Allow",
        "Action": ["codepipeline:CreatePipeline","codepipeline:DeletePipeline","codepipeline:GetPipeline","codepipeline:PutJobFailureResult","codepipeline:PutJobSuccessResult", 
        "codepipeline:UpdatePipeline","codepipeline:UntagResource","codepipeline:TagResource","codepipeline:GetPipelineExecution","codepipeline:ListTagsForResource",
        "codepipeline:GetPipelineState"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["codebuild:CreateProject","codebuild:DeleteProject","codebuild:ListProjects","codebuild:UpdateProject"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["codecommit:CreateRepository","codecommit:DeleteRepository","codecommit:GetRepository","codecommit:UpdateRepositoryDescription", 
        "codecommit:UpdateRepositoryName","codecommit:TagResource","codecommit:ListTagsForResource","codecommit:UntagResource","codecommit:ListRepositories"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["kms:CreateAlias","kms:CreateKey","kms:DeleteAlias","kms:DescribeKey","kms:DisableKey","kms:DisableKeyRotation","kms:EnableKey", 
        "kms:EnableKeyRotation","kms:ScheduleKeyDeletion","kms:RetireGrant","kms:PutKeyPolicy","kms:GenerateDataKeyPair","kms:GetKeyRotationStatus",
        "kms:ListGrants","kms:ListKeys","kms:encrypt","kms:RevokeGrant","kms:UntagResource","kms:ListResourceTags","kms:CreateGrant","kms:GetKeyPolicy",
        "kms:Decrypt","kms:TagResource","kms:ListKeyPolicies","kms:GenerateDataKey"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["ecr:CreateRepository","ecr:DeleteRepository","ecr:TagResource","ecr:UntagResource"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["s3:CreateBucket","s3:DeleteBucket","s3:DeleteObject","s3:DeleteBucketPolicy","s3:PutBucketPolicy","s3:PutBucketAcl","s3:GetBucketPolicy",
        "s3:GetEncryptionConfiguration","s3:ListBucket","s3:PutBucketTagging","s3:GetBucketPolicyStatus","s3:GetBucketAcl"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["events:CreateEventBus","events:DeleteEventBus","events:CreateEndpoint","events:DeleteEndpoint","events:DeleteRule","events:PutEvents",
        "events:PutTargets","events:RemoveTargets","events:UpdateEndpoint","events:PutPermission","events:RemovePermission","events:DescribeRule","events:PutRule",
        "events:DescribeEventSource","events:DescribeEndpoint","events:TagResource","events:UntagResource","events:ListTagsForResource","events:ListRules"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["rds:CreateDBCluster","rds:CreateDBInstance","rds:DeleteDBInstance","rds:DeleteDBCluster","rds:StartDBCluster","rds:StartDBInstance","rds:StopDBCluster", 
        "rds:StopDBInstance","rds:CreateDBSubnetGroup","rds:AddTagsToResource","rds:ListTagsForResource","rds:CreateDBParameterGroup","rds:DescribeDBSubnetGroups",
        "rds:DeleteDBSecurityGroup","rds:DescribeDBInstances","rds:DescribeDBSecurityGroups","rds:DeleteDBSubnetGroup","rds:DeleteDBParameterGroup","rds:RemoveTagsFromResource",
        "rds:CreateDBSecurityGroup","rds:DescribeDBClusters","rds:DescribeEngineDefaultParameters","rds:DescribeDBParameterGroups","rds:DescribeDBParameters","rds:ModifyDBParameterGroup",
        "rds:ModifyDBInstance","rds:RebootDBInstance"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["acm:DeleteCertificate","acm:RequestCertificate","acm:UpdateCertificateOptions","acm:PutAccountConfiguration","acm:AddTagsToCertificate",
        "acm:GetCertificate","acm:ListTagsForCertificate","acm:DescribeCertificate","acm:RemoveTagsFromCertificate",
        "acm:ListCertificates"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["wafv2:PutPermissionPolicy","wafv2:DeletePermissionPolicy","wafv2:CreateIPSet","wafv2:AssociateWebACL","wafv2:CreateWebACL", 
        "wafv2:DeleteIPSet","wafv2:DeleteWebACL","wafv2:DisassociateWebACL","wafv2:UpdateIPSet","wafv2:UpdateRuleGroup","wafv2:UpdateWebACL",
        "wafv2:GetIPSet","wafv2:GetWebACL","wafv2:ListRuleGroups","wafv2:UntagResource","wafv2:ListWebACLs","wafv2:TagResource","wafv2:ListTagsForResource"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["ec2:AuthorizeSecurityGroupIngress","ec2:DescribeSecurityGroups","ec2:DeleteSecurityGroup","ec2:RevokeSecurityGroupEgress","ec2:CreateTags",
        "ec2:RevokeSecurityGroupIngress","ec2:DeleteTags","ec2:CreateSecurityGroup","ec2:AuthorizeSecurityGroupEgress","ec2:DescribeTags"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["secretsmanager:ListSecrets","secretsmanager:TagResource","secretsmanager:UpdateSecret","secretsmanager:CreateSecret","secretsmanager:RotateSecret",
        "secretsmanager:PutSecretValue","secretsmanager:DeleteSecret","secretsmanager:DescribeSecret","secretsmanager:UntagResource"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["logs:TagLogGroup","logs:UntagLogGroup","logs:TagResource","logs:CreateLogGroup","logs:DeleteLogGroup","logs:UntagResource","logs:PutRetentionPolicy"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["iam:PutRolePolicy","iam:GetRole","iam:TagPolicy","iam:UntagRole","iam:TagRole","iam:DeleteRolePolicy","iam:CreatePolicy",
        "iam:UpdateRole","iam:UpdateAssumeRolePolicy","iam:GetPolicyVersion","iam:DeleteServiceLinkedRole","iam:DeletePolicy","iam:CreatePolicyVersion","iam:GetInstanceProfile",
        "iam:DeleteAccessKey","iam:GetPolicy","iam:DeleteRole","iam:GetRolePolicy","iam:CreateInstanceProfile","iam:DeleteInstanceProfile","iam:TagInstanceProfile",
        "iam:SetDefaultPolicyVersion","iam:CreateRole","iam:AttachRolePolicy","iam:DetachRolePolicy","iam:DeletePolicyVersion"],
        "Resource": "*"
    }
     ]
}')
POLICY_CF_ARN=$(aws --region "$REGION" --query Policy.Arn --output text iam create-policy --policy-name "$CLOUDFORMATION_CF_POLICY" --policy-document '{
    "Version": "2012-10-17",
    "Statement": [ {
        "Effect": "Allow",
        "Action": ["cloudfront:CreateDistribution","cloudfront:CreateCachePolicy","cloudfront:CreateOriginAccessControl","cloudfront:CreateOriginRequestPolicy",
        "cloudfront:DeleteCachePolicy","cloudfront:DeleteDistribution","cloudfront:DeleteOriginAccessControl","cloudfront:DeleteOriginRequestPolicy", 
        "cloudfront:UpdateDistribution","cloudfront:UpdateCachePolicy","cloudfront:UpdateOriginAccessControl","cloudfront:UpdateOriginRequestPolicy", 
        "cloudfront:GetCachePolicy","cloudfront:GetDistribution","cloudfront:GetOriginAccessControl","cloudfront:GetOriginRequestPolicy","cloudfront:UntagResource",
        "cloudfront:TagResource","cloudfront:ListTagsForResource","cloudfront:GetCachePolicyConfig","cloudfront:GetCloudFrontOriginAccessIdentity",
        "cloudfront:GetCloudFrontOriginAccessIdentityConfig","cloudfront:GetDistributionConfig","cloudfront:GetOriginAccessControlConfig","cloudfront:GetOriginRequestPolicyConfig",
        "cloudfront:ListCachePolicies","cloudfront:ListCloudFrontOriginAccessIdentities","cloudfront:ListOriginAccessControls","cloudfront:ListOriginRequestPolicies","cloudfront:ListUsages",
        "cloudfront:ListResponseHeadersPolicies","cloudfront:ListDistributionsByCachePolicyId","cloudfront:ListInvalidations","cloudfront:ListDistributions",
        "cloudfront:ListDistributionsByWebACLId","cloudfront:ListDistributionsByOriginRequestPolicyId"],
        "Resource": "*"
    }
    ]}')
aws iam attach-role-policy --policy-arn "arn:aws:iam::$ACCOUNT:policy/$CLOUDFORMATION_POLICY"  --role-name "$CLOUDFORMATION_ROLE"
aws iam attach-role-policy --policy-arn "arn:aws:iam::$ACCOUNT:policy/$CLOUDFORMATION_CF_POLICY"  --role-name "$CLOUDFORMATION_ROLE"

# end datetime
echo "end datetime: $(date)"