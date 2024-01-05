#! /bin/bash

# start datetime
echo "start datetime: $(date)";

# env variables
REGION='us-east-1'
EKS_CLUSTER_NAME='dev-security-cluster-model'
EKS_CLUSTER_VERSION='1.24'
EKS_APP_NAMESPACE='wp'
EKS_APP_IAM_SERVICE_ACCOUNT_NAME='wp-deployment-sa'
EKS_APP_IAM_POLICY_NAME='wp-deployment-policy-model'

# verify cluster exists or not
eksctl get cluster --name "$EKS_CLUSTER_NAME"
retval=$?
echo $retval
if [ $retval -ne 0 ]; then
    # create cluster
    eksctl create cluster \
    --name "$EKS_CLUSTER_NAME" \
    --region "$REGION" \
    --version "$EKS_CLUSTER_VERSION"
else
    echo "cluster $EKS_CLUSTER_NAME already exists"
fi

# verify cluster node group exists or not
eksctl get nodegroup --cluster "$EKS_CLUSTER_NAME" --region "$REGION" --name my-mng
retval=$?
echo $retval
if [ $retval -ne 0 ]; then
    # create cluster node group
    eksctl create nodegroup \
    --cluster "$EKS_CLUSTER_NAME" \
    --region "$REGION" \
    --name my-mng \
    --node-ami-family AmazonLinux2 \
    --node-type m5.large \
    --nodes 2 \
    --nodes-min 2 \
    --nodes-max 3 \
    --node-private-networking
else
    echo "cluster node group my-mng already exists"
fi

# set cluster context
aws eks update-kubeconfig --name "$EKS_CLUSTER_NAME"

# associate oidc provider with cluster
eksctl utils associate-iam-oidc-provider --region="$REGION" --cluster="$EKS_CLUSTER_NAME" --approve

# create iam policy
POLICY_ARN=$(aws --region "$REGION" --query Policy.Arn --output text iam create-policy --policy-name "$EKS_APP_IAM_POLICY_NAME" --policy-document '{
    "Version": "2012-10-17",
    "Statement": [ {
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
        "Resource": "*"
    },{
        "Effect": "Allow",
        "Action": ["kms:DescribeKey", "kms:GenerateDataKey", "kms:Decrypt"],
        "Resource": "*"
    } ]
}')

# create wordpress specific EKS_APP_NAMESPACE
kubectl create ns "$EKS_APP_NAMESPACE"

# create iam serviceaccount
eksctl create iamserviceaccount --name "$EKS_APP_IAM_SERVICE_ACCOUNT_NAME" --region="$REGION" --cluster "$EKS_CLUSTER_NAME" --attach-policy-arn "$POLICY_ARN" --approve --override-existing-serviceaccounts --namespace "$EKS_APP_NAMESPACE"

# end datetime
echo "end datetime: $(date)"