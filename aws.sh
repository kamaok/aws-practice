#!/bin/bash

function installpythonpipaws () {
echo "Updating installed packages"
apt-get update && apt-get upgrade -y

PYTHON_PACKAGE=$(dpkg -l |  grep ii | grep -w ' python ' | wc -l)
if [ "${PYTHON_PACKAGE}" -eq "0" ]
  then
     echo "Python isn't installed"
     echo "Installation python..."
     apt-get install python -y
fi
echo "Installation PIP"
curl -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py  --user
echo "export PATH=~/.local/bin:$PATH" >> ~/.profile
source ~/.profile

echo "Installation AWS CLI"
pip install awscli --upgrade --user
aws --version

# pip install pip --upgrade --user
# pip install awscli --upgrade --user
echo "Enabling aws autocomplete"
AWS_COMPLETER=$(which aws_completer)
complete -C ""${AWS_COMPLETER}"" aws
echo "complete -C ""${AWS_COMPLETER}"" aws" >> ~/.profile
}

installpythonpipaws

echo "Export AWS-credentials,settings"
export AWS_DEFAULT_OUTPUT="json"
export AWS_ACCESS_KEY_ID="my_access_key"
export AWS_SECRET_ACCESS_KEY="my_secret_key"
export AWS_DEFAULT_REGION=eu-west-1

### Or via config file
#aws configure << EOF
#my_access_key
#my_secret_key
#us-west-1
#json
#EOF

echo "Creating VPC demo_vpc..."
aws ec2 create-vpc --cidr-block 11.0.0.0/16 > /tmp/aws.txt
VPC_ID=$(grep VpcId /tmp/aws.txt | awk '{print $2}' | sed 's/"//g' | sed 's/,//')
echo "Adding tag Key=Name,Value=demo_vpc to VPC demo_vpc..."
aws ec2 create-tags --resources ${VPC_ID} --tags Key=Name,Value=demo_vpc
echo "Check VPC demp_vpc..."
aws ec2 describe-vpcs --filters 'Name=tag:Name,Values=demo_vpc'
aws ec2 describe-vpcs --vpc-ids ${VPC_ID}
#sleep 20

echo "Creating subnet demo_public_net in demo_vpc..."
aws ec2 create-subnet --vpc-id ${VPC_ID} --cidr-block 11.0.1.0/24 > /tmp/subnet.txt
SUBNET_ID=$(grep SubnetId  /tmp/subnet.txt | awk '{print $2}' | sed 's/"//g' | sed 's/,//')
echo "Adding tag Key=Name,Value=demo_public_net to subnet demo_public_net..."
aws ec2 create-tags --resources ${SUBNET_ID} --tags Key=Name,Value=demo_public_net
echo "Check subnet demo_public_net..."
aws ec2 describe-subnets --filters 'Name=tag:Name,Values=demo_public_net'
aws ec2 describe-subnets --filters Name=vpc-id,Values=${VPC_ID}
#sleep 20

echo "Creating internet gateway demo_internet_gw..."
aws ec2 create-internet-gateway > /tmp/ig.txt
IG_ID=$(grep InternetGatewayId  /tmp/ig.txt | awk '{print $2}' | sed 's/"//g')
echo "Attaching internet gateway demo_internet_gw to VPC demo_vpc..."
aws ec2 attach-internet-gateway --internet-gateway-id ${IG_ID} --vpc-id ${VPC_ID}
echo "Adding tag Key=Name,Value=demo_internet_gw to internet gateway..."
aws ec2 create-tags --resources ${IG_ID} --tags Key=Name,Value=demo_internet_gw
echo "Check internet gateway demo_internet_gw..."
aws ec2 describe-internet-gateways --filters 'Name=tag:Name,Values=demo_internet_gw'
aws ec2 describe-internet-gateways --filters Name=internet-gateway-id,Values=${IG_ID}
#sleep 20

echo "Creating routing table in VPC demo_vpc..."
aws ec2 create-route-table --vpc-id ${VPC_ID} > /tmp/route.txt
ROUTE_TABLE_ID=$(grep RouteTableId /tmp/route.txt | awk '{print $2}' | sed 's/"//g' | sed 's/,//')
echo "Adding routing rule to routing table..."
aws ec2 create-route --route-table-id ${ROUTE_TABLE_ID} --destination-cidr-block 0.0.0.0/0 --gateway-id ${IG_ID}
echo "Adding tag Key=Name,Value=demo_route_table to route table..."
aws ec2 create-tags --resources ${ROUTE_TABLE_ID} --tags Key=Name,Value=demo_route_table
echo "Adding route table demo_route_table to subnet demo_public_net..."
aws ec2 associate-route-table --route-table-id ${ROUTE_TABLE_ID} --subnet-id ${SUBNET_ID}
echo "Check route rable demo_route_table..."
aws ec2 describe-route-tables --route-table-id ${ROUTE_TABLE_ID}
aws ec2 describe-route-tables --filters 'Name=tag:Name,Values=demo_route_table'
echo "Enabling auto-assign public IP in subnet demo_public_net"
aws ec2 modify-subnet-attribute --subnet-id ${SUBNET_ID} --map-public-ip-on-launch
#sleep 20

echo "Adding security group demo_public_sg"
aws ec2 create-security-group --group-name demo_public_sg --description "Public security group" --vpc-id ${VPC_ID} > /tmp/sg.txt
GROUP_ID=$(grep GroupId /tmp/sg.txt | awk '{print $2}' | sed 's/"//g')
echo "Adding ALLOW all INPUT traffic..."
aws ec2 authorize-security-group-ingress --group-id ${GROUP_ID} --protocol all --cidr 0.0.0.0/0
#sleep 20

echo "Creating pair SSH-keys"
#aws ec2 create-key-pair --key-name my_aws_ssh_key --query 'KeyMaterial' --output text > ~/.ssh/my_aws_ssh_key.pem
#chmod 400 ~/.ssh/my_aws_ssh_key.pem

SERVERNAME_STOP="c.kamaok.org.ua"
DOMAINNAME="kamaok.org.ua"

function creatingec2 () {
echo "Creating 3 EC2-instances {a,b,c}.$DOMAINNAME type t2.micro  in subnet demo_public_net with security group demo_public_sg..."
###aws ec2 run-instances --image-id ami-25110f45 --count 3 --instance-type t2.micro --key-name my_aws_ssh_key --security-group-ids ${GROUP_ID} --subnet-id ${SUBNET_ID}
aws ec2 run-instances --image-id ami-25110f45 --count 1 --instance-type t2.micro --key-name my_aws_ssh_key --security-group-ids ${GROUP_ID} --subnet-id ${SUBNET_ID} --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=a.$DOMAINNAME}]"
aws ec2 run-instances --image-id ami-25110f45 --count 1 --instance-type t2.micro --key-name my_aws_ssh_key --security-group-ids ${GROUP_ID} --subnet-id ${SUBNET_ID} --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=b.$DOMAINNAME}]"
aws ec2 run-instances --image-id ami-25110f45 --count 1 --instance-type t2.micro --key-name my_aws_ssh_key --security-group-ids ${GROUP_ID} --subnet-id ${SUBNET_ID} --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=c.$DOMAINNAME}]"
}

function stoponeec2 () {
echo "Stopping one EC2-instance"
INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=${SERVERNAME_STOP}" | grep -i instanceid | awk '{print $2}' | sed 's/"//g' | sed 's/,//')
aws ec2 stop-instances  --instance-ids ${INSTANCE_ID}
}

[ $(dpkg -l | grep -w netcat-openbsd | grep ii  | wc -l) -eq "0" ] && apt-get install netcat-openbsd -y

function checkservername () {
echo "Check TCP and HTTP-ports..."
for servername in {a,b,c}.$DOMAINNAME; do
	PORT=80
	SERVICE="HTTP"
		 nc -w 3 $servername ${PORT} > /dev/null 2>&1; EXIT_CODE=$(echo $?)
		 if [ "${EXIT_CODE}"  -eq "0" ];
		        then
				echo "${SERVICE}-service is running on the server $servername"
			else
				echo "${SERVICE} is NOT running on the server $servername"
		 fi
	PORT=22
	SERVICE="SSH"
		 nc -w 3 $servername ${PORT} > /dev/null 2>&1; EXIT_CODE=$(echo $?)
                 if [ "${EXIT_CODE}"  -eq "0" ];
                        then
                                echo "${SERVICE}-service is running on the server $servername"
                        else
                                echo "${SERVICE} is NOT running on the server $servername"
                 fi
done
}

function creatingami () {
echo "Creating AMI for EC2-instance"

STOPPED_INSTANCE_ID="${INSTANCE_ID}"
STOPPED_INSTANCE_NAME=$(aws ec2 describe-instances --filter --instance-ids ${STOPPED_INSTANCE_ID} | grep -i Value | awk '{print $2}' | sed 's/"//g' | sed 's/,//')
DATE=$(date +"%Y-%m-%d")

aws ec2 create-image --instance-id ${STOPPED_INSTANCE_ID} --name "${STOPPED_INSTANCE_NAME}-$DATE" --description "${STOPPED_INSTANCE_NAME}-$DATE"  > /tmp/ami.txt
AMI_ID=$(grep ami /tmp/ami.txt | awk '{print $2}' | sed 's/"//g')
echo "Adding tag Key=Name,Value=${STOPPED_INSTANCE_NAME} to ami ${AMI_ID}..."
aws ec2 create-tags --resources ${AMI_ID} --tags Key=Name,Value=${STOPPED_INSTANCE_NAME}
}

function statusami () {
STATUS_AMI=$(aws ec2 describe-images --owners self --filters "Name=name,Values=${STOPPED_INSTANCE_NAME}-$DATE" | grep -i state | awk '{print $2}' | sed 's/"//g' | sed 's/,//')
}

function terminatingoneec2 () {
echo "Teminating ${STOPPED_INSTANCE_NAME} EC2-instance..."
aws ec2 terminate-instances --instance-ids ${STOPPED_INSTANCE_ID}
}

function cleanami () {
echo "Installation amicleaner from https://github.com/bonclay7/aws-amicleaner"
#pip install pip --upgrade --user
#pip install future
#pip install aws-amicleaner
#ln -s /usr/local/bin/aws_completer ~/.local/bin/

amicleaner --mapping-key name --mapping-values ${STOPPED_INSTANCE_NAME} --full-report --keep-previous 0 --ami-min-days 7 --force-delete
}

creatingec2
sleep 300

stoponeec2
sleep 180

checkservername

creatingami
sleep 60

statusami

while  [ "${STATUS_AMI}"  != "available" ]; do
        echo "Creating AMI in progress"
        sleep 30
        statusami
done

terminatingoneec2

cleanami

echo "Check all EC2-instances..."
aws ec2 describe-instances | tee  /tmp/ec2.txt
grep --color=auto  -E "pending|running|shutting-down|terminated|stopping|stopped|$DOMAINNAME" /tmp/ec2.txt
