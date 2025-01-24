import boto3
import argparse
import botocore.exceptions

def check_ec2_instances(security_group_id, session):
    ec2 = session.client('ec2')
    instances = ec2.describe_instances(
        Filters=[{'Name': 'instance.group-id', 'Values': [security_group_id]}]
    )
    results = []
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            results.append({
                'InstanceId': instance['InstanceId'],
                'State': instance['State']['Name']
            })
    return results

def check_network_interfaces(security_group_id, session):
    ec2 = session.client('ec2')
    network_interfaces = ec2.describe_network_interfaces(
        Filters=[{'Name': 'group-id', 'Values': [security_group_id]}]
    )
    results = []
    for interface in network_interfaces['NetworkInterfaces']:
        results.append({
            'NetworkInterfaceId': interface['NetworkInterfaceId'],
            'InstanceId': interface['Attachment'].get('InstanceId') if interface.get('Attachment') else None,
            'PrivateIpAddress': interface['PrivateIpAddress']
        })
    return results

def check_load_balancers(security_group_id, session):
    elbv2 = session.client('elbv2')
    results = []
    load_balancers = elbv2.describe_load_balancers()['LoadBalancers']
    for lb in load_balancers:
        if security_group_id in lb.get('SecurityGroups', []):
            results.append(lb['LoadBalancerArn'])
    return results

def check_rds_instances(security_group_id, session):
    rds = session.client('rds')
    instances = rds.describe_db_instances()['DBInstances']
    results = []
    for db_instance in instances:
        for vpc_sg in db_instance.get('VpcSecurityGroups', []):
            if vpc_sg['VpcSecurityGroupId'] == security_group_id:
                results.append(db_instance['DBInstanceIdentifier'])
    return results

def check_lambda_functions(security_group_id, session):
    lambda_client = session.client('lambda')
    functions = lambda_client.list_functions()['Functions']
    results = []
    for function in functions:
        vpc_config = function.get('VpcConfig')
        if vpc_config and security_group_id in vpc_config.get('SecurityGroupIds', []):
            results.append(function['FunctionName'])
    return results

def validate_profile_and_sg(profile_name, security_group_id):
    try:
        session = boto3.Session(profile_name=profile_name)
        ec2 = session.client('ec2')

        # Validate the security group exists
        ec2.describe_security_groups(GroupIds=[security_group_id])
        return session
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
            print(f"Error: Security Group {security_group_id} does not exist.")
        else:
            print(f"Error: {e.response['Error']['Message']}")
        exit(1)
    except botocore.exceptions.ProfileNotFound as e:
        print(f"Error: AWS profile '{profile_name}' not found.")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Check resources associated with a specific AWS Security Group.")
    parser.add_argument('--profile', required=True, help="AWS profile name")
    parser.add_argument('--sg', required=True, help="Security Group ID")
    args = parser.parse_args()

    profile_name = args.profile
    security_group_id = args.sg

    session = validate_profile_and_sg(profile_name, security_group_id)

    print(f"Checking resources associated with Security Group: {security_group_id}\n")

    resource_counts = {
        'EC2 Instances': 0,
        'Network Interfaces': 0,
        'Load Balancers': 0,
        'RDS Instances': 0,
        'Lambda Functions': 0
    }

    print("EC2 Instances:")
    ec2_instances = check_ec2_instances(security_group_id, session)
    resource_counts['EC2 Instances'] = len(ec2_instances)
    for instance in ec2_instances:
        print(instance)

    print("\nNetwork Interfaces:")
    network_interfaces = check_network_interfaces(security_group_id, session)
    resource_counts['Network Interfaces'] = len(network_interfaces)
    for interface in network_interfaces:
        print(interface)

    print("\nLoad Balancers:")
    load_balancers = check_load_balancers(security_group_id, session)
    resource_counts['Load Balancers'] = len(load_balancers)
    for lb in load_balancers:
        print(lb)

    print("\nRDS Instances:")
    rds_instances = check_rds_instances(security_group_id, session)
    resource_counts['RDS Instances'] = len(rds_instances)
    for db in rds_instances:
        print(db)

    print("\nLambda Functions:")
    lambda_functions = check_lambda_functions(security_group_id, session)
    resource_counts['Lambda Functions'] = len(lambda_functions)
    for function in lambda_functions:
        print(function)

    print("\nSummary of Resources:")
    for resource, count in resource_counts.items():
        print(f"{resource}: {count}")

if __name__ == "__main__":
    main()
