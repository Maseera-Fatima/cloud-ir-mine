import boto3
import os
from datetime import datetime

# AWS setup - uses default credentials (IAM role, AWS CLI config, or environment variables)
region = os.getenv('AWS_DEFAULT_REGION', 'ap-south-1')
ec2_client = boto3.client('ec2', region_name=region)
iam_client = boto3.client('iam', region_name=region)

def isolate_vm(instance_id):
    """Stop EC2 instance (equivalent to deallocate in Azure)"""
    try:
        response = ec2_client.stop_instances(InstanceIds=[instance_id])
        print(f"Stopping instance {instance_id}")
        
        # Wait for instance to stop
        waiter = ec2_client.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=[instance_id])
        print(f"Instance {instance_id} has been stopped")
        
        return response
    except Exception as e:
        print(f"Error stopping instance {instance_id}: {e}")
        raise

def snapshot_disk(instance_id):
    """Create snapshots of all volumes attached to the EC2 instance"""
    try:
        # Get instance details
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        snapshots_created = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Get all volumes attached to the instance
                for block_device in instance.get('BlockDeviceMappings', []):
                    volume_id = block_device['Ebs']['VolumeId']
                    device_name = block_device['DeviceName']
                    
                    # Create snapshot name
                    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
                    snapshot_name = f"{instance_id}-{device_name.replace('/', '-')}-snapshot-{timestamp}"
                    
                    # Create snapshot
                    snapshot_response = ec2_client.create_snapshot(
                        VolumeId=volume_id,
                        Description=f"Emergency snapshot of {device_name} from {instance_id}",
                        TagSpecifications=[
                            {
                                'ResourceType': 'snapshot',
                                'Tags': [
                                    {'Key': 'Name', 'Value': snapshot_name},
                                    {'Key': 'SourceInstance', 'Value': instance_id},
                                    {'Key': 'SourceVolume', 'Value': volume_id},
                                    {'Key': 'DeviceName', 'Value': device_name},
                                    {'Key': 'Purpose', 'Value': 'IncidentResponse'}
                                ]
                            }
                        ]
                    )
                    
                    snapshot_id = snapshot_response['SnapshotId']
                    snapshots_created.append({
                        'snapshot_id': snapshot_id,
                        'volume_id': volume_id,
                        'device_name': device_name
                    })
                    
                    print(f"Created snapshot {snapshot_id} for volume {volume_id} ({device_name})")
        
        return snapshots_created
        
    except Exception as e:
        print(f"Error creating snapshots for instance {instance_id}: {e}")
        raise

def revoke_user_access(username):
    """Revoke IAM user access by detaching policies and removing from groups"""
    try:
        print(f"Revoking access for user: {username}")
        
        # Detach managed policies
        try:
            attached_policies = iam_client.list_attached_user_policies(UserName=username)
            for policy in attached_policies['AttachedPolicies']:
                iam_client.detach_user_policy(
                    UserName=username,
                    PolicyArn=policy['PolicyArn']
                )
                print(f"Detached managed policy: {policy['PolicyName']}")
        except iam_client.exceptions.NoSuchEntityException:
            print(f"User {username} not found in IAM")
            return
        
        # Delete inline policies
        try:
            inline_policies = iam_client.list_user_policies(UserName=username)
            for policy_name in inline_policies['PolicyNames']:
                iam_client.delete_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )
                print(f"Deleted inline policy: {policy_name}")
        except Exception as e:
            print(f"Error removing inline policies: {e}")
        
        # Remove from groups
        try:
            groups = iam_client.get_groups_for_user(UserName=username)
            for group in groups['Groups']:
                iam_client.remove_user_from_group(
                    GroupName=group['GroupName'],
                    UserName=username
                )
                print(f"Removed from group: {group['GroupName']}")
        except Exception as e:
            print(f"Error removing from groups: {e}")
        
        print(f"Successfully revoked access for user: {username}")
        
    except Exception as e:
        print(f"Error revoking access for {username}: {e}")
        raise

# Example usage
if __name__ == "__main__":
    # Replace with actual values
    instance_id = "i-0693358207b1c05f1"  # Your EC2 instance ID
    username = "maseera"  # IAM username to revoke access
    
    try:
        # 1. Isolate the compromised instance
        print("Step 1: Isolating VM...")
        isolate_vm(instance_id)
        
        # 2. Create forensic snapshots
        print("\nStep 2: Creating disk snapshots...")
        snapshots = snapshot_disk(instance_id)
        print(f"Created {len(snapshots)} snapshots")
        
        # 3. Revoke user access (uncomment when needed)
        # print(f"\nStep 3: Revoking user access...")
        # revoke_user_access(username)
        
        print("\nIncident response actions completed successfully!")
        
    except Exception as e:
        print(f"Error during incident response: {e}")
