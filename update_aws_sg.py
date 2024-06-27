import boto3
from botocore.config import Config
import argparse
from pathlib import Path
import logging
import urllib.request

from configparser import ConfigParser

CONFIG_FILE = Path.home() / ".config" / "aws-sg" / "aws-sg.cfg"
URL = "https://checkip.amazonaws.com"


def myip():
    with (urllib.request.urlopen(URL)) as response:
        bytes_response = response.read()
        my_ip = bytes_response.decode('utf-8').strip() + "/32"
        return my_ip


class UpdateAwsSg:
    def __init__(self, arguments):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        self.logger.info(f"Checking config file {CONFIG_FILE}")

        self.my_ip = myip()
        self.logger.info(f"My IP is {self.my_ip}")

        if not CONFIG_FILE.exists():
            raise FileNotFoundError(CONFIG_FILE)

        self.description = arguments.description

        self.section = arguments.aws_profile

        self.config = ConfigParser()
        self.config.read(CONFIG_FILE)
        self.security_groups = {security_group: region for security_group, region in self.config.items(self.section)}

    def update_security_groups(self):
        for security_group, region in self.security_groups.items():
            self.logger.info(f"Updating security group {security_group} in region {region}")

            session = boto3.Session(profile_name=self.section)
            config = Config(region_name=region)
            client = session.client("ec2", config=config)

            # response = client.describe_security_groups()
            #
            # for r in response['SecurityGroups']:
            #     print(f"{r['GroupName']},{r['GroupId']}")

            response = client.describe_security_groups(GroupIds=[security_group])
            ip_ranges = response['SecurityGroups'][0]['IpPermissions'][0]['IpRanges']

            found = False

            for ip_range in ip_ranges:
                self.logger.info(ip_range)
                if ip_range['Description'] == self.description:
                    found = True
                    self.logger.info("Checking %s", ip_range['CidrIp'])
                    if ip_range['CidrIp'] != self.my_ip:
                        self.revoke_cidr(security_group, ip_range['CidrIp'], ip_range['Description'], client)
                        self.update_cidr(security_group, region, client)

            if not found:
                self.update_cidr(security_group, region, client)

    def update_cidr(self, security_group, region, client):
        self.logger.info(f"Updating CIDR for {security_group} in region {region}")
        client.authorize_security_group_ingress(
            GroupId=security_group,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'IpRanges': [
                        {
                            'CidrIp': self.my_ip,
                            'Description': self.description
                        }
                    ],
                }
            ],
        )

    def revoke_cidr(self, security_group, old_ip_range, description, client):
        self.logger.info(f"Revoking CIDR for {security_group} for ip range {old_ip_range}")
        client.revoke_security_group_ingress(
            GroupId=security_group,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'IpRanges': [
                        {
                            'CidrIp': old_ip_range,
                            'Description': self.description
                        }
                    ],
                }
            ],
        )

    def list_security_groups(self):
        print(f"[{self.section}]")
        for security_group, region in self.security_groups.items():
            print(f"{security_group} = {region}")

    def list_all_security_groups(self):
        for section in self.config.sections():
            print(f"[{section}]")
            for security_group, region in self.config.items(section):
                print(f"{security_group} = {region}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-u", "--update", help="Update the security groups", action="store_true")
    group.add_argument("-l", "--list", help="List the security groups for the current profile", action="store_true")
    group.add_argument("--list-all", help="List all security groups for all profiles", action="store_true")
    
    parser.add_argument('-a', '--aws-profile', default="default", help='AWS configuration profile')
    parser.add_argument('-d', '--description', default="Home", help='The location to update')

    args = parser.parse_args()

    update_aws_sg = UpdateAwsSg(args)
    if args.list:
        update_aws_sg.list_security_groups()
    elif args.list_all:
        update_aws_sg.list_all_security_groups()
    else:
        update_aws_sg.update_security_groups()
