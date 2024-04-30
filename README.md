    usage: update_aws_sg.py [-h] [-u | -l | --list-all] [-a AWS_PROFILE] [-d DESCRIPTION]
    
    options:
      -h, --help            show this help message and exit
      -u, --update          Update the security groups
      -l, --list            List the security groups for the current profile
      --list-all            List all security groups for all profiles
      -a AWS_PROFILE, --aws-profile AWS_PROFILE
                            AWS configuration profile
      -d DESCRIPTION, --description DESCRIPTION
                            The location to update

Requires a configuration file, currently hardcoded in 

    ~/.config/aws-sg/aws-sg.fg

For example,

[default]
sg-249857620984756 = us-west-1


