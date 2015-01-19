#!/usr/bin/env bash
#
# Set-up/Provision a Vagrant Kali linux box

echo ".."
echo "setting up and provisioning a kali linux vm..."
echo ".."

# install some commaon packages
sudo apt-get update && \
sudo apt-get -y install python-software-properties \
software-properties-common \
git \
gcc \
lynx-cur \
build-essential \
python-dev \
python-setuptools \
python-pip \
curl && \
sudo pip install --upgrade pip && \
sudo pip install virtualenv virtualenvwrapper && \

# install packages crucial for wifiphiser. iwconfig is found in the wireless-tools package
sudo apt-get -y install python-scapy \
wireless-tools

# TODO 
# * enable the ansible provisioning

# install ansible
# sudo add-apt-repository -y ppa:rquillo/ansible && \
# sudo apt-get update && \
# sudo apt-get -y install ansible

# ran ansible playbook
# PYTHONUNBUFFERED=1 ansible-playbook /vagrant/devops/setup.yml \
#     --inventory-file=/vagrant/devops/development \
#     --connection=local
