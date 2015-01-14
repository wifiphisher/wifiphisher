#!/usr/bin/env ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  # Every Vagrant virtual environment requires a box to build off of.
  config.vm.box = "svigneux/kali-linux-1.0.6-amd64-mini"
  config.vm.box_check_update = false

  # The url from where the box will be fetched
  # config.vm.box_url = "http://URL"

  # Create a forwarded port mapping which allows access to a specific port 
  config.vm.network :forwarded_port, guest: 8080, host: 8080
  config.vm.network :forwarded_port, guest: 443, host: 8443

  config.ssh.forward_agent = true
  
  # Bootstrap provisioning with the shell.
  config.vm.provision :shell, :path => "devops/boot.sh"

  #disable ssl cert verification
  config.vm.box_download_insecure = true

  config.vm.synced_folder './devops', '/vagrant/devops', 
      :mount_options => ['fmode=666']

  # Cache apt-get package downloads to speed things up
  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
  end

end
