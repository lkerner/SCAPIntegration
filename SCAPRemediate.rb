
# Author: Lucy Kerner(lkerner@redhat.com)

$evm.log("info", "SCAP Remediate Start")

require 'rubygems'
require 'net/ssh'
require 'rest_client'
require "xmlrpc/client"


#We can only work with a VM that's powered on
vm = $evm.root['vm']
if vm.power_state == "off"
  $evm.log("info", "SCAP - VM not powered on")
  exit MIQ_ABORT
end

#Definitions for the Satellite
@SATELLITE_URL = "http://" + $evm.object['satellite_ip'] + "/rpc/api"
@SATELLITE_LOGIN = $evm.object['satellite_user']
@SATELLITE_PASSWORD = $evm.object.decrypt('satellite_password')

#Get the chosen SCAP profile
#profile = $evm.root['dialog_SCAP_Profiles']
profile = $evm.root['dialog_SCAPProfiles']
@PROFILE = "--profile " + "#{profile}"
$evm.log("info", "SCAP - Profile: #{@PROFILE}")
if @PROFILE == "--profile "
  $evm.log("info", "SCAP - Exit, no profile")
  exit MIQ_OK
end

#Definitions for the client; it would be better if I could get the domain name
theserver = "#{vm.name}"
$evm.log("info", "SCAP - Server: #{theserver}")
#USER = 'cf3operator'
USER = $evm.object['vm_user']
PASS = $evm.object.decrypt('vm_password')

#Get the IP address of the client
vm.ipaddresses.each do |vm_ipaddress|
  $evm.log("info", "SCAP - IP address: #{vm_ipaddress}")
  HOSTIP = vm_ipaddress
end
$evm.log("info", "Before logging into satellite...")

#Get the xccdf file that the chosen profile is in
Net::SSH.start( HOSTIP, USER, :password => PASS, :paranoid=> false ) do|ssh|
  ospcommand="oscap xccdf eval #{@PROFILE} --results /dev/null --remediate --cpe /usr/share/xml/scap/ssg/content/ssg-rhel6-cpe-dictionary.xml /usr/share/xml/scap/ssg/content/ssg-rhel6-xccdf.xml"
  $evm.log("info", "SCAP - Remediation Command ospcommand is: #{ospcommand}")
  REMEDIATIONOUT = ssh.exec!(ospcommand)
  $evm.log("info", "SCAP - Remediation Command STDOUT is: #{REMEDIATIONOUT}")
end


$evm.log("info", "SCAPRemediate Method Ended")
exit MIQ_OK
