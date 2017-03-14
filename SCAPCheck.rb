#
#            Automate Method
#
$evm.log("info", "SCAPCheck Automate Method Started")
#
#            Method Code Goes here
#
#!/usr/bin/env ruby
require "xmlrpc/client"

failresult = 0
systeminfo = ""
@SATELLITE_URL = "http://" + $evm.object['satellite_ip'] + "/rpc/api"
@SATELLITE_LOGIN = $evm.object['satellite_user']
@SATELLITE_PASSWORD = $evm.object.decrypt('satellite_password')
@client = XMLRPC::Client.new2(@SATELLITE_URL)
@key = @client.call('auth.login', @SATELLITE_LOGIN, @SATELLITE_PASSWORD)

#Definitions for the client; it would be better if I could get the domain name
vm = $evm.root['vm']
theserver = "#{vm.name}"
$evm.log("info", "SCAPCheck - Server: #{theserver}")

#Get the Satellite details of the client
systeminfo = @client.call('system.getId', @key, theserver)
$evm.log("info", "SCAPCheck - <#{systeminfo[0]}>")

if systeminfo[0] == nil
  $evm.log("info", "SCAPCheck - #{theserver} is not defined in Satellite")
  exit MIQ_OK
end

systemname = systeminfo[0]['name']
$evm.log("info", "SCAPCheck - Checking SCAP for #{systemname}")

#Schedule a SCAP scan
@serverID = systeminfo[0]["id"]

#Get a list of the SCAP scans that have been performed and use the very last one
scans = @client.call('system.scap.listXccdfScans', @key, @serverID)
$evm.log("info", "SCAPCheck - Printing SCANS #{scans}")
for scan in scans do
	@xID = scan["xid"]
	theresults = @client.call('system.scap.getXccdfScanRuleResults', @key, @xID)
	for theresult in theresults do
		if theresult["result"] == "fail"
			failresult = 1
			break
		end
	end
	break
end

#Tag the VM with the relevant compliance/non-compliance result
#The catagory/tag will should be in the format:
#    scap_{profile}/compliant
#    scap_{profile}/non_compliant

#Get the profile and massage it to work within the name convention
theprofile = @client.call('system.scap.getXccdfScanDetails', @key, @xID)
profiledown = theprofile["profile"].downcase
profile = profiledown.tr("-", "_")
profilecategory = "scap_#{profile}"

#To ensure that we have a self-managed environment, if the tags for the profile don't exist, create them
#Start with the tag category
if $evm.execute('category_exists?', "#{profilecategory}")
  $evm.log("info", "SCAPCheck - #{profilecategory} exists")
else
  $evm.log("info", "SCAPCheck - Adding new category: #{profilecategory}")
  $evm.execute('category_create', :name => "#{profilecategory}", :single_value => true, :description => "SCAP - #{profile} profile")
end

#And then the tags
if $evm.execute('tag_exists?', "#{profilecategory}", "compliant") && $evm.execute('tag_exists?', "#{profilecategory}", "non_compliant")
  $evm.log("info", "SCAPCheck - #{profile} exists and is evaluated")
else
  $evm.log("info", "SCAPCheck - Adding new tags for #{profile}")
  $evm.execute('tag_create',"#{profilecategory}", :name => "compliant", :description => "Compliant")
  $evm.execute('tag_create',"#{profilecategory}", :name => "non_compliant", :description => "Non-compliant")
end

if failresult == 1
  vm.tag_assign("#{profilecategory}/non_compliant")
  $evm.log("info", "SCAPCheck - #{theserver} has failed an SCAP(#{profile}) policy")
else
  vm.tag_assign("#{profilecategory}/compliant")
  $evm.log("info", "SCAPCheck - #{theserver} has passed all SCAP(#{profile}) policies")
end
@client.call('auth.logout', @key)

#
$evm.log("info", "SCAPCheck Automate Method Ended")
exit MIQ_OK

