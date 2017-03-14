#
#            Automate Method
#
#
#            Method Code Goes here
#
$evm.log("info", "SCAP Schedule Start")

require 'rubygems'
require 'net/ssh'
require 'rest_client'
require "xmlrpc/client"
require 'time'

def log(level, msg, update_message = false)
  $evm.log(level, "#{msg}")
  @task.message = msg if @task && (update_message || level == 'error')
end

def latestsatelliteresultID (satelliteresults, profile) 
	max_xID=-1
  $evm.log("info", "Printing SCAP SatResults: #{satelliteresults}")
  	satelliteresults.each do |satelliteresult|
      $evm.log("info", "SCAP Profile: #{satelliteresult["profile"]} \t xid = #{satelliteresult["xid"]}  max so far #{max_xID}\t ")
      
    	if profile==satelliteresult["profile"]
          	currentxID=satelliteresult["xid"]
            if currentxID > max_xID
              max_xID=currentxID
  	  	    end
  		end
    
    end

    return max_xID 
end

#SERVICENOW CODE
def call_servicenow(action, tablename='incident', body=nil)
  require 'rest_client'
  require 'json'
  require 'base64'

  servername = nil || $evm.object['servername']
  username = nil   || $evm.object['username']
  password = nil   || $evm.object.decrypt('password')
  url = "https://#{servername}/api/now/table/#{tablename}"

  params = {
    :method=>action, :url=>url, 
    :headers=>{ :content_type=>:json, :accept=>:json, :authorization => "Basic #{Base64.strict_encode64("#{username}:#{password}")}" }
  }
  params[:payload] = body.to_json
  log(:info, "Calling url: #{url} action: #{action} payload: #{params[:payload]}")

  snow_response = RestClient::Request.new(params).execute
  log(:info, "response headers: #{snow_response.headers}")
  log(:info, "response code: #{snow_response.code}")
  log(:info, "response: #{snow_response}")
  snow_response_hash = JSON.parse(snow_response)
  return snow_response_hash['result']
end

# create_vm_incident
def build_vm_body(vm)
  comments = "VM: #{vm.name}\n"
  comments += "Hostname: #{vm.hostnames.first}\n" unless vm.hostnames.nil?
  comments += "Guest OS Description: #{vm.hardware.guest_os_full_name.inspect}\n" unless vm.hardware.guest_os_full_name.nil?
  comments += "IP Address: #{vm.ipaddresses}\n"
  comments += "Provider: #{vm.ext_management_system.name}\n" unless vm.ext_management_system.nil?
  comments += "Cluster: #{vm.ems_cluster.name}\n" unless vm.ems_cluster.nil?
  comments += "Host: #{vm.host.name}\n" unless vm.host.nil?
  comments += "CloudForms Server: #{$evm.root['miq_server'].hostname}\n"
  comments += "Region Number: #{vm.region_number}\n"
  comments += "vCPU: #{vm.num_cpu}\n"
  comments += "vRAM: #{vm.mem_cpu}\n"
  comments += "Disks: #{vm.num_disks}\n"
  comments += "Power State: #{vm.power_state}\n"
  comments += "Storage Name: #{vm.storage_name}\n"
  comments += "Allocated Storage: #{vm.allocated_disk_storage}\n"
  comments += "Provisioned Storage: #{vm.provisioned_storage}\n"
  comments += "GUID: #{vm.guid}\n"
  comments += "Tags: #{vm.tags.inspect}\n"
  (body_hash ||= {})['comments'] = comments
  return body_hash
end

begin
  $evm.root.attributes.sort.each { |k, v| $evm.log(:info, "Root:<$evm.root> Attribute - #{k}: #{v}")}

  object = $evm.root[$evm.root['vmdb_object_type']]

  case $evm.root['vmdb_object_type']
  when 'vm'
    body_hash = build_vm_body(object)
  when 'host'
    body_hash = build_host_body(object)
  else
    raise "Invalid $evm.root['vmdb_object_type']: #{object}"
  end

  unless body_hash.nil?
    # object_name = 'Event' means that we were triggered from an Alert
    if $evm.root['object_name'] == 'Event'
      $evm.log(:info, "Detected Alert driven event")
      body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{object.name} - #{$evm.root['miq_alert_description']}"
    elsif $evm.root['ems_event']
      # ems_event means that were triggered via Control Policy
      $evm.log(:info, "Detected Policy driven event")
      $evm.log(:info, "Inspecting $evm.root['ems_event']:<#{$evm.root['ems_event'].inspect}>")
      body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{object.name} - #{$evm.root['ems_event'].event_type}"
    else
      unless $evm.root['dialog_miq_alert_description'].nil?
        $evm.log(:info, "Detected service dialog driven event")
        # If manual creation add dialog input notes to body_hash
        body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{object.name} - #{$evm.root['dialog_miq_alert_description']}"
      else
        $evm.log(:info, "Detected manual driven event")
        # If manual creation add default notes to body_hash
        body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{object.name} - Incident manually created"
      end
    end
end
end


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

if vm.vendor_display == 'RedHat'
theserver = "#{vm.name}"
end

if vm.vendor_display == 'VMware'
theserver = "#{vm.hostnames[0]}"
end

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
    PATH2CONTENT = ssh.exec!('for x in `locate xccdf|grep xml`; do grep -li "Profile id=\"' + "#{profile.strip}" + '" $x; done|head -1')
end
$evm.log("info", "SCAP - Directory: #{PATH2CONTENT}")

$evm.log("info", "SCAP Before logging into satellite...")

#Log into the Satellite
@client = XMLRPC::Client.new2(@SATELLITE_URL)
@key = @client.call('auth.login', @SATELLITE_LOGIN, @SATELLITE_PASSWORD)
$evm.log("info", "SCAP After logging into satellite...")

#Get the Satellite details of the client
systeminfo = @client.call('system.getId', @key, theserver)
$evm.log("info", "SCAP Satellite Details of Client: #{systeminfo}")

#Check to see if the system is defined in Satellite
if systeminfo[0] == nil
    $evm.log("info", "SCAP - #{theserver} doesn't exist in Satellite")
    exit MIQ_ABORT
end
@serverID = systeminfo[0]["id"]
systemname = systeminfo[0]['name']
$evm.log("info", "Scheduling SCAP for #{systemname}")

#Get set of scans before we start
existingresults= @client.call('system.scap.listXccdfScans', @key, @serverID)
$evm.log("info", "SCAP ExistingResults #{existingresults}")
latestIDbeforestart=latestsatelliteresultID(existingresults,profile) 
$evm.log("info", "SCAP LatestSatelliteResultID #{latestIDbeforestart}")

#Schedule a SCAP scan

scanID = @client.call('system.scap.scheduleXccdfScan', @key, @serverID, PATH2CONTENT, @PROFILE)
$evm.log("info", "SCAPSched SCANS: #{scanID}")

#
#Force the client to check-in to run the scan
$evm.log("info", "SCAP - Starting a rhn_check for #{theserver} #{HOSTIP}")
Net::SSH.start( HOSTIP, USER, :password => PASS, :paranoid=> false ) do|ssh|
  rhn_check = ssh.exec!('/usr/sbin/rhn_check')
end


i=0
num=10
foundresults=false
while i <num do 
  sleep 10
  $evm.log("info", "SCAPSched loop: #{i}")
  i +=1
  
  theresults = @client.call('system.scap.listXccdfScans', @key, @serverID)
  $evm.log("info", "SCAPSched Results: #{theresults}")
  
  currentmaxID=latestsatelliteresultID(theresults,profile)
  $evm.log("info", "SCAP CurrentMaxID #{currentmaxID}")
  if currentmaxID != latestIDbeforestart
    $evm.log("info", "SCAP Results are done!: #{currentmaxID}")
    foundresults=true
    break
  
  end
  
	
end
if foundresults==false
  $evm.log("info","SCAP Unable to get results after timeout")
  exit MIQ_ERROR
end

failresult=false
theresults = @client.call('system.scap.getXccdfScanRuleResults', @key, currentmaxID)
	for theresult in theresults do
		if theresult["result"] == "fail"
          failresult = true
			break
		end
	end

#Tag the VM with the relevant compliance/non-compliance result
#The catagory/tag will should be in the format:
#    scap_{profile}/compliant
#    scap_{profile}/non_compliant

#Get the profile and massage it to work within the name convention
theprofile = @client.call('system.scap.getXccdfScanDetails', @key, currentmaxID)

#Added:6/9/16
endtime=theprofile["end_time"]
#$evm.log("info","===HERE_IS_END_TIME====== #{endtime.to_time.httpdate}")
#vm.custom_set("lastendscantime",endtime.to_time.httpdate)
timestamp = endtime.to_time.to_s
$evm.log("info","===HERE_IS_END_TIME====== #{timestamp}")
vm.custom_set("lastendscantime",timestamp)

#profiledown = theprofile["profile"].downcase
#profile = profiledown.tr("-", "_")


if failresult==true
  profilecategory = "scap_noncompliant"
  category_to_remove = "scap_compliant"
else
  profilecategory= "scap_compliant"
  category_to_remove = "scap_noncompliant"
end

#To ensure that we have a self-managed environment, if the tags for the profile don't exist, create them
#Start with the tag category
if $evm.execute('category_exists?', "#{profilecategory}")
  $evm.log("info", "SCAPCheck - #{profilecategory} exists")
else
  $evm.log("info", "SCAPCheck - Adding new category: #{profilecategory}")
  $evm.execute('category_create', :name => "#{profilecategory}", :single_value => false, :description => "#{profilecategory}")
end

#And then the tags
if $evm.execute('tag_exists?', "#{profilecategory}", "#{profile}")
  $evm.log("info", "SCAPCheck - #{profile} exists and is evaluated")
else
  $evm.log("info", "SCAPCheck - Adding new tags for #{profile}")
  $evm.execute('tag_create',"#{profilecategory}", :name => "#{profile}", :description => "#{profile}")
end

loggedincfuser = $evm.root['user']
$evm.log("info", "USERNAME: #{loggedincfuser.userid}")

if failresult == true
  vm.tag_assign("#{profilecategory}/#{profile}")
  $evm.log("info", "You have an OpenSCAP Scan Failure! Your VM: #{theserver} has failed the following SCAP policy profile: #{profile}")
  to = "lkerner@redhat.com"
  from = "noreply@redhat.com"
  subject =  "You have an OpenSCAP Scan Failure! Your VM: #{theserver} has failed the following SCAP policy profile: #{profile}"
  body = "Hi #{loggedincfuser.userid}, <br><br> You have an OpenSCAP Scan Failure! Your VM :<b>#{theserver}</b> has failed the following SCAP policy profile: <b>#{profile}</b>.<br>Please fix the security failures within 48 hours. Your VM will automatically be remediated if it fails the security scan checks in 48 hours.<br><br>Thank You for your cooperation.<br><br>From,<br>Your Friendly Security Team"
  $evm.execute('send_email', to, from , subject, body)
  
  #SERVICENOW
  subjectservicenow="#{theserver} failed SCAP policy: #{profile}.VM owner is :#{loggedincfuser.userid}."
  body_hash['short_description'] = subjectservicenow
  # call servicenow
    $evm.log(:info, "Calling ServiceNow: incident information: #{body_hash.inspect}")
    insert_incident_result = call_servicenow(:post, 'incident', body_hash)

    #$evm.log(:info, "insert_incident_result: #{insert_incident_result.inspect}")
    $evm.log(:info, "insert_incident_result: #{insert_incident_result.inspect}")
    $evm.log(:info, "number: #{insert_incident_result['number']}")
    $evm.log(:info, "sys_id: #{insert_incident_result['sys_id']}")

    $evm.log(:info, "Adding custom attribute :servicenow_incident_number => #{insert_incident_result['number']} to #{$evm.root['vmdb_object_type']}: #{object.name}")
    object.custom_set(:servicenow_incident_number, insert_incident_result['number'].to_s)
    $evm.log(:info, "Adding custom attribute :servicenow_incident_sysid => #{insert_incident_result['sys_id']}> to #{$evm.root['vmdb_object_type']}: #{object.name}")
    object.custom_set(:servicenow_incident_sysid, insert_incident_result['sys_id'].to_s)
  
else
  vm.tag_assign("#{profilecategory}/#{profile}")
  $evm.log("info", "SCAPCheck - #{theserver} has passed all SCAP(#{profile}) policies")
end
vm.tag_unassign("#{category_to_remove}/#{profile}")
@client.call('auth.logout', @key)


$evm.log("info", "SCAPSched Method Ended")
exit MIQ_OK

