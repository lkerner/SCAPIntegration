#
# Authors: Jeff Watts(jwatts@redhat.com) and Lucy Kerner(lkerner@redhat.com)
#
$evm.log("info", "Get SCAP Profiles Method Started")
#
#            Method Code Goes here
require "net/ssh"

vm = $evm.root['vm']
USER = $evm.object['vm_user']
PASS = $evm.object.decrypt('vm_password')

#HOSTIP = ""

#dialog_field = $evm.object

# sort_by: value / description / none
#dialog_field["sort_by"] = "value"
#	  sort_order:	  ascending	  /	  descending
#dialog_field["sort_order"] = "ascending"
#	  data_type:	  string	  /	  integer
#dialog_field["data_type"] = "string"
#	  required:	  true	  /	  false
#dialog_field["required"] = "true"
 values_hash = {}

if vm.power_state == "on"
  vm.ipaddresses.each do |vm_ipaddress|
    $evm.log("info", "SCAPProfiles - IP address: #{vm_ipaddress}")
    $evm.log("info", "SCAPProfiles - User: #{USER}")
#    $evm.log("info", "SCAPProfiles - PASS: #{PASS}")
    HOSTIP = vm_ipaddress
  end
  if HOSTIP == ""
    $evm.log("info", "SCAPProfiles - Cannot determine IP address")
    #dialog_field["values"] = "---Cannot contact VM---"
    values_hash['none'] =  "---Cannot contact VM---"
   # exit MIQ_OK
  else

    $evm.log("info", "SCAPProfiles - Getting profiles from #{vm.name} #{HOSTIP}")
  
    Net::SSH.start( HOSTIP, USER, :password => PASS ) do|ssh|
      scap_profiles = ssh.exec!('updatedb;/bin/grep "Profile id" `locate xccdf|grep xml`|/usr/bin/cut -f2 -d\"& sleep 5;kill $! >/dev/null 2>&1')
      values_hash['!'] = '---Choose SCAP Profile---'
    # Build the array
      $evm.log("info", "SCAPProfiles - Retrieved profiles -->#{scap_profiles}<--")
    # because of the bug...we need to reverse   scapprofiles = Array.new(['---Choose SCAP Profile---'])
    
    #scapprofiles = Array.new(['---eliforP PACS esoohC---'])
      scap_profiles.each_line do |scapped|
        scap = scapped.strip
        #scap = scap.downcase
        #scap = scap.tr("-", "_")
        
        $evm.log("info", "#{@method} - Trying to add #{scap} to the list")
        
        values_hash[scap] = "#{scap} --NOTSCANNED"
        
        if vm.tagged_with?("scap_compliant", scap)
        #scapprofiles.push(scap.reverse => "#{scap} --PASSED")
           values_hash[scap] = "#{scap} --PASSED"
        end
        
        if vm.tagged_with?("scap_noncompliant", scap)
        #scapprofiles.push(scap.reverse => "#{scap} --FAILED")
          values_hash[scap] = "#{scap} --FAILED"
         
        end
      end
      if values_hash.empty?
      #dialog_field["values"] = "No SCAP profiles defined for this VM"
        values_hash['none'] = "No SCAP Profiles defined for this VM"
    #else
     # dialog_field["values"] = scapprofiles
      end
    end
  end  
else
  $evm.log("info", "SCAPProfiles - VM not powered on")
  #dialog_field["values"] = "VM not powered on: Press Cancel"
  values_hash['none'] = "VM not powered on: Press Cancel"
#  exit MIQ_OK
end

list_values = {
     'sort_by'    => :value,
     'data_type'  => :string,
     'required'   => true,
     'values'     => values_hash
  }
list_values.each { |key, value| $evm.object[key] = value }


  
$evm.log("info", "Get SCAP Profiles Method Ended")
exit MIQ_OK
