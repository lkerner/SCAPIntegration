# Authors: Lucy Kerner(lkerner@redhat.com)

vm = $evm.root['vm']

lastendscantime = vm.custom_get(:lastendscantime)

unless lastendscantime.nil?
  datetimestamp = lastendscantime
else
  datetimestamp = "never scanned"
end


dialog_field = $evm.object

dialog_field["value"] = datetimestamp
dialog_field["read_only"] = true

#dialog_field["default_value"] = 2
