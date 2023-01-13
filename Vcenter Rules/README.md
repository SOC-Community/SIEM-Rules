# Log Source: Vcenter Access Log

Reference: https://kb.vmware.com/s/article/1021804

# Example Logs:

![ảnh](https://user-images.githubusercontent.com/3302470/212289270-0b27141b-e98f-4c85-96c8-93e50f79310d.png)

# Blacklist URL Attack:
```
/websso/SAML2/SSO/vsphere.local
/portal/info.jsp
/ui/vcav-bootstrap/rest/vcav-providers/provider-logo
/ui/login.action
/api/2.0/services/usermgmt/password/
/hybridity/api/sessions
/dr/authentication/oauth2/oauth2login
/configure/app/landing/welcome-srm-va.html
/..%252F..%252F..%252F..%252F..%252F..%252F
/proxy.stream
/oauth/authorize
/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData
/logupload?logMetaData=
/casa/nodes/thumbprints
/hystrix/;a=a/
/ui/vropspluginui/rest/services/getvcdetails
/Catalog/BlobHandler.ashx
/ui/vropspluginui/rest/services/getstatus
/functionRouter
/SAAS/t/_/;/WEB-INF/web.xml
/catalog-portal/ui/oauth/verify
/actuator/gateway/routes/
/vcac/
/portal/webclient/index.html
/cloud/
/AirWatch/Login
/eam/vib?id=
```
Following by nuclei, metasploit, google:dork attack...

# Graylog Pineline Rule Example:
```
rule "vcenter_check_blacklist_url"
when
  contains(to_string($message.message), "/websso/SAML2/SSO/vsphere.local", true) || 
  contains(to_string($message.message), "/portal/info.jsp", true) || 
  contains(to_string($message.message), "/ui/vcav-bootstrap/rest/vcav-providers/provider-logo", true) || 
  contains(to_string($message.message), "/ui/login.action", true) || 
  contains(to_string($message.message), "/api/2.0/services/usermgmt/password", true) || 
  contains(to_string($message.message), "/hybridity/api/sessions", true) || 
  contains(to_string($message.message), "/dr/authentication/oauth2/oauth2login", true) || 
  contains(to_string($message.message), "/configure/app/landing/welcome-srm-va.html", true) || 
  contains(to_string($message.message), "/..%252F..%252F..%252F..%252F..%252F..%252F", true) || 
  contains(to_string($message.message), "/proxy.stream", true) || 
  contains(to_string($message.message), "/oauth/authorize", true) || 
  contains(to_string($message.message), "/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData", true) || 
  contains(to_string($message.message), "/logupload?logMetaData=", true) || 
  contains(to_string($message.message), "/casa/nodes/thumbprints", true) || 
  contains(to_string($message.message), "/hystrix/;a=a/", true) || 
  contains(to_string($message.message), "/ui/vropspluginui/rest/services/getvcdetails", true) || 
  contains(to_string($message.message), "/Catalog/BlobHandler.ashx", true) || 
  contains(to_string($message.message), "/ui/vropspluginui/rest/services/getstatus", true) || 
  contains(to_string($message.message), "/functionRouter", true) || 
  contains(to_string($message.message), "/SAAS/t/_/;/WEB-INF/web.xml", true) || 
  contains(to_string($message.message), "/catalog-portal/ui/oauth/verify", true) || 
  contains(to_string($message.message), "/actuator/gateway/routes", true) || 
  contains(to_string($message.message), "/vcac/", true) || 
  contains(to_string($message.message), "/portal/webclient/index.html", true) || 
  contains(to_string($message.message), "/cloud/", true) || 
  contains(to_string($message.message), "/AirWatch/Login", true) || 
  contains(to_string($message.message), "/eam/vib?id=", true)
then
  set_field("blacklist_url", true);
end
```

# Graylog Dashboard:
![ảnh](https://user-images.githubusercontent.com/3302470/212289950-a2e69fa9-3ff6-464a-8598-0dba4b87bee3.png)
