is_on_siprnet = attribute('is_on_siprnet')
control 'V-32832' do
  title 'The option to enable online certificate validation must be enabled.'
  desc  "Online certificate validation provides a real-time option to validate a certificate. When enabled, if a certificate is presented, the status of the certificate is requested. The status is sent back as 'current', 'expired', or 'unknown'. Online certificate validation provides a greater degree of validation of certificates when running a signed Java applet. Permitting execution of an applet with an invalid certificate may result in malware execution , system modification, invasion of privacy, and denial of service. NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0040 Enable online certificate validation'
  tag "gid": 'V-32832'
  tag "rid": 'SV-43618r2_rule'
  tag "stig_id": 'JRE0040-UX'
  tag "cci": 'CCI-000185'
  tag "nist": ['IA-5 (2)(a)', 'Rev_4']
  tag "check": "If the system is on the SIPRNET, this requirement is NA. Navigate to the 'deployment.properties' file for Java. /usr/java/jre/lib/deployment.properties Examine the deployment.properties file for the 'deployment.security.validation.ocsp' key. If the 'deployment.security.validation.ocsp' key is not present, this is a finding. If the key 'deployment.security.validation.ocsp' is set to 'false', this is a finding. "
  tag "fix": "If the system is on the SIPRNET, this requirement is NA. Enable the 'Enable online certificate validation' option. Navigate to the 'deployment.properties' file for Java. /usr/java/jre/lib/deployment.properties Add or update the key 'deployment.security.validation.ocsp' to be 'true'. "

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/usr/java/jre/lib/deployment.properties') do
      its('content') { should match(/deployment.security.validation.ocsp=true/) }
    end
  end
end
