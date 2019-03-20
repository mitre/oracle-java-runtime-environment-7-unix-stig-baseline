is_on_siprnet = attribute('is_on_siprnet')
control 'V-32833' do
  title 'The option to enable online certificate validation must be locked.'
  desc  "Online certificate validation provides a real-time option to validate a certificate. When enabled, if a certificate is presented, the status of the certificate is requested. The status is sent back as 'current', 'expired', or 'unknown'. Online certificate validation provides a greater degree of validation of certificates when running a signed Java applet. Permitting execution of an applet with an invalid certificate may result in malware, system modification, invasion of privacy, and denial of service. Ensuring users cannot change settings contributes to a more consistent security profile. NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0050 Lock online certificate validation'
  tag "gid": 'V-32833'
  tag "rid": 'SV-43619r2_rule'
  tag "stig_id": 'JRE0050-UX'
  tag "cci": 'CCI-000185'
  tag "nist": ['IA-5 (2)(a)', 'Rev_4']
  tag "check": "If the system is on the SIPRNET, this requirement is NA. Navigate to the 'deployment.properties' file for Java. /usr/java/jre/lib/deployment.properties If the key 'deployment.security.validation.ocsp.locked' is not present, this is a finding. "
  tag "fix": "If the system is on the SIPRNET, this requirement is NA. Lock the 'Enable online certificate validation' option. Navigate to the 'deployment.properties' file for Java. /usr/java/jre/lib/deployment.properties Add the key 'deployment.security.validation.ocsp.locked'. "

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/usr/java/jre/lib/deployment.properties') do
      its('content') { should match(/deployment.security.validation.ocsp.locked/) }
    end
  end
end
