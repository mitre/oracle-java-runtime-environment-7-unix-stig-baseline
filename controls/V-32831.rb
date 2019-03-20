is_on_siprnet = attribute('is_on_siprnet')
control 'V-32831' do
  title 'The setting enabling users to configure the check publisher certificates for revocation must be locked.'
  desc  "Certificates may be revoked due to improper issuance, compromise of the certificate, and failure to adhere to policy. Therefore, any certificate found revoked on a CRL or via Online Certificate Status Protocol (OCSP) should not be trusted. Permitting execution of an applet published with a revoked certificate may result in spoofing, malware, system modification, invasion of privacy, and denial of service. Ensuring users cannot change these settings assures a more consistent security profile. NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0030 Lock the option to check certificates for revocation'
  tag "gid": 'V-32831'
  tag "rid": 'SV-43617r3_rule'
  tag "stig_id": 'JRE0030-UX'
  tag "cci": 'CCI-001991'
  tag "nist": ['IA-5 (2) (d)', 'Rev_4']
  tag "cci": 'CCI-000185'
  tag "nist": ['IA-5 (2)(a)', 'Rev_4']
  tag "check": "If the system is on the SIPRNET, this requirement is NA. Navigate to the system 'deployment.properties' file for Java, the default location is /usr/java/jre/lib/deployment.properties. If the 'deployment.security.validation.crl.locked' key is not present within the deployment.properties file, this is a finding. If the 'deployment.security.validation.ocsp.locked' key is not present within the deployment.properties file, this is a finding."
  tag "fix": "Navigate to the system 'deployment.properties' file for Java, the default location is /usr/java/jre/lib/deployment.properties. Add the 'deployment.security.validation.crl.locked' key to the deployment.properties file. Add the 'deployment.security.validation.ocsp.locked' key to the deployment.properties file."

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/usr/java/jre/lib/deployment.properties') do
      its('content') { should match(/deployment.security.validation.crl.locked/) }
    end
    describe file('/usr/java/jre/lib/deployment.properties') do
      its('content') { should match(/deployment.security.validation.ocsp.locked/) }
    end
  end
end
