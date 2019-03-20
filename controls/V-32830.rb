is_on_siprnet = attribute('is_on_siprnet')
control 'V-32830' do
  title 'The setting for users to check publisher certificates for revocation must be enabled.'
  desc  "A certificate revocation list is a directory which contains a list of certificates that have been revoked for various reasons. Certificates may be revoked due to improper issuance, compromise of the certificate, and failure to adhere to policy. Therefore, any certificate found on a CRL should not be trusted. Permitting execution of an applet published with a revoked certificate may result in spoofing, malware, system modification, invasion of privacy, and denial of service.

  NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0020 Enable revocation check on publisher certificates'
  tag "gid": 'V-32830'
  tag "rid": 'SV-43604r2_rule'
  tag "stig_id": 'JRE0020-UX'
  tag "cci": 'CCI-001991'
  tag "nist": ['IA-5 (2) (d)', 'Rev_4']
  tag "check": "If the system is on the SIPRNET, this requirement is NA. Navigate to the 'deployment.properties' file for Java, the default location is /usr/java/jre/lib/deployment.properties. If the 'deployment.security.validation.crl' key is not present, this is a finding. If the 'deployment.security.validation.crl' key is present and set to 'false', this is a finding."
  tag "fix": "Enable the 'Check certificates for revocation using Certificate Revocation Lists (CRL)' option. Navigate to the 'deployment.properties' file for Java, the default location is /usr/java/jre/lib/deployment.properties Add or update the 'deployment.security.validation.crl' key. Set the value to 'true'. "

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/usr/java/jre/lib/deployment.properties') do
      its('content') { should match(/deployment.security.validation.crl=true/) }
    end
  end
end
