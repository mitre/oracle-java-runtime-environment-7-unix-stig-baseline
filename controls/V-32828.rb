is_on_siprnet = attribute('is_on_siprnet')
control 'V-32828' do
  title 'The dialog to enable users to grant permissions to execute signed content from an un-trusted authority must be disabled'
  desc  "
    Java applets exist both signed and unsigned. Even for signed applets, there can be many sources, some of which may be purveyors of malware. Applet sources considered trusted can have their information populated into the browser, enabling Java to validate applets against trusted sources. Permitting execution of signed Java applets from un-trusted sources may result in acquiring malware, and risks system modification, invasion of privacy, or denial of service. NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed.
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0001 Disable ability to grant permission to untrusted authority'
  tag "gid": 'V-32828'
  tag "rid": 'SV-43596r2_rule'
  tag "stig_id": 'JRE0001-UX'
  tag "cci": 'CCI-001695'
  tag "nist": ['SC-18 (3)', 'Rev_4']
  tag "check": "If the system is on the SIPRNET, this requirement is NA.

  Examine the system 'deployment.properties' file for Java which is located by default at
  /usr/java/jre/lib/deployment.properties.

  If the 'deployment.security.askgrantdialog.notinca=false' key is not present, this is a finding.

  If the key 'deployment.security.askgrantdialog.notinca' exists and is set to true, this is a finding. "

  tag "fix": "Disable the 'Allow user to grant permissions to content from an un-trusted authority' feature.

  Navigate to the 'deployment.properties' file for Java, the default location is
  /usr/java/jre/lib/deployment.properties

  If the key does not exist, create the 'deployment.security.askgrantdialog.notinca' key and set the value to 'false'.

  If the key does exist. update the 'deployment.security.askgrantdialog.notinca' key to be a value of 'false'."

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/usr/java/jre/lib/deployment.properties') do
      its('content') { should match(/deployment.security.askgrantdialog.notinca=false/) }
    end
  end
end
