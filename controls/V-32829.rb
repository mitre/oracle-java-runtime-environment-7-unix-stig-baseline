is_on_siprnet = attribute('is_on_siprnet')
control 'V-32829' do
  title 'The dialog enabling users to grant permissions to execute signed content from an un-trusted authority must be locked.'
  desc  "Java applets exist both signed and unsigned. Even for signed applets, there can be many sources, some of which may be purveyors of malware. Applet sources considered trusted can have their information populated into the browser, enabling Java to validate applets against trusted sources. Permitting execution of signed Java applets from un-trusted sources may result in malware running on the system, and risks system modification, invasion of privacy, or denial of service. Ensuring users cannot change the permission settings which control the execution of signed Java applets contributes to a more consistent security profile. NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed.  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0010 Lock out option to grant permission to untrusted'
  tag "gid": 'V-32829'
  tag "rid": 'SV-43601r2_rule'
  tag "stig_id": 'JRE0010-UX'
  tag "cci": 'CCI-001695'
  tag "nist": ['SC-18 (3)', 'Rev_4']
  tag "check": "If the system is on the SIPRNET this requirement is NA. Navigate to the 'deployment.properties' file for Java, the default location is /usr/java/jre/lib/deployment.properties Review the file. If the 'deployment.security.askgrantdialog.notinca.locked' key is not present this is a finding."

  tag "fix": "Lock the 'Allow user to grant permissions to content from an un-trusted authority' feature. Navigate to the 'deployment.properties' file for Java, the default location is /usr/java/jre/lib/deployment.properties Edit the file and add the 'deployment.security.askgrantdialog.notinca.locked' key."

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/usr/java/jre/lib/deployment.properties') do
      its('content') { should match(/deployment.security.askgrantdialog.notinca.locked/) }
    end
  end
end
