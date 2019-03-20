control 'V-32902' do
  title 'A properties file must be present to hold all the keys that establish properties within the Java control panel.'
  desc  "The deployment.properties file is used for specifying keys for the Java Runtime Environment. Each option in the Java control panel is represented by property keys. These keys adjust the options in the Java control panel based on the value assigned to that key. By default no deployment.properties file exists; thus, no system-wide deployment exists. Without the deployment.properties file, setting particular options for the Java control panel is impossible. NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0080 Properties file must exist'
  tag "gid": 'V-32902'
  tag "rid": 'SV-43620r2_rule'
  tag "stig_id": 'JRE0080-UX'
  tag "cci": 'CCI-000366'
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "check": "Navigate to the lib directory: /usr/java/jre/lib/ If there is no properties file entitled 'deployment.properties', this is a finding."
  tag "fix": "Create the Java deployment properties file. Navigate to the lib directory: /usr/java/jre/lib/ Create a properties file entitled 'deployment.properties'."

  describe file('/usr/java/jre/lib/deployment.properties') do
    it { should exist }
  end
end
