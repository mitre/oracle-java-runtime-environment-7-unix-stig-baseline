control 'V-32901' do
  title 'A configuration file must be present to deploy properties for JRE.'
  desc  "The deployment.config file is used for specifying the location and execution of system-level properties for the Java Runtime Environment. By default no deployment.config file exists; thus, no system-wide deployment.properties file exists. Without the deployment.config file, setting particular options for the Java control panel is impossible. NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0070 Configuration file must be present'
  tag "gid": 'V-32901'
  tag "rid": 'SV-43621r1_rule'
  tag "stig_id": 'JRE0070-UX'
  tag "cci": 'CCI-000366'
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "check": "Navigate to the lib directory: /usr/java/jre/lib/ If there is no configuration file entitled 'deployment.config', this is a finding. "
  tag "fix": "Create a JRE deployment configuration file. Navigate to the lib directory: /usr/java/jre/lib/ Create a configuration file entitled 'deployment.config'. "

  describe file('/usr/java/jre/lib/deployment.config') do
    it { should exist }
  end
end
