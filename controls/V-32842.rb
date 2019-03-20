control 'V-32842' do
  title 'The configuration file must contain proper keys and values to deploy settings correctly.'
  desc  "This configuration file must hold values of the location of the deployment.properties file as well as the enforcement of these properties. Without a proper path for the properties file, deployment would not be possible. If the path specified does not lead to a properties file the value of the 'deployment.system.config. mandatory' key determines how to handle the situation. If the value of this key is true, JRE will not run if the path to the properties file is invalid. NOTE: The 'JRE' directory in the file path may reflect the specific JRE release installed."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE0060 The deployment.config file must be properly configured'
  tag "gid": 'V-32842'
  tag "rid": 'SV-43649r1_rule'
  tag "stig_id": 'JRE0060-UX'
  tag "cci": 'CCI-000366'
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "check": "Navigate to the deployment.config file. /usr/java/jre/lib/deployment.config If the configuration file does not contain 'deployment.system.config=file:/usr/java/jre/lib/deployment.properties', this is a finding. If the configuration file does not contain 'deployment.system.config.mandatory=false', this is a finding."
  tag "fix": "Specify the path to the deployment.properties file and set the mandatory configuration values. Navigate to the deployment.config file. /usr/java/jre/lib/deployment.properties Include the following keys in the configuration file: 'deployment.system.config=file:/usr/java/jre/lib/deployment.properties' 'deployment.system.config.mandatory=false'."

  describe file('/usr/java/jre/lib/deployment.config') do
    its('content') { should match(%r{deployment.system.config=file:/usr/java/jre/lib/deployment.properties}) }
  end
  describe file('/usr/java/jre/lib/deployment.config') do
    its('content') { should match(/deployment.system.config.mandatory=false/) }
  end
end
