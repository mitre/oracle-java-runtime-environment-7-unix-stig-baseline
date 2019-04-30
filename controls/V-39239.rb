control 'V-39239' do
  title 'The version of the JRE running on the system must be the most current available.'
  desc  'The JRE is being continually updated by the vendor in order to address identified security vulnerabilities. Running an older version of the JRE can introduce security vulnerabilities to the system.'
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'JRE must be the most recent version available.'
  tag "gid": 'V-39239'
  tag "rid": 'SV-51133r1_rule'
  tag "stig_id": 'JRE0090-UX'
  tag "cci": 'CCI-002605'
  tag "nist": ['SI-2 c', 'Rev_4']
  tag "check": 'Open a terminal window and type the command; java -version sans quotes. The return value should contain Java build information; Java (TM) SE Runtime Environment (build x.x.x.x) Cross reference the build information on the system with the Oracle Java site to identify the most recent build available. http://www.oracle.com/technetwork/java/javase/downloads/index.html'

  tag "fix": 'Test applications to ensure operational compatibility with new version of Java. Install latest version of Java JRE.'
  
  java_cmd = command('java -version').stderr&.lines&.first&.strip&.split&.last
  describe 'The java version installed' do
    it "should be attribute('java_version" do
      expect(java_cmd).to(match attribute('java_version'))
    end
  end
end
