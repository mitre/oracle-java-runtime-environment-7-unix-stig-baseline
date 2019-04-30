control 'V-61037' do
  title 'Java Runtime Environment (JRE) versions that are no longer supported by the vendor for security updates must not be installed on a system.'
  desc  'Java Runtime Environment (JRE) versions that are no longer supported by Oracle for security updates are not evaluated or updated for vulnerabilities leaving them open to potential attack. Organizations must transition to a supported Java Runtime Environment (JRE) version to ensure continued support.'
  impact 0.7
  tag "severity": 'high'
  tag "gtitle": 'Unsupported Java Runtime Environment (JRE) applications'
  tag "gid": 'V-61037'
  tag "rid": 'SV-75505r2_rule'
  tag "stig_id": 'JRE9999-UX'
  tag "cci": 'CCI-002605'
  tag "nist": ['SI-2 c', 'Rev_4']
  tag "check": 'Oracle support for Java Runtime Environment (JRE) 7 for Unix ended 2015 April. If JRE 7 for Unix is installed on a system, this is a finding. If an extended support agreement providing security patches for the unsupported product is procured from the vendor, this finding may be downgraded to a CAT III.'

  tag "fix": 'Upgrade Java Runtime Environment (JRE) 7 for Unix software to a supported version.'



  java_cmd = command('java -version').stderr&.lines&.first&.strip&.split&.last
  describe 'The java version installed' do
    it "should be attribute('java_version" do
      expect(java_cmd).to(match attribute('java_version'))
    end
  end
end
