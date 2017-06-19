# encoding: utf-8
# author: ApexInfra

title 'MS17-010: Security update for Windows SMB Server: March 14, 2017'

control 'ms17-010-security-update' do
  impact 1.0
  title 'Security update for Windows SMB Server'

  desc 'This security update resolves vulnerabilities in Microsoft Windows.
        The most severe of the vulnerabilities could allow remote code
        execution if an attacker sends specially crafted messages to a
        Microsoft Server Message Block 1.0 (SMBv1) server.'

  os_version = powershell('(Get-WmiObject -Class Win32_OperatingSystem).Version').strip.to_sym

  platform_hotfixes = { '10.0.15063'.to_sym => /KB4022725/, # Windows 10 (1703)
                        '10.0.14393'.to_sym => /KB4022715/, # Windows Server 2016; Windows 10 (1607)
                        '10.0.10586'.to_sym => /KB4022714/, # Windows 10 (1511)
                        '10.0.10240'.to_sym => /KB4022727/, # Windows 10
                        '6.3.9600'.to_sym => /KB4012726/, # Windows Server 2012 R2, Windows 8.1
                        '6.2.9200'.to_sym => /KB4012217/, # Windows Server 2012; Windows 8
                        '6.1.7601'.to_sym => /KB4022719/, # Windows Server 2008 R2 (SP1); Windows 7 (SP1)
                        '6.1.7600'.to_sym => //, # Windows Server 2008 R2; Windows 7
                        '6.0.6002'.to_sym => /KB4012598/, # Windows Server 2008 (SP2);	Windows Vista (SP2)
                        '6.0.6001'.to_sym => //, # Windows Server 2008 (SP1); Windows Vista (SP1)
                        '6.0.6000'.to_sym => // } # Windows Vista

  describe powershell('Get-HotFix | Select \'HotFixID\'') do
    its('stdout') { should match(platform_hotfixes[os_version]) }
  end
end

control 'smb-registry-key-check' do
  title 'SMB (version 1) is disabled'
  desc 'All Windows Shares are Configured to disable the SMB1 protocol'
  impact 1.0
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('SMB1') { should eq 0 }
  end
end
