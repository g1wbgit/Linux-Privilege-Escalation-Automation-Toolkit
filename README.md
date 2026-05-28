# Linux-Privilege-Escalation-Automation-Toolkit
A python based automated toolkit used to scan SUID/SGID binaries, Root owned Processes, Cron jobs and weak file directories, generates a report that displays the findings to be used in reviewing and mitigating misconfigurations and assessing severity of escalations of files   

# Features
The application checks:
1. OS & Kernel Info
2. Current User Info
3. Root Owned Processes
4. SUID/SGID files
5. Cron Jobs
6. Running systemmd Services
7. World-Writable Files
8. Writable Directories
9. Path Variables

# Applications
The toolkit is used solely for scanning the all the files that may be exploited to access higher privileges in a user's system. The scanner thus is used can be used for :
1. Vulnerability Assessment
2. Analyzing high-risk files
3. Identify misconfigured and vulnerable files and mitigate steps to implement fixes and patches

This project is limited to Linux based OS only

# Running
Clone the repo on a linux machine using: git clone https://github.com/g1wbgit/Linux-Privilege-Escalation-Automation-Toolkit.git
Then run following commands:
1. cd Linux-Privilege-Escalation-Automation-Toolkit
2. cd 'Linux PEAT'
3. python3 'Linux Privilege Escalation Automation Toolkit.py' 

This will initialize the script and the application will run

# Output Checks 
Output can be checked using the following command:
> mousepad privilege_escalation_report.txt

This will display the most recent scan that was chosen by user as well as a timestamp for when the report was generated on the top

# Disclaimer
This project is developed strictly for educational and authorized security auditing purposes only. Unauthorized use against systems without permission is illegal and unethical.


