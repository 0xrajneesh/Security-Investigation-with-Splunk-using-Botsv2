# Security Investigation using Splunk SIEM Boss of the SOC (BOTS) v2 Dataset

## Introduction
In this lab, you will learn how to use Splunk SIEM for security investigations by analyzing the Boss of the SOC (BOTS) v2 dataset. The BOTS v2 dataset is a comprehensive simulation of various cybersecurity incidents, providing a realistic environment for honing your skills. Through a series of exercises, you will investigate suspicious activities, identify key indicators of compromise, and analyze data to draw meaningful conclusions.

## Prerequisites
Before starting this lab, you should have:
1. Basic understanding of cybersecurity concepts.
2. Familiarity with Splunk's interface and basic query language.
3. Access to a running instance of Splunk Enterprise.

## Lab Setup and Tools
1. **Splunk Enterprise**: Download and install Splunk Enterprise from [Splunk's official website](https://www.splunk.com/en_us/download/splunk-enterprise.html).
2. **BOTS v2 Dataset**: Download the BOTS v2 dataset from [Splunk's BOTS GitHub repository](https://github.com/splunk/botsv2).
3. **Splunk Apps**: Ensure you have the required Splunk Apps installed:
   - Splunk Add-on for Stream
   - Splunk Security Essentials

### Setting Up the Lab Environment
1. **Install Splunk Enterprise**:
   - Follow the instructions on the Splunk website to install Splunk Enterprise.
   - Start Splunk and log in with your admin credentials.

2. **Load the BOTS v2 Dataset**:
   - Download the BOTS v2 dataset and follow the instructions to import the data into your Splunk instance.

3. **Install Required Splunk Apps**:
   - Go to the Splunkbase and install the Splunk Add-on for Stream and Splunk Security Essentials.

## Exercises

### Exercise 1: Identifying the Website Domain Visited by Amber Turing
#### Objective
Identify the domain name of the website visited by Amber Turing.

#### Steps
1. **Search for Amber Turing's IP Address**:
   ```spl
   index=botsv2 earliest=0 amber
Identify the client_ip field associated with Amber Turing.

2. Analyze Web Traffic from Amber's IP:

```spl
index=botsv2 earliest=0 src_ip=identified_ip stream:http
```
Replace identified_ip with Amber's actual IP address. Examine the site values.

3. Identify the Domain Name:

Look for the domain names of rival beer companies in the site values.
Expected Output
A domain name such as rivalbeer.com.

### Exercise 2: Finding the CEO's Name
Objective
Identify the name of the CEO to whom Amber sent an email.

Steps
1. Search for Emails Sent by Amber:

```spl
Copy code
index=botsv2 earliest=0 sourcetype=stream:smtp sender=aturing@froth.ly
```
Look for emails sent to the domain identified in Exercise 1.

2. Examine Email Content:

- Open the email to find the CEO's name mentioned.

Expected Output
The CEO's name, such as John Doe.

### Exercise 3: Identifying the Email Address of Another Employee
Objective
Identify the email address of another employee contacted by Amber.

Steps
Analyze Amber's Email Traffic:

spl
Copy code
index=botsv2 earliest=0 sourcetype=stream:smtp sender=aturing@froth.ly
Look for the last email sent to the domain identified in Exercise 1.

Identify the Recipient's Email Address:

Examine the recipient field in the identified email.
Expected Output
An email address such as employee@rivalbeer.com.

Exercise 4: Identifying the File Attachment Sent by Amber
Objective
Identify the name of the file attachment sent by Amber.

Steps
Search for Emails Sent by Amber with Attachments:

spl
Copy code
index=botsv2 earliest=0 sourcetype=stream:smtp sender=aturing@froth.ly
Look for emails with attachments sent to the email address identified in Exercise 3.

Examine the Attachment Details:

Open the email and look for the file attachment name.
Expected Output
The file attachment name, such as confidential.docx.

Exercise 5: Identifying Amber's Personal Email Address
Objective
Identify Amber's personal email address used for obfuscation.

Steps
Review Emails Sent by Amber:

spl
Copy code
index=botsv2 earliest=0 sourcetype=stream:smtp sender=aturing@froth.ly
Look for base64-encoded email bodies.

Decode Base64 Content:

Decode the base64 content to reveal Amber's personal email address.
Expected Output
A personal email address such as amber.turing@gmail.com.

Exercise 6: Determining the Version of TOR Installed by Amber
Objective
Identify the version of TOR installed by Amber.

Steps
Search for TOR Installation Logs:

spl
Copy code
index=botsv2 earliest=0 amber TOR
Look for logs indicating TOR installation.

Examine Installation Details:

Identify the TOR version mentioned in the logs.
Expected Output
A version number such as 0.4.5.6.

Exercise 7: Finding the Public IPv4 Address of www.brewertalk.com
Objective
Identify the public IPv4 address of the server running www.brewertalk.com.

Steps
Analyze HTTP Traffic to www.brewertalk.com:

spl
Copy code
index=botsv2 earliest=0 stream:http www.brewertalk.com
Look for the destination IP address.

Identify the Public IPv4 Address:

Examine the destination IP address field in the HTTP traffic logs.
Expected Output
An IP address such as 192.168.1.100.

Exercise 8: Identifying the IP Address Used for a Web Vulnerability Scan
Objective
Identify the IP address used to run a web vulnerability scan against www.brewertalk.com.

Steps
Search for Web Vulnerability Scan Indicators:

spl
Copy code
index=botsv2 earliest=0 scan www.brewertalk.com
Look for scan-related events.

Identify the Source IP Address:

Examine the source IP address field in the scan events.
Expected Output
An IP address such as 192.168.1.101.

Exercise 9: Determining the URI Path Targeted by an Attack
Objective
Identify the URI path targeted by an attack from the scanning system.

Steps
Analyze HTTP Traffic from the Scanning System:

spl
Copy code
index=botsv2 earliest=0 src_ip=192.168.1.101 stream:http
Examine the different HTTP user agents and URI paths.

Identify the Targeted URI Path:

Look for the URI path associated with a different HTTP user agent indicating an attack.
Expected Output
A URI path such as /phpinfo.php.

Exercise 10: Identifying the SQL Function Abused in an Attack
Objective
Identify the SQL function being abused on the URI path targeted by an attack.

Steps
Search for SQL Injection Indicators:

spl
Copy code
index=botsv2 earliest=0 src_ip=192.168.1.101 stream:http "/phpinfo.php"
Look for SQL injection indicators in the dest_content field.

Identify the Abused SQL Function:

Examine the SQL commands used in the attack.
Expected Output
A SQL function such as UPDATE.

Exercise 11: Determining Frank Ester's Password Salt Value
Objective
Identify Frank Ester's password salt value on www.brewertalk.com.

Steps
Search for SQL Injection Traffic:

spl
Copy code
index=botsv2 earliest=0 src_ip=192.168.1.101 stream:http "XPATH syntax error"
Look for events containing SQL injection traffic.

Extract the Password Salt Value:

Use the provided regular expression to extract the salt value from the dest_content field.
Expected Output
A salt value such as tlX7cQPE.

Exercise 12: Identifying btun's Password
Objective
Identify the password for user btun on brewertalk.com.

Steps
Search for Password Hash and Salt:

spl
Copy code
index=botsv2 earliest=0 src_ip=192.168.1.101 stream:http "f91904c1dd2723d5911eeba409cc0d14"
Look for events containing the password hash and salt.

Use the Top 1000 Password List:

spl
Copy code
| inputlookup top_1000.csv
Use the list to find the matching password.

Reconstruct the Password Hash:

Use the provided hash function to reconstruct the password hash and find the matching password.
Expected Output
A password such as password123.

Exercise 13: Identifying the Cookie Value in an XSS Attack
Objective
Identify the value of the cookie transmitted by Kevin's browser in an XSS attack.

Steps
Search for XSS Indicators:

spl
Copy code
index=botsv2 earliest=0 stream:http "uri_query"
Look for XSS-related events.

Extract the Cookie Value:

Examine the uri_query field for the cookie value.
Expected Output
A numeric value such as 123456789.

Exercise 14: Identifying the Anti-CSRF Token
Objective
Identify the value of the anti-CSRF token stolen from Kevin Lagerfield's computer.

Steps
Search for Anti-CSRF Token Indicators:

spl
Copy code
index=botsv2 earliest=0 stream:http "my_post_key"
Look for events containing the anti-CSRF token.

Extract the Anti-CSRF Token:

Examine the hidden form elements for the token value.
Expected Output
An anti-CSRF token value such as abc123def456.

Exercise 15: Identifying the Maliciously Created Username
Objective
Identify the username maliciously created through a spearphishing attack.

Steps
Search for Spearphishing Indicators:

spl
Copy code
index=botsv2 earliest=0 spearphishing
Look for events related to the creation of a new user.

Identify the Malicious Username:

Examine the user creation events for a homograph attack.
Expected Output
A username such as adm1n.

Conclusion
By completing these exercises, you have practiced key skills in security investigation using Splunk SIEM and the BOTS v2 dataset. These tasks included identifying suspicious web traffic, analyzing email communications, and decoding obfuscated data. Mastery of these skills is essential for effective cybersecurity operations and incident response. Continue to explore the BOTS dataset for more challenges and enhance your proficiency with Splunk SIEM.
