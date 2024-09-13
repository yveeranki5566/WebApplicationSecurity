 # Web-Application-Security
 **Implementing web application security controls to make the network more robust and secure.**

 1. Configuring Firewall rules for the server.

Login into phpMyAdmin using URL http://localhost/phpmyadmin with root as username and check if the server is up and running.

![image](https://github.com/user-attachments/assets/93ff44af-1818-41ae-be50-568c08e2d2d5)

![image](https://github.com/user-attachments/assets/b2293db5-4bb4-49b1-b9c8-4e9e0ec85b20)

Now define firewall inbound rule to allow traffic on port 80. 

![image](https://github.com/user-attachments/assets/c696cf8c-77ff-4811-b9dd-86bf596c24d9)

![image](https://github.com/user-attachments/assets/40c5753e-6a0b-474e-83d7-824323e53a6e)

Next, connect to WAMP server from the Kali Linux VM.
Scan windows VM with Nmap from Kali Linux Terminal and we can see port 80 is open.

![image](https://github.com/user-attachments/assets/ff650b62-0516-4d46-bb43-167d61b79fe4)

2. Install and configure SSL for the web application server.

   Data encryption for web applications is crucial for protecting sensitive information from unauthorized access. Both data in transit and data at rest must be encrypted using TLS/SSL. TLS/SSL can be used to secure HTTP connections or data in transit. Configure the web server and application to support HTTPS.

   Let's install OpenSSL.

   ![image](https://github.com/user-attachments/assets/8c36050b-24c6-49d1-a36e-11e03acda862)

  After successful installation, open command prompt and change directory to the
  bin folder in the installed OpenSSL path. Then create a private key and certificate using 
  below commands.

  openssl genrsa -aes256 -out private.key 2048

  ![image](https://github.com/user-attachments/assets/8a806629-6361-4696-a6c5-580a259a3712)

  This command uses OpenSSL to generate the key with 256 AES standard for encryption and writes output to private.key file. It prompts for a pass phrase. 

Now regenerate key file using existing private key without pass phrase for easy usage
by executing the following command.

openssl rsa -in private.key -out private.key

Type the pass phrase which was entered during the private key creation.

Next, create a certificate using the below command.

C:\Program files\OpenSSL-Win64\bin > opessl req -new -x509 -nodes -sha1 -key private.key -out certificate.crt -days 36500

The command generates a new self-signed X.509 certificate using a SHA-1 signature and an existing private key, without requiring a passphrase ,valid for 10 years.

When prompted enter localhost for common name field.

![image](https://github.com/user-attachments/assets/85e670fc-6b73-4a93-bc23-68d1bb2846e0)

![image](https://github.com/user-attachments/assets/9a9a3184-8a42-41b8-8f31-87c90a62bf63)

Create a folder named “key” in the c:/wamp64/bin/apache/apache2.4.51/conf/ directory and move the created private.key and certificate.crt into the key folder.

Open C:\wamp64\bin\apache\apache2.4.51\conf\httpd.conf in Notepad++ and uncomment the below lines.

LoadModule ssl_module modules/mod_ssl.so
Include conf/extra/httpd-ssl.conf
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so

![image](https://github.com/user-attachments/assets/1ea47250-5fca-4fb2-a8e6-77c59c741ed1)

![image](https://github.com/user-attachments/assets/234e68f6-dbf6-41cf-a05c-50fa7631a669)

![image](https://github.com/user-attachments/assets/0ddbd862-493d-4801-9bd5-286e43ddbc06)

![image](https://github.com/user-attachments/assets/94711959-9a3f-4728-8370-bf74da0adada)

Open C:\wamp64\bin\apache\apache2.4.51\conf \extra\httpd-ssl.conf and change all the parameters to the ones shown below.

DocumentRoot "c:/wamp64/www"
ServerName localhost:443
ServerAdmin admin@example.com
ErrorLog "${SRVROOT}/logs/error.log"
TransferLog "${SRVROOT}/logs/access.log"
SSLSessionCache "shmcb:${SRVROOT}/logs/ssl_scache(512000)"
SSLCertificateFile "${SRVROOT}/conf/key/certificate.crt"
SSLCertificateKeyFile "${SRVROOT}/conf/key/private.key"
CustomLog "${SRVROOT}/logs/ssl_request.log"

![image](https://github.com/user-attachments/assets/850f2c97-cd5f-45a8-81f2-b436ea4c5f6b)

![image](https://github.com/user-attachments/assets/5bc20f99-f054-4f4c-a1c8-078a2f4c659b)

Restart the WAMP server and check if we can reach the server from your Windows VM.

Next, modify the virtual hosts file Open C:\wamp64\bin\apache\apache2.4.51\conf \extra\httpd-vhosts.conf and update virtual host.

Change the port :80 to :443 and add the following lines into the Virtual Host.

SSLEngine on
SSLCertificateFile "${SRVROOT}/conf/key/certificate.crt"
SSLCertificateKeyFile "${SRVROOT}/conf/key/private.key"

![image](https://github.com/user-attachments/assets/d03a7ce3-cca6-41d1-9246-93dfed3a423a)

Lets restart the server.

Disable the inbound firewall rule that allows traffic on the HTTP protocol and create a new inbound rule that allows HTTPS on port 443.

![image](https://github.com/user-attachments/assets/bd4ee3f7-14c5-4274-8d4d-1e09a0eb0df4)

Test access again from both the Windows and Kali VMs.

We can observe that port 80 is now closed and port 443 is open and the server can be accessed using HTTPS.

![image](https://github.com/user-attachments/assets/f9f69e38-ab8b-4b82-a327-74010f760951)

![image](https://github.com/user-attachments/assets/2b3074bf-c920-4738-b7d9-e02fef787a5d)

3. Implementing parameterized queries and Security Headers.

By configuring security headers, such as Content Security Policy (CSP), X-Content-Type-Options, and X-Frame-Options, we can significantly reduce the risk of common vulnerabilities like cross-site scripting (XSS) and clickjacking. These headers help control how the content is loaded and executed, protect against malicious data injection, and ensure that your application adheres to best practices for secure interactions. Implementing these headers strengthens the overall defense of web applications, contributing to a more resilient and secure environment.

Ensure that all input from users is validated on both client and server sides. Remove or encode special characters to prevent SQL injection, XSS, and other attacks. Using whitelist validation and pattern matching helps prevent injection attacks and other vulnerabilities by rejecting malicious inputs before they are processed or stored. Implementing parameterized queries and prepared statements further secures the application by separating data from executable code.

Create a sample web application in the Wamp server with a login page and database with a user table having login details.

Create a new folder of the sample web application in this directory C:\wamp64\bin\www.

![image](https://github.com/user-attachments/assets/046af144-2692-4a63-89d5-5c0c6a0c3d9f)

Login to phpMyAdmin and create a database and then create a table with login data.

![image](https://github.com/user-attachments/assets/db1c5eeb-dbf2-4a0b-98a6-16f65a7c8dd6)

Create a php script for the web application with parameterized queries and prepared statements which protects the application from SQL injection attacks.

The SQL query string with the placeholder (?) is sent to the database server first. This query does not change based on user input. Only the placeholder values change. The bind_param() method ensures that user input is treated as data, not code. Prepared statements with parameterized queries prevent SQL injection by separating SQL Code from data and treating inputs as data.

![image](https://github.com/user-attachments/assets/bb0fb446-5d88-420c-ab2c-72c85d024ca2)

Go to https://windows_ip/ficbank/login.php and test the application access.

![image](https://github.com/user-attachments/assets/528aff83-9590-4e9f-ad3c-328371ea4933)

Next, add CSP and X-XSS-Protection headers to the script. CSP header prevents XSS attacks by specifying which sources are allowed to load resources and X-XSS-Protection header enables the browser’s built-in XSS protection.

![image](https://github.com/user-attachments/assets/c1aa97d6-bd8b-4bd3-b361-968dffbd40e6)

Let’s test the application first by giving the right login credentials.

![image](https://github.com/user-attachments/assets/590f65a6-27b5-47ff-9b93-ea5e70cc53da)

Next, attempt an SQL Injection attack and test the application if it is vulnerable.

![image](https://github.com/user-attachments/assets/51f9bf2a-c6e3-4037-921e-af588e2e9837)

The attack was a failure.

When a malicious script was given as input, it still shows an Invalid username or password confirming that the application is secure from these attacks.

![image](https://github.com/user-attachments/assets/bc88a527-288b-4fc3-b326-e3177eee1a09)

Implementing security headers like CSP and using parameterized queries are critical in web application security as they prevent common vulnerabilities such as Cross-Site Scripting (XSS) and SQL injection by enforcing secure content policies and safely handling user inputs. Together, they significantly reduce the attack surface of web applications.

Conclusion:

This project successfully implemented and evaluated key web application security controls, adhering to industry best practices to safeguard the web application. By integrating SSL, configuring firewalls, enabling security headers, and using parameterized queries, the security posture of the application was significantly enhanced. These measures protect against common vulnerabilities such as SQL injection and cross-site scripting, ensuring that the application stays secure against potential threats.









      






















