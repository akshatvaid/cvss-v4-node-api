This is the node API implementation of the CVSSv4 calculator present at https://github.com/RedHatProductSecurity/cvss-v4-calculator.git

app.js in cvss-v4-calculator/ has been rewritten to work as a NodeJS API. Other changes are also included as this implementation doenst have a UI version

get_scores.py is a py file to generate CVSSv4 vector stings and gather scores in cvss_vectors.txt (currently limited to 100 vectors for samplig)


To setup on a *nix instance:
1) Navigate to the cvss-v4-calculator/ dirctory
1) Run "npm install" 
2) Run "nohup node app.js" (app should be available on port 22177. it can be changed from app.js)


 To use the API, send a request to http://10.85.234.18:22177/cvss?q=<vector-string> 


 Example:
 [root@RHEL8 ~]# curl http://10.85.234.18:22177/cvss?q=CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L
 {"vector":"CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L","score":2.4,"severity":"Low"}
