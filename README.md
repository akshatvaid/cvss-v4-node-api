This is an API implementation of the CVSSv4 calculator present at https://github.com/RedHatProductSecurity/cvss-v4-calculator.git

app.js from cvss-v4-calculator/ has been rewritten to work as a NodeJS API. Other changes are also included as this implementation doesn’t have a UI version

To setup on a *nix instance:
1) Download the code in a clean directory 
1) Run "npm install"
2) Run "npm start" (app should be available on port 22177. it can be changed from app.js)


 To use the API, send a request to http://localhost<or IP>:22177/cvss?q=<vector-string>


 Example:
 [root@RHEL8 ~]# curl http://localhost:22177/cvss?q=CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L
 {"vector":"CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L","score":2.4,"severity":"Low"}
