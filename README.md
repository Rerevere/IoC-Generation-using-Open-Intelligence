IOC Generation using open intelligence

This tool was created to employ the knowledge to automatically generate an indicator of compromise (IOC) based on the structure set by Mandiant and OpenIOC to be integrated into endpoint products.
The main issue for this was that creating IOC files lacked the resources allowed for sharing or creation of files. There is also a lack of a tool that will instantly generate an IOC from Open Intelligence, as IOC Bucket no longer works with Virustotal.
Many databases for "publicly" known IOCs had not been updated and this tool will introduce a method to make it more accessible. 


The tool pulls reports from both Virustotal and Hybrid-Analysis based on a sha256 hash, but only parses the information that is needed for the IOC. It then generates an IOC based on the logic set for the MD5, SHA1, and SHA256 sums.
Generation of the IOC will ask for its: name, description, and author.

In order to use the tool, three fields must be changed: 

Virustotal

params = {'apikey': '###################################################', 'resource': prov_hash}

Hybrid-Analysis

KEY_Hybrid = '##################################'
SECRET_Hybrid = '################################################'

These should be changed to your own public/private api key for use.

Other requirements can be found on the Virustotal and Hybrid-Analysis pages respectively.

https://www.virustotal.com/en/documentation/public-api/

https://www.hybrid-analysis.com/apikeys/info