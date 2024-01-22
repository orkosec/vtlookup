# vtlookup
a web service/cmdline tool written in go to look up hashes in VirusTotal 

## put your VirusTotal API KEY to your ENV
echo 'export VIRUSTOTAL_API_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"' >> ~/.zshrc

## Usage 
Send your hashes via POST request:

go run main.go
curl -XPOST 127.0.0.1:8080/vt  -d 'hash=70102db9c85f064df588c383cb8d9b662eb8057ea6405b4d81e5c77a27e27ca8,8d3f68b16f0710f858d8c1d2c699260e6f43161a5510abb0e7ba567bd72c965b'

or via list of hashes

go run main.go -file hash.txt
