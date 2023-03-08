<p align="center">
  <img width="460" height="300" src="images/logo.png">
  <br>
  <p align="center">
  <a href="https://github.com/m3n0sd0n4ld/uCVE/releases/tag/">
    <img src="https://img.shields.io/github/v/release/m3n0sd0n4ld/uCVE?include_prereleases&style=flat-square">
  </a>
  <a href="https://github.com/m3n0sd0n4ld/uCVE/issues?q=is%3Aissue+is%3Aopen">
    <img src="https://img.shields.io/github/issues/m3n0sd0n4ld/uCVE?style=flat-square">
  <a href="https://github.com/m3n0sd0n4ld/uCVE/commits/master">
    <img src="https://img.shields.io/github/last-commit/m3n0sd0n4ld/uCVE?style=flat-square">
  </a>
  <h1 align="center">uCVE - Fast CVE Reporting</h1>
  <br>
</p>
    
## Description
**uCVE** is a tool written in GO that allows to extract CVE's related to a specific software and version, obtaining a report in HTML format with the result and/or exporting it to the pentesting report.
    
## Download and install
```
git clone https://github.com/m3n0sd0n4ld/uCVE.git
cd uCVE
go build uCVE uCVE.go
```
### Download the compiled binary for Windows, Linux or MacOS
[Download the latest version](https://github.com/m3n0sd0n4ld/uCVE/releases)
    
### Error: version 'GLIBC_2.32' not found (Any Ubuntu version/Debian/Kali/Parrot OS 64bits)
```
git clone https://github.com/m3n0sd0n4ld/uCVE.git
cd uCVE
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o uCVE uCVE.go
``` 
    
## Use
### Menu
```
> uCVE -h

         ___________    ___________
  ____  ___  ____/_ |  / /__  ____/
  _  / / /  /    __ | / /__  __/   
  / /_/ // /___  __ |/ / _  /___   
  \__,_/ \____/  _____/  /_____/ v.2.0
  
          by M3n0sD0n4ld and Siriil

             
uCVE parameter:

    -cvss: Filter vulnerabilities by CVSS [critical,high,medium,low,none] (default is all)
    -iJSON: List products with version in JSON file ({Soft1:1.2.1, Soft2:2.1.2, Soft3: 3.0})
    -lg: Set language of information [en,es] (default is English (en))
    -lvp: Save list updated of vendors and products (file list.lvp aprox 3' processing)
    -oCSV: Save CVEs list in CSV file
    -oHTML: Save CVEs list in HTML file
    -oJSON: Save CVEs list in JSON file
    -oSTD: Save CVEs list in Std Out
    -oXML: Save CVEs list in XML file
    -p: Search CVEs by product software (required)
    -spc: Search product software contains in list.lvp (it is required to save this file in the same executation path script)
    -spl: Search product software literal match in list.lvp (it is required to save this file in the same executation path script)
    -v: Show version
    -vp: Set version of product software (required)
    -vr: Set vendor of product software. if you can set character '*', script will search all vendor by product (required)

Usage:
    uCVE -vr <vendor> -p <product> -vp <version_product>
         [-cvss <all,critical,high,medium,low,none>] [-lg <en,es>] [-oSTD]
         [-oHTML|-oCSV|-oJSON|-oXML <filename>] [-lvp] [-spc|-spl <product>]

Examples:
    uCVE -vr '*' -p jquery_ui -vp 1.12.1
    uCVE -vr apache -p tomcat -vp 8.5.4 -oSTD
    uCVE -vr oracle -p "database server" -vp 11.2.0.4
    uCVE -vr oracle -p sunos -vp 5.5.1 -cvss critical,high,medium -lg es -oHTML report -oCSV report
    uCVE -lvp
    uCVE -spc jquery
    uCVE -spl jquery_ui
```

### CVE's search by default (includes all types of criticality)
```
> uCVE -vr eclipse -p jetty -vp 9.3-z -lg es

         ___________    ___________
  ____  ___  ____/_ |  / /__  ____/
  _  / / /  /    __ | / /__  __/   
  / /_/ // /___  __ |/ / _  /___   
  \__,_/ \____/  _____/  /_____/ v.2.0
  
          by M3n0sD0n4ld and Siriil

             
[+] Language selected is Spanish (es)

[!] This could take a few minutes, please wait

[+] 6 results found for vendor eclipse product jetty version 9.3-z

    Fabricante  Producto  Version  Cve             Vulnerabilidad                               Fecha de Publicacion  Puntuacion  Riesgo  Acceso   Complejidad  
    ----------  --------  -------  ---             --------------                               --------------------  ----------  ------  ------   -----------  
    eclipse     jetty     9.3-z    CVE-2022-2048   Recurso no Controlado                        07/07/2022            7.5         Alta    Red      Baja         
    eclipse     jetty     9.3-z    CVE-2022-2047   Validacion Incorrecta de Entrada             07/07/2022            2.7         Baja    Red      Baja         
    eclipse     jetty     9.3-z    CVE-2021-34428  Sesion sin Expiracion                        22/06/2021            3.5         Baja    Físico  Baja         
    eclipse     jetty     9.3-z    CVE-2021-28169  Otro                                         08/06/2021            5.3         Media   Red      Baja         
    eclipse     jetty     9.3-z    CVE-2021-28165  Improper Handling of Exceptional Conditions  01/04/2021            7.5         Alta    Red      Baja         
    eclipse     jetty     9.3-z    CVE-2020-27216  Otro                                         23/10/2020            7.0         Alta    Local    Alta         

[!] Results will be exported to HTML file by default

[+] Results saved in 'report_jetty_9.3-z_eclipse.html'
```
### Search for CVE's by filtering by criticality (separated by commas and without spaces).
```
> uCVE -vr eclipse -p jetty -vp 9.3-z -lg es -cvss critical,high

         ___________    ___________
  ____  ___  ____/_ |  / /__  ____/
  _  / / /  /    __ | / /__  __/   
  / /_/ // /___  __ |/ / _  /___   
  \__,_/ \____/  _____/  /_____/ v.2.0
  
          by M3n0sD0n4ld and Siriil

             
[+] Language selected is Spanish (es)

[!] This could take a few minutes, please wait

[+] 3 results found for vendor eclipse product jetty version 9.3-z

    Fabricante  Producto  Version  Cve             Vulnerabilidad                               Fecha de Publicacion  Puntuacion  Riesgo  Acceso  Complejidad  
    ----------  --------  -------  ---             --------------                               --------------------  ----------  ------  ------  -----------  
    eclipse     jetty     9.3-z    CVE-2022-2048   Recurso no Controlado                        07/07/2022            7.5         Alta    Red     Baja         
    eclipse     jetty     9.3-z    CVE-2021-28165  Improper Handling of Exceptional Conditions  01/04/2021            7.5         Alta    Red     Baja         
    eclipse     jetty     9.3-z    CVE-2020-27216  Otro                                         23/10/2020            7.0         Alta    Local   Alta         

[!] Results will be exported to HTML file by default

[+] Results saved in 'report_jetty_9.3-z_eclipse.html'
```

### Viewing the report
uCVE allows you to sort by CVE identifier, date, vulnerability type, score... Ideal for reporting in your pentesting reports!
	  
![Screenshot](images/table-1.png)
	  
In addition, it also incorporates a search engine to filter by type of vulnerability or attack.
	  
![Screenshot](images/table-2.png)
	  
## Credits

###### Authors: 
- [Iván Santos (AKA. Siriil)](https://es.linkedin.com/in/siriil/)
- [David Utón (AKA. M3n0sd0n4ld)](https://twitter.com/David_Uton)
    
## Disclaimer and Acknowledgments
The authors of the tool are not responsible for the misuse of the tool, nor are they responsible for errors in the information obtained and shown in the report.

All information is obtained from the official resource [https://cve.mitre.org](https://cve.mitre.org).

Thanks to **MITRE** and the users who use **uCVE**.
