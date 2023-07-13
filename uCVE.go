package main

import (
	"fmt"
	"bufio"
	"os"
	"runtime"
	"flag"
	"regexp"
	"strings"
	"strconv"
	"time"
	"reflect"
	"html"
	"io"
	"io/ioutil"
	"net/http"
	"encoding/json"
	"encoding/xml"
	"archive/zip"
)

var SCRIPT_NAME = "uCVE"
var VERSION = "2.0"
var FILENAME_CPE = "official-cpe-dictionary_v2.3"
var FILENAME_LVP = "list.lvp"
var URL_GITHUB_FILENAME_LVP = "https://github.com/m3n0sd0n4ld/uCVE"
var URL_NVD_NIST_SEARCH = "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_product=cpe:/:vendor:product:version"
var OS = get_os()
var BANNER = `
         ___________    ___________
  ____  ___  ____/_ |  / /__  ____/
  _  / / /  /    __ | / /__  __/   
  / /_/ // /___  __ |/ / _  /___   
  \__,_/ \____/  _____/  /_____/ ` + string_color("blue", "v." + VERSION) + `
  
          by ` + string_color("cyan", "M3n0sD0n4ld") + ` and ` + string_color("cyan", "Siriil") + `

             `

// OTHER //

var StopSpinner = false
var channel_spinner chan struct{} = make(chan struct{})
func Spinner(delay time.Duration) {
	for !StopSpinner {
		for _, r := range `-\|/` {
			fmt.Printf("\r%c", r)
			time.Sleep(delay)
		}
	}
	fmt.Printf("\r \r")
	channel_spinner <- struct{}{}
}

func start_spinner() {
	go Spinner(200 * time.Millisecond)
	StopSpinner = false
}

func stop_spinner() {
	StopSpinner = true
	<-channel_spinner
}

func get_os() string {
	// return "linux", ...
	return string(runtime.GOOS)
}

func string_color(color string, main_string string) string {
	var return_string = main_string
	if (OS == "linux") {
		//\033
		var start_color = "\x1b[0;00m"
		var end_color = "\x1b[0;00m"
		switch (color) {
			case "red":
				start_color = "\x1b[0;31m"
			break;
			case "green":
				start_color = "\x1b[0;32m"
			break;
			case "yellow":
				start_color = "\x1b[0;33m"
			break;
			case "blue":
				start_color = "\x1b[0;34m"
			break;
			case "purple":
				start_color = "\x1b[0;35m"
			break;
			case "cyan":
				start_color = "\x1b[0;36m"
			break;
			default:
				start_color = "\x1b[0;00m"
			break;
		}
		return_string = start_color + main_string + end_color
	}
	return return_string
}

func delete(slice []string, index int) []string {
	// delete element in []string
	return append(slice[:index], slice[index+1:]...)
}

func parse_vector_access(vector string, language string) string {
	if (strings.Contains(vector, "AV:N")) {
		if (language == "es") {
			return "Red"
		} else {
			return "Network"
		}
	} else if (strings.Contains(vector, "AV:A")) {
		return "Vpn"
	} else if (strings.Contains(vector, "AV:L")) {
		return "Local"
	} else if (strings.Contains(vector, "AV:P")) {
		if (language == "es") {
			return "Físico"
		} else {
			return "Physical"
		}
	} else {
		return "N/A"
	}
}

func parse_vector_complexity(vector string, language string) string {
	if (strings.Contains(vector, "AC:H")) {
		if (language == "es") {
			return "Alta"
		} else {
			return "High"
		}
	} else if (strings.Contains(vector, "AC:M")) {
		if (language == "es") {
			return "Media"
		} else {
			return "Medium"
		}
	} else if (strings.Contains(vector, "AC:L")) {
		if (language == "es") {
			return "Baja"
		} else {
			return "Low"
		}
	} else {
		return "N/A"
	}
}

func parse_type_score(score string, language string) string {
	if s, err := strconv.ParseFloat(score, 32); err == nil {
		if (s >= 9.0) {
			if (language == "es") {
				return "Critica"
			} else {
				return "Critical"
			}
		} else if ((s >= 7.0)&&(s <= 8.9)) {
			if (language == "es") {
				return "Alta"
			} else {
				return "High"
			}
		} else if ((s >= 4.0)&&(s <= 6.9)) {
			if (language == "es") {
				return "Media"
			} else {
				return "Medium"
			}
		} else if ((s >= 0.1)&&(s <= 3.9)) {
			if (language == "es") {
				return "Baja"
			} else {
				return "Low"
			}
		} else if ((s >= 0.1)&&(s <= 3.9)) {
			if (language == "es") {
				return "Informativa"
			} else {
				return "None"
			}
		} else {
			return "N/A"
		}
	} else {
		return "N/A"
	}
}

func parse_vulnerability(vul string, language string) string {
	vul = html.UnescapeString(vul)
	if (strings.Contains(vul, "Out-of-bounds Write")) {
		if (language == "es") {
			return "Escritura fuera de limites"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Cross-site Scripting")) {
		return "XSS"
	} else if (strings.Contains(vul, "SQL Injection")) {
		return "SQLi"
	} else if (strings.Contains(vul, "Improper Input Validation")) {
		if (language == "es") {
			return "Validacion Incorrecta de Entrada"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Out-of-bounds Read")) {
		if (language == "es") {
			return "Lectura Fuera de Limites"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "OS Command Injection")) {
		if (language == "en") {
			return "OS Command Injection"
		} else if (language == "es") {
			return "Inyeccion de Comando en el SO"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Path Traversal")) {
		return "Path Traversal"
	} else if (strings.Contains(vul, "CSRF")) {
		return "CSRF"
	} else if (strings.Contains(vul, "Unrestricted Upload of File")) {
		if (language == "en") {
			return "Unrestricted Upload File"
		} else if (language == "es") {
			return "Subida de Fichero no Controlada"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "NULL Pointer Dereference")) {
		if (language == "es") {
			return "Referenciar Puntero NULL"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Deserialization of Untrusted Data")) {
		if (language == "es") {
			return "Deserializacion de Datos no Seguros"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Integer Overflow")) {
		return "Integer Overflow"
	} else if (strings.Contains(vul, "Improper Authentication")) {
		if (language == "es") {
			return "Autenticacion Incorrecta"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Hard-coded Credentials")) {
		if (language == "en") {
			return "Hard-Coded Credentials"
		} else if (language == "es") {
			return "Credenciales Codificadas"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Missing Authorization")) {
		if (language == "es") {
			return "Falta de Autorizacion"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Command Injection")) {
		if (language == "en") {
			return "Command Injection"
		} else if (language == "es") {
			return "Inyeccion de Comandos"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Bounds of a Memory Buffer")) {
		return "Buffer Overflow"
	} else if (strings.Contains(vul, "Incorrect Default Permissions")) {
		if (language == "es") {
			return "Permisos por Defecto Incorrectos"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "SSRF")) {
		return "SSRF"
	} else if (strings.Contains(vul, "Race Condition")) {
		if (language == "en") {
			return "Race Condition"
		} else if (language == "es") {
			return "Condicion de Carrera"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Uncontrolled Resource Consumption")) {
		if (language == "es") {
			return "Recurso no Controlado"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "XML External Entity")) {
		return "XXE"
	} else if (strings.Contains(vul, "Code Injection")) {
		if (language == "en") {
			return "Code Injection"
		} else if (language == "es") {
			return "Inyeccion de Codigo"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Prototype Pollution")) {
		if (language == "en") {
			return "Prototype Pollution"
		} else if (language == "es") {
			return "Contaminacion de Prototipo"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Injection")) {
		if (language == "en") {
			return "Injection"
		} else if (language == "es") {
			return "Inyeccion"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Open Redirect")) {
		return "Open Redirect"
	} else if (strings.Contains(vul, "Insufficient Information")) {
		if (language == "es") {
			return "Informacion Insuficiente"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Cleartext Storage of Sensitive Information")) {
		if (language == "es") {
			return "Informacion Sensible Almacenada en Texto Claro"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Insufficient Session Expiration")) {
		if (language == "es") {
			return "Sesion sin Expiracion"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Generation of Error Message Containing Sensitive Information")) {
		if (language == "es") {
			return "Mensaje de Error con Informacion Sensible"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Permissions, Privileges, and Access Controls")) {
		if (language == "es") {
			return "Permisos, Privilegios y Accesos de Control"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Allocation of Resources Without Limits or Throttling")) {
		if (language == "es") {
			return "Asignacion de Recursos sin Limites"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "Download of Code Without Integrity Check")) {
		if (language == "es") {
			return "Descarga de Codigo sin Control de Integridad"
		} else {
			return vul
		}
	} else if (strings.Contains(vul, "HTTP Request/Response Smuggling")) {
		return "HTTP Smuggling"
	} else if (strings.Contains(vul, "Other")) {
		if (language == "es") {
			return "Otro"
		} else {
			return vul
		}
	} else {
		return vul
	}
}

func getHtml(url string) string {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla")
	response, err := client.Do(req)
	//response, err := http.Get(url)
	if (err != nil) {
		fmt.Println("[" + string_color("red", "x") + "] Error: " + "HTTP Get CVE information on " + url)
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if (err != nil) {
		fmt.Println("[" + string_color("red", "x") + "] Error: " + "Read all response body CVE information on " + url)
	}
	return string(responseData)
}

type Cve struct {
	Vendor string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
	Id string `json:"id"`
	Vulnerability string `json:"vulnerability"`
	Datepublished string `json:"datepublished"`
	Score string `json:"score"`
	Tscore string `json:"tscore"`
	Access string `json:"access"`
	Complexity string `json:"complexity"`
}

func get_cves_by_product_version(product string, version string, cvss string, vendor string, language string) ([]Cve, string) {
	msg_error := ""
	var cves []Cve

	url_base := "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_product=cpe:/:"
	url_base = url_base + vendor + ":" + product + ":" + version

	display_matches := 0
	count_matches := 0
	index := 0
	for (display_matches <= count_matches) {
		url := url_base + "&startIndex=" + strconv.Itoa(index)
		responseString := getHtml(url)

		r_trs := regexp.MustCompile(`(?s)<tr.*?<\/tr>`)
		trs := r_trs.FindAllString(responseString, -1)
		if (len(trs) > 0) {
			trs = delete(trs, 0)
			for _, tr := range trs {
				var item Cve
				r_cve := regexp.MustCompile(`>(CVE-\d{4}-\d+)<`)
				m_cve := r_cve.FindAllStringSubmatch(tr, -1)
				if (len(m_cve) > 0) {
					item.Id = m_cve[0][1]
				} else {
					item.Id = "N/A"
				}
				r_score := regexp.MustCompile(`(?s)V3\.[01].*?>(\d{1,2}\.\d)\s*[A-Z]+<\/a>`)					
				m_score := r_score.FindAllStringSubmatch(tr, -1)
				vector := "N/A"
				if (len(m_score) > 0) {
					item.Score = m_score[0][1]
					r_vector := regexp.MustCompile(`(?s)V3\.[01].*?vector=(.*);version=3\.[01]`)					
					m_vector := r_vector.FindAllStringSubmatch(tr, -1)
					if (len(m_vector) > 0) {
						vector = m_vector[0][1]
					}
				} else {
					r_score = regexp.MustCompile(`(?s)V2\.[01].*?>(\d{1,2}\.\d)\s*[A-Z]+<\/a>`)					
					m_score = r_score.FindAllStringSubmatch(tr, -1)
					if (len(m_score) > 0) {
						item.Score = m_score[0][1]
						r_vector := regexp.MustCompile(`(?s)V2\.[01].*?vector=(.*);version=2\.[01]`)					
						m_vector := r_vector.FindAllStringSubmatch(tr, -1)
						if (len(m_vector) > 0) {
							vector = m_vector[0][1]
						}
					} else {
						item.Score = "N/A"
					}
				}
				item.Product = product
				item.Vendor = vendor
				if (vendor == "*") {
					item.Vendor = "N/A"
				}
				item.Version = version
				item.Tscore = parse_type_score(item.Score, "en")
				item.Access = parse_vector_access(vector, language)
				item.Complexity = parse_vector_complexity(vector, language)
				if (strings.Contains(cvss, strings.ToLower(item.Tscore))) {
					item.Tscore = parse_type_score(item.Score, language)
					cves = append(cves, item)
				}
			}
		}

		r2 := regexp.MustCompile(`<strong\s+data-testid="vuln-displaying-count-from">(?P<left>\d+)</strong>.*<strong\s+data-testid="vuln-displaying-count-through">(?P<right>\d+)</strong>`)
		matches2 := r2.FindStringSubmatch(responseString)
		if (len(matches2) > 0) {
			display_matches, _ = strconv.Atoi(matches2[r2.SubexpIndex("left")])
			count_matches, _ = strconv.Atoi(matches2[r2.SubexpIndex("right")])			
		}

		index = index + 20
	}

	if (len(cves)>0) {
		msg_error = ""
	}

	return cves, msg_error
}

func get_cves_info(cves []Cve, n_cves int, language string) {
	for index:=0; index<n_cves; index++ {
		// Get HTML - NVD.NIST.GOV
		url_base := "https://nvd.nist.gov/vuln/detail/"
		url := url_base + cves[index].Id
		response := getHtml(url)

		// Set Vulnerability - NVD.NIST.GOV
		var vulnerability = ""
		re_vul := regexp.MustCompile(`<td\s+data-testid="vuln-CWEs-link-0">(.*?)</td>\s*<td\s+data-testid="vuln-cwes-assigner-0">`)
		matches_vul := re_vul.FindAllStringSubmatch(response, -1)
		for _, match_vul := range matches_vul {
			vulnerability = match_vul[1] + "," + vulnerability
		}
		vulnerability = strings.TrimSuffix(vulnerability, ",")
		if (vulnerability == "") {
			vulnerability = "N/A"
		}
		cves[index].Vulnerability = parse_vulnerability(vulnerability, language)

		// Set Date Published - NVD.NIST.GOV
		var date_published = ""
		re_dp := regexp.MustCompile(`data-testid="vuln-published-on">(?P<Month>\d{2})/(?P<Day>\d{2})/(?P<Year>\d{4})<\/`)
		matches_dp := re_dp.FindStringSubmatch(response)
		if (language == "es") {
			date_published = matches_dp[re_dp.SubexpIndex("Day")] + "/" + matches_dp[re_dp.SubexpIndex("Month")] + "/" + matches_dp[re_dp.SubexpIndex("Year")]
		} else {
			date_published = matches_dp[re_dp.SubexpIndex("Month")] + "/" + matches_dp[re_dp.SubexpIndex("Day")] + "/" + matches_dp[re_dp.SubexpIndex("Year")]
		}
		cves[index].Datepublished = date_published
	}
}

type Vp struct {
	Vendor string
	Product string
}

func print_table_vp(array []Vp, operation string, product_found string) {
	index := -1
	var matches []Vp
	matches = append(matches, Vp{string_color("blue", "Vendor"), string_color("blue", "Product")})
	matches = append(matches, Vp{string_color("blue", "------"), string_color("blue", "-------")})
	irow := 0
	color_row_odd := "cyan"
	color_row_even := "purple"
	color := ""

	if (operation == "contains") {
		for _, item := range array {
			file_vendor := item.Vendor
			file_product := item.Product
			file_vendor = strings.Replace(file_vendor, " ", "_", -1)
			file_vendor = strings.ToLower(file_vendor)
			file_product = strings.Replace(file_product, " ", "_", -1)
			file_product = strings.ToLower(file_product)
			index = strings.Index(file_product, product_found)
			if (index > -1) {
				n_len := len(product_found)
				n2_len := len(file_product)
				color := ""
				if (irow % 2 == 0) {
					color = color_row_even
				} else {
					color = color_row_odd
				}
				if ((index == 0)&&(n_len == n2_len)) {
					matches = append(matches, Vp{string_color(color, file_vendor), string_color("green", file_product)})
				} else if ((index == 0)&&(n_len < n2_len)) {
					matches = append(matches, Vp{string_color(color, file_vendor), string_color("green", file_product[:n_len]) + string_color(color, file_product[(n_len):])})
				} else if (index == (len(file_product)-n_len)) {
					matches = append(matches, Vp{string_color(color, file_vendor), string_color(color, file_product[:index]) + string_color("green", file_product[index:])})
				} else {
					matches = append(matches, Vp{string_color(color, file_vendor), string_color(color, file_product[:index]) + string_color("green", file_product[index:(n_len+index)]) + string_color(color, file_product[(n_len+index):])})
				}
				irow = irow + 1
			}
		}
	} else if (operation == "literal") {
		for _, item := range array {
			if (irow % 2 == 0) {
				color = color_row_even
			} else {
				color = color_row_odd
			}
			file_vendor := item.Vendor
			file_product := item.Product
			file_vendor = strings.Replace(file_vendor, " ", "_", -1)
			file_vendor = strings.ToLower(file_vendor)
			file_product = strings.Replace(file_product, " ", "_", -1)
			file_product = strings.ToLower(file_product)
			if (file_product == product_found) {
				matches = append(matches, Vp{string_color(color, file_vendor), string_color(color, file_product)})
			}
			irow = irow + 1
		}
	} else {
		for _, item := range array {
			if (irow % 2 == 0) {
				color = color_row_even
			} else {
				color = color_row_odd
			}
			file_vendor := item.Vendor
			file_product := item.Product
			file_vendor = strings.Replace(file_vendor, " ", "_", -1)
			file_vendor = strings.ToLower(file_vendor)
			file_product = strings.Replace(file_product, " ", "_", -1)
			file_product = strings.ToLower(file_product)
			matches = append(matches, Vp{string_color(color, file_vendor), string_color(color, file_product)})
			irow = irow + 1
		}
	}

	max_vendor := 0
	for _, element := range matches {
		n_vendor := len(element.Vendor)
		if (n_vendor >= max_vendor) {
			max_vendor = n_vendor
		}
	}

	for _, item := range matches {
		n_padding := max_vendor - len(item.Vendor)
		padding := strings.Repeat(" ", n_padding)
		fmt.Println("    " + item.Vendor + padding + "  " + item.Product)
	}
	fmt.Println()
}

func print_table_cve(array []Cve, color_header string, color_row_even string, color_row_odd string) {

	val := reflect.ValueOf(&array[0]).Elem()
	max_keys := make([]int, val.NumField())

	for index, _ := range array {
		val = reflect.ValueOf(&array[index]).Elem()
		for i:=0; i<val.NumField(); i++ {
			str := fmt.Sprintf("%v", val.Field(i).Interface())
			n := len(str)
			if (n >= max_keys[i]) {
				max_keys[i] = n
			}
		}
	}

	for index2, _ := range array {
		val = reflect.ValueOf(&array[index2]).Elem()
		row := "    "
		for j:=0; j<val.NumField(); j++ {
			str := fmt.Sprintf("%v", val.Field(j).Interface())
			n_padding := max_keys[j] - len(str)
			padding := strings.Repeat(" ", n_padding)
			row = row + str + padding + "  "
		}
		if (index2 < 2) {
			fmt.Println(string_color(color_header, row))
		} else if (index2 % 2 == 0) {
			fmt.Println(string_color(color_row_even, row))
		} else {
			fmt.Println(string_color(color_row_odd, row))
		}
		
	}
	fmt.Println()
}

func check_str_in_array_str(array []string, str string) bool {
	for _, item := range array {
		if (str == item) {
			return true
		}
	}
	return false
}

func get_list_vendors_products() {
	fmt.Println("[" + string_color("green", "+") + "] " + string_color("green", "LVP") + " downloading file CPE in nvd.nist.gov (Aprox 3')")
	fmt.Println()
	start_spinner()
	// Get filename_cpe_xml_zip
	filename_cpe_xml := FILENAME_CPE + ".xml"
	filename_cpe_xml_zip := filename_cpe_xml + ".zip"
	url := "https://nvd.nist.gov/feeds/xml/cpe/dictionary/" + filename_cpe_xml_zip
	resp, err := http.Get(url)
	if (err != nil) {
		stop_spinner()
		fmt.Println("[" + string_color("red", "x") + "] Error: Get HTTP '" + string_color("red", url) + "'")
		fmt.Println()
		os.Exit(0)
	}
	defer resp.Body.Close()
	if (resp.StatusCode == 200) {
		out, err := os.Create(filename_cpe_xml_zip)
		if (err != nil) {
			stop_spinner()
			fmt.Println("[" + string_color("red", "x") + "] Error: Create file '" + string_color("red", filename_cpe_xml) + "'")
			fmt.Println()
			os.Exit(0)
		}
		defer out.Close()
		_, err = io.Copy(out, resp.Body)
		if (err != nil) {
			stop_spinner()
			fmt.Println("[" + string_color("red", "x") + "] Error: Save file '" + string_color("red", filename_cpe_xml) + "'")
			fmt.Println()
			os.Exit(0)
		}
	}
	stop_spinner()
	fmt.Println("[" + string_color("green", "+") + "] File '" + string_color("green", filename_cpe_xml_zip) + "' downloaded")
	fmt.Println()

	// Unzip filename_cpe_xml_zip
	start_spinner()
	reader, _ := zip.OpenReader(filename_cpe_xml_zip)
	defer reader.Close()
	for _, file := range reader.File {
		in, _ := file.Open()
		defer in.Close()
		out, _ := os.Create(file.Name)
		defer out.Close()
		io.Copy(out, in)
	}
	reader.Close()
	stop_spinner()

	// Process filename_cpe_xml
	fmt.Println("[" + string_color("green", "+") + "] Processing " + string_color("green", "LVP") + " list of vendors and products")
	fmt.Println()
	start_spinner()
	filename := FILENAME_LVP
	f, err3 := os.Create(filename)
	if (err3 != nil) {
		stop_spinner()
		fmt.Println("[" + string_color("red", "x") + "] Error: Create " + string_color("red", "List Vendor/Product") + " on file '" + string_color("red", FILENAME_LVP) + "'")
		start_spinner()
	}
	defer f.Close()
	// Write header
	header := "Vendor,Product"
	_, err4 := f.WriteString(header + "\n")
	if (err4 != nil) {
		stop_spinner()
		fmt.Println("[" + string_color("red", "x") + "] Error: Write header " + string_color("red", "List Vendor/Product") + " on file '" + string_color("red", "x") + "'")
		start_spinner()
	}
	// Write lines
	var list []string
	file, err5 := os.Open(filename_cpe_xml)
	if (err5 != nil) {
		stop_spinner()
		fmt.Println("[" + string_color("red", "x") + "] Error: Open file '" + string_color("red", filename_cpe_xml) + "'")
		start_spinner()
	}
	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		line := fileScanner.Text()
		r_cpe := regexp.MustCompile(`cpe:2\.[23]:[hoa]:([0-9a-z_\-]+):([0-9a-z_\-]+):`)
		m_cpe := r_cpe.FindAllStringSubmatch(line, -1)
		if (len(m_cpe) > 0) {
			file_vendor := m_cpe[0][1]
			file_product := m_cpe[0][2]
			row := file_vendor + "," + file_product
			if (!check_str_in_array_str(list, row)) {
				list = append(list, row)
				// Append row in FILENAME_LVP
				_, err6 := f.WriteString(row + "\n")
				if (err6 != nil) {
					stop_spinner()
					fmt.Println("[" + string_color("red", "x") + "] Error: Write row " + string_color("red", row) + " on file '" + string_color("red", FILENAME_LVP) + "'")
					start_spinner()
				}
			}
		}
	}
	if err7 := fileScanner.Err(); err7 != nil {
		stop_spinner()
		fmt.Println("[" + string_color("red", "x") + "] Error: Reading file '" + string_color("red", filename_cpe_xml) + "'")
		start_spinner()
	}
	file.Close()
	f.Close()
	stop_spinner()

	fmt.Println("[" + string_color("green", "+") + "] List saved in '" + string_color("green", filename) + "'")
	fmt.Println()
}

func search_products_in_lvp(product string, operation string) []Vp {
	product = strings.Replace(product, " ", "_", -1)
	product = strings.ToLower(product)

	file, err := os.Open(FILENAME_LVP)
	if (err != nil) {
		fmt.Println("[" + string_color("red", "x") + "] Error: Do not exist '" + string_color("red", FILENAME_LVP) + "' in the same executation path")
		fmt.Println()
		get_list_vendors_products()
		file, err = os.Open(FILENAME_LVP)
		if (err != nil) {
			fmt.Println("[" + string_color("red", "x") + "] Error: Delete '" + string_color("red", FILENAME_LVP) + "' and execute '" + string_color("red", SCRIPT_NAME + " -lvp") + "'")
			fmt.Println()
			os.Exit(0)	
		}
	}
	fileScanner := bufio.NewScanner(file)
	var matches []Vp
	if (operation == "contains") {
		for fileScanner.Scan() {
			file := strings.Split(fileScanner.Text(), ",")
			file_vendor := file[0]
			file_product := file[1]
			file_product = strings.Replace(file_product, " ", "_", -1)
			file_product = strings.ToLower(file_product)
			if (strings.Contains(file_product, product)) {
				matches = append(matches, Vp{file_vendor, file_product})
			}
		}
	} else if (operation == "literal") {
		for fileScanner.Scan() {
			file := strings.Split(fileScanner.Text(), ",")
			file_vendor := file[0]
			file_product := file[1]
			file_product = strings.Replace(file_product, " ", "_", -1)
			file_product = strings.ToLower(file_product)
			if (file_product == product) {
				matches = append(matches, Vp{file_vendor, file_product})
			}
		}
	} else {
		fmt.Println("[" + string_color("red", "x") + "] Error: Operation mode on search product in '" + FILENAME_LVP + "'")
		fmt.Println()
		os.Exit(0)
	}

	if err := fileScanner.Err(); err != nil {
		fmt.Println("[" + string_color("red", "x") + "] Error: Reading File " + FILENAME_LVP)
		fmt.Println()
		os.Exit(0)	
	}
	file.Close()

	return matches
}

func set_headers(language string) []Cve {
	var headers []Cve
	if (language == "es") {
		headers = append(headers, Cve{"Fabricante", "Producto", "Version", "Cve", "Vulnerabilidad", "Fecha de Publicacion", "Puntuacion", "Riesgo", "Acceso", "Complejidad"})
		headers = append(headers, Cve{"----------", "--------", "-------", "---", "--------------", "--------------------", "----------", "------", "------", "-----------"})
	} else {
		headers = append(headers, Cve{"Vendor", "Product", "Version", "Cve", "Vulnerability", "Date Published", "Score", "Risk", "Access", "Complexity"})
		headers = append(headers, Cve{"------", "-------", "-------", "---", "-------------", "--------------", "-----", "----", "------", "----------"})
	}
	return headers
}

// INPUT //

type Software struct {
	Vendor string
	Product string
	Version string
}

func check_softwares(softwares []Software) []Software {
	var array []Software
	for _, software := range softwares {
		if (software.Vendor == "*") {
			matches := search_products_in_lvp(software.Product, "literal")
			for _, match := range matches {
				array = append(array, Software{match.Vendor, software.Product, software.Version})
			}
		} else {
				array = append(array, software)		
		}
	}
	return array
}

func input_json(file string) []Software {
	var softwares []Software
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("[" + string_color("red", "x") + "] Error: Read '" + string_color("red", file) + "' File")
		fmt.Println()
		os.Exit(0)
	}
	content := string(bytes)
	r_json_format := regexp.MustCompile(`(?s){(.*?)}`)					
	m_json := r_json_format.FindAllStringSubmatch(content, -1)
	if (len(m_json) > 0) {
		data := m_json[0][1]
		data = strings.ToLower(data)
		r_softs := regexp.MustCompile(`["']([\w-_ ]+)["']\s*:\s*["']\D*((\d\.*)+)["']`)					
		m_softs := r_softs.FindAllStringSubmatch(data, -1)
		if (len(m_softs) > 0) {
			for _, slice := range m_softs {
				if (len(slice) >= 3) {
					iproduct := strings.Replace(slice[1], " ", "_", -1)
					iversion := strings.Replace(slice[2], " ", "_", -1)
					softwares = append(softwares, Software{"*", iproduct, iversion})
				}
			}
		} else {
			fmt.Println("[" + string_color("red", "x") + "] Error: Format I " + string_color("red", "JSON") + " File")
			fmt.Println()
			os.Exit(0)	
		}
	} else {
		fmt.Println("[" + string_color("red", "x") + "] Error: Format II " + string_color("red", "JSON") + " File")
		fmt.Println()
		os.Exit(0)
	}

	return softwares
}

// OUTPUT //

func output_html(cves []Cve, filename string, language string) {
	filename = strings.Replace(strings.ToLower(filename), ":", "_", -1)
	
	if (!strings.Contains(filename, ".html")) {
		filename = filename + ".html"
	}

	f, err1 := os.Create(filename)
	if (err1 != nil) {
		fmt.Println("[" + string_color("red", "x") + "] Error: Create HTML File")
	}
	defer f.Close()

	title_product := "Product"
	title_vendor := "Vendor"
	title_version := "Version"
	title_vulnerability := "Vulnerability"
	title_date_published := "Published Date"
	title_score := "Score"
	title_access := "Access"
	title_complexity := "Complexity"
	title_header_I := "uCVE Report HTML"
	title_header_II := "List of Vulnerabilities"
	if (language == "es") {
		title_product = "Producto"
		title_vendor = "Fabricante"
		title_version = "Versión"
		title_vulnerability = "Vulnerabilidad"
		title_date_published = "Fecha de Publicación"
		title_score = "Puntuación"
		title_access = "Acceso"
		title_complexity = "Complejidad"
		title_header_I = "uCVE Reporte HTML"
		title_header_II = "Listado de Vulnerabilidades"
	}

	header := `
		<!DOCTYPE html>
		<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>` + title_header_I + `</title>
				<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/meyer-reset/2.0/reset.min.css">
				<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css'>
				<link rel='stylesheet' href='https://cdn.datatables.net/1.10.16/css/dataTables.bootstrap.min.css'>
				<style type="text/css" media="screen">
					.dataTables_length,
					.dataTables_wrapper {
					  font-size: 1.6rem;
					}
					.dataTables_length select,
					.dataTables_length input,
					.dataTables_wrapper select,
					.dataTables_wrapper input {
					  background-color: #f9f9f9;
					  border: 1px solid #999;
					  border-radius: 4px;
					  height: 3rem;
					  line-height: 2;
					  font-size: 1.8rem;
					  color: #333;
					}
					.dataTables_length .dataTables_length,
					.dataTables_length .dataTables_filter,
					.dataTables_wrapper .dataTables_length,
					.dataTables_wrapper .dataTables_filter {
					  margin-top: 30px;
					  margin-right: 20px;
					  margin-bottom: 10px;
					  display: inline-flex;
					}

					.paginate_button {
					  min-width: 4rem;
					  display: inline-block;
					  text-align: center;
					  padding: 1rem 1.6rem;
					  margin-top: -1rem;
					  border: 2px solid lightblue;
					}
					.paginate_button:not(.previous) {
					  border-left: none;
					}
					.paginate_button.previous {
					  border-radius: 8px 0 0 8px;
					  min-width: 7rem;
					}
					.paginate_button.next {
					  border-radius: 0 8px 8px 0;
					  min-width: 7rem;
					}
					.paginate_button:hover {
					  cursor: pointer;
					  background-color: #eee;
					  text-decoration: none;
					}
				</style>
			</head>
			<body>
				<p><h1>` + title_header_II + `</h1></p>
				<div class="container">
					<div class="row">
						<table id="example" class="table table-striped table-bordered" cellspacing="0" width="100%">
							<thead>
								<tr>
									<th class="text-center">` + title_vendor + `</th>
									<th class="text-center">` + title_product + `</th>
									<th class="text-center">` + title_version + `</th>
									<th class="text-center">CVE</th>
									<th class="text-center">` + title_vulnerability + `</th>
									<th class="text-center">` + title_date_published + `</th>
									<th class="text-center">` + title_score + `</th>
									<th class="text-center">` + title_access + `</th>
									<th class="text-center">` + title_complexity + `</th>
								</tr>
							</thead>
							<tbody>
			`

	_, err2 := f.WriteString(header)
	if (err2 != nil) {
		fmt.Println("[" + string_color("red", "x") + "] Error: WriteString I")
	}

	for _, cve := range cves {
		row_cve := `
			<tr>
				<td style='text-align: center'>` + cve.Vendor + `</td>
				<td style='text-align: center'>` + cve.Product + `</td>
				<td style='text-align: center'>` + cve.Version + `</td>
				<td style='text-align: center'><a href="https://nvd.nist.gov/vuln/detail/` + cve.Id + `" target="_blank">`+cve.Id+`</a></td>
				<td style='text-align: center'>` + cve.Vulnerability + `</td>
				<td style='text-align: center'>` + cve.Datepublished + `</td>
				<td style='text-align: center'>` + cve.Score + `</td>
				<td style='text-align: center'>` + cve.Access + `</td>
				<td style='text-align: center'>` + cve.Complexity + `</td>
			</tr>
				`
		_, err3 := f.WriteString(row_cve)
		if (err3 != nil) {
			fmt.Println("[" + string_color("red", "x") + "] Error: WriteString II")
		}
	}

	footer := `
							</tbody>
						</table>
					</div>
				</div>
				<script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js'></script>
				<script src='https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js'></script>
				<script src='https://cdn.datatables.net/1.10.16/js/jquery.dataTables.min.js'></script>
				<script>$(document).ready(function(){$("#example").DataTable();});</script>
			</body>
		</html>
			`

	_, err4 := f.WriteString(footer)
	if (err4 != nil) {
		fmt.Println("[" + string_color("red", "x") + "] Error: WriteString III")
	}

	fmt.Println("[" + string_color("green", "+") + "] Results saved in '" + string_color("green", filename) + "'")
	fmt.Println()
}

func output_csv(cves []Cve, filename string, language string) {
	filename = strings.Replace(strings.ToLower(filename), ":", "_", -1)

	if (!strings.Contains(filename, ".csv")) {
		filename = filename + ".csv"
	}

	f, err1 := os.Create(filename)
	if (err1 != nil) {
		fmt.Println("[" + string_color("red", "x") + "] Error: Create CSV File")
	}
	defer f.Close()

	title_product := "Product"
	title_vendor := "Vendor"
	title_version := "Version"
	title_vulnerability := "Vulnerability"
	title_date_published := "Published Date"
	title_score := "Score"
	title_access := "Access"
	title_complexity := "Complexity"
	if (language == "es") {
		title_product = "Producto"
		title_vendor = "Fabricante"
		title_version = "Versión"
		title_vulnerability = "Vulnerabilidad"
		title_date_published = "Fecha de Publicación"
		title_score = "Puntuación"
		title_access = "Acceso"
		title_complexity = "Complejidad"
	}

	header := title_vendor + "," + title_product + "," + title_version + "," + "CVE"
	header = header + "," + title_vulnerability + "," + title_date_published + "," + title_score
	header = header + "," + title_access + "," + title_complexity
	_, err2 := f.WriteString(header + "\n")
	if (err2 != nil) {
		fmt.Println("[" + string_color("red", "x") + "] Error: WriteString I")
	}

	for _, cve := range cves {
		row_cve := cve.Vendor + "," + cve.Product + "," + cve.Version + "," + cve.Id
		row_cve = row_cve + "," + cve.Vulnerability + "," + cve.Datepublished + "," + cve.Score
		row_cve = row_cve + "," + cve.Access + "," + cve.Complexity
		_, err3 := f.WriteString(row_cve + "\n")
		if (err3 != nil) {
			fmt.Println("[" + string_color("red", "x") + "] Error: WriteString II")
		}
	}

	fmt.Println("[" + string_color("green", "+") + "] Results saved in '" + string_color("green", filename) + "'")
	fmt.Println()
}

func output_json(cves []Cve, filename string) {
	filename = strings.Replace(strings.ToLower(filename), ":", "_", -1)

	if (!strings.Contains(filename, ".json")) {
		filename = filename + ".json"
	}

	file, _ := json.MarshalIndent(cves, "", " ")
	_ = ioutil.WriteFile(filename, file, 0644)

	fmt.Println("[" + string_color("green", "+") + "] Results saved in '" + string_color("green", filename) + "'")
	fmt.Println()
}

func output_xml(cves []Cve, filename string) {
	filename = strings.Replace(strings.ToLower(filename), ":", "_", -1)

	if (!strings.Contains(filename, ".xml")) {
		filename = filename + ".xml"
	}

	file, _ := xml.MarshalIndent(cves, "", " ")
	_ = ioutil.WriteFile(filename, file, 0644)

	fmt.Println("[" + string_color("green", "+") + "] Results saved in '" + string_color("green", filename) + "'")
	fmt.Println()
}

// CHECK FLAG //

func check_version_show_flag(version_show bool) {
	if (version_show) {
		fmt.Println("[" + string_color("green", "+") + "] Version is " + string_color("green", "v." + VERSION))
		fmt.Println()
		os.Exit(0)
	}
}

func check_list_vendor_product_flag(list_vendor_product bool) {
	if (list_vendor_product) {
		get_list_vendors_products()
		fmt.Println()
		os.Exit(0)
	}
}

func check_search_product_literal_flag(search_product_literal string) {
	if (search_product_literal != "") {
		fmt.Println("[" + string_color("green", "+") + "] " + string_color("green", "Search literal") + " product '" + string_color("green", search_product_literal) + "' in '" + string_color("green", FILENAME_LVP) + "'")
		fmt.Println()
		matches := search_products_in_lvp(search_product_literal, "literal")
		print_table_vp(matches, "literal", search_product_literal)
		os.Exit(0)
	}
}

func check_search_product_contains_flag(search_product_contains string) {
	if (search_product_contains != "") {
		fmt.Println("[" + string_color("green", "+") + "] " + string_color("green", "Search contains") + " product '" + string_color("green", search_product_contains) + "' in '" + string_color("green", FILENAME_LVP) + "'")
		fmt.Println()
		matches := search_products_in_lvp(search_product_contains, "contains")
		print_table_vp(matches, "contains", search_product_contains)
		os.Exit(0)
	}
}

func check_cvss_product_flag(cvss_product string) string {
	cvss := strings.ToLower(cvss_product)
	if (strings.Contains(cvss, "all")) {
		cvss = "critical,high,medium,low,none"
	}
	return cvss
}

func check_product_version_vendor_flag(product string, version string, vendor string) (string, string, string) {
	product_r := product
	version_r := version
	vendor_r := vendor
	must_exit := false

	if ((product_r == "")&&(version_r == "")&&(vendor_r == "")) {
		fmt.Println("[" + string_color("red", "x") + "] Error: Parameter vendor '" + string_color("red", "-vr") + "' product '" + string_color("red", "-p") + "' and version '" + string_color("red", "-vp") + "' are required")
		fmt.Println()
		must_exit = true
	} else {
		if (vendor_r == "") {
			fmt.Println("[" + string_color("red", "x") + "] Error: Parameter vendor of product '" + string_color("red", "-vr") + "' is required")
			fmt.Println()
			must_exit = true
		}	
		if (product_r == "") {
			fmt.Println("[" + string_color("red", "x") + "] Error: Parameter product '" + string_color("red", "-p") + "' is required")
			fmt.Println()
			must_exit = true
		}
		if (version_r == "") {
			fmt.Println("[" + string_color("red", "x") + "] Error: Parameter version of product '" + string_color("red", "-vp") + "' is required")
			fmt.Println()
			must_exit = true
		}	
	}

	if (must_exit) {
		os.Exit(0)
	}

	product_r = strings.Replace(product_r, " ", "_", -1)
	version_r = strings.Replace(version_r, " ", "_", -1)
	vendor_r = strings.Replace(vendor_r, " ", "_", -1)

	product_r = strings.ToLower(product_r)
	version_r = strings.ToLower(version_r)
	vendor_r = strings.ToLower(vendor_r)

	return product_r, version_r, vendor_r
}

func check_language_flag(language string) string {
	language_r := strings.ToLower(language)

	if (language_r == "*") {
		fmt.Println("[" + string_color("yellow", "!") + "] " + string_color("yellow", "Language") + " selected is " + string_color("yellow", "English") + " (" + string_color("yellow", "en") + ") by default")
		language_r = "en"
		fmt.Println()
	} else if (language_r == "en") {
		fmt.Println("[" + string_color("green", "+") + "] " + string_color("green", "Language") + " selected is " + string_color("green", "English") + " (" + string_color("green", "en") + ")")
		fmt.Println()
	} else if (language_r == "es") {
		fmt.Println("[" + string_color("green", "+") + "] " + string_color("green", "Language") + " selected is " + string_color("green", "Spanish") + " (" + string_color("green", "es") + ")")
		fmt.Println()	
	} else {
		fmt.Println("[" + string_color("yellow", "!") + "] " + string_color("yellow", "Language") + " selected is " + string_color("yellow", "English") + " (" + string_color("yellow", "en") + ") because (" + string_color("red", language_r) + ") is not supported")
		language_r = "en"
		fmt.Println()
	}

	return language_r
}

func main() {

	flag.Usage = func() {
		fmt.Println(SCRIPT_NAME + " parameter:")
		fmt.Println()

		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("    -" + f.Name + ": " + f.Usage + "\n")
		})

		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("    " + SCRIPT_NAME + " -vr <vendor> -p <product> -vp <version_product>\n         [-cvss <all,critical,high,medium,low,none>] [-lg <en,es>] [-oSTD]\n         [-oHTML|-oCSV|-oJSON|-oXML <filename>] [-lvp] [-spc|-spl <product>]")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("    " + SCRIPT_NAME + " -vr '*' -p jquery_ui -vp 1.12.1")
		fmt.Println("    " + SCRIPT_NAME + " -vr apache -p tomcat -vp 8.5.4 -oSTD")
		fmt.Println("    " + SCRIPT_NAME + " -vr oracle -p \"database server\" -vp 11.2.0.4")
		fmt.Println("    " + SCRIPT_NAME + " -vr oracle -p sunos -vp 5.5.1 -cvss critical,high,medium -lg es -oHTML report -oCSV report")
		fmt.Println("    " + SCRIPT_NAME + " -lvp")
		fmt.Println("    " + SCRIPT_NAME + " -spc jquery")
		fmt.Println("    " + SCRIPT_NAME + " -spl jquery_ui")
		fmt.Println()
	}

	fmt.Println(BANNER)

	vendor_flag := flag.String("vr", "", "Set vendor of product software. if you can set character '*', script will search all vendor by product (required)")
	product_flag := flag.String("p", "", "Search CVEs by product software (required)")
	version_product_flag := flag.String("vp", "", "Set version of product software (required)")
	search_product_literal_flag := flag.String("spl", "", "Search product software literal match in list.lvp (it is required to save this file in the same executation path script)")
	search_product_contains_flag := flag.String("spc", "", "Search product software contains in list.lvp (it is required to save this file in the same executation path script)")
	cvss_product_flag := flag.String("cvss", "critical,high,medium,low,none", "Filter vulnerabilities by CVSS [critical,high,medium,low,none] (default is all)")
	language_flag := flag.String("lg", "*", "Set language of information [en,es] (default is English (en))")
	list_vendor_product_flag := flag.Bool("lvp", false, "Save list updated of vendors and products (file list.lvp aprox 3' processing)")
	i_json_flag := flag.String("iJSON", "*", "List products with version in JSON file ({Soft1:1.2.1, Soft2:2.1.2, Soft3: 3.0})")
	o_html_flag := flag.String("oHTML", "*", "Save CVEs list in HTML file")
	o_csv_flag := flag.String("oCSV", "*", "Save CVEs list in CSV file")
	o_json_flag := flag.String("oJSON", "*", "Save CVEs list in JSON file")
	o_xml_flag := flag.String("oXML", "*", "Save CVEs list in XML file")
	o_std_flag := flag.Bool("oSTD", false, "Save CVEs list in Std Out")
	version_show_flag := flag.Bool("v", false, "Show version")
	flag.Parse()

	check_version_show_flag(*version_show_flag)
	check_list_vendor_product_flag(*list_vendor_product_flag)
	check_search_product_literal_flag(*search_product_literal_flag)
	check_search_product_contains_flag(*search_product_contains_flag)
	*cvss_product_flag = check_cvss_product_flag(*cvss_product_flag)
	
	var softwares []Software
	if (*i_json_flag != "*") {
		fmt.Println("[" + string_color("green", "+") + "] Read " + string_color("green", "JSON") + " file '" + string_color("green", *i_json_flag) + "'")
		fmt.Println()
		softwares = input_json(*i_json_flag)
	} else {
		*product_flag, *version_product_flag, *vendor_flag = check_product_version_vendor_flag(*product_flag, *version_product_flag, *vendor_flag)
		softwares = append(softwares, Software{*vendor_flag, *product_flag, *version_product_flag})
	}
	softwares = check_softwares(softwares)

	*language_flag = check_language_flag(*language_flag)

	fmt.Println("[" + string_color("yellow", "!") + "] This could " + string_color("yellow", "take") + " a " + string_color("yellow", "few minutes") + ", please wait")
	fmt.Println()

	var cves []Cve
	error_amount_software := 0 
	for _, software := range softwares {
		start_spinner()
		cves_tmp, msg_error := get_cves_by_product_version(software.Product, software.Version, *cvss_product_flag, software.Vendor, *language_flag)
		if (msg_error != "") {
			stop_spinner()
			fmt.Println("[" + string_color("red", "x") + "] Error: Vendor " + software.Vendor + " Product " + software.Product + " Version " + software.Version + " " + msg_error)
			fmt.Println()
			start_spinner()
		}
		stop_spinner()

		n_cves_tmp := len(cves_tmp)
		if (n_cves_tmp > 0) {
			fmt.Println("[" + string_color("green", "+") + "] " + string_color("green", strconv.Itoa(n_cves_tmp) + " results") + " found for vendor " + string_color("green", software.Vendor) + " product " + string_color("green", software.Product) + " version " + string_color("green", software.Version))
			fmt.Println()
			start_spinner()
			get_cves_info(cves_tmp, n_cves_tmp, *language_flag)
			cves = append(cves, cves_tmp...)
			stop_spinner()
		} else {
			error_amount_software = error_amount_software + 1
			fmt.Println("[" + string_color("red", "x") + "] " + string_color("red", "No results") + " found for vendor " + string_color("red", software.Vendor) + " product " + string_color("red", software.Product) + " version " + string_color("red", software.Version))
			fmt.Println()
		}
	}
	if (error_amount_software > 0) {
			fmt.Println("[" + string_color("yellow", "!") + "] You can use parameters '" + string_color("yellow", "-spl") + "' and '" + string_color("yellow", "-spc") + "' to search product in '" + string_color("yellow", FILENAME_LVP) + "'")
			fmt.Println()
			fmt.Println("[" + string_color("yellow", "!") + "] You should revise parameters product, version and vendor with correct format for NIST NVD")
			fmt.Println("    " + URL_NVD_NIST_SEARCH)
			fmt.Println()
	}

	headers := set_headers(*language_flag)
	headers = append(headers, cves...)

	n_cves := len(cves)
	n_softwares := len(softwares)
	if (n_cves > 0) {
		if ((*o_html_flag == "*")&&(*o_csv_flag == "*")&&(*o_json_flag == "*")&&(*o_xml_flag == "*")&&(!*o_std_flag)) {
			print_table_cve(headers, "blue", "cyan", "purple")
			fmt.Println("[" + string_color("yellow", "!") + "] Results will be exported to " + string_color("yellow", "HTML") + " file by default")
			fmt.Println()
			filename := ""
			if (n_softwares > 1) {
				now := time.Now()
				filename = fmt.Sprintf("report_softwares_%02d-%02d-%d_%02d-%02d-%02d", now.Day(), now.Month(), now.Year(), now.Hour(), now.Minute(), now.Second())
			} else {
				filename = "report_" + *product_flag + "_" + *version_product_flag + "_" + *vendor_flag
			}
			output_html(cves, filename, *language_flag)
		} else {
			if (*o_html_flag != "*") {
				output_html(cves, *o_html_flag, *language_flag)
			}
			if (*o_csv_flag != "*") {
				output_csv(cves, *o_csv_flag, *language_flag)
			}
			if (*o_json_flag != "*") {
				output_json(cves, *o_json_flag)
			}
			if (*o_xml_flag != "*") {
				output_xml(cves, *o_xml_flag)
			}
			if (*o_std_flag) {
				print_table_cve(headers, "blue", "purple", "cyan")
			}
		}
	} else {
		if (n_softwares > 2) {
			fmt.Println("[" + string_color("red", "x") + "] " + string_color("red", "No results") + " found for any software")
			fmt.Println()
		}
	}

	os.Exit(0)
}
