package main

import (
	"fmt"
	"os"
	"runtime"
	"flag"
	"regexp"
	"net/http"
	"io/ioutil"
	"strings"
	"strconv"
)

var SCRIPT_NAME = "uCVE"
var VERSION = "1.0"
var OS = get_os()
var BANNER = `
	          .d8888b.  888     888 8888888888 
	         d88P  Y88b 888     888 888        
	         888    888 888     888 888        
	888  888 888        Y88b   d88P 8888888    
	888  888 888         Y88b d88P  888        
	888  888 888    888   Y88o88P   888        
	Y88b 888 Y88b  d88P    Y888P    888        
	 "Y88888  "Y8888P"      Y8P     8888888888 

	    by M3n0sD0n4ld and Siriil
			`

func get_os() string {
	// return "linux", ...
	return string(runtime.GOOS)
}

func string_color(color string, main_string string) string {
	var return_string = main_string
	if (OS == "linux") {
		var start_color = "\033[0;0m"
		var end_color="\033[0m"
		switch (color) {
			case "red":
				start_color = "\033[0;31m"
			break;
			case "green":
				start_color = "\033[0;32m"
			break;
			case "yellow":
				start_color = "\033[0;33m"
			break;
			default:
				start_color = "\033[0;0m"
			break;
		}
		return_string = start_color + main_string + end_color
	}
	return return_string
}

func remove_duplicate_str(strSlice [][]string) []string {
    allKeys := make(map[string]bool)
    list := []string{}
    for _, item := range strSlice {
        if _, value := allKeys[item[0]]; !value {
            allKeys[item[0]] = true
            list = append(list, item[0])
        }
    }
    return list
}

func append_without_duplicates(a []string, b []string) []string {
	check := make(map[string]int)
	d := append(a, b...)
	res := make([]string, 0)
	for _, val := range d {
		check[val] = 1
	}
	for letter, _ := range check {
		res = append(res, letter)
	}
	return res
}

func get_all_cves_search_html(url_base string) ([]string, string) {
	msg_error := ""
	var cves []string
	display_matches := 0
	count_matches := 0
	index := 0
	for ((display_matches==0&&count_matches==0)||(display_matches<count_matches)) {
		url := url_base + "&startIndex=" + strconv.Itoa(index)
	
		response, err := http.Get(url)
		if (err != nil) {
			msg_error = "HTTP GET List CVEs on " + url
		}
		defer response.Body.Close()
		responseData, err := ioutil.ReadAll(response.Body)
		if (err != nil) {
			msg_error = "Read all response body on " + url
		}
		responseString := string(responseData)

		r := regexp.MustCompile(`CVE-\d{4}-\d+`)
		matches := r.FindAllStringSubmatch(responseString, -1)
		cves_tmp := remove_duplicate_str(matches)
		cves = append_without_duplicates(cves, cves_tmp)

		r2 := regexp.MustCompile(`<strong\s+data-testid="vuln-displaying-count-from">(?P<left>\d+)</strong>.*<strong\s+data-testid="vuln-displaying-count-through">(?P<right>\d+)</strong>`)
		matches2 := r2.FindStringSubmatch(responseString)
		display_matches, _ = strconv.Atoi(matches2[r2.SubexpIndex("left")])
		count_matches, _ = strconv.Atoi(matches2[r2.SubexpIndex("right")])

		index = index + 20
	}

	return cves, msg_error
}

func get_cves_by_product_version(product string, version string, cvss string) ([]string, string) {
	msg_error := ""
	var cves []string
	cvss_upper := strings.ToUpper(cvss)

	url_base := "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_product=cpe:/:*:"
	url := url_base + product + ":" + version

	if ((strings.Contains(cvss_upper, "CRITICAL"))&&(strings.Contains(cvss_upper, "HIGH"))&&(strings.Contains(cvss_upper, "MEDIUM"))&&(strings.Contains(cvss_upper, "LOW"))&&(strings.Contains(cvss_upper, "NONE"))) {
		cvss_upper = "ALL"
	}

	if (cvss_upper == "ALL") {
		cves, msg_error = get_all_cves_search_html(url)
	} else {
		var cves_tmp []string
		if (strings.Contains(cvss_upper, "CRITICAL")) {
			url_cvss3_critical := url + "&cvss_version=3&cvss_v3_severity=CRITICAL"
			cves_tmp, msg_error = get_all_cves_search_html(url_cvss3_critical)
			cves = append_without_duplicates(cves, cves_tmp)
		}
		if (strings.Contains(cvss_upper, "HIGH")) {
			url_cvss3_high := url + "&cvss_version=3&cvss_v3_severity=HIGH"
			cves_tmp, msg_error = get_all_cves_search_html(url_cvss3_high)
			cves = append_without_duplicates(cves, cves_tmp)
			url_cvss2_high := url + "&cvss_version=2&cvss_v2_severity=HIGH"
			cves_tmp, msg_error = get_all_cves_search_html(url_cvss2_high)
			cves = append_without_duplicates(cves, cves_tmp)
		}
		if (strings.Contains(cvss_upper, "MEDIUM")) {
			url_cvss3_medium := url + "&cvss_version=3&cvss_v3_severity=MEDIUM"
			cves_tmp, msg_error = get_all_cves_search_html(url_cvss3_medium)
			cves = append_without_duplicates(cves, cves_tmp)
			url_cvss2_medium := url + "&cvss_version=2&cvss_v2_severity=MEDIUM"
			cves_tmp, msg_error = get_all_cves_search_html(url_cvss2_medium)
			cves = append_without_duplicates(cves, cves_tmp)
		}
		if (strings.Contains(cvss_upper, "LOW")) {
			url_cvss3_low := url + "&cvss_version=3&cvss_v3_severity=LOW"
			cves_tmp, msg_error = get_all_cves_search_html(url_cvss3_low)
			cves = append_without_duplicates(cves, cves_tmp)
			url_cvss2_low := url + "&cvss_version=2&cvss_v2_severity=LOW"
			cves_tmp, msg_error = get_all_cves_search_html(url_cvss2_low)
			cves = append_without_duplicates(cves, cves_tmp)
		}
		if (strings.Contains(cvss_upper, "NONE")) {
			url_cvss3_none := url + "&cvss_version=3&cvss_v3_severity=NONE"
			cves_tmp, msg_error = get_all_cves_search_html(url_cvss3_none)
			cves = append_without_duplicates(cves, cves_tmp)
		}
	}

	if (len(cves)>0) {
		msg_error = ""
	}

	return cves, msg_error
}

func getHtml(url string) string {
	response, err := http.Get(url)
	if (err != nil) {
		fmt.Println(string_color("red", "[x] Error: " + "HTTP Get CVE information on " + url))
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if (err != nil) {
		fmt.Println(string_color("red", "[x] Error: " + "Read all response body CVE information on " + url))
	}
	return string(responseData)
}

func parse_vector_acceso(vector string) string {
	if ((vector == "NETWORK")||(vector == "N")) {
		return "Network"
	} else if ((vector == "LOCAL")||(vector == "L")) {
		return "Local"
	} else if ((vector == "ADJACENT NETWORK")||(vector == "A")) {
		return "Vpn"
	} else if ((vector == "PHYSICAL")||(vector == "P")) {
		return "Physical"
	} else {
		return "N/A"
	}
}

func parse_complexity_complejidad(complexity string) string {
	if ((complexity == "HIGH")||(complexity == "H")) {
		return "High"
	} else if ((complexity == "MEDIUM")||(complexity == "M")) {
		return "Medium"
	} else if ((complexity == "LOW")||(complexity == "L")) {
		return "Low"
	} else {
		return "N/A"
	}
}

func get_cve_info(cve string) (string, string, string, string, string) {
    // Get HTML - NVD.NIST.GOV
    url_base := "https://nvd.nist.gov/vuln/detail/"
    url := url_base + cve
    response := getHtml(url)

	var vulnerability = ""
	var date_published = ""
	var score = ""
	var vector = ""
	var complexity = ""

	// Set Vulnerability - NVD.NIST.GOV
	re_vul := regexp.MustCompile(`<td\s+data-testid="vuln-CWEs-link-0">(.*?)</td>\s*<td\s+data-testid="vuln-cwes-assigner-0">`)
	matches_vul := re_vul.FindAllStringSubmatch(response, -1)
	for _, match_vul := range matches_vul {
		vulnerability = match_vul[1] + "," + vulnerability
	}
	vulnerability = strings.TrimSuffix(vulnerability, ",")
	if (vulnerability == "") {
		vulnerability = "N/A"
	}

	// Set Date Published - NVD.NIST.GOV
	re_dp := regexp.MustCompile(`data-testid="vuln-published-on">(?P<Month>\d{2})/(?P<Day>\d{2})/(?P<Year>\d{4})<\/`)
	matches_dp := re_dp.FindStringSubmatch(response)
	date_published = matches_dp[re_dp.SubexpIndex("Day")] + "/" + matches_dp[re_dp.SubexpIndex("Month")] + "/" + matches_dp[re_dp.SubexpIndex("Year")]

	// Set Score - NVD.NIST.GOV
	re_scov3 := regexp.MustCompile(`data-testid="vuln-cvss3-panel-score"\s*class=".*">(?P<cvss3>\d{1,2}\.\d{1,2}) \w+</a>`)
	matches_scov3 := re_scov3.FindStringSubmatch(response)
	if (len(matches_scov3) > 0) {
		score = matches_scov3[re_scov3.SubexpIndex("cvss3")]
	} else {
		re_scov2 := regexp.MustCompile(`id="Cvss2CalculatorAnchor"\s*href=".*".*>(?P<cvss2>\d{1,2}\.\d{1,2}) \w+</a>`)
		matches_scov2 := re_scov2.FindStringSubmatch(response)
		if (len(matches_scov2) > 0) {
			score = matches_scov2[re_scov2.SubexpIndex("cvss2")]
		} else {
			score = "N/A"
		}
	}

	// Set Vector and Complexity - NVD.NIST.GOV
	re_vec := regexp.MustCompile(`CVSS:3\.\d/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]`)
	matches_vec := re_vec.FindStringSubmatch(response)
	if (len(matches_vec) > 0) {
		vector = parse_vector_acceso(matches_vec[re_vec.SubexpIndex("AV")])
		complexity = parse_complexity_complejidad(matches_vec[re_vec.SubexpIndex("AC")])
	} else {
		re_vec = regexp.MustCompile(`\(AV:(?P<AV>[LAN])/AC:(?P<AC>[HML])/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]\)`)
		matches_vec = re_vec.FindStringSubmatch(response)
		if (len(matches_vec) > 0) {
			vector = parse_vector_acceso(matches_vec[re_vec.SubexpIndex("AV")])
			complexity = parse_complexity_complejidad(matches_vec[re_vec.SubexpIndex("AC")])
		} else {
			vector = "N/A"
			complexity = "N/A"
		}
	}

	return vulnerability, date_published, score, vector, complexity
}

func main() {

	flag.Usage = func() {
		fmt.Println(SCRIPT_NAME+" parameter:")
		fmt.Println()

		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("    -"+f.Name+": "+f.Usage+"\n")
		})

		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("    "+SCRIPT_NAME+" -p <product> -vp <version_product> [-cvss (all,critical,high,medium,low,none)]")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("    "+SCRIPT_NAME+" -p jquery -vp 1.2.1")
		fmt.Println("    "+SCRIPT_NAME+" -p sunos -vp 5.5.1 -cvss critical,high,medium")
		fmt.Println()
	}

	fmt.Println()
	fmt.Println(BANNER)
	fmt.Println()

	product_flag := flag.String("p", "", "Search CVEs by product software (required)")
	version_product_flag := flag.String("vp", "", "Set version on product software (required)")
	cvss_product_flag := flag.String("cvss", "all", "Filter vulnerabilities by CVSS [all,critical,high,medium,low,none] (default is all)")
	version_show_flag := flag.Bool("v", false, "Show version")
	flag.Parse()

	if (*version_show_flag) {
		fmt.Println(string_color("green", "[+] Version is " + VERSION))
		fmt.Println()
		os.Exit(0)
	}

	if ((*product_flag == "")&&(*version_product_flag == "")) {
		fmt.Println(string_color("red", "[x] Error: Parameter product '-p' and version of product '-vp' are required"))
		fmt.Println()
		os.Exit(0)	
	} else {
		if (*product_flag == "") {
			fmt.Println(string_color("red", "[x] Error: Parameter product '-p' is required"))
			fmt.Println()
			os.Exit(0)
		}
		if (*version_product_flag == "") {
			fmt.Println(string_color("red", "[x] Error: Parameter version of product '-vp' is required"))
			fmt.Println()
			os.Exit(0)
		}
	}

	fmt.Println(string_color("yellow", "[!] This could take a few minutes, please wait..."))
	fmt.Println()

	cves, msg_error := get_cves_by_product_version(*product_flag, *version_product_flag, *cvss_product_flag)
	if (msg_error != "") {
		fmt.Println(string_color("red", "[x] Error: " + msg_error))
		fmt.Println()
	}

	n_cves := len(cves)
	if (n_cves>0) {
		fmt.Println(string_color("green", "[+] Results " + strconv.Itoa(n_cves) + " found, then processing"))
		fmt.Println()

		f, err1 := os.Create(*product_flag+"_"+*version_product_flag+".html")
		if (err1 != nil) {
			fmt.Println(string_color("red", "[x] Error: "))
		}
		defer f.Close()

		header := `
			<!DOCTYPE html>
			<html lang="en">
				<head>
					<meta charset="UTF-8">
					<title>uCVE - `+*product_flag+" "+*version_product_flag+`</title>
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
					<p><h1>List of vulnerabilities: <b>`+*product_flag+" "+*version_product_flag+`</b></h1></p>
					<div class="container">
						<div class="row">
							<table id="example" class="table table-striped table-bordered" cellspacing="0" width="100%">
								<thead>
									<tr>
										<th class="text-center">CVE</th>
										<th class="text-center">Vulnerability</th>
										<th class="text-center">Published Date</th>
										<th class="text-center">Score</th>
										<th class="text-center">Access</th>
										<th class="text-center">Complexity</th>
									</tr>
								</thead>
								<tbody>
				`
		_, err2 := f.WriteString(header)
		if (err2 != nil) {
			fmt.Println(string_color("red", "[x] Error: WriteString"))
		}

		for _, cve := range cves {
			vulnerability, date_published, score, vector, complexity := get_cve_info(cve)
			row_cve := `
				<tr>
					<td style='text-align: center'><a href="https://nvd.nist.gov/vuln/detail/`+cve+`" target="_blank">`+cve+`</a></td>
					<td style='text-align: center'>`+vulnerability+`</td>
					<td style='text-align: center'>`+date_published+`</td>
					<td style='text-align: center'>`+score+`</td>
					<td style='text-align: center'>`+vector+`</td>
					<td style='text-align: center'>`+complexity+`</td>
				</tr>
					`
			_, err3 := f.WriteString(row_cve)
			if (err3 != nil) {
				fmt.Println(string_color("red", "[x] Error: WriteString"))
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
			fmt.Println(string_color("red", "[x] Error: WriteString"))
		}

		fmt.Println(string_color("green", "[+] Results saved in '" + *product_flag+"_"+*version_product_flag+".html'"))
		fmt.Println()

	} else {
		fmt.Println(string_color("red", "[x] No results found"))
		fmt.Println()
	}

	os.Exit(0)
}