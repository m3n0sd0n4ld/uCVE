package main

import (
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "html/template"
    "io"
    "net/http"
    "net/url"
    "os"
    "runtime"
    "strconv"
    "strings"
    "time"
    "unicode/utf8"
)

const (
    Reset       = "\033[0m"
    Cyan        = "\033[36m"
    Magenta     = "\033[35m"
    Green       = "\033[32m"
    Orange      = "\033[33m"
    Red         = "\033[31m"
    BrightRed   = "\033[91m"
    Bold        = "\033[1m"
    BrightWhite = "\033[97m"
)

var useColors = runtime.GOOS != "windows"

const bannerColored = `
         ___________    ___________
  ____  ___  ____/_ |  / /__  ____/
  _  / / /  /    __ | / /__  __/   
  / /_/ // /___  __ |/ / _  /___   
  \__,_/ \____/  _____/  /_____/ ` + Red + `v.3.0` + Reset + `

          by` + Bold + Orange + ` M3n0sD0n4ld ` + Reset + `and` + Bold + Orange + ` Siriil ` + Reset + `
`

const bannerPlain = `
         ___________    ___________
  ____  ___  ____/_ |  / /__  ____/
  _  / / /  /    __ | / /__  __/   
  / /_/ // /___  __ |/ / _  /___   
  \__,_/ \____/  _____/  /_____/ v.3.0

          by M3n0sD0n4ld and Siriil
`

type VulnerabilityItem struct {
    CVE struct {
        ID           string `json:"id"`
        Published    string `json:"published"`
        Descriptions []struct {
            Lang  string `json:"lang"`
            Value string `json:"value"`
        } `json:"descriptions"`
        Metrics struct {
            CvssMetricV40 []struct {
                Source   string `json:"source"`
                Type     string `json:"type"`
                CvssData struct {
                    BaseScore        float64 `json:"baseScore"`
                    BaseSeverity     string  `json:"baseSeverity"`
                    AttackVector     string  `json:"attackVector"`
                    AttackComplexity string  `json:"attackComplexity"`
                } `json:"cvssData"`
            } `json:"cvssMetricV40"`
            CvssMetricV31 []struct {
                Source   string `json:"source"`
                Type     string `json:"type"`
                CvssData struct {
                    BaseScore        float64 `json:"baseScore"`
                    BaseSeverity     string  `json:"baseSeverity"`
                    AttackVector     string  `json:"attackVector"`
                    AttackComplexity string  `json:"attackComplexity"`
                } `json:"cvssData"`
            } `json:"cvssMetricV31"`
            CvssMetricV2 []struct {
                CvssData struct {
                    BaseScore        float64 `json:"baseScore"`
                    AccessVector     string  `json:"accessVector"`
                    AccessComplexity string  `json:"accessComplexity"`
                } `json:"cvssData"`
                BaseSeverity string `json:"baseSeverity"`
            } `json:"cvssMetricV2"`
        } `json:"metrics"`
        Weaknesses []struct {
            Description []struct {
                Lang  string `json:"lang"`
                Value string `json:"value"`
            } `json:"description"`
        } `json:"weaknesses"`
        Configurations []struct {
            Nodes []struct {
                CpeMatch []struct {
                    Vulnerable          bool   `json:"vulnerable"`
                    Criteria            string `json:"criteria"`
                    VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
                    VersionEndIncluding string `json:"versionEndIncluding,omitempty"`
                    MatchCriteriaId     string `json:"matchCriteriaId"`
                } `json:"cpeMatch"`
            } `json:"nodes"`
        } `json:"configurations"`
    } `json:"cve"`
}

type NVDSearchResponse struct {
    Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type vulnDisplay struct {
    Vuln               VulnerabilityItem
    VendorRaw          string
    ProductRaw         string
    Vendor             string
    Product            string
    Version            string
    CVE                string
    Published          string
    VulnerabilityTitle string
    Score              string
    RiskText           string
    RiskClass          string
    Access             string
    Complexity         string
}

type HTMLData struct {
    Title         string
    Version       string
    Lang          string
    GeneratedDate string
    Vulns         []vulnDisplay
}

func showHelp() {
    fmt.Println()
    fmt.Println(`Use: uCVE -s <product> -vp <version> [-lg <en|es>] [-r <risks>] [-e <vendors>] [-i <vendors>] [-o <filename.txt>] [-oHTML <filename.html>] [-oJSON <filename.json>] [-oCSV <filename.csv>] [-x <host:port>]

Parameters:
  -s          Product to search for (example: crushftp, jquery)
  -vp         Product version (required, example: 10.8.4)
  -lg         Language (en or es), optional, default "en"
  -r          Risk levels to filter (comma-separated, example: critical,high)
  -e          Vendors to exclude (comma-separated, example: Dennis Bruecke,Jqueryui)
  -i          Vendors to include (comma-separated, example: jquery,jqueryui)
  -o          Name of the text file to save the console output (optional)
  -oHTML      Output HTML file name (optional)
  -oJSON      Output JSON file name (optional)
  -oCSV       Output CSV file name (optional)
  -x          HTTP proxy (host:port format) (optional)
  -h          Show help`)
}

func compareVersions(v1, v2 string) int {
    v1 = strings.TrimPrefix(v1, "v")
    v2 = strings.TrimPrefix(v2, "v")
    v1Parts := strings.Split(v1, ".")
    v2Parts := strings.Split(v2, ".")
    maxLen := len(v1Parts)
    if len(v2Parts) < maxLen {
        maxLen = len(v2Parts)
    }
    for i := 0; i < maxLen; i++ {
        n1, err1 := strconv.Atoi(strings.TrimSpace(v1Parts[i]))
        n2, err2 := strconv.Atoi(strings.TrimSpace(v2Parts[i]))
        if err1 != nil || err2 != nil {
            return strings.Compare(v1Parts[i], v2Parts[i])
        }
        if n1 < n2 {
            return -1
        } else if n1 > n2 {
            return 1
        }
    }
    if len(v1Parts) < len(v2Parts) {
        return -1
    } else if len(v1Parts) > len(v2Parts) {
        return 1
    }
    return 0
}

func normalizeName(name string) string {
    if name == "" || name == "unknown" {
        return name
    }
    name = strings.ReplaceAll(name, "_", " ")
    words := strings.Split(name, " ")
    for i, word := range words {
        if len(word) > 0 {
            words[i] = strings.Title(strings.ToLower(word))
        }
    }
    return strings.Join(words, " ")
}

func extractCPEInfo(cpe string) (vendor, product string) {
    parts := strings.Split(cpe, ":")
    if len(parts) >= 5 {
        vendor = parts[3]
        product = parts[4]
    } else {
        vendor = "unknown"
        product = "unknown"
    }
    return
}

func formatDate(d string) string {
    t, err := time.Parse("2006-01-02", d)
    if err != nil {
        return d
    }
    return t.Format("02/01/2006")
}

func truncateString(str string, maxLen int) string {
    if utf8.RuneCountInString(str) > maxLen {
        runes := []rune(str)
        return string(runes[:maxLen-3]) + "..."
    }
    return str
}

func generateHTMLTable(filename, product, version, lang string, data []vulnDisplay) {
    htmlTemplate := `
<!DOCTYPE html>
<html lang="{{.Lang}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{if eq .Lang "es"}}Informe de Vulnerabilidades para {{.Title}}{{else}}Vulnerability Report for {{.Title}}{{end}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol'; margin: 20px; background-color: #f4f4f9; color: #333; }
        h1 { color: #2c3e50; text-align: center; }
        .info { text-align: center; margin-bottom: 20px; font-style: italic; color: #555; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); background-color: #fff; }
        th, td { padding: 12px 15px; border: 1px solid #ddd; vertical-align: top; }
        thead th { background-color: #34495e; color: #fff; font-weight: bold; cursor: pointer; position: relative; text-align: left; }
        thead th:hover { background-color: #446889; }
        tbody tr td { text-align: center; } 
        .sort-icons { float: right; margin-left: 5px; display: flex; flex-direction: column; }
        .sort-icon { line-height: 0.8; font-size: 0.8em; opacity: 0.3; }
        th.sorted-asc .sort-asc { opacity: 1; color: #f1c40f; }
        th.sorted-desc .sort-desc { opacity: 1; color: #f1c40f; }
        .filter-row td { padding: 5px 15px; border: 1px solid #ddd; background-color: #f0f0f0; }
        .filter-row input { width: 100%; box-sizing: border-box; padding: 5px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px; }
        tbody tr:nth-child(even) { background-color: #f9f9f9; }
        tbody tr:hover { background-color: #f1f1f1; }
        .score, .risk, .access, .complexity { text-align: center; white-space: nowrap; }
        .cve { min-width: 140px; white-space: nowrap; }
        .risk.LOW { color: #27ae60; font-weight: bold; }
        .risk.MEDIUM { color: #f39c12; font-weight: bold; }
        .risk.HIGH { color: #e74c3c; font-weight: bold; }
        .risk.CRITICAL { color: #c0392b; font-weight: bold; }
        footer { text-align: center; margin-top: 40px; font-size: 0.9em; color: #888; }
    </style>
</head>
<body>
    <h1>{{if eq .Lang "es"}}Informe de Vulnerabilidades{{else}}Vulnerability Report{{end}}</h1>
    <p class="info">{{if eq .Lang "es"}}Resultados para el producto <strong>{{.Title}}</strong> (versión: {{.Version}}) - Generado el {{.GeneratedDate}}{{else}}Results for product <strong>{{.Title}}</strong> (version: {{.Version}}) - Generated on {{.GeneratedDate}}{{end}}</p>
    
    <table id="vulnerability-table">
        <thead>
            <tr>
                <th onclick="sortTable(0)">{{if eq .Lang "es"}}Fabricante{{else}}Vendor{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th onclick="sortTable(1)">{{if eq .Lang "es"}}Producto{{else}}Product{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th onclick="sortTable(2)">{{if eq .Lang "es"}}Versión{{else}}Version{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th class="cve" onclick="sortTable(3)">CVE <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th onclick="sortTable(4)">{{if eq .Lang "es"}}Vulnerabilidad{{else}}Vulnerability{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th onclick="sortTable(5)">{{if eq .Lang "es"}}Fecha Publicación{{else}}Published Date{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th class="score" onclick="sortTable(6)">{{if eq .Lang "es"}}Puntuación{{else}}Score{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th class="risk" onclick="sortTable(7)">{{if eq .Lang "es"}}Riesgo{{else}}Risk{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th class="access" onclick="sortTable(8)">{{if eq .Lang "es"}}Acceso{{else}}Access{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
                <th class="complexity" onclick="sortTable(9)">{{if eq .Lang "es"}}Complejidad{{else}}Complexity{{end}} <span class="sort-icons"><span class="sort-icon sort-asc">▲</span><span class="sort-icon sort-desc">▼</span></span></th>
            </tr>
            <tr class="filter-row">
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por fabricante...{{else}}Filter by vendor...{{end}}" data-column="0"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por producto...{{else}}Filter by product...{{end}}" data-column="1"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por versión...{{else}}Filter by version...{{end}}" data-column="2"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por CVE...{{else}}Filter by CVE...{{end}}" data-column="3"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por vulnerabilidad...{{else}}Filter by vulnerability...{{end}}" data-column="4"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por fecha...{{else}}Filter by date...{{end}}" data-column="5"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por puntuación...{{else}}Filter by score...{{end}}" data-column="6"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por riesgo...{{else}}Filter by risk...{{end}}" data-column="7"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por acceso...{{else}}Filter by access...{{end}}" data-column="8"></td>
                <td><input type="text" onkeyup="filterTable()" placeholder="{{if eq .Lang "es"}}Filtrar por complejidad...{{else}}Filter by complexity...{{end}}" data-column="9"></td>
            </tr>
        </thead>
        <tbody>
            {{range .Vulns}}
            <tr>
                <td>{{.Vendor}}</td>
                <td>{{.Product}}</td>
                <td>{{.Version}}</td>
                <td class="cve"><a href="https://nvd.nist.gov/vuln/detail/{{.CVE}}" target="_blank">{{.CVE}}</a></td>
                <td>{{.VulnerabilityTitle}}</td>
                <td>{{.Published}}</td>
                <td class="score">{{.Score}}</td>
                <td class="risk {{.RiskClass}}">{{.RiskText}}</td>
                <td class="access">{{.Access}}</td>
                <td class="complexity">{{.Complexity}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>

    <script>
        let currentSortColumn = -1;
        let isAscending = true;

        function filterTable() {
            const filters = Array.from(document.querySelectorAll('.filter-row input')).map(input => input.value.toLowerCase());
            const table = document.getElementById('vulnerability-table');
            const tr = table.getElementsByTagName('tr');

            for (let i = 2; i < tr.length; i++) { 
                let displayRow = true;
                for (let j = 0; j < filters.length; j++) {
                    const cell = tr[i].cells[j];
                    if (cell) {
                        const cellText = cell.textContent.toLowerCase();
                        if (filters[j] && !cellText.includes(filters[j])) {
                            displayRow = false;
                            break;
                        }
                    }
                }
                tr[i].style.display = displayRow ? "" : "none";
            }
        }

        function sortTable(column) {
            const table = document.getElementById('vulnerability-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const headers = table.querySelectorAll('th');

            if (currentSortColumn === column) {
                isAscending = !isAscending;
            } else {
                currentSortColumn = column;
                isAscending = true;
            }

            headers.forEach(header => {
                header.classList.remove('sorted-asc', 'sorted-desc');
            });
            
            const currentHeader = headers[column];
            currentHeader.classList.add(isAscending ? 'sorted-asc' : 'sorted-desc');

            rows.sort((a, b) => {
                const aText = a.cells[column].textContent.trim();
                const bText = b.cells[column].textContent.trim();
                let comparison = 0;

                if (column === 5) { 
                    const aDate = aText.split('/').reverse().join('-');
                    const bDate = bText.split('/').reverse().join('-');
                    comparison = aDate.localeCompare(bDate);
                } else if (column === 6) { 
                    const aScore = parseFloat(aText) || 0;
                    const bScore = parseFloat(bText) || 0;
                    comparison = aScore - bScore;
                } else { 
                    comparison = aText.localeCompare(bText, 'es', { numeric: true, sensitivity: 'base' });
                }

                return isAscending ? comparison : -comparison;
            });

            rows.forEach(row => tbody.appendChild(row));
        }
    </script>
    <footer>
        <p>Powered by <a href="https://github.com/m3n0sd0n4ld/uCVE" target="_blank">uCVE</a></p>
    </footer>
</body>
</html>
`
    f, err := os.Create(filename)
    if err != nil {
        if useColors {
            log.Printf("[%s!%s] Error creating HTML file: %v", Red, Reset, err)
        } else {
            log.Printf("[!] Error creating HTML file: %v", err)
        }
        return
    }
    defer f.Close()

    tmpl := template.Must(template.New("vulnerabilities").Parse(htmlTemplate))

    dataToRender := HTMLData{
        Title:         product,
        Version:       version,
        Lang:          lang,
        GeneratedDate: time.Now().Format("02/01/2006"),
        Vulns:         data,
    }

    err = tmpl.Execute(f, dataToRender)
    if err != nil {
        if useColors {
            log.Printf("[%s!%s] Error executing HTML template: %v", Red, Reset, err)
        } else {
            log.Printf("[!] Error executing HTML template: %v", err)
        }
    } else {
        if useColors {
            fmt.Printf("[%s+%s] Vulnerabilities table exported to '%s'\n", Green, Reset, filename)
        } else {
            fmt.Printf("[+] Vulnerabilities table exported to '%s'\n", filename)
        }
    }
}

func generateJSON(filename string, data []vulnDisplay) {
    type jsonVuln struct {
        Vendor            string `json:"vendor"`
        Product           string `json:"product"`
        Version           string `json:"version"`
        CVE               string `json:"cve"`
        VulnerabilityTitle string `json:"vulnerability"`
        Published         string `json:"published"`
        Score             string `json:"score"`
        RiskText          string `json:"risk"`
        Access            string `json:"access"`
        Complexity        string `json:"complexity"`
    }

    jsonData := make([]jsonVuln, len(data))
    for i, dv := range data {
        jsonData[i] = jsonVuln{
            Vendor:            dv.Vendor,
            Product:           dv.Product,
            Version:           dv.Version,
            CVE:               dv.CVE,
            VulnerabilityTitle: dv.VulnerabilityTitle,
            Published:         dv.Published,
            Score:             dv.Score,
            RiskText:          dv.RiskText,
            Access:            dv.Access,
            Complexity:        dv.Complexity,
        }
    }

    f, err := os.Create(filename)
    if err != nil {
        if useColors {
            log.Printf("[%s!%s] Error creating JSON file: %v", Red, Reset, err)
        } else {
            log.Printf("[!] Error creating JSON file: %v", err)
        }
        return
    }
    defer f.Close()

    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    if err := enc.Encode(jsonData); err != nil {
        if useColors {
            log.Printf("[%s!%s] Error writing JSON: %v", Red, Reset, err)
        } else {
            log.Printf("[!] Error writing JSON: %v", err)
        }
        return
    }

    if useColors {
        fmt.Printf("[%s+%s] Data exported to '%s'\n", Green, Reset, filename)
    } else {
        fmt.Printf("[+] Data exported to '%s'\n", filename)
    }
}

func generateCSV(filename, lang string, data []vulnDisplay) {
    f, err := os.Create(filename)
    if err != nil {
        if useColors {
            log.Printf("[%s!%s] Error creating CSV file: %v", Red, Reset, err)
        } else {
            log.Printf("[!] Error creating CSV file: %v", err)
        }
        return
    }
    defer f.Close()

    writer := csv.NewWriter(f)
    defer writer.Flush()

    headers := []string{
        "Fabricante", "Producto", "Versión", "CVE", "Vulnerabilidad",
        "Fecha Publicación", "Puntuación", "Riesgo", "Acceso", "Complejidad",
    }
    if lang != "es" {
        headers = []string{
            "Vendor", "Product", "Version", "CVE", "Vulnerability",
            "Published Date", "Score", "Risk", "Access", "Complexity",
        }
    }
    if err := writer.Write(headers); err != nil {
        if useColors {
            log.Printf("[%s!%s] Error writing CSV headers: %v", Red, Reset, err)
        } else {
            log.Printf("[!] Error writing CSV headers: %v", err)
        }
        return
    }

    for _, dv := range data {
        record := []string{
            dv.Vendor, dv.Product, dv.Version, dv.CVE, dv.VulnerabilityTitle,
            dv.Published, dv.Score, dv.RiskText, dv.Access, dv.Complexity,
        }
        if err := writer.Write(record); err != nil {
            if useColors {
                log.Printf("[%s!%s] Error writing CSV row: %v", Red, Reset, err)
            } else {
                log.Printf("[!] Error writing CSV row: %v", err)
            }
            return
        }
    }

    if useColors {
        fmt.Printf("[%s+%s] Data exported to '%s'\n", Green, Reset, filename)
    } else {
        fmt.Printf("[+] Data exported to '%s'\n", filename)
    }
}

func printConsoleTable(displayVulns []vulnDisplay, lang, search, version string) string {
    var sb strings.Builder

    riskColorMap := map[string]string{
        "BAJO":     Green,
        "MEDIO":    Orange,
        "ALTO":     BrightRed,
        "CRÍTICO":  Red,
        "NONE":     "",
        "LOW":      Green,
        "MEDIUM":   Orange,
        "HIGH":     BrightRed,
        "CRITICAL": Red,
    }

    if useColors {
        sb.WriteString(fmt.Sprintf("[%s+%s] %d resultados para %s, versión: %s\n", Green, Reset, len(displayVulns), search, version))
    } else {
        sb.WriteString(fmt.Sprintf("[+] %d resultados para %s, versión: %s\n", len(displayVulns), search, version))
    }

    if lang == "es" {
        sb.WriteString("┌────────────────────────┬──────────────────────────────┬────────────┬────────────────┬─────────────────────────────────────┬───────────────────┬────────────┬──────────┬──────────┬─────────────┐\n")
        if useColors {
            sb.WriteString(fmt.Sprintf("│ %s%s%-22s%s │ %s%s%-28s%s │ %s%s%-10s%s │ %s%s%-14s%s │ %s%s%-35s%s │ %s%s%-17s%s │ %s%s%-10s%s │ %s%s%-8s%s │ %s%s%-8s%s │ %s%s%-11s%s │\n",
                BrightWhite, Bold, "Fabricante", Reset,
                BrightWhite, Bold, "Producto", Reset,
                BrightWhite, Bold, "Versión", Reset,
                BrightWhite, Bold, "CVE", Reset,
                BrightWhite, Bold, "Vulnerabilidad", Reset,
                BrightWhite, Bold, "Fecha Publicación", Reset,
                BrightWhite, Bold, "Puntuación", Reset,
                BrightWhite, Bold, "Riesgo", Reset,
                BrightWhite, Bold, "Acceso", Reset,
                BrightWhite, Bold, "Complejidad", Reset))
        } else {
            sb.WriteString(fmt.Sprintf("│ %-22s │ %-28s │ %-10s │ %-14s │ %-35s │ %-17s │ %-10s │ %-8s │ %-8s │ %-11s │\n",
                "Fabricante", "Producto", "Versión", "CVE", "Vulnerabilidad",
                "Fecha Publicación", "Puntuación", "Riesgo", "Acceso", "Complejidad"))
        }
        sb.WriteString("├────────────────────────┼──────────────────────────────┼────────────┼────────────────┼─────────────────────────────────────┼───────────────────┼────────────┼──────────┼──────────┼─────────────┤\n")
    } else {
        sb.WriteString("┌────────────────────────┬──────────────────────────────┬────────────┬────────────────┬─────────────────────────────────────┬───────────────────┬────────────┬──────────┬──────────────┬─────────────┐\n")
        if useColors {
            sb.WriteString(fmt.Sprintf("│ %s%s%-22s%s │ %s%s%-28s%s │ %s%s%-10s%s │ %s%s%-14s%s │ %s%s%-35s%s │ %s%s%-17s%s │ %s%s%-10s%s │ %s%s%-8s%s │ %s%s%-12s%s │ %s%s%-11s%s │\n",
                BrightWhite, Bold, "Vendor", Reset,
                BrightWhite, Bold, "Product", Reset,
                BrightWhite, Bold, "Version", Reset,
                BrightWhite, Bold, "CVE", Reset,
                BrightWhite, Bold, "Vulnerability", Reset,
                BrightWhite, Bold, "Published Date", Reset,
                BrightWhite, Bold, "Score", Reset,
                BrightWhite, Bold, "Risk", Reset,
                BrightWhite, Bold, "Access", Reset,
                BrightWhite, Bold, "Complexity", Reset))
        } else {
            sb.WriteString(fmt.Sprintf("│ %-22s │ %-28s │ %-10s │ %-14s │ %-35s │ %-17s │ %-10s │ %-8s │ %-12s │ %-11s │\n",
                "Vendor", "Product", "Version", "CVE", "Vulnerability",
                "Published Date", "Score", "Risk", "Access", "Complexity"))
        }
        sb.WriteString("├────────────────────────┼──────────────────────────────┼────────────┼────────────────┼─────────────────────────────────────┼───────────────────┼────────────┼──────────┼──────────────┼─────────────┤\n")
    }

    for i, dv := range displayVulns {
        truncatedVendor := truncateString(dv.Vendor, 22)
        truncatedProduct := truncateString(dv.Product, 28)
        truncatedTitle := truncateString(dv.VulnerabilityTitle, 35)
        truncatedCVE := truncateString(dv.CVE, 14)

        var rowColor, riskColor string
        if useColors {
            rowColor = Cyan
            if i%2 == 1 {
                rowColor = Magenta
            }
            riskColor = riskColorMap[dv.RiskText]
            if riskColor == "" {
                riskColor = Reset
            }
        }

        if lang == "es" {
            if useColors {
                sb.WriteString(fmt.Sprintf("│ %s%-22s%s │ %s%-28s%s │ %s%-10s%s │ %s%-14s%s │ %s%-35s%s │ %s%-17s%s │ %s%-10s%s │ %s%-8s%s │ %s%-8s%s │ %s%-11s%s │\n",
                    rowColor, truncatedVendor, Reset,
                    rowColor, truncatedProduct, Reset,
                    rowColor, dv.Version, Reset,
                    rowColor, truncatedCVE, Reset,
                    rowColor, truncatedTitle, Reset,
                    rowColor, dv.Published, Reset,
                    rowColor, dv.Score, Reset,
                    riskColor, dv.RiskText, Reset,
                    rowColor, dv.Access, Reset,
                    rowColor, dv.Complexity, Reset))
            } else {
                sb.WriteString(fmt.Sprintf("│ %-22s │ %-28s │ %-10s │ %-14s │ %-35s │ %-17s │ %-10s │ %-8s │ %-8s │ %-11s │\n",
                    truncatedVendor, truncatedProduct, dv.Version, truncatedCVE,
                    truncatedTitle, dv.Published, dv.Score, dv.RiskText, dv.Access, dv.Complexity))
            }
        } else {
            if useColors {
                sb.WriteString(fmt.Sprintf("│ %s%-22s%s │ %s%-28s%s │ %s%-10s%s │ %s%-14s%s │ %s%-35s%s │ %s%-17s%s │ %s%-10s%s │ %s%-8s%s │ %s%-12s%s │ %s%-11s%s │\n",
                    rowColor, truncatedVendor, Reset,
                    rowColor, truncatedProduct, Reset,
                    rowColor, dv.Version, Reset,
                    rowColor, truncatedCVE, Reset,
                    rowColor, truncatedTitle, Reset,
                    rowColor, dv.Published, Reset,
                    rowColor, dv.Score, Reset,
                    riskColor, dv.RiskText, Reset,
                    rowColor, dv.Access, Reset,
                    rowColor, dv.Complexity, Reset))
            } else {
                sb.WriteString(fmt.Sprintf("│ %-22s │ %-28s │ %-10s │ %-14s │ %-35s │ %-17s │ %-10s │ %-8s │ %-12s │ %-11s │\n",
                    truncatedVendor, truncatedProduct, dv.Version, truncatedCVE,
                    truncatedTitle, dv.Published, dv.Score, dv.RiskText, dv.Access, dv.Complexity))
            }
        }
    }

    if lang == "es" {
        sb.WriteString("└────────────────────────┴──────────────────────────────┴────────────┴────────────────┴─────────────────────────────────────┴───────────────────┴────────────┴──────────┴──────────┴─────────────┘\n")
    } else {
        sb.WriteString("└────────────────────────┴──────────────────────────────┴────────────┴────────────────┴─────────────────────────────────────┴───────────────────┴────────────┴──────────┴──────────────┴─────────────┘\n")
    }

    return sb.String()
}

func main() {
    if useColors {
        fmt.Print(bannerColored)
    } else {
        fmt.Print(bannerPlain)
    }
    fmt.Println()

    searchFlag := flag.String("s", "", "Product to search for")
    versionFlag := flag.String("vp", "", "Product version (required)")
    langFlag := flag.String("lg", "en", "Language (en|es)")
    riskFlag := flag.String("r", "", "Risk levels to filter (comma-separated, example: critical,high)")
    excludeVendorsFlag := flag.String("e", "", "Vendors to exclude (comma-separated, example: Dennis Bruecke,Jqueryui)")
    includeVendorsFlag := flag.String("i", "", "Vendors to include (comma-separated, example: jquery,jqueryui)")
    helpFlag := flag.Bool("h", false, "Show help")
    htmlFileFlag := flag.String("oHTML", "", "Name of the output HTML file")
    jsonFileFlag := flag.String("oJSON", "", "Name of the output JSON file")
    csvFileFlag := flag.String("oCSV", "", "Name of the output CSV file")
    consoleFileFlag := flag.String("o", "", "Name of the text file for the output")
    proxyFlag := flag.String("x", "", "HTTP proxy (host:port format)")

    flag.Parse()

    search := *searchFlag
    version := *versionFlag
    lang := *langFlag
    risk := *riskFlag
    excludeVendors := *excludeVendorsFlag
    includeVendors := *includeVendorsFlag
    htmlFile := *htmlFileFlag
    jsonFile := *jsonFileFlag
    csvFile := *csvFileFlag
    consoleFile := *consoleFileFlag
    help := *helpFlag
    proxy := *proxyFlag

    if help || search == "" {
        showHelp()
        return
    }

    if version == "" {
        if useColors {
            fmt.Printf("[%s!%s] Version parameter (-vp) is required\n", Red, Reset)
        } else {
            fmt.Println("[!] Version parameter (-vp) is required")
        }
        showHelp()
        return
    }

    if lang != "en" && lang != "es" {
        if useColors {
            fmt.Printf("[%s!%s] Language not supported. Only 'en' or 'es'.\n", Red, Reset)
        } else {
            fmt.Println("[!] Language not supported. Only 'en' or 'es'.")
        }
        return
    }

    if proxy != "" {
        parts := strings.Split(proxy, ":")
        if len(parts) != 2 {
            if useColors {
                fmt.Printf("[%s!%s] Invalid proxy format. Use host:port (example: 127.0.0.1:8080).\n", Red, Reset)
            } else {
                fmt.Println("[!] Invalid proxy format. Use host:port (example: 127.0.0.1:8080).")
            }
            return
        }
        _, err := strconv.Atoi(parts[1])
        if err != nil {
            if useColors {
                fmt.Printf("[%s!%s] The proxy port must be a valid number.\n", Red, Reset)
            } else {
                fmt.Println("[!] The proxy port must be a valid number.")
            }
            return
        }
    }

    var riskLevels []string
    validRisks := map[string]bool{
        "LOW":      true,
        "MEDIUM":   true,
        "HIGH":     true,
        "CRITICAL": true,
        "NONE":     true,
        "BAJO":     true,
        "MEDIO":    true,
        "ALTO":     true,
        "CRÍTICO":  true,
        "NINGUNO":  true,
    }
    if risk != "" {
        riskLevels = strings.Split(strings.ToUpper(risk), ",")
        for i, r := range riskLevels {
            r = strings.TrimSpace(r)
            if lang == "es" {
                switch r {
                case "BAJO":
                    r = "LOW"
                case "MEDIO":
                    r = "MEDIUM"
                case "ALTO":
                    r = "HIGH"
                case "CRÍTICO":
                    r = "CRITICAL"
                case "NINGUNO":
                    r = "NONE"
                }
            }
            if !validRisks[r] {
                if useColors {
                    fmt.Printf("[%s!%s] Invalid risk level: %s. Use comma-separated values (e.g., critical,high or crítico,alto).\n", Red, Reset, r)
                } else {
                    fmt.Println("[!] Invalid risk level: " + r + ". Use comma-separated values (e.g., critical,high or crítico,alto).")
                }
                return
            }
            riskLevels[i] = r
        }
    }

    var excludeVendorsList []string
    if excludeVendors != "" {
        excludeVendorsList = strings.Split(excludeVendors, ",")
        for i, v := range excludeVendorsList {
            v = strings.TrimSpace(v)
            if v == "" {
                if useColors {
                    fmt.Printf("[%s!%s] Invalid vendor name: empty value in exclude list.\n", Red, Reset)
                } else {
                    fmt.Println("[!] Invalid vendor name: empty value in exclude list.")
                }
                return
            }
            excludeVendorsList[i] = strings.ToLower(v)
        }
    }

    var includeVendorsList []string
    if includeVendors != "" {
        includeVendorsList = strings.Split(includeVendors, ",")
        for i, v := range includeVendorsList {
            v = strings.TrimSpace(v)
            if v == "" {
                if useColors {
                    fmt.Printf("[%s!%s] Invalid vendor name: empty value in include list.\n", Red, Reset)
                } else {
                    fmt.Println("[!] Invalid vendor name: empty value in include list.")
                }
                return
            }
            includeVendorsList[i] = strings.ToLower(v)
        }
    }

    if len(excludeVendorsList) > 0 && len(includeVendorsList) > 0 {
        for _, includeVendor := range includeVendorsList {
            for _, excludeVendor := range excludeVendorsList {
                if includeVendor == excludeVendor {
                    if useColors {
                        fmt.Printf("[%s!%s] Conflict: vendor '%s' is both included and excluded.\n", Red, Reset, includeVendor)
                    } else {
                        fmt.Println("[!] Conflict: vendor '" + includeVendor + "' is both included and excluded.")
                    }
                    return
                }
            }
        }
    }

    client := &http.Client{}
    if proxy != "" {
        proxyURL, err := url.Parse("http://" + proxy)
        if err != nil {
            if useColors {
                fmt.Printf("[%s!%s] Error parsing the proxy URL: %v\n", Red, Reset, err)
            } else {
                fmt.Println("[!] Error parsing the proxy URL: " + err.Error())
            }
            return
        }
        transport := &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
        }
        client.Transport = transport
    }

    encodedSearch := strings.ReplaceAll(search, " ", "+")
    searchURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s", encodedSearch)

    resp, err := client.Get(searchURL)
    if err != nil {
        if useColors {
            log.Fatalf("[%s!%s] Error querying the search API: %v", Red, Reset, err)
        } else {
            log.Fatalf("[!] Error querying the search API: %v", err)
        }
    }

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if useColors {
            log.Fatalf("[%s!%s] API returned non-200 status: %s\nResponse: %s", Red, Reset, resp.Status, string(body))
        } else {
            log.Fatalf("[!] API returned non-200 status: %s\nResponse: %s", resp.Status, string(body))
        }
    }

    var result NVDSearchResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if useColors {
            log.Fatalf("[%s!%s] Error decoding search JSON: %v\nResponse: %s", Red, Reset, err, string(body))
        } else {
            log.Fatalf("[!] Error decoding search JSON: %v\nResponse: %s", err, string(body))
        }
    }
    defer resp.Body.Close()

    var validVulns []VulnerabilityItem
    for _, v := range result.Vulnerabilities {
        vulnerable := false
        for _, config := range v.CVE.Configurations {
            for _, node := range config.Nodes {
                for _, cpeMatch := range node.CpeMatch {
                    if cpeMatch.Vulnerable && strings.Contains(strings.ToLower(cpeMatch.Criteria), strings.ToLower(search)) {
                        if version != "" {
                            if cpeMatch.VersionEndIncluding == "" || compareVersions(version, cpeMatch.VersionEndIncluding) <= 0 {
                                vulnerable = true
                                break
                            }
                        } else {
                            vulnerable = true
                            break
                        }
                    }
                }
                if vulnerable {
                    break
                }
            }
            if vulnerable {
                break
            }
        }
        if !vulnerable {
            for _, desc := range v.CVE.Descriptions {
                if desc.Lang == "en" && strings.Contains(strings.ToLower(desc.Value), strings.ToLower(search)) {
                    if version != "" {
                        descLower := strings.ToLower(desc.Value)
                        versionLower := strings.ToLower(version)
                        if strings.Contains(descLower, versionLower) ||
                            strings.Contains(descLower, "up to "+versionLower) ||
                            strings.Contains(descLower, versionLower+" or earlier") ||
                            strings.Contains(descLower, versionLower+" or before") ||
                            strings.Contains(descLower, "before "+versionLower) ||
                            strings.Contains(descLower, "hasta "+versionLower) ||
                            strings.Contains(descLower, versionLower+" o anterior") {
                            vulnerable = true
                            break
                        }
                    } else {
                        vulnerable = true
                        break
                    }
                }
            }
        }
        if vulnerable {
            validVulns = append(validVulns, v)
        }
    }

    if len(validVulns) == 0 {
        msg := "[!] No vulnerabilities were found for the product " + search
        if version != "" {
            msg += " and version " + version
        }
        if risk != "" {
            msg += " with risk levels " + risk
        }
        if excludeVendors != "" {
            msg += " excluding vendors " + excludeVendors
        }
        if includeVendors != "" {
            msg += " including vendors " + includeVendors
        }
        if useColors {
            fmt.Println(fmt.Sprintf("[%s!%s] %s.", Red, Reset, msg[3:]))
        } else {
            fmt.Println(msg + ".")
        }
        return
    }

    riskMap := map[string]string{
        "LOW":      "BAJO",
        "MEDIUM":   "MEDIO",
        "HIGH":     "ALTO",
        "CRITICAL": "CRÍTICO",
        "NONE":     "NINGUNO",
    }

    accessMap := map[string]map[string]string{
        "en": {
            "NETWORK":         "NETWORK",
            "ADJACENT_NETWORK": "ADJ. NETWORK",
            "LOCAL":           "LOCAL",
            "PHYSICAL":        "PHYSICAL",
        },
        "es": {
            "NETWORK":         "RED",
            "ADJACENT_NETWORK": "RED ADY.",
            "LOCAL":           "LOCAL",
            "PHYSICAL":        "FÍSICO",
        },
    }

    complexityMap := map[string]string{
        "LOW":    "BAJA",
        "MEDIUM": "MEDIA",
        "HIGH":   "ALTA",
    }

    cweTitles := map[string]map[string]string{
        "CWE-502":  {"en": "Untrusted Deserialization", "es": "Deserialización no fiable"},
        "CWE-284":  {"en": "Improper Access Control", "es": "Control de acceso inadecuado"},
        "CWE-200":  {"en": "Sensitive Info Exposure", "es": "Exposición de datos sensibles"},
        "CWE-610":  {"en": "Externally Controlled Ref", "es": "Ref. controlada externamente"},
        "CWE-552":  {"en": "Accessible Files/Dirs", "es": "Archivos/dirs. accesibles"},
        "CWE-209":  {"en": "Sensitive Info in Errors", "es": "Info sensible en errores"},
        "CWE-295":  {"en": "Improper Cert Validation", "es": "Validación de cert. incorrecta"},
        "CWE-273":  {"en": "Improper Dropped Priv Check", "es": "Verif. de priv. incorrecta"},
        "CWE-754":  {"en": "Exceptional Cond. Check", "es": "Verif. de cond. excepcionales"},
        "CWE-913":  {"en": "Improper Dyn. Code Control", "es": "Control de código dinámico"},
        "CWE-94":   {"en": "Code Injection", "es": "Inyección de código"},
        "CWE-116":  {"en": "Improper Output Encoding", "es": "Codificación de salida errónea"},
        "CWE-924":  {"en": "Improper Message Integrity", "es": "Integridad de mensajes errónea"},
        "CWE-178":  {"en": "Improper Case Handling", "es": "Manejo de mayúsculas erróneo"},
        "CWE-755":  {"en": "Exceptional Cond. Handling", "es": "Manejo de cond. excepcionales"},
        "CWE-665":  {"en": "Improper Initialization", "es": "Inicialización incorrecta"},
        "CWE-20":   {"en": "Improper Input Validation", "es": "Validación de entrada incorrecta"},
        "CWE-22":   {"en": "Path Traversal", "es": "Recorrido de directorios"},
        "CWE-59":   {"en": "Link Following", "es": "Seguimiento de enlaces"},
        "CWE-667":  {"en": "Improper Locking", "es": "Bloqueo incorrecto"},
        "CWE-88":   {"en": "Argument Injection", "es": "Inyección de argumentos"},
        "CWE-1236": {"en": "CSV Formula Injection", "es": "Inyección de fórmula CSV"},
        "CWE-79":   {"en": "Cross-site Scripting", "es": "Cross-site Scripting"},
        "CWE-74":   {"en": "Injection", "es": "Inyección"},
        "CWE-77":   {"en": "Command Injection", "es": "Inyección de comandos"},
        "CWE-917":  {"en": "Expression Lang. Injection", "es": "Inyección de leng. de expr."},
        "CWE-78":   {"en": "OS Command Injection", "es": "Inyección de comandos OS"},
        "CWE-89":   {"en": "SQL Injection", "es": "Inyección SQL"},
        "CWE-281":  {"en": "Improper Perm. Preservation", "es": "Preservación de perm. errónea"},
        "CWE-269":  {"en": "Improper Privilege Mgmt", "es": "Gestión de priv. incorrecta"},
        "CWE-212":  {"en": "Improper Sensitive Data Rem.", "es": "Elim. de info. sensible errónea"},
        "CWE-404":  {"en": "Improper Resource Release", "es": "Liberación de recursos errónea"},
        "CWE-307":  {"en": "Improper Auth. Restr.", "es": "Restr. de autenticación errónea"},
        "CWE-119":  {"en": "Improper Mem. Buffer Restr.", "es": "Restr. en búfer de memoria"},
        "CWE-920":  {"en": "Improper Power Consumption", "es": "Consumo de energía erróneo"},
        "CWE-776":  {"en": "XML Entity Expansion", "es": "Expansión de entidad XML"},
        "CWE-1021": {"en": "Improper UI Layer Restr.", "es": "Restr. en capas de interfaz"},
        "CWE-611":  {"en": "Improper XML Ext. Ref.", "es": "Restr. de ref. XML ext."},
        "CWE-662":  {"en": "Improper Synchronization", "es": "Sincronización incorrecta"},
        "CWE-129":  {"en": "Improper Array Index", "es": "Índice de array incorrecto"},
        "CWE-354":  {"en": "Improper Integrity Check", "es": "Verif. de integridad errónea"},
        "CWE-1284": {"en": "Improper Input Quantity", "es": "Cant. especificada en entrada"},
        "CWE-347":  {"en": "Improper Crypto Signature", "es": "Firma criptog. incorrecta"},
        "CWE-1321": {"en": "Prototype Pollution", "es": "Contaminación de prototipos"},
        "CWE-326":  {"en": "Inadequate Encryption Str.", "es": "Fuerza de cifrado inadecuada"},
        "CWE-838":  {"en": "Inappropriate Output Encoding", "es": "Codificación de salida inadecuada"},
        "CWE-829":  {"en": "Untrusted Control Inclusion", "es": "Inclusión de control no fiable"},
        "CWE-459":  {"en": "Incomplete Cleanup", "es": "Limpieza incompleta"},
        "CWE-444":  {"en": "HTTP Smuggling", "es": "Manipulación HTTP"},
        "CWE-863":  {"en": "Incorrect Authorization", "es": "Autorización incorrecta"},
        "CWE-682":  {"en": "Incorrect Calculation", "es": "Cálculo incorrecto"},
        "CWE-131":  {"en": "Incorrect Buffer Size", "es": "Tamaño de búfer incorrecto"},
        "CWE-697":  {"en": "Incorrect Comparison", "es": "Comparación incorrecta"},
        "CWE-681":  {"en": "Incorrect Numeric Conv.", "es": "Conversión numérica incorrecta"},
        "CWE-276":  {"en": "Incorrect Default Perms", "es": "Permisos por defecto erróneos"},
        "CWE-732":  {"en": "Incorrect Critical Perms", "es": "Permisos en recurso crítico"},
        "CWE-669":  {"en": "Incorrect Resource Transfer", "es": "Transferencia de recursos errónea"},
        "CWE-704":  {"en": "Incorrect Type Conversion", "es": "Conversión de tipo errónea"},
        "CWE-335":  {"en": "Incorrect PRNG Seeds", "es": "Semillas PRNG incorrectas"},
        "CWE-407":  {"en": "Inefficient Algorithm", "es": "Algoritmo ineficiente"},
        "CWE-1333": {"en": "Inefficient Regex", "es": "Regex ineficiente"},
        "CWE-1188": {"en": "Insecure Default Init.", "es": "Inicialización por defecto insegura"},
        "CWE-922":  {"en": "Insecure Sensitive Storage", "es": "Almacenamiento de datos sensible"},
        "CWE-532":  {"en": "Sensitive Data in Logs", "es": "Datos sensibles en logs"},
        "CWE-331":  {"en": "Insufficient Entropy", "es": "Entropía insuficiente"},
        "NVD-CWE-noinfo": {"en": "Insufficient Information", "es": "Información insuficiente"},
        "CWE-613":  {"en": "Insufficient Session Exp.", "es": "Expiración de sesión insuficiente"},
        "CWE-345":  {"en": "Data Authenticity Fail", "es": "Verif. de datos insuficiente"},
        "CWE-522":  {"en": "Weak Credentials", "es": "Credenciales débiles"},
        "CWE-190":  {"en": "Integer Overflow", "es": "Desbordamiento de enteros"},
        "CWE-191":  {"en": "Integer Underflow", "es": "Subdesbordamiento de enteros"},
        "CWE-436":  {"en": "Interpretation Conflict", "es": "Conflicto de interpretación"},
        "CWE-835":  {"en": "Infinite Loop", "es": "Bucle infinito"},
        "CWE-306":  {"en": "Missing Auth. for Critical", "es": "Falta de autenticación"},
        "CWE-862":  {"en": "Missing Authorization", "es": "Falta de autorización"},
        "CWE-311":  {"en": "Missing Data Encryption", "es": "Falta de cifrado de datos"},
        "CWE-909":  {"en": "Missing Resource Init.", "es": "Inicialización de recurso falta"},
        "CWE-401":  {"en": "Missing Mem. Release", "es": "Falta liberación de memoria"},
        "CWE-772":  {"en": "Missing Resource Release", "es": "Falta liberación de recursos"},
        "CWE-476":  {"en": "NULL Pointer Dereference", "es": "Desreferencia de puntero NULL"},
        "CWE-203":  {"en": "Observable Discrepancy", "es": "Discrepancia observable"},
        "CWE-193":  {"en": "Off-by-one Error", "es": "Error por uno"},
        "CWE-672":  {"en": "Op. on Released Resource", "es": "Op. en recurso liberado"},
        "CWE-346":  {"en": "Origin Validation Error", "es": "Error de validación de origen"},
        "NVD-CWE-Other": {"en": "Other", "es": "Otro"},
        "CWE-125":  {"en": "Out-of-bounds Read", "es": "Lectura fuera de límites"},
        "CWE-787":  {"en": "Out-of-bounds Write", "es": "Escritura fuera de límites"},
        "CWE-617":  {"en": "Reachable Assertion", "es": "Aserción alcanzable"},
        "CWE-763":  {"en": "Invalid Pointer Release", "es": "Liberación de puntero inválido"},
        "CWE-565":  {"en": "Unvalidated Cookies", "es": "Cookies sin validación"},
        "CWE-918":  {"en": "Server-Side Request Forgery", "es": "Falsificación de solicitud SSRF"},
        "CWE-384":  {"en": "Session Fixation", "es": "Fijación de sesión"},
        "CWE-367":  {"en": "TOCTOU Race Condition", "es": "Condición de carrera TOCTOU"},
        "CWE-252":  {"en": "Unchecked Return Value", "es": "Valor de retorno sin verificar"},
        "CWE-674":  {"en": "Uncontrolled Recursion", "es": "Recursión incontrolada"},
        "CWE-400":  {"en": "Uncontrolled Resource Use", "es": "Consumo de recursos incontrolado"},
        "CWE-427":  {"en": "Uncontrolled Search Path", "es": "Ruta de búsqueda incontrolada"},
        "CWE-428":  {"en": "Unquoted Search Path", "es": "Ruta de búsqueda sin comillas"},
        "CWE-434":  {"en": "Unrestricted File Upload", "es": "Carga de archivos sin restricción"},
        "CWE-426":  {"en": "Untrusted Search Path", "es": "Ruta de búsqueda no fiable"},
        "CWE-601":  {"en": "URL Redirect to Untrusted", "es": "Redirección a sitio no fiable"},
        "CWE-416":  {"en": "Use After Free", "es": "Uso después de liberar"},
        "CWE-327":  {"en": "Broken Crypto Algorithm", "es": "Algoritmo cripto. roto"},
        "CWE-338":  {"en": "Weak Crypto PRNG", "es": "PRNG cripto. débil"},
        "CWE-134":  {"en": "Ext. Controlled Format String", "es": "Cadena de formato controlada"},
        "CWE-470":  {"en": "Unsafe Reflection", "es": "Reflexión insegura"},
        "CWE-798":  {"en": "Hard-coded Credentials", "es": "Credenciales hardcodeadas"},
        "CWE-706":  {"en": "Incorrect Name/Ref. Use", "es": "Uso de nombre/ref. incorrecto"},
        "CWE-330":  {"en": "Insufficient Random Values", "es": "Valores aleatorios insuficientes"},
        "CWE-916":  {"en": "Weak Password Hash", "es": "Hash de contraseña débil"},
        "CWE-908":  {"en": "Uninitialized Resource", "es": "Recurso no inicializado"},
        "CWE-640":  {"en": "Weak Password Recovery", "es": "Recuperación de contraseña débil"},
        "CWE-521":  {"en": "Weak Password Requirements", "es": "Requisitos de contraseña débiles"},
        "CWE-91":   {"en": "XML Injection", "es": "Inyección XML"},
        "CWE-668":  {"en": "Resource Exposure", "es": "Exposición de recursos errónea"},
        "CWE-362":  {"en": "Race Condition", "es": "Condición de carrera"},
        "CWE-523":  {"en": "Unsecured Cred. Transport", "es": "Transporte cred. inseguro"},
        "CWE-352":  {"en": "Cross-Site Request Forgery (CSRF)", "es": "Falsificación de solicitud CSRF"},
        "CWE-264":  {"en": "Access Controls", "es": "Control de acceso"},
        "CWE-254":  {"en": "Security Features", "es": "Funciones de seguridad"},
        "CWE-287":  {"en": "Improper Authentication", "es": "Autenticación incorrecta"},
        "CWE-399":  {"en": "Resource Management Errors", "es": "Errores de gestión de recursos"},
        "CWE-255":  {"en": "Credentials Management Errors", "es": "Errores en gestión de credenciales"},
        "CWE-189":  {"en": "Numeric Errors", "es": "Errores numéricos"},
        "CWE-320":  {"en": "Key Management Errors", "es": "Errores en gestión de claves"},
        "CWE-388":  {"en": "Error Handling", "es": "Manejo de errores"},
        "CWE-80":   {"en": "Basic XSS", "es": "XSS Básico"},
        "CWE-90":   {"en": "LDAP Injection", "es": "Inyección LDAP"},
        "CWE-120":  {"en": "Buffer Copy No Check", "es": "Copia Búfer Sin Verif."},
        "CWE-122":  {"en": "Heap Buffer Overflow", "es": "Desb. Búfer Montón"},
        "CWE-126":  {"en": "Buffer Over-read", "es": "Sobrelectura Búfer"},
        "CWE-201":  {"en": "Sensitive Info Leak", "es": "Fuga Info Sensible"},
        "CWE-415":  {"en": "Double Free", "es": "Liberación Doble"},
        "CWE-417":  {"en": "Uninit. Variable Use", "es": "Uso Var. No Inicial."},
        "CWE-664":  {"en": "Resource Lifecycle Err", "es": "Error Ciclo Recurso"},
        "CWE-703":  {"en": "Exception Handling Err", "es": "Error Manejo Excep."},
        "CWE-1004": {"en": "Cookie No HttpOnly", "es": "Cookie Sin HttpOnly"},
        "CWE-843":  {"en": "Type Confusion", "es": "Confusión de Tipo"},
        "CWE-824":  {"en": "Uninit. Pointer Access", "es": "Acceso Puntero No Init."},
        "CWE-770":  {"en": "Resource Alloc. No Limit", "es": "Asign. Recurso Sin Límite"},
        "CWE-670":  {"en": "Incorrect Control Flow", "es": "Flujo Control Erróneo"},
        "CWE-294":  {"en": "Auth Bypass Replay", "es": "Bypass Autent. por Replay"},
        "CWE-290":  {"en": "Auth Bypass Spoofing", "es": "Bypass Autent. por Spoofing"},
        "CWE-639":  {"en": "Auth Bypass User Key", "es": "Bypass Aut. por Clave User"},
        "CWE-369":  {"en": "Divide By Zero", "es": "División por Cero"},
        "CWE-312":  {"en": "Cleartext Sens. Info", "es": "Info Sens. en Claro"},
        "CWE-319":  {"en": "Cleartext Sens. Trans.", "es": "Trans. Sens. en Claro"},
        "CWE-425":  {"en": "Forced Browsing", "es": "Navegación Forzada"},
        "CWE-494":  {"en": "No Integrity Code DL", "es": "Descarga Código Sin Integr."},
        "CWE-834":  {"en": "Excessive Iteration", "es": "Iteración Excesiva"},
    }

    var displayVulns []vulnDisplay
    for _, v := range validVulns {
        vendorRaw := "unknown"
        productRaw := search
        vendor := "Unknown"
        product := normalizeName(search)

        for _, config := range v.CVE.Configurations {
            for _, node := range config.Nodes {
                for _, cpeMatch := range node.CpeMatch {
                    if cpeMatch.Vulnerable && strings.Contains(strings.ToLower(cpeMatch.Criteria), strings.ToLower(search)) {
                        vendorRaw, productRaw = extractCPEInfo(cpeMatch.Criteria)
                        vendor = normalizeName(vendorRaw)
                        product = normalizeName(productRaw)
                        break
                    }
                }
                if vendorRaw != "unknown" {
                    break
                }
            }
            if vendorRaw != "unknown" {
                break
            }
        }

        if vendorRaw == "unknown" {
            for _, desc := range v.CVE.Descriptions {
                if desc.Lang == "en" && strings.Contains(strings.ToLower(desc.Value), strings.ToLower(search)) {
                    vendorRaw = strings.ToLower(search)
                    vendor = normalizeName(vendorRaw)
                    break
                }
            }
        }

        if len(includeVendorsList) > 0 {
            vendorLower := strings.ToLower(vendorRaw)
            include := false
            for _, included := range includeVendorsList {
                if vendorLower == included {
                    include = true
                    break
                }
            }
            if !include {
                continue
            }
        }

        if len(excludeVendorsList) > 0 {
            vendorLower := strings.ToLower(vendorRaw)
            exclude := false
            for _, excluded := range excludeVendorsList {
                if vendorLower == excluded {
                    exclude = true
                    break
                }
            }
            if exclude {
                continue
            }
        }

        cve := v.CVE.ID
        pubDate := "-"
        if len(v.CVE.Published) >= 10 {
            pubDate = v.CVE.Published[:10]
        }
        fmtDate := formatDate(pubDate)

        cweCode := ""
        found := false
        for _, weakness := range v.CVE.Weaknesses {
            if found {
                break
            }
            for _, wd := range weakness.Description {
                if strings.HasPrefix(wd.Value, "CWE-") || strings.HasPrefix(wd.Value, "NVD-CWE-") {
                    cweCode = wd.Value
                    found = true
                    break
                }
            }
        }
        title, ok := cweTitles[cweCode][lang]
        if !ok || cweCode == "" {
            title = map[string]string{"en": "Other", "es": "Otro"}[lang]
        }

        score := "-"
        severity := "-"
        vector := "-"
        complexity := "-"

        if len(v.CVE.Metrics.CvssMetricV40) > 0 {
            cvss := v.CVE.Metrics.CvssMetricV40[0].CvssData
            score = fmt.Sprintf("%.1f", cvss.BaseScore)
            severity = cvss.BaseSeverity
            if cvss.BaseScore >= 9.1 {
                severity = "CRITICAL"
            }
            vector = cvss.AttackVector
            complexity = cvss.AttackComplexity
        } else if len(v.CVE.Metrics.CvssMetricV31) > 0 {
            cvss := v.CVE.Metrics.CvssMetricV31[0].CvssData
            score = fmt.Sprintf("%.1f", cvss.BaseScore)
            severity = cvss.BaseSeverity
            if cvss.BaseScore >= 9.1 {
                severity = "CRITICAL"
            }
            vector = cvss.AttackVector
            complexity = cvss.AttackComplexity
        } else if len(v.CVE.Metrics.CvssMetricV2) > 0 {
            cvss := v.CVE.Metrics.CvssMetricV2[0]
            score = fmt.Sprintf("%.1f", cvss.CvssData.BaseScore)
            severity = cvss.BaseSeverity
            if cvss.CvssData.BaseScore >= 9.1 {
                severity = "CRITICAL"
            }
            vector = cvss.CvssData.AccessVector
            complexity = cvss.CvssData.AccessComplexity
        }

        riskText := severity
        if lang == "es" {
            riskText = strings.ToUpper(severity)
            if val, ok := riskMap[riskText]; ok {
                riskText = val
            }
            vector = strings.ToUpper(vector)
            if val, ok := accessMap[lang][vector]; ok {
                vector = val
            }
            complexity = strings.ToUpper(complexity)
            if val, ok := complexityMap[complexity]; ok {
                complexity = val
            }
        }

        riskClass := strings.ToUpper(severity)

        if vector == "ADJACENT_NETWORK" {
            if lang == "es" {
                vector = "RED ADY."
            } else {
                vector = "ADJ. NETWORK"
            }
        }

        if len(riskLevels) > 0 {
            normalizedRisk := riskText
            if lang == "es" {
                for en, es := range riskMap {
                    if es == riskText {
                        normalizedRisk = en
                        break
                    }
                }
            }
            match := false
            for _, r := range riskLevels {
                if r == normalizedRisk {
                    match = true
                    break
                }
            }
            if !match {
                continue
            }
        }

        displayVulns = append(displayVulns, vulnDisplay{
            Vuln:               v,
            VendorRaw:          vendorRaw,
            ProductRaw:         productRaw,
            Vendor:             vendor,
            Product:            product,
            Version:            version,
            CVE:                cve,
            VulnerabilityTitle: title,
            Published:          fmtDate,
            Score:              score,
            RiskText:           riskText,
            RiskClass:          riskClass,
            Access:             vector,
            Complexity:         complexity,
        })
    }

    if len(displayVulns) == 0 {
        msg := "[!] No vulnerabilities were found for the product " + search
        if version != "" {
            msg += " and version " + version
        }
        if risk != "" {
            msg += " with risk levels " + risk
        }
        if excludeVendors != "" {
            msg += " excluding vendors " + excludeVendors
        }
        if includeVendors != "" {
            msg += " including vendors " + includeVendors
        }
        if useColors {
            fmt.Println(fmt.Sprintf("[%s!%s] %s.", Red, Reset, msg[3:]))
        } else {
            fmt.Println(msg + ".")
        }
        return
    }

    tableOutput := printConsoleTable(displayVulns, lang, search, version)
    fmt.Print(tableOutput)

    if consoleFile != "" {
        f, err := os.Create(consoleFile)
        if err != nil {
            if useColors {
                log.Printf("[%s!%s] Error saving output to '%s': %v", Red, Reset, consoleFile, err)
            } else {
                log.Printf("[!] Error saving output to '%s': %v", consoleFile, err)
            }
            return
        }
        defer f.Close()

        if runtime.GOOS == "windows" {
            _, err = f.Write([]byte{0xEF, 0xBB, 0xBF}) 
            if err != nil {
                if useColors {
                    log.Printf("[%s!%s] Error writing UTF-8 BOM to '%s': %v", Red, Reset, consoleFile, err)
                } else {
                    log.Printf("[!] Error writing UTF-8 BOM to '%s': %v", consoleFile, err)
                }
                return
            }
        }

        banner := bannerPlain
        if useColors {
            banner = bannerColored
        }
        content := banner + "\n\n" + tableOutput
        if runtime.GOOS == "windows" {
            content = strings.ReplaceAll(content, "\n", "\r\n")
        }
        _, err = f.WriteString(content)
        if err != nil {
            if useColors {
                log.Printf("[%s!%s] Error writing output to '%s': %v", Red, Reset, consoleFile, err)
            } else {
                log.Printf("[!] Error writing output to '%s': %v", consoleFile, err)
            }
            return
        }

        if useColors {
            fmt.Printf("[%s+%s] Console output saved in '%s'\n", Green, Reset, consoleFile)
        } else {
            fmt.Printf("[+] Console output saved in '%s'\n", consoleFile)
        }
    }

    if htmlFile != "" {
        generateHTMLTable(htmlFile, search, version, lang, displayVulns)
    }

    if jsonFile != "" {
        generateJSON(jsonFile, displayVulns)
    }

    if csvFile != "" {
        generateCSV(csvFile, lang, displayVulns)
    }
}
