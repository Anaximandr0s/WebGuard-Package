<?php

namespace MohamedDoukkani\WebGuard;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;



class WebGuard
{
    public function processRequest(Request $request)
    {
        // Apply Custom Rules
        $customRules = $this->getRules();

        // Loop through each rule
        foreach ($customRules as $rule) {
            // Check if the current request matches the rule
            if ($this->matchesRule($request, $rule)) {
                return true;
            }
        }

        // Apply Analyses
        $analyses = $this->getAnalyses();

        // Loop through each Analyse
        foreach ($analyses as $analyse) {
            // Check if the current request matches the Analyse
            if ($this->matchesAnalyse($request, $analyse)) {
                return true;
            }
        }

        return false;
    }


################################################################ CustomRules #################################################

public function getRules()
{
    // Path to the rules file
    $rulesFilePath = __DIR__ . '/database/rules.txt'; // Adjust the path as needed

    // Check if the rules file exists
    if (!file_exists($rulesFilePath)) {
        // Handle the case when the rules file does not exist
        return [];
    }

    // Read the contents of the rules file
    $rulesContent = file_get_contents($rulesFilePath);

    // Split the content into lines
    $rulesLines = explode("\n", $rulesContent);

    // Initialize an array to store the parsed rules
    $customRules = [];

    // Skip the header line (assuming the first line contains column names)
    unset($rulesLines[0]);

    // Parse each rule line
    foreach ($rulesLines as $ruleLine) {
        // Trim any whitespace
        $ruleLine = trim($ruleLine);

        // Skip empty lines
        if (empty($ruleLine)) {
            continue;
        }

        // Split the rule line into fields (assuming fields are separated by commas)
        $ruleFields = explode(",", $ruleLine);

        // Extract rule details from the fields
        $ruleId = $ruleFields[0];
        $ruleName = $ruleFields[1];
        $targetType = $ruleFields[2];
        $content = $ruleFields[3];

        // Create an associative array representing the rule
        $rule = [
            'rule_id' => $ruleId,
            'rule_name' => $ruleName,
            'target_type' => $targetType,
            'content' => $content,
        ];

        // Add the rule to the array of custom rules
        $customRules[] = $rule;
    }

    // Return the parsed custom rules
    return $customRules;
}

protected function matchesRule(Request $request, $rule)
{
    switch ($rule['target_type']) {
        case 'sourceIp':
            return $request->ip() == $rule['content'];
        case 'User-Agent':
            return $request->header('User-Agent') == $rule['content'];
        case 'Path':
            return $request->path() == trim($rule['content'], '/');
        case 'Host':
            return $request->getHost() == $rule['content'];
        case 'Body':
            // Check if the request body contains any word specified in the rule's content
            $body = $request->getContent();
            $keywords = explode(' ', $rule['content']);
            foreach ($keywords as $keyword) {
                if (stripos($body, $keyword) !== false) {
                    return true;
                }
            }
            return false;
        case 'Method':
            return $request->method() == $rule['content'];
        default:
            return false;
    }
}
############################################################### Analyses ####################################################

public function getAnalyses()
{
    // Path to the analyses file
    $analysesFilePath = __DIR__ . '/database/analyses.txt'; // Adjust the path as needed

    // Check if the analyses file exists
    if (!file_exists($analysesFilePath)) {
        // Handle the case when the analyses file does not exist
        return [];
    }

    // Read the contents of the analyses file
    $analysesContent = file_get_contents($analysesFilePath);

    // Split the content into lines
    $analysesLines = explode("\n", $analysesContent);

    // Initialize an array to store the parsed analyses
    $analyses = [];

    // Skip the header line (assuming the first line contains column names)
    unset($analysesLines[0]);

    // Parse each analysis line
    foreach ($analysesLines as $analysisLine) {
        // Trim any whitespace
        $analysisLine = trim($analysisLine);

        // Skip empty lines
        if (empty($analysisLine)) {
            continue;
        }

        // Split the analysis line into fields (assuming fields are separated by commas)
        $analysisFields = explode(",", $analysisLine);

        // Extract analysis details from the fields
        $analysisId = $analysisFields[0];
        $analysisName = $analysisFields[1];
        $analysisType = $analysisFields[2];
        $analysisDescr = $analysisFields[3];

        // Create an associative array representing the analysis
        $analysis = [
            'Analyse_id' => $analysisId,
            'Analyse_Name' => $analysisName,
            'Analyse_Type' => $analysisType,
            'Analyse_Descr' => $analysisDescr,
        ];

        // Add the analysis to the array of analyses
        $analyses[] = $analysis;
    }

    // Return the parsed analyses
    return $analyses;
}

protected function matchesAnalyse(Request $request, $analyse)
{
    switch ($analyse['Analyse_Type']) {
        case 'Blacklist':
            return $this->isBlacklisted($request);
        case 'SQLI':
             return $this->detectSqlInjection($request);
        case 'XSS':
             return $this->detectXss($request);
        case 'Size':
             return $this->isRequestSizeExceeded($request);
        case 'AI':
             return $this->checkForXss($request);
        default:
            return false;
    }
}

public function getBlacklistIPs()
{
    // Path to the blacklist IPs file
    $blacklistFilePath = __DIR__ . '/database/BlackList.txt'; // Adjust the path as needed

    // Check if the file exists
    if (!file_exists($blacklistFilePath)) {
        // Handle the case when the file does not exist
        return [];
    }

    // Read the contents of the file
    $content = file_get_contents($blacklistFilePath);

    // Split the content into lines
    $lines = explode("\n", $content);

    // Initialize an array to store the parsed data
    $blacklistIPs = [];

    // Skip the header line (assuming the first line contains column names)
    unset($lines[0]);

    // Parse each line
    foreach ($lines as $line) {
        // Trim any whitespace
        $line = trim($line);

        // Skip empty lines
        if (empty($line)) {
            continue;
        }

        // Split the line into fields (assuming fields are separated by commas)
        $fields = explode(",", $line);

        // Extract data from fields
        $blacklistIPId = $fields[0];
        $ipAddress = $fields[1];
        $userAgent = $fields[2];

        // Create an associative array representing the blacklist IP
        $blacklistIP = [
            'blacklist_ip_id' => $blacklistIPId,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
        ];

        // Add the blacklist IP to the array
        $blacklistIPs[] = $blacklistIP;
    }

    // Return the parsed data
    return $blacklistIPs;
}

// ///////////////////////////////////////////////// Analyse 1 : Black List Ips ///////////////////////////////////////////////////////
protected function isBlacklisted(Request $request)
{
    // Fetch all blacklisted records
    $blacklistedRecords = $this->getBlacklistIPs();

    foreach ($blacklistedRecords as $record) {
        if ($record['ip_address'] === $request->ip() && $record['user_agent'] === $request->userAgent()) {
            return true;
        }
    }
    return false;
}
// ///////////////////////////////////////////////// Analyse 2 : SQL Injection ///////////////////////////////////////////////////////
protected function detectSqlInjection(Request $request)
{
    // Common SQL injection patterns
    $patterns = [
        '/\bselect\b\s+(?:.*\s+)?\bfrom\b/i',
        '/\bunion\b\s+(?:.*\s+)?\bselect\b/i',
        '/\binsert\b\s+into\b/i',
        '/\border\b\s+by\b/i',
        '/\bupdate\b\s+set\b/i',
        '/\bdelete\b\s+from\b/i',
        '/\bdrop\b\s+table\b/i',
        '/\balter\b\s+table\b/i',
        '/\bcreate\b\s+table\b/i',
        '/\btruncate\b\s+table\b/i',
        '/\bexec\b\s*\(/i',
        '/\bexecute\b\s+immediate\b/i',
        '/\b(?!http)[\w-]+\s*=.*\b(?:exec|execute)\b/i', // Avoid matching URLs with exec or execute
        '/\'\s*(?:OR|AND)\s+\'\s*=\s*\'/i', // Common SQL injection payloads
        '/\bphsql\b/i', // PHSQL function
        '/\bupper\b\s*\(/i', // UPPER function
        '/\blower\b\s*\(/i', // LOWER function
        '/\bmid\b\s*\(/i', // MID function
        '/\blike\b/i', // LIKE operator
        '/\bconcat\b\s*\(/i', // CONCAT function
        '/\bsubstring\b\s*\(/i', // SUBSTRING function
        '/\bcast\b\s*\(/i', // CAST function
        '/\bconvert\b\s*\(/i', // CONVERT function
        '/\bchar\b\s*\(/i', // CHAR function
        '/\bsleep\b\s*\(/i', // SLEEP function, used in time-based SQL injection
        '/\bbenchmark\b\s*\(/i', // BENCHMARK function, used in time-based SQL injection
        '/\bpg_sleep\b\s*\(/i', // pg_sleep function, used in PostgreSQL time-based SQL injection
        '/\bdbms_pipe\.receive_message\b/i', // Oracle-specific function
        '/--/', // SQL comment
        '/;/', // Statement terminator
        '/#/' // Another SQL comment
    ];


    // Check request parameters for SQL injection patterns
    $requestContent = [
        $request->input(),
        $request->getContent(),
        json_encode($request->all())
    ];

    foreach ($requestContent as $content) {
        if ($content && $this->containsSqlInjection($content, $patterns)) {
            return true;
        }
    }

    return false;
}


protected function containsSqlInjection($input, $patterns)
{
    // Convert array input to string
    if (is_array($input)) {
        $input = implode(' ', $input);
    }

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }
    return false;
}

// ///////////////////////////////////////////////// Analyse 3 : XSS ///////////////////////////////////////////////////////

protected function detectXss(Request $request)
{
    // Advanced XSS patterns
    $patterns = [
        // Common HTML tags and attributes
        '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i', // <script>...</script>
        '/<img\b[^>]*\bsrc\b\s*=\s*["\']?javascript:/i', // <img src="javascript:...">
        '/<iframe\b[^>]*>/i', // <iframe>...</iframe>
        '/<object\b[^>]*>/i', // <object>...</object>
        '/<embed\b[^>]*>/i', // <embed>...</embed>
        '/<link\b[^>]*\shref\b\s*=\s*["\']?javascript:/i', // <link href="javascript:...">
        '/<body\b[^>]*\sonload\b\s*=\s*["\']?[^"\'>]*/i', // <body onload="...">
        '/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/i', // <style>...</style>
        '/\bon\w+=["\'][^"\'>]+["\']/i', // on* event handlers

        // JavaScript functions
        '/\beval\s*\(/i', // eval(...)
        '/\balert\s*\(/i', // alert(...)
        '/\bprompt\s*\(/i', // prompt(...)
        '/\bconfirm\s*\(/i', // confirm(...)
        '/\bdocument\.cookie\b/i', // document.cookie
        '/\bwindow\.location\b/i', // window.location
        '/\bdocument\.write\b/i', // document.write

        '/%3C/i', // URL encoded <
        '/%3E/i', // URL encoded >
        '/%253C/i', // URL encoded <
        '/%253E/i', // URL encoded >
        '/&#x3C;/i', // Hexadecimal encoded <
        '/&#x3E;/i', // Hexadecimal encoded >

        // File extension checks
        '/\.js\b/i', // .js files
        '/\.html\b/i', // .html files
        '/\.php\b/i', // .php files
    ];

    // Check request parameters for XSS patterns
    $requestContent = [
        $request->input(),
        $request->getContent(),
        json_encode($request->all())
    ];

    foreach ($requestContent as $content) {
        if ($content && $this->containsXss($content, $patterns)) {
            return true;
        }
    }

    // Check request headers for XSS patterns
    foreach ($request->headers->all() as $key => $values) {
        foreach ($values as $value) {
            if ($this->containsXss($value, $patterns)) {
                return true;
            }
        }
    }

    return false;
}

protected function containsXss($input, $patterns)
{
    // Convert array input to string
    if (is_array($input)) {
        $input = implode(' ', $input);
    }

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }
    return false;
}



///////////////////////////////////////////////// Analyse 5 : Request Size Limitation ///////////////////////////////////////////////////////


protected function isRequestSizeExceeded(Request $request)
{
    $maxRequestSize = 5*1024*1024; // Limit request size to 5 MB
    $requestContent = $request->getContent();
    $requestSize = strlen($requestContent);

    // Check if request size limit is exceeded
    if ($requestSize > $maxRequestSize) {
        return true;
    }
    return false;
}


// ///////////////////////////////////////////////// Analyse 6 : Refferer header validation ///////////////////////////////////////////////////////


protected function isValidReferer(Request $request)
{
    $referer = $request->header('Referer');

    // Check if the Referer header exists
    if (!$referer) {
        // true header is missing, consider it invalid
        return true;
    }

    // List of allowed domains
    $allowedDomains = [
        'example1.com',
        'example2.com',
        'google.com',
        'mozilla.org',
    ];

    // Extract the host part of the referer
    $refererHost = parse_url($referer, PHP_URL_HOST);

    // Check if the referer host matches any of the allowed domains
    foreach ($allowedDomains as $allowedDomain) {
        if (stripos($refererHost, $allowedDomain) !== false) {
            // Referer matches an allowed domain, consider it valid
            return true;
        }
    }

    // If the referer host does not match any of the allowed domains, consider it invalid
    return false;
}


######################################################################## AI Analyse ##############################################
    protected function checkForXss(Request $request): bool
{
      try {
        // Get request query parameters and request body
            $queryParams = $request->input();

        // Check if query parameters or body content are empty
            if (empty($queryParams)) {
                // No data to send, return the request to the next middleware
                return false;
            }

        // Prepare data for the Flask API
        $data = ['url' => $request->fullUrl()];

        // Send request to Flask API
        $response = Http::post('http://192.168.1.102:5000/analyze', $data);

        // Check if the response was successful
        if ($response->successful()) {
            $result = $response->json();
            if ($result['status'] === 'dangerous') {
                return true; // XSS detected
            } else {
                return false; // Safe
            }
        } else {
            // Handle unsuccessful response
            return false; // Assume dangerous if unable to communicate
        } } catch (\Exception $e) {
            // Log any exceptions
            return false; // Assume safe if exception occurs
        }
}



}

