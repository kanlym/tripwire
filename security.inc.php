<?php

//xss mitigation function
function xssafe($data) {
    return htmlspecialchars($data, ENT_QUOTES | ENT_HTML401, 'UTF-8');
}

//xss filter used for arrays
function xss_filter(&$value) {
    $value = htmlspecialchars($value, ENT_QUOTES | ENT_HTML401, 'UTF-8');
}

?>
