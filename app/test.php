<?php
require( dirname( __FILE__ ) . '/wp-blog-header.php' ); //EDIT THIS PATH SO IT IS CORRECT FOR YOUR test.php file relative to the wp-blog-header.php file
global $wpdb;
$row = $wpdb->get_row( "SHOW STATUS LIKE 'Ssl_cipher'" );
var_dump($row);

/*
If you are connected over SSL this should output something like:
object(stdClass)#116 (2) { ["Variable_name"]=> string(10) "Ssl_cipher" ["Value"]=> string(10) "AES256-SHA" }

If you are NOT connected over SSL this should output something like:
object(stdClass)#116 (2) { ["Variable_name"]=> string(10) "Ssl_cipher" ["Value"]=> string(10) "" }

*/
?>