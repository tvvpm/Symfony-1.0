<?php
if (in_array($column->getColumn()->getPropelType(), array('VARCHAR', 'LONGVARCHAR', 'DATE', 'DATETIME','CHAR'))) { 
    //PHP7.4 mysql_escape_string a mysql_real_escape_string
    print "'" . mysql_real_escape_string($column->getValue()) . "'";
} else {
    print $column->getValue();
}
?>
